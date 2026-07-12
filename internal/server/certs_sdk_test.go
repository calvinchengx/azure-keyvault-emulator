package server_test

// P2 e2e: the real azcertificates SDK creates a self-signed certificate and
// imports one. The interop proof: the emulator-issued cert is a genuine,
// parseable X.509 whose public key matches the materialized /keys entry, and
// the certificate's private key is retrievable as the linked /secrets PFX.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func (f *fixture) certsClient(t *testing.T) *azcertificates.Client {
	t.Helper()
	transport := &combinedTransport{
		entraHost: strings.TrimPrefix(f.emu.Origin, "https://"),
		entra:     f.emu.HTTPClient(),
		vault:     f.kv.Client(),
	}
	c, err := azcertificates.NewClient(f.kv.URL, f.creds, &azcertificates.ClientOptions{
		ClientOptions:                        policy.ClientOptions{Transport: transport},
		DisableChallengeResourceVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAzcertificatesSelfSignedLifecycle(t *testing.T) {
	f := newFixture(t)
	cc := f.certsClient(t)
	ctx := context.Background()

	subject := "CN=emulator.example.com"
	created, err := cc.CreateCertificate(ctx, "web", azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			IssuerParameters: &azcertificates.IssuerParameters{Name: to.Ptr("Self")},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{
				Subject:                 to.Ptr(subject),
				SubjectAlternativeNames: &azcertificates.SubjectAlternativeNames{DNSNames: to.SliceOfPtrs("emulator.example.com")},
			},
			KeyProperties: &azcertificates.KeyProperties{KeyType: to.Ptr(azcertificates.KeyTypeRSA), KeySize: to.Ptr(int32(2048))},
		},
	}, nil)
	if err != nil {
		t.Fatalf("CreateCertificate via real SDK: %v", err)
	}
	if created.Status == nil || *created.Status != "completed" {
		t.Fatalf("operation status = %v", created.Status)
	}

	// Poll the operation (SDK path the real client uses).
	op, err := cc.GetCertificateOperation(ctx, "web", nil)
	if err != nil || op.Status == nil || *op.Status != "completed" {
		t.Fatalf("GetCertificateOperation = %v, %v", op.Status, err)
	}

	got, err := cc.GetCertificate(ctx, "web", "", nil)
	if err != nil || len(got.CER) == 0 {
		t.Fatalf("GetCertificate: %v", err)
	}
	// Interop: CER is a genuine, parseable X.509 with our subject + SAN.
	cert, err := x509.ParseCertificate(got.CER)
	if err != nil {
		t.Fatalf("emulator CER is not a valid X.509: %v", err)
	}
	if cert.Subject.CommonName != "emulator.example.com" {
		t.Fatalf("subject CN = %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "emulator.example.com" {
		t.Fatalf("SANs = %v", cert.DNSNames)
	}
	if got.KID == nil || got.SID == nil {
		t.Fatalf("cert bundle missing kid/sid: %+v", got)
	}

	// Linked key: the materialized /keys entry exists with a public JWK.
	kc := f.keysClient(t)
	key, err := kc.GetKey(ctx, "web", "", nil)
	if err != nil {
		t.Fatalf("linked GetKey: %v", err)
	}
	if key.Key == nil || len(key.Key.N) == 0 {
		t.Fatalf("linked key JWK missing: %+v", key.Key)
	}

	// Linked secret: the PFX-equivalent bundle carries the private key.
	sc := f.client(t)
	secret, err := sc.GetSecret(ctx, "web", "", nil)
	if err != nil || secret.Value == nil {
		t.Fatalf("linked GetSecret: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(*secret.Value)
	if err != nil {
		t.Fatalf("secret not base64: %v", err)
	}
	var bundle struct{ Key, Cer string }
	if err := json.Unmarshal(raw, &bundle); err != nil || bundle.Key == "" {
		t.Fatalf("secret bundle = %s (%v)", raw, err)
	}

	// Soft delete → recover.
	if _, err := cc.DeleteCertificate(ctx, "web", nil); err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
	if _, err := cc.GetCertificate(ctx, "web", "", nil); err == nil {
		t.Fatal("deleted certificate still readable")
	}
	if _, err := cc.RecoverDeletedCertificate(ctx, "web", nil); err != nil {
		t.Fatalf("RecoverDeletedCertificate: %v", err)
	}
	if _, err := cc.GetCertificate(ctx, "web", "", nil); err != nil {
		t.Fatalf("recovered certificate unreadable: %v", err)
	}

	// List pager sees it.
	pager := cc.NewListCertificatePropertiesPager(nil)
	found := false
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range page.Value {
			if it.ID != nil && it.ID.Name() == "web" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("recovered certificate missing from list")
	}
}

func TestAzcertificatesImportPKCS12(t *testing.T) {
	f := newFixture(t)
	cc := f.certsClient(t)
	ctx := context.Background()

	// Build a real self-signed cert + key, encode as PFX, import it.
	certDER, keyDER := selfSignedPair(t)
	cert, _ := x509.ParseCertificate(certDER)
	key, _ := x509.ParsePKCS8PrivateKey(keyDER)
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	imported, err := cc.ImportCertificate(ctx, "imported", azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: to.Ptr(base64.StdEncoding.EncodeToString(pfx)),
	}, nil)
	if err != nil {
		t.Fatalf("ImportCertificate: %v", err)
	}
	if len(imported.CER) == 0 {
		t.Fatal("imported cert has no CER")
	}
	roundTrip, err := x509.ParseCertificate(imported.CER)
	if err != nil || roundTrip.Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("imported CER mismatch: %v", err)
	}

	// PEM import too.
	pemBundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if _, err := cc.ImportCertificate(ctx, "imported-pem", azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: to.Ptr(base64.StdEncoding.EncodeToString([]byte(pemBundle))),
	}, nil); err != nil {
		t.Fatalf("PEM ImportCertificate: %v", err)
	}
}

// selfSignedPair builds a real self-signed cert + PKCS#8 key for import tests.
func selfSignedPair(t *testing.T) (certDER, keyDER []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "imported.example.com"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
	}
	certDER, err = x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyDER
}
