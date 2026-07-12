package server_test

// P4 e2e: the real azkeys / azcertificates SDKs drive the parity surface —
// key import, GetRandomBytes, key + certificate backup/restore, key rotation
// policy, and the certificate issuers/contacts sub-resources. Proves the wire
// shapes match what the SDKs emit and expect, not just our own handlers.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func TestAzkeysImportAndSign(t *testing.T) {
	f := newFixture(t)
	kc := f.keysClient(t)
	ctx := context.Background()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := &azkeys.JSONWebKey{
		Kty: to.Ptr(azkeys.KeyTypeRSA),
		N:   k.N.Bytes(),
		E:   big.NewInt(int64(k.E)).Bytes(),
		D:   k.D.Bytes(),
		P:   k.Primes[0].Bytes(),
		Q:   k.Primes[1].Bytes(),
	}
	imported, err := kc.ImportKey(ctx, "imported", azkeys.ImportKeyParameters{Key: jwk}, nil)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if imported.Key == nil || len(imported.Key.N) == 0 {
		t.Fatalf("import bundle missing public material: %+v", imported.Key)
	}

	// The imported private key really signs: a signature the emulator produces
	// verifies against the caller's own public key.
	digest := sha256.Sum256([]byte("imported material"))
	signed, err := kc.Sign(ctx, "imported", "", azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256),
		Value:     digest[:],
	}, nil)
	if err != nil {
		t.Fatalf("Sign with imported: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], signed.Result); err != nil {
		t.Fatalf("imported-key signature does not verify against the source key: %v", err)
	}
}

func TestAzkeysRandomBytes(t *testing.T) {
	f := newFixture(t)
	kc := f.keysClient(t)
	resp, err := kc.GetRandomBytes(context.Background(), azkeys.GetRandomBytesParameters{Count: to.Ptr(int32(32))}, nil)
	if err != nil {
		t.Fatalf("GetRandomBytes: %v", err)
	}
	if len(resp.Value) != 32 {
		t.Fatalf("random bytes = %d; want 32", len(resp.Value))
	}
}

func TestAzkeysBackupRestore(t *testing.T) {
	f := newFixture(t)
	kc := f.keysClient(t)
	ctx := context.Background()

	if _, err := kc.CreateKey(ctx, "bk", azkeys.CreateKeyParameters{Kty: to.Ptr(azkeys.KeyTypeRSA)}, nil); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	backup, err := kc.BackupKey(ctx, "bk", nil)
	if err != nil {
		t.Fatalf("BackupKey: %v", err)
	}
	// Purge so restore has an empty name to land in.
	if _, err := kc.DeleteKey(ctx, "bk", nil); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if _, err := kc.PurgeDeletedKey(ctx, "bk", nil); err != nil {
		t.Fatalf("PurgeDeletedKey: %v", err)
	}
	restored, err := kc.RestoreKey(ctx, azkeys.RestoreKeyParameters{KeyBackup: backup.Value}, nil)
	if err != nil {
		t.Fatalf("RestoreKey: %v", err)
	}
	if restored.Key == nil || restored.Key.KID.Name() != "bk" {
		t.Fatalf("restored key = %+v", restored.Key)
	}
}

func TestAzkeysRotationPolicy(t *testing.T) {
	f := newFixture(t)
	kc := f.keysClient(t)
	ctx := context.Background()

	if _, err := kc.CreateKey(ctx, "rp", azkeys.CreateKeyParameters{Kty: to.Ptr(azkeys.KeyTypeRSA)}, nil); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	// Unset policy deserializes cleanly (the disabled-rotation default).
	if _, err := kc.GetKeyRotationPolicy(ctx, "rp", nil); err != nil {
		t.Fatalf("GetKeyRotationPolicy (default): %v", err)
	}
	policy := azkeys.KeyRotationPolicy{
		Attributes: &azkeys.KeyRotationPolicyAttributes{ExpiryTime: to.Ptr("P90D")},
		LifetimeActions: []*azkeys.LifetimeAction{{
			Trigger: &azkeys.LifetimeActionTrigger{TimeBeforeExpiry: to.Ptr("P30D")},
			Action:  &azkeys.LifetimeActionType{Type: to.Ptr(azkeys.KeyRotationPolicyActionNotify)},
		}},
	}
	if _, err := kc.UpdateKeyRotationPolicy(ctx, "rp", policy, nil); err != nil {
		t.Fatalf("UpdateKeyRotationPolicy: %v", err)
	}
	got, err := kc.GetKeyRotationPolicy(ctx, "rp", nil)
	if err != nil {
		t.Fatalf("GetKeyRotationPolicy: %v", err)
	}
	if len(got.LifetimeActions) != 1 || got.Attributes == nil || *got.Attributes.ExpiryTime != "P90D" {
		t.Fatalf("rotation policy did not round-trip: %+v", got.KeyRotationPolicy)
	}
}

func TestAzcertificatesBackupRestore(t *testing.T) {
	f := newFixture(t)
	cc := f.certsClient(t)
	ctx := context.Background()

	if _, err := cc.CreateCertificate(ctx, "bc", azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			IssuerParameters:          &azcertificates.IssuerParameters{Name: to.Ptr("Self")},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{Subject: to.Ptr("CN=backup.test")},
		},
	}, nil); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	backup, err := cc.BackupCertificate(ctx, "bc", nil)
	if err != nil {
		t.Fatalf("BackupCertificate: %v", err)
	}
	if _, err := cc.DeleteCertificate(ctx, "bc", nil); err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
	if _, err := cc.PurgeDeletedCertificate(ctx, "bc", nil); err != nil {
		t.Fatalf("PurgeDeletedCertificate: %v", err)
	}
	if _, err := cc.RestoreCertificate(ctx, azcertificates.RestoreCertificateParameters{CertificateBackup: backup.Value}, nil); err != nil {
		t.Fatalf("RestoreCertificate: %v", err)
	}
	if _, err := cc.GetCertificate(ctx, "bc", "", nil); err != nil {
		t.Fatalf("GetCertificate after restore: %v", err)
	}
}

func TestAzcertificatesIssuers(t *testing.T) {
	f := newFixture(t)
	cc := f.certsClient(t)
	ctx := context.Background()

	if _, err := cc.SetIssuer(ctx, "myca", azcertificates.SetIssuerParameters{Provider: to.Ptr("Test")}, nil); err != nil {
		t.Fatalf("SetIssuer: %v", err)
	}
	got, err := cc.GetIssuer(ctx, "myca", nil)
	if err != nil {
		t.Fatalf("GetIssuer: %v", err)
	}
	if got.Provider == nil || *got.Provider != "Test" {
		t.Fatalf("issuer provider = %+v", got.Provider)
	}
	pager := cc.NewListIssuerPropertiesPager(nil)
	found := false
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatalf("list issuers: %v", err)
		}
		for _, it := range page.Value {
			if it.ID != nil && strings.HasSuffix(*it.ID, "/myca") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("issuer missing from list pager")
	}
	if _, err := cc.DeleteIssuer(ctx, "myca", nil); err != nil {
		t.Fatalf("DeleteIssuer: %v", err)
	}
}

func TestAzkeysRelease(t *testing.T) {
	f := newFixture(t)
	kc := f.keysClient(t)
	ctx := context.Background()

	created, err := kc.CreateKey(ctx, "releasable", azkeys.CreateKeyParameters{Kty: to.Ptr(azkeys.KeyTypeRSA)}, nil)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	resp, err := kc.Release(ctx, "releasable", created.Key.KID.Version(), azkeys.ReleaseParameters{
		TargetAttestationToken: to.Ptr("emulator-attestation"),
	}, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if resp.Value == nil || len(strings.Split(*resp.Value, ".")) != 3 {
		t.Fatalf("release value is not a signed JWS: %v", resp.Value)
	}
}

func TestAzcertificatesMerge(t *testing.T) {
	f := newFixture(t)
	cc := f.certsClient(t)
	ctx := context.Background()

	// A named issuer produces a pending operation with a CSR.
	op, err := cc.CreateCertificate(ctx, "external", azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			IssuerParameters:          &azcertificates.IssuerParameters{Name: to.Ptr("MyExternalCA")},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{Subject: to.Ptr("CN=external.test")},
		},
	}, nil)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if op.Status == nil || *op.Status != "inProgress" || len(op.CSR) == 0 {
		t.Fatalf("expected inProgress operation with CSR, got status=%v csrLen=%d", op.Status, len(op.CSR))
	}

	// Act as the external CA: sign the CSR.
	leaf := signCSRAsCA(t, op.CSR)

	merged, err := cc.MergeCertificate(ctx, "external", azcertificates.MergeCertificateParameters{
		X509Certificates: [][]byte{leaf},
	}, nil)
	if err != nil {
		t.Fatalf("MergeCertificate: %v", err)
	}
	if len(merged.CER) == 0 {
		t.Fatal("merged certificate has no CER")
	}
	if _, err := cc.GetCertificate(ctx, "external", "", nil); err != nil {
		t.Fatalf("GetCertificate after merge: %v", err)
	}
}

// signCSRAsCA parses a CSR and returns a DER leaf signed by a throwaway CA over
// the CSR's public key — the external-issuer half of the merge flow.
func signCSRAsCA(t *testing.T, csrDER []byte) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Unix(1_600_000_000, 0)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "External CA"},
		NotBefore: nb, NotAfter: nb.AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: csr.Subject,
		NotBefore: nb, NotAfter: nb.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leaf, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestAzcertificatesContacts(t *testing.T) {
	f := newFixture(t)
	cc := f.certsClient(t)
	ctx := context.Background()

	set, err := cc.SetContacts(ctx, azcertificates.Contacts{
		ContactList: []*azcertificates.Contact{{Email: to.Ptr("admin@example.com")}},
	}, nil)
	if err != nil {
		t.Fatalf("SetContacts: %v", err)
	}
	if len(set.ContactList) != 1 || *set.ContactList[0].Email != "admin@example.com" {
		t.Fatalf("set contacts = %+v", set.ContactList)
	}
	got, err := cc.GetContacts(ctx, nil)
	if err != nil {
		t.Fatalf("GetContacts: %v", err)
	}
	if len(got.ContactList) != 1 {
		t.Fatalf("get contacts = %+v", got.ContactList)
	}
	if _, err := cc.DeleteContacts(ctx, nil); err != nil {
		t.Fatalf("DeleteContacts: %v", err)
	}
}
