package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func makeCert(t *testing.T, key any, pub any) []byte {
	t.Helper()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unit.test"},
		NotBefore:    time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseImportPEMVariants(t *testing.T) {
	// RSA via PKCS#8 block.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER := makeCert(t, rsaKey, &rsaKey.PublicKey)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pemBundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	if _, _, _, _, _, kty, err := parseImport(pemBundle, ""); err != nil || kty != "RSA" {
		t.Fatalf("PKCS8 PEM = kty %q, %v", kty, err)
	}

	// RSA via PKCS#1 block, base64-wrapped.
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	pem1 := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1}))
	if _, _, _, _, _, _, err := parseImport(base64.StdEncoding.EncodeToString([]byte(pem1)), ""); err != nil {
		t.Fatalf("PKCS1 PEM: %v", err)
	}

	// EC via EC PRIVATE KEY block.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecCert := makeCert(t, ecKey, &ecKey.PublicKey)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecCert})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))
	if _, _, _, _, _, kty, err := parseImport(ecPEM, ""); err != nil || kty != "EC" {
		t.Fatalf("EC PEM = kty %q, %v", kty, err)
	}

	// Cert-only PEM (no key) still imports.
	certOnly := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	if _, priv, _, _, _, _, err := parseImport(certOnly, ""); err != nil || priv != "" {
		t.Fatalf("cert-only PEM: priv=%q %v", priv, err)
	}

	// PEM with no certificate block errors.
	if _, _, _, _, _, _, err := parseImport(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), ""); err == nil {
		t.Fatal("PEM without cert accepted")
	}
}

// TestImportMaterializesKeyAndSecret drives the handler happy path so the
// linked key/secret materialization is covered end to end.
func TestImportMaterializesKeyAndSecret(t *testing.T) {
	s, st := newService(t, "")
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER := makeCert(t, rsaKey, &rsaKey.PublicKey)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	pemBundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	body := `{"value":"` + base64.StdEncoding.EncodeToString([]byte(pemBundle)) + `"}`
	if w := do(s.importCertificate, "POST", "/x", body, map[string]string{"name": "imp"}); w.Code != http.StatusOK {
		t.Fatalf("import = %d %s", w.Code, w.Body.Bytes())
	}
	if _, err := st.GetKey("emulator", "imp"); err != nil {
		t.Fatalf("linked key missing: %v", err)
	}
	if _, err := st.GetSecret("emulator", "imp"); err != nil {
		t.Fatalf("linked secret missing: %v", err)
	}
}
