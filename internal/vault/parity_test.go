package vault

// Direct handler tests for the P4 parity surface: GetRandomBytes, key import,
// key/certificate backup+restore, key rotation policy, certificate
// update/policy-update, and the issuers/contacts sub-resources.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signCSR acts as an external CA: it parses a PKCS#10 CSR and returns a DER
// leaf certificate over the CSR's public key, signed by a throwaway CA.
func signCSR(t *testing.T, csrDER []byte) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Unix(1_600_000_000, 0)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: notBefore, NotAfter: notBefore.AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: csr.Subject,
		NotBefore: notBefore, NotAfter: notBefore.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leaf, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestReleaseKey(t *testing.T) {
	s, _ := newService(t, "")

	// Release on a missing key 404s.
	if w := do(s.releaseKey, "POST", "/x", `{}`, map[string]string{"name": "nope", "version": ""}); w.Code != http.StatusNotFound {
		t.Fatalf("release missing = %d", w.Code)
	}
	createTestKey(t, s, "rk", `{"kty":"RSA"}`)
	v, _ := s.Store.GetKey("emulator", "rk")
	w := do(s.releaseKey, "POST", "/x", `{"target":"aas-attestation","nonce":"n1"}`,
		map[string]string{"name": "rk", "version": v.Version})
	if w.Code != http.StatusOK {
		t.Fatalf("release = %d %s", w.Code, w.Body.Bytes())
	}
	var out struct{ Value string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if parts := strings.Split(out.Value, "."); len(parts) != 3 {
		t.Fatalf("release token is not a 3-part JWS: %q", out.Value)
	} else if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		t.Fatalf("signature segment not base64url: %v", err)
	}

	// A disabled key cannot be released.
	createTestKey(t, s, "off", `{"kty":"RSA","attributes":{"enabled":false}}`)
	ov, _ := s.Store.LatestKeyIncludingDeleted("emulator", "off")
	if w := do(s.releaseKey, "POST", "/x", `{}`, map[string]string{"name": "off", "version": ov.Version}); w.Code != http.StatusForbidden {
		t.Fatalf("release disabled = %d", w.Code)
	}
}

func TestCertMergeFlow(t *testing.T) {
	s, _ := newService(t, "")
	nv := map[string]string{"name": "ext"}

	// A named issuer starts a pending operation exposing a CSR.
	cw := createTestCert(t, s, "ext",
		`{"policy":{"issuer":{"name":"DigiCert"},"x509_props":{"subject":"CN=ext.test"}}}`)
	if cw.Code != http.StatusAccepted {
		t.Fatalf("create pending = %d %s", cw.Code, cw.Body.Bytes())
	}
	op := do(s.getCertificateOperation, "GET", "/x", "", nv)
	if op.Code != http.StatusOK || !strings.Contains(op.Body.String(), `"inProgress"`) {
		t.Fatalf("operation = %d %s", op.Code, op.Body.Bytes())
	}

	p, err := s.Store.GetPendingCert("emulator", "ext")
	if err != nil {
		t.Fatalf("pending missing: %v", err)
	}
	csrDER, _ := base64.StdEncoding.DecodeString(p.CSRDER)

	// Merge missing pending → 404.
	empty, _ := json.Marshal(map[string]any{"x5c": [][]byte{signCSR(t, csrDER)}})
	if w := do(s.mergeCertificate, "POST", "/x", string(empty), map[string]string{"name": "none"}); w.Code != http.StatusNotFound {
		t.Fatalf("merge no pending = %d", w.Code)
	}
	// Bad body / empty chain / non-base64 / valid-base64-but-not-a-cert → 400.
	for _, body := range []string{`{`, `{"x5c":[]}`, `{"x5c":["!!!!"]}`, `{"x5c":["aGVsbG8="]}`} {
		if w := do(s.mergeCertificate, "POST", "/x", body, nv); w.Code != http.StatusBadRequest {
			t.Fatalf("merge %q = %d", body, w.Code)
		}
	}
	// A cert over the wrong key is rejected.
	other, _ := json.Marshal(map[string]any{"x5c": [][]byte{signWrongKey(t)}})
	if w := do(s.mergeCertificate, "POST", "/x", string(other), nv); w.Code != http.StatusBadRequest {
		t.Fatalf("merge wrong key = %d %s", w.Code, w.Body.Bytes())
	}

	// The real merge: sign the CSR, submit the chain, complete the cert.
	good, _ := json.Marshal(map[string]any{"x5c": [][]byte{signCSR(t, csrDER)}, "tags": map[string]string{"t": "1"}})
	mw := do(s.mergeCertificate, "POST", "/x", string(good), nv)
	if mw.Code != http.StatusCreated {
		t.Fatalf("merge = %d %s", mw.Code, mw.Body.Bytes())
	}
	// The certificate is now retrievable, the pending is gone, and the linked
	// key/secret materialized.
	if w := do(s.getCertificate, "GET", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("get merged = %d", w.Code)
	}
	if _, err := s.Store.GetPendingCert("emulator", "ext"); err == nil {
		t.Fatal("pending survived merge")
	}
	if _, err := s.Store.GetKey("emulator", "ext"); err != nil {
		t.Fatalf("linked key missing after merge: %v", err)
	}
	// Operation now reports completed.
	if w := do(s.getCertificateOperation, "GET", "/x", "", nv); !strings.Contains(w.Body.String(), `"completed"`) {
		t.Fatalf("operation after merge = %s", w.Body.Bytes())
	}
}

func TestPendingCertBranches(t *testing.T) {
	s, _ := newService(t, "")

	// An EC key policy exercises the EC CSR path, then a full merge exercises
	// the EC materialize path.
	if w := createTestCert(t, s, "ec-ext",
		`{"policy":{"issuer":{"name":"CA"},"key_props":{"kty":"EC","crv":"P-384"}}}`); w.Code != http.StatusAccepted {
		t.Fatalf("ec pending = %d %s", w.Code, w.Body.Bytes())
	}
	ecp, err := s.Store.GetPendingCert("emulator", "ec-ext")
	if err != nil {
		t.Fatal(err)
	}
	ecCSR, _ := base64.StdEncoding.DecodeString(ecp.CSRDER)
	ecMerge, _ := json.Marshal(map[string]any{"x5c": [][]byte{signCSR(t, ecCSR)}})
	if w := do(s.mergeCertificate, "POST", "/x", string(ecMerge), map[string]string{"name": "ec-ext"}); w.Code != http.StatusCreated {
		t.Fatalf("ec merge = %d %s", w.Code, w.Body.Bytes())
	}
	if k, err := s.Store.GetKey("emulator", "ec-ext"); err != nil || k.Kty != "EC" {
		t.Fatalf("ec linked key = %+v %v", k, err)
	}
	// A bad key policy fails CSR key generation → 400.
	if w := createTestCert(t, s, "bad",
		`{"policy":{"issuer":{"name":"CA"},"key_props":{"kty":"RSA","key_size":123}}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad-key pending = %d", w.Code)
	}
	// Starting a pending op over a soft-deleted name conflicts.
	createTestCert(t, s, "gone", `{"policy":{"issuer":{"name":"Self"}}}`)
	if _, err := s.Store.DeleteCert("emulator", "gone", 90); err != nil {
		t.Fatal(err)
	}
	if w := createTestCert(t, s, "gone", `{"policy":{"issuer":{"name":"CA"}}}`); w.Code != http.StatusConflict {
		t.Fatalf("pending over deleted = %d", w.Code)
	}
}

// TestPendingMergeStorageFailures drops the tables under the pending/merge
// handlers to reach their 500 paths.
func TestPendingMergeStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, st := newService(t, dir)

	// A pending op whose CSR we sign up-front, before breaking the DB.
	createTestCert(t, s, "mp", `{"policy":{"issuer":{"name":"CA"}}}`)
	p, err := st.GetPendingCert("emulator", "mp")
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := base64.StdEncoding.DecodeString(p.CSRDER)
	good, _ := json.Marshal(map[string]any{"x5c": [][]byte{signCSR(t, csr)}})

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Merge fails when it can't persist the completed cert.
	if _, err := db.Exec(`DROP TABLE cert_versions`); err != nil {
		t.Fatal(err)
	}
	if w := do(s.mergeCertificate, "POST", "/x", string(good), map[string]string{"name": "mp"}); w.Code != http.StatusInternalServerError {
		t.Fatalf("merge with no cert_versions = %d", w.Code)
	}
	// Starting a pending op fails when it can't persist the pending row.
	if _, err := db.Exec(`DROP TABLE cert_pending`); err != nil {
		t.Fatal(err)
	}
	if w := createTestCert(t, s, "q", `{"policy":{"issuer":{"name":"CA"}}}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("pending create with no cert_pending = %d", w.Code)
	}
}

// signWrongKey returns a self-signed leaf over a fresh, unrelated key.
func signWrongKey(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Unix(1_600_000_000, 0)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "wrong"},
		NotBefore: notBefore, NotAfter: notBefore.AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func b64uStr(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// rsaImportBody builds a full import-key request body from a fresh RSA key.
func rsaImportBody(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{
		"kty": "RSA",
		"n":   b64uStr(k.N.Bytes()),
		"e":   b64uStr(big.NewInt(int64(k.E)).Bytes()),
		"d":   b64uStr(k.D.Bytes()),
		"p":   b64uStr(k.Primes[0].Bytes()),
		"q":   b64uStr(k.Primes[1].Bytes()),
	}
	raw, _ := json.Marshal(map[string]any{"key": jwk, "attributes": map[string]any{"enabled": true}, "tags": map[string]string{"a": "b"}})
	return string(raw)
}

func ecImportBody(t *testing.T, keyOps []string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{
		"kty":     "EC",
		"crv":     "P-256",
		"x":       b64uStr(k.X.Bytes()),
		"y":       b64uStr(k.Y.Bytes()),
		"d":       b64uStr(k.D.Bytes()),
		"key_ops": keyOps,
	}
	raw, _ := json.Marshal(map[string]any{"key": jwk})
	return string(raw)
}

func TestGetRandomBytes(t *testing.T) {
	s, _ := newService(t, "")
	if w := do(s.getRandomBytes, "POST", "/rng", `{`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", w.Code)
	}
	for _, body := range []string{`{"count":0}`, `{"count":129}`} {
		if w := do(s.getRandomBytes, "POST", "/rng", body, nil); w.Code != http.StatusBadRequest {
			t.Fatalf("count %s = %d", body, w.Code)
		}
	}
	w := do(s.getRandomBytes, "POST", "/rng", `{"count":32}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("rng = %d %s", w.Code, w.Body.Bytes())
	}
	var out struct{ Value string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	b, err := base64.RawURLEncoding.DecodeString(out.Value)
	if err != nil || len(b) != 32 {
		t.Fatalf("value = %q (%d bytes) err=%v", out.Value, len(b), err)
	}
}

func TestImportKey(t *testing.T) {
	s, _ := newService(t, "")
	nv := map[string]string{"name": "imp"}

	// Malformed / missing kty.
	if w := do(s.importKey, "PUT", "/keys/imp", `{`, nv); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", w.Code)
	}
	if w := do(s.importKey, "PUT", "/keys/imp", `{"key":{"kty":""}}`, nv); w.Code != http.StatusBadRequest {
		t.Fatalf("empty kty = %d", w.Code)
	}

	// RSA import, then a real sign proves the private material round-tripped.
	w := do(s.importKey, "PUT", "/keys/imp", rsaImportBody(t), nv)
	if w.Code != http.StatusOK {
		t.Fatalf("rsa import = %d %s", w.Code, w.Body.Bytes())
	}
	if !strings.Contains(w.Body.String(), `"n"`) || !strings.Contains(w.Body.String(), `"a":"b"`) {
		t.Fatalf("import bundle = %s", w.Body.Bytes())
	}
	digest := make([]byte, 32)
	sw := do(s.cryptoOp("sign"), "POST", "/x", `{"alg":"RS256","value":"`+b64uStr(digest)+`"}`, nv)
	if sw.Code != http.StatusOK {
		t.Fatalf("sign with imported = %d %s", sw.Code, sw.Body.Bytes())
	}

	// EC import with explicit key_ops.
	if w := do(s.importKey, "PUT", "/keys/ec", ecImportBody(t, []string{"sign"}), map[string]string{"name": "ec"}); w.Code != http.StatusOK {
		t.Fatalf("ec import = %d %s", w.Code, w.Body.Bytes())
	}

	// Invalid materials.
	bad := map[string]string{
		"rsa missing member": `{"key":{"kty":"RSA","n":"AQAB","e":"AQAB"}}`,
		"rsa bad base64":     `{"key":{"kty":"RSA","n":"!!!","e":"AQAB","d":"AQAB","p":"AQAB","q":"AQAB"}}`,
		"ec bad curve":       `{"key":{"kty":"EC","crv":"P-999","x":"AQAB","y":"AQAB","d":"AQAB"}}`,
		"ec bad point":       `{"key":{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","d":"AQAB"}}`,
		"unsupported kty":    `{"key":{"kty":"OKP","crv":"Ed25519"}}`,
	}
	for name, body := range bad {
		if w := do(s.importKey, "PUT", "/x", body, map[string]string{"name": "b"}); w.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d %s", name, w.Code, w.Body.Bytes())
		}
	}

	// Import onto a soft-deleted name conflicts.
	createTestKey(t, s, "gone", `{"kty":"RSA"}`)
	if _, err := s.Store.DeleteKey("emulator", "gone", 90); err != nil {
		t.Fatal(err)
	}
	if w := do(s.importKey, "PUT", "/x", rsaImportBody(t), map[string]string{"name": "gone"}); w.Code != http.StatusConflict {
		t.Fatalf("import over deleted = %d", w.Code)
	}
}

func TestUpdateKeyLatest(t *testing.T) {
	s, _ := newService(t, "")
	if w := do(s.updateKeyLatest, "PATCH", "/keys/nope", `{}`, map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("missing = %d", w.Code)
	}
	createTestKey(t, s, "k", `{"kty":"RSA"}`)
	w := do(s.updateKeyLatest, "PATCH", "/keys/k", `{"attributes":{"enabled":false},"tags":{"t":"1"}}`, map[string]string{"name": "k"})
	if w.Code != http.StatusOK {
		t.Fatalf("patch latest = %d %s", w.Code, w.Body.Bytes())
	}
	v, _ := s.Store.LatestKeyIncludingDeleted("emulator", "k")
	if v.Enabled {
		t.Fatal("enabled not applied to latest version")
	}
}

func TestKeyBackupRestore(t *testing.T) {
	s, _ := newService(t, "")
	createTestKey(t, s, "bk", `{"kty":"RSA"}`)
	createTestKey(t, s, "bk", `{"kty":"EC"}`)

	if w := do(s.backupKey, "POST", "/x", "", map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("backup missing = %d", w.Code)
	}
	w := do(s.backupKey, "POST", "/x", "", map[string]string{"name": "bk"})
	if w.Code != http.StatusOK {
		t.Fatalf("backup = %d %s", w.Code, w.Body.Bytes())
	}
	var blob struct{ Value string }
	_ = json.Unmarshal(w.Body.Bytes(), &blob)

	// Restore over the live name → 409.
	if w := do(s.restoreKey, "POST", "/x", `{"value":"`+blob.Value+`"}`, nil); w.Code != http.StatusConflict {
		t.Fatalf("restore over live = %d", w.Code)
	}
	// Purge then restore both versions.
	if _, err := s.Store.DeleteKey("emulator", "bk", 90); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.PurgeKey("emulator", "bk"); err != nil {
		t.Fatal(err)
	}
	if w := do(s.restoreKey, "POST", "/x", `{"value":"`+blob.Value+`"}`, nil); w.Code != http.StatusOK {
		t.Fatalf("restore = %d %s", w.Code, w.Body.Bytes())
	}
	if vs, _ := s.Store.ListKeyVersions("emulator", "bk"); len(vs) != 2 {
		t.Fatalf("restored versions = %d", len(vs))
	}
	// Malformed restore bodies.
	for _, body := range []string{`{`, `{"value":"!!!"}`, `{"value":"bm90LWpzb24"}`} {
		if w := do(s.restoreKey, "POST", "/x", body, nil); w.Code != http.StatusBadRequest {
			t.Fatalf("restore %q = %d", body, w.Code)
		}
	}
}

func TestKeyRotationPolicy(t *testing.T) {
	s, _ := newService(t, "")
	nv := map[string]string{"name": "rp"}

	// Policy calls on a missing key 404.
	if w := do(s.getKeyRotationPolicy, "GET", "/x", "", map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d", w.Code)
	}
	if w := do(s.setKeyRotationPolicy, "PUT", "/x", `{}`, map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("set missing = %d", w.Code)
	}

	createTestKey(t, s, "rp", `{"kty":"RSA"}`)

	// Default policy before any set.
	w := do(s.getKeyRotationPolicy, "GET", "/x", "", nv)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "lifetimeActions") {
		t.Fatalf("default policy = %d %s", w.Code, w.Body.Bytes())
	}

	// Malformed set.
	if w := do(s.setKeyRotationPolicy, "PUT", "/x", `{`, nv); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed set = %d", w.Code)
	}
	// Set, then read back.
	pol := `{"lifetimeActions":[{"trigger":{"timeBeforeExpiry":"P30D"},"action":{"type":"Notify"}}],"attributes":{"expiryTime":"P90D"}}`
	if w := do(s.setKeyRotationPolicy, "PUT", "/x", pol, nv); w.Code != http.StatusOK {
		t.Fatalf("set = %d %s", w.Code, w.Body.Bytes())
	}
	w = do(s.getKeyRotationPolicy, "GET", "/x", "", nv)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "P30D") || !strings.Contains(w.Body.String(), "/keys/rp/rotationpolicy") {
		t.Fatalf("get after set = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestCertBackupRestore(t *testing.T) {
	s, _ := newService(t, "")
	// Two versions so restore exercises the loop more than once.
	if w := createTestCert(t, s, "bc", `{"policy":{"issuer":{"name":"Self"}}}`); w.Code != http.StatusAccepted {
		t.Fatalf("create = %d %s", w.Code, w.Body.Bytes())
	}
	if w := createTestCert(t, s, "bc", `{"policy":{"issuer":{"name":"Self"}}}`); w.Code != http.StatusAccepted {
		t.Fatalf("create v2 = %d %s", w.Code, w.Body.Bytes())
	}

	if w := do(s.backupCertificate, "POST", "/x", "", map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("backup missing = %d", w.Code)
	}
	w := do(s.backupCertificate, "POST", "/x", "", map[string]string{"name": "bc"})
	if w.Code != http.StatusOK {
		t.Fatalf("backup = %d %s", w.Code, w.Body.Bytes())
	}
	var blob struct{ Value string }
	_ = json.Unmarshal(w.Body.Bytes(), &blob)

	if w := do(s.restoreCertificate, "POST", "/x", `{"value":"`+blob.Value+`"}`, nil); w.Code != http.StatusConflict {
		t.Fatalf("restore over live = %d", w.Code)
	}

	// Restore #1: purge only the cert, leaving the linked key/secret. Restore
	// must skip re-materializing (the versions already exist).
	purgeCert := func() {
		if _, err := s.Store.DeleteCert("emulator", "bc", 90); err != nil {
			t.Fatal(err)
		}
		if err := s.Store.PurgeCert("emulator", "bc"); err != nil {
			t.Fatal(err)
		}
	}
	purgeCert()
	if w := do(s.restoreCertificate, "POST", "/x", `{"value":"`+blob.Value+`"}`, nil); w.Code != http.StatusOK {
		t.Fatalf("restore (skip materialize) = %d %s", w.Code, w.Body.Bytes())
	}

	// Restore #2: purge the cert and its linked key/secret so restore takes the
	// re-materialize path.
	purgeCert()
	if err := s.Store.PurgeKey("emulator", "bc"); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.PurgeSecret("emulator", "bc"); err != nil {
		t.Fatal(err)
	}
	if w := do(s.restoreCertificate, "POST", "/x", `{"value":"`+blob.Value+`"}`, nil); w.Code != http.StatusOK {
		t.Fatalf("restore (re-materialize) = %d %s", w.Code, w.Body.Bytes())
	}
	// Linked key/secret re-materialized on restore.
	if _, err := s.Store.GetKey("emulator", "bc"); err != nil {
		t.Fatalf("linked key missing after restore: %v", err)
	}
	for _, body := range []string{`{`, `{"value":"!!!"}`, `{"value":"bm90LWpzb24"}`} {
		if w := do(s.restoreCertificate, "POST", "/x", body, nil); w.Code != http.StatusBadRequest {
			t.Fatalf("restore %q = %d", body, w.Code)
		}
	}
}

func TestUpdateCertificateAndPolicy(t *testing.T) {
	s, _ := newService(t, "")
	createTestCert(t, s, "uc", `{"policy":{"issuer":{"name":"Self"}}}`)
	nv := map[string]string{"name": "uc"}

	// Update missing.
	if w := do(s.updateCertificate, "PATCH", "/x", `{}`, map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("update missing = %d", w.Code)
	}
	// Malformed.
	if w := do(s.updateCertificate, "PATCH", "/x", `{`, nv); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", w.Code)
	}
	// Update enabled + tags + policy (no-version form).
	body := `{"attributes":{"enabled":false},"tags":{"t":"1"},"policy":{"x509_props":{"subject":"CN=upd"}}}`
	w := do(s.updateCertificate, "PATCH", "/x", body, nv)
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d %s", w.Code, w.Body.Bytes())
	}
	v, _ := s.Store.GetCert("emulator", "uc")
	if v.Enabled || !strings.Contains(v.PolicyJSON, "CN=upd") {
		t.Fatalf("update not applied: enabled=%v policy=%s", v.Enabled, v.PolicyJSON)
	}

	// Policy update endpoint.
	if w := do(s.updateCertificatePolicy, "PATCH", "/x", `{}`, map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("policy update missing = %d", w.Code)
	}
	if w := do(s.updateCertificatePolicy, "PATCH", "/x", `{`, nv); w.Code != http.StatusBadRequest {
		t.Fatalf("policy update malformed = %d", w.Code)
	}
	if w := do(s.updateCertificatePolicy, "PATCH", "/x", `{"key_props":{"kty":"EC"}}`, nv); w.Code != http.StatusOK {
		t.Fatalf("policy update = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestCertIssuers(t *testing.T) {
	s, _ := newService(t, "")
	nv := map[string]string{"name": "iss"}

	if w := do(s.getCertIssuer, "GET", "/x", "", nv); w.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d", w.Code)
	}
	if w := do(s.deleteCertIssuer, "DELETE", "/x", "", nv); w.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d", w.Code)
	}
	if w := do(s.setCertIssuer, "PUT", "/x", `{`, nv); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed set = %d", w.Code)
	}

	set := do(s.setCertIssuer, "PUT", "/x", `{"provider":"Test","credentials":{"account_id":"a"}}`, nv)
	if set.Code != http.StatusOK || !strings.Contains(set.Body.String(), "/certificates/issuers/iss") {
		t.Fatalf("set = %d %s", set.Code, set.Body.Bytes())
	}
	if w := do(s.getCertIssuer, "GET", "/x", "", nv); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Test") {
		t.Fatalf("get = %d %s", w.Code, w.Body.Bytes())
	}
	// Update (PATCH shares setCertIssuer).
	if w := do(s.setCertIssuer, "PATCH", "/x", `{"provider":"Test2"}`, nv); w.Code != http.StatusOK {
		t.Fatalf("patch = %d", w.Code)
	}
	lw := do(s.listCertIssuers, "GET", "/certificates/issuers?api-version=7.5", "", nil)
	if lw.Code != http.StatusOK || !strings.Contains(lw.Body.String(), "Test2") {
		t.Fatalf("list = %d %s", lw.Code, lw.Body.Bytes())
	}
	if w := do(s.deleteCertIssuer, "DELETE", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("delete = %d", w.Code)
	}
	if w := do(s.getCertIssuer, "GET", "/x", "", nv); w.Code != http.StatusNotFound {
		t.Fatalf("get after delete = %d", w.Code)
	}

	// A stored document that unmarshals to nil still renders with an id.
	if err := s.Store.SetCertIssuer("emulator", "nul", "null"); err != nil {
		t.Fatal(err)
	}
	if w := do(s.getCertIssuer, "GET", "/x", "", map[string]string{"name": "nul"}); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "/certificates/issuers/nul") {
		t.Fatalf("null issuer = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestCertContacts(t *testing.T) {
	s, _ := newService(t, "")
	if w := do(s.getCertContacts, "GET", "/certificates/contacts", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("get empty = %d", w.Code)
	}
	if w := do(s.deleteCertContacts, "DELETE", "/certificates/contacts", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("delete empty = %d", w.Code)
	}
	if w := do(s.setCertContacts, "PUT", "/certificates/contacts", `{`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", w.Code)
	}
	set := do(s.setCertContacts, "PUT", "/certificates/contacts", `{"contacts":[{"email":"a@b.com"}]}`, nil)
	if set.Code != http.StatusOK || !strings.Contains(set.Body.String(), "/certificates/contacts") {
		t.Fatalf("set = %d %s", set.Code, set.Body.Bytes())
	}
	if w := do(s.getCertContacts, "GET", "/certificates/contacts", "", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "a@b.com") {
		t.Fatalf("get = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.deleteCertContacts, "DELETE", "/certificates/contacts", "", nil); w.Code != http.StatusOK {
		t.Fatalf("delete = %d", w.Code)
	}

	// A stored document that unmarshals to nil still renders with an id.
	if err := s.Store.SetCertContacts("emulator", "null"); err != nil {
		t.Fatal(err)
	}
	if w := do(s.getCertContacts, "GET", "/certificates/contacts", "", nil); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "/certificates/contacts") {
		t.Fatalf("null contacts = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestCryptoParityHelpers(t *testing.T) {
	// b64uDecode tolerates padded input.
	if _, err := b64uDecode(base64.URLEncoding.EncodeToString([]byte("hello"))); err != nil {
		t.Fatalf("padded decode: %v", err)
	}
	if _, err := b64uDecode("!!!"); err == nil {
		t.Fatal("expected error on garbage")
	}
	// ktyOf on a non-key returns "".
	if got := ktyOf("not a key"); got != "" {
		t.Fatalf("ktyOf non-key = %q", got)
	}
	// randomBytes bounds.
	if _, err := randomBytes(0); err == nil {
		t.Fatal("expected error for count 0")
	}
	if b, err := randomBytes(16); err != nil || len(b) != 16 {
		t.Fatalf("randomBytes(16) = %v %v", len(b), err)
	}
}

// TestParityStorageFailures drops the backing tables under live handlers to
// exercise the 500 paths in the parity store methods.
func TestParityStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, st := newService(t, dir)
	createTestKey(t, s, "k", `{"kty":"RSA"}`)
	if err := st.SetKeyRotationPolicy("emulator", "k", `{"id":"x"}`); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCertIssuer("emulator", "iss", `{"provider":"P"}`); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCertContacts("emulator", `{"contacts":[]}`); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tbl := range []string{"key_rotation_policies", "cert_issuers", "cert_contacts"} {
		if _, err := db.Exec(`DROP TABLE ` + tbl); err != nil {
			t.Fatal(err)
		}
	}

	cases := map[string]*httptest.ResponseRecorder{
		"get rotation":  do(s.getKeyRotationPolicy, "GET", "/x", "", map[string]string{"name": "k"}),
		"set rotation":  do(s.setKeyRotationPolicy, "PUT", "/x", `{}`, map[string]string{"name": "k"}),
		"get issuer":    do(s.getCertIssuer, "GET", "/x", "", map[string]string{"name": "iss"}),
		"set issuer":    do(s.setCertIssuer, "PUT", "/x", `{}`, map[string]string{"name": "iss"}),
		"delete issuer": do(s.deleteCertIssuer, "DELETE", "/x", "", map[string]string{"name": "iss"}),
		"list issuers":  do(s.listCertIssuers, "GET", "/certificates/issuers", "", nil),
		"get contacts":  do(s.getCertContacts, "GET", "/certificates/contacts", "", nil),
		"set contacts":  do(s.setCertContacts, "PUT", "/certificates/contacts", `{}`, nil),
		"del contacts":  do(s.deleteCertContacts, "DELETE", "/certificates/contacts", "", nil),
	}
	for name, w := range cases {
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with no table = %d; want 500", name, w.Code)
		}
	}
}

// TestParityVersionStorageFailures drops the key/cert version tables to reach
// the 500 paths in import, update, and restore.
func TestParityVersionStorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	createTestKey(t, s, "k", `{"kty":"RSA"}`)
	if w := createTestCert(t, s, "c", `{"policy":{"issuer":{"name":"Self"}}}`); w.Code != http.StatusAccepted {
		t.Fatal("cert create failed")
	}
	// Grab valid backup blobs before dropping the tables.
	kb := do(s.backupKey, "POST", "/x", "", map[string]string{"name": "k"})
	cb := do(s.backupCertificate, "POST", "/x", "", map[string]string{"name": "c"})
	var kblob, cblob struct{ Value string }
	_ = json.Unmarshal(kb.Body.Bytes(), &kblob)
	_ = json.Unmarshal(cb.Body.Bytes(), &cblob)

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tbl := range []string{"key_versions", "cert_versions"} {
		if _, err := db.Exec(`DROP TABLE ` + tbl); err != nil {
			t.Fatal(err)
		}
	}

	cases := map[string]*httptest.ResponseRecorder{
		"import key":   do(s.importKey, "PUT", "/x", rsaImportBody(t), map[string]string{"name": "k2"}),
		"update key":   do(s.updateKeyLatest, "PATCH", "/x", `{}`, map[string]string{"name": "k"}),
		"restore key":  do(s.restoreKey, "POST", "/x", `{"value":"`+kblob.Value+`"}`, nil),
		"update cert":  do(s.updateCertificate, "PATCH", "/x", `{"attributes":{"enabled":false}}`, map[string]string{"name": "c"}),
		"cert policy":  do(s.updateCertificatePolicy, "PATCH", "/x", `{}`, map[string]string{"name": "c"}),
		"restore cert": do(s.restoreCertificate, "POST", "/x", `{"value":"`+cblob.Value+`"}`, nil),
	}
	for name, w := range cases {
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with no table = %d; want 500", name, w.Code)
		}
	}
}
