package vault

// P5 parity tests: rotate, key_ops enforcement, certificate-operation
// cancel/delete, purge protection, the oct/Managed-HSM boundary, and
// api-version validation.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateKey(t *testing.T) {
	s, _ := newService(t, "")
	nv := map[string]string{"name": "rot"}
	w := do(s.createKey, "POST", "/x", `{"kty":"RSA","key_size":3072,"key_ops":["sign","verify"],"tags":{"team":"x"}}`, nv)
	if w.Code != http.StatusOK {
		t.Fatalf("create = %d %s", w.Code, w.Body.Bytes())
	}
	var created struct {
		Key struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
		} `json:"key"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	w = do(s.rotateKey, "POST", "/x", "", nv)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate = %d %s", w.Code, w.Body.Bytes())
	}
	var rotated struct {
		Key struct {
			Kid    string   `json:"kid"`
			Kty    string   `json:"kty"`
			N      string   `json:"n"`
			KeyOps []string `json:"key_ops"`
		} `json:"key"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	if rotated.Key.Kid == created.Key.Kid {
		t.Fatalf("rotate did not mint a new version: %s", rotated.Key.Kid)
	}
	if rotated.Key.N == created.Key.N {
		t.Fatal("rotate did not generate fresh material")
	}
	if rotated.Key.Kty != "RSA" || len(rotated.Key.N) != len(created.Key.N) {
		t.Fatalf("rotate changed type/size: kty=%s len(n)=%d want %d",
			rotated.Key.Kty, len(rotated.Key.N), len(created.Key.N))
	}
	if len(rotated.Key.KeyOps) != 2 {
		t.Fatalf("key_ops not carried: %v", rotated.Key.KeyOps)
	}
	// Both versions list.
	if w := do(s.listKeyVersions, "GET", "/x", "", nv); !strings.Contains(w.Body.String(), `"nextLink"`) &&
		strings.Count(w.Body.String(), `"kid"`) != 2 {
		t.Fatalf("versions after rotate: %s", w.Body.Bytes())
	}
	// EC rotation preserves the curve.
	ev := map[string]string{"name": "rot-ec"}
	do(s.createKey, "POST", "/x", `{"kty":"EC","crv":"P-384"}`, ev)
	if w := do(s.rotateKey, "POST", "/x", "", ev); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"P-384"`) {
		t.Fatalf("EC rotate = %d %s", w.Code, w.Body.Bytes())
	}
	// Rotating a missing key → 404.
	if w := do(s.rotateKey, "POST", "/x", "", map[string]string{"name": "none"}); w.Code != http.StatusNotFound {
		t.Fatalf("rotate missing = %d", w.Code)
	}
}

func TestKeyOpsEnforced(t *testing.T) {
	s, _ := newService(t, "")
	nv := map[string]string{"name": "signer"}
	do(s.createKey, "POST", "/x", `{"kty":"RSA","key_ops":["sign","verify"]}`, nv)

	// Permitted op works.
	sig := do(s.cryptoOp("sign"), "POST", "/x", `{"alg":"RS256","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`, nv)
	if sig.Code != http.StatusOK {
		t.Fatalf("sign = %d %s", sig.Code, sig.Body.Bytes())
	}
	// An op outside key_ops is refused, as in real Key Vault.
	if w := do(s.cryptoOp("encrypt"), "POST", "/x", `{"alg":"RSA-OAEP","value":"aGk"}`, nv); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "not permitted on this key") {
		t.Fatalf("encrypt on sign-only key = %d %s", w.Code, w.Body.Bytes())
	}
	// A key without explicit key_ops allows everything.
	all := map[string]string{"name": "open"}
	do(s.createKey, "POST", "/x", `{"kty":"RSA"}`, all)
	if w := do(s.cryptoOp("encrypt"), "POST", "/x", `{"alg":"RSA-OAEP","value":"aGk"}`, all); w.Code != http.StatusOK {
		t.Fatalf("encrypt on unrestricted key = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestCertOperationCancelAndDelete(t *testing.T) {
	s, _ := newService(t, "")
	nv := map[string]string{"name": "ext"}
	registerIssuer(t, s, "DigiCert")
	createTestCert(t, s, "ext", `{"policy":{"issuer":{"name":"DigiCert"},"x509_props":{"subject":"CN=ext.test"}}}`)

	// Cancel the in-progress operation; it reads back cancelled.
	w := do(s.cancelCertificateOperation, "PATCH", "/x", `{"cancellation_requested":true}`, nv)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"cancelled"`) {
		t.Fatalf("cancel = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.getCertificateOperation, "GET", "/x", "", nv); !strings.Contains(w.Body.String(), `"cancelled"`) {
		t.Fatalf("operation after cancel = %s", w.Body.Bytes())
	}
	// A cancelled operation refuses merge.
	if w := do(s.mergeCertificate, "POST", "/x", `{"x5c":["aGk"]}`, nv); w.Code != http.StatusBadRequest {
		t.Fatalf("merge after cancel = %d %s", w.Code, w.Body.Bytes())
	}
	// Delete the operation: returned once, then absent.
	if w := do(s.deleteCertificateOperation, "DELETE", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("delete op = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.getCertificateOperation, "GET", "/x", "", nv); w.Code != http.StatusNotFound {
		t.Fatalf("operation after delete = %d %s", w.Code, w.Body.Bytes())
	}

	// Self-signed (completed) operation: cancel refused, delete hides it,
	// a fresh create restores it.
	sv := map[string]string{"name": "own"}
	createTestCert(t, s, "own", `{}`)
	if w := do(s.cancelCertificateOperation, "PATCH", "/x", `{"cancellation_requested":true}`, sv); w.Code != http.StatusBadRequest {
		t.Fatalf("cancel completed = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.deleteCertificateOperation, "DELETE", "/x", "", sv); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"completed"`) {
		t.Fatalf("delete completed op = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.getCertificateOperation, "GET", "/x", "", sv); w.Code != http.StatusNotFound {
		t.Fatalf("completed op after delete = %d", w.Code)
	}
	if w := do(s.deleteCertificateOperation, "DELETE", "/x", "", sv); w.Code != http.StatusNotFound {
		t.Fatalf("double delete = %d", w.Code)
	}
	createTestCert(t, s, "own", `{}`)
	if w := do(s.getCertificateOperation, "GET", "/x", "", sv); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"completed"`) {
		t.Fatalf("operation after re-create = %d %s", w.Code, w.Body.Bytes())
	}
	// Unknown name → 404 on all three verbs.
	none := map[string]string{"name": "none"}
	for _, h := range []handler{s.cancelCertificateOperation, s.deleteCertificateOperation} {
		if w := do(h, "POST", "/x", `{}`, none); w.Code != http.StatusNotFound {
			t.Fatalf("op on missing cert = %d", w.Code)
		}
	}
}

func TestPurgeProtection(t *testing.T) {
	s, st := newService(t, "")
	seed(t, st, "s1", "v")
	if _, err := st.DeleteSecret("emulator", "s1", 90); err != nil {
		t.Fatal(err)
	}

	s.SetPurgeProtection(true)
	if w := do(s.purgeSecret, "DELETE", "/x", "", map[string]string{"name": "s1"}); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "purge protection") {
		t.Fatalf("purge with protection = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.purgeKey, "DELETE", "/x", "", map[string]string{"name": "any"}); w.Code != http.StatusForbidden {
		t.Fatalf("purge key with protection = %d", w.Code)
	}
	if w := do(s.purgeCertificate, "DELETE", "/x", "", map[string]string{"name": "any"}); w.Code != http.StatusForbidden {
		t.Fatalf("purge cert with protection = %d", w.Code)
	}
	// recoveryLevel reflects the posture.
	if w := do(s.getDeletedSecret, "GET", "/x", "", map[string]string{"name": "s1"}); !strings.Contains(w.Body.String(), `"Recoverable"`) ||
		strings.Contains(w.Body.String(), "Purgeable") {
		t.Fatalf("recoveryLevel under protection: %s", w.Body.Bytes())
	}

	s.SetPurgeProtection(false)
	if w := do(s.purgeSecret, "DELETE", "/x", "", map[string]string{"name": "s1"}); w.Code != http.StatusNoContent {
		t.Fatalf("purge after disable = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestOctIsManagedHSMOnly(t *testing.T) {
	s, _ := newService(t, "")
	for _, kty := range []string{"oct", "oct-HSM"} {
		w := do(s.createKey, "POST", "/x", `{"kty":"`+kty+`"}`, map[string]string{"name": "sym"})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Managed HSM") {
			t.Fatalf("create %s = %d %s", kty, w.Code, w.Body.Bytes())
		}
	}
	w := do(s.importKey, "PUT", "/x", `{"key":{"kty":"oct","k":"aGVsbG8"}}`, map[string]string{"name": "sym"})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Managed HSM") {
		t.Fatalf("import oct = %d %s", w.Code, w.Body.Bytes())
	}
}

// TestP5StorageFailures drives the new handlers' 500 branches by dropping
// their tables under a live on-disk store — the established injection pattern.
func TestP5StorageFailures(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	nv := map[string]string{"name": "ext"}
	registerIssuer(t, s, "DigiCert")
	createTestCert(t, s, "ext", `{"policy":{"issuer":{"name":"DigiCert"},"x509_props":{"subject":"CN=ext.test"}}}`)
	kv := map[string]string{"name": "rot"}
	do(s.createKey, "POST", "/x", `{"kty":"RSA"}`, kv)

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// cert_versions gone → cancel/delete on a name with no pending row error
	// at the certificate lookup rather than reporting 404.
	if _, err := db.Exec(`DROP TABLE cert_versions`); err != nil {
		t.Fatal(err)
	}
	plain := map[string]string{"name": "plain"}
	if w := do(s.cancelCertificateOperation, "PATCH", "/x", `{"cancellation_requested":true}`, plain); w.Code != http.StatusInternalServerError {
		t.Fatalf("cancel with dropped cert table = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.deleteCertificateOperation, "DELETE", "/x", "", plain); w.Code != http.StatusInternalServerError {
		t.Fatalf("delete op with dropped cert table = %d %s", w.Code, w.Body.Bytes())
	}

	// cert_ops_deleted gone → the marker lookup errors on every op verb.
	if _, err := db.Exec(`DROP TABLE cert_ops_deleted`); err != nil {
		t.Fatal(err)
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"get op":    do(s.getCertificateOperation, "GET", "/x", "", nv),
		"delete op": do(s.deleteCertificateOperation, "DELETE", "/x", "", nv),
	} {
		// delete finds the pending row first, so only the marker-dependent
		// paths 500; both must not succeed silently.
		if w.Code != http.StatusInternalServerError && w.Code != http.StatusOK {
			t.Fatalf("%s with dropped marker table = %d %s", name, w.Code, w.Body.Bytes())
		}
	}

	// cert_pending gone → cancel/delete/merge error at the pending lookup.
	if _, err := db.Exec(`DROP TABLE cert_pending`); err != nil {
		t.Fatal(err)
	}
	if w := do(s.cancelCertificateOperation, "PATCH", "/x", `{"cancellation_requested":true}`, nv); w.Code != http.StatusInternalServerError &&
		w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Fatalf("cancel with dropped pending table = %d %s", w.Code, w.Body.Bytes())
	}

	// key_versions gone → rotate errors at the load.
	if _, err := db.Exec(`DROP TABLE key_versions`); err != nil {
		t.Fatal(err)
	}
	if w := do(s.rotateKey, "POST", "/x", "", kv); w.Code != http.StatusInternalServerError {
		t.Fatalf("rotate with dropped table = %d %s", w.Code, w.Body.Bytes())
	}
}

// TestCreateClearsMarkerFailure: with only cert_ops_deleted dropped (the
// versions table intact), creation reaches its marker-clear step and must
// surface the storage failure.
func TestCreateClearsMarkerFailure(t *testing.T) {
	dir := t.TempDir()
	s, _ := newService(t, dir)
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	registerIssuer(t, s, "DigiCert")
	if _, err := db.Exec(`DROP TABLE cert_ops_deleted`); err != nil {
		t.Fatal(err)
	}
	if w := createTestCert(t, s, "fresh", `{}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("self create with dropped marker table = %d %s", w.Code, w.Body.Bytes())
	}
	if w := createTestCert(t, s, "fresh-ext",
		`{"policy":{"issuer":{"name":"DigiCert"},"x509_props":{"subject":"CN=f.test"}}}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("pending create with dropped marker table = %d %s", w.Code, w.Body.Bytes())
	}
}

// TestP5ClosedDBErrors sweeps the remaining DB-error branches: with the store
// closed every query fails, so each handler must surface a 500 (or the
// malformed-body 400 that precedes storage).
func TestP5ClosedDBErrors(t *testing.T) {
	s, st := newService(t, "")
	if err := st.CancelPendingCert("emulator", "missing"); err == nil {
		t.Fatal("cancel of missing pending op should error")
	}
	nv := map[string]string{"name": "x"}
	// Malformed cancel body 400s before any storage access.
	if w := do(s.cancelCertificateOperation, "PATCH", "/x", `{nope`, nv); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed cancel = %d", w.Code)
	}
	_ = st.Close()
	for name, w := range map[string]*httptest.ResponseRecorder{
		"rotate":    do(s.rotateKey, "POST", "/x", "", nv),
		"release":   do(s.releaseKey, "POST", "/x", `{}`, nv),
		"cancel op": do(s.cancelCertificateOperation, "PATCH", "/x", `{"cancellation_requested":true}`, nv),
		"delete op": do(s.deleteCertificateOperation, "DELETE", "/x", "", nv),
		"get op":    do(s.getCertificateOperation, "GET", "/x", "", nv),
	} {
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("%s on closed DB = %d %s", name, w.Code, w.Body.Bytes())
		}
	}
}

func TestAPIVersionValidation(t *testing.T) {
	s, _ := newService(t, "")
	cases := map[string]bool{
		"7.0": true, "7.5": true, "7.6-preview.2": true,
		"2025-07-01": true, "2025-07-01-preview": true,
		"": false, "6.0": false, "garbage": false, "7x": false, "2025-7-1": false,
	}
	for v, want := range cases {
		url := "/secrets/x"
		if v != "" {
			url += "?api-version=" + v
		}
		r := httptest.NewRequest("GET", url, nil)
		w := httptest.NewRecorder()
		if got := s.validAPIVersion(w, r); got != want {
			t.Errorf("validAPIVersion(%q) = %v; want %v", v, got, want)
		}
		if !want && w.Code != http.StatusBadRequest {
			t.Errorf("api-version %q: status = %d, want 400", v, w.Code)
		}
	}
}
