package vault

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func createTestCert(t *testing.T, s *Service, name, body string) *httptest.ResponseRecorder {
	t.Helper()
	return do(s.createCertificate, "POST", "/x", body, map[string]string{"name": name})
}

func TestCreateCertificateBranches(t *testing.T) {
	s, _ := newService(t, "")

	if w := createTestCert(t, s, "c", `{`); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", w.Code)
	}
	// A non-Self issuer starts an async (pending) operation, not a rejection.
	if w := createTestCert(t, s, "ext", `{"policy":{"issuer":{"name":"DigiCert"}}}`); w.Code != http.StatusAccepted {
		t.Fatalf("non-Self issuer = %d %s", w.Code, w.Body.Bytes())
	} else if !strings.Contains(w.Body.String(), `"inProgress"`) || !strings.Contains(w.Body.String(), `"csr"`) {
		t.Fatalf("pending op = %s", w.Body.Bytes())
	}
	// Bad key policy → 400 from generateKey.
	if w := createTestCert(t, s, "c", `{"policy":{"key_props":{"kty":"RSA","key_size":123}}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad key_size = %d", w.Code)
	}
	// Self-signed with subject + SAN + EC key + validity.
	w := createTestCert(t, s, "web",
		`{"policy":{"issuer":{"name":"Self"},"key_props":{"kty":"EC","crv":"P-256"},"x509_props":{"subject":"CN=x.test","sans":{"dns_names":["x.test"]},"validity_months":6}},"tags":{"a":"b"}}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create = %d %s", w.Code, w.Body.Bytes())
	}
	var op struct{ Status, Target string }
	_ = json.Unmarshal(w.Body.Bytes(), &op)
	if op.Status != "completed" {
		t.Fatalf("op = %+v", op)
	}
	// Materialized key + secret exist under the same name.
	if _, err := s.Store.GetKey("emulator", "web"); err != nil {
		t.Fatalf("linked key missing: %v", err)
	}
	if _, err := s.Store.GetSecret("emulator", "web"); err != nil {
		t.Fatalf("linked secret missing: %v", err)
	}
	// Conflict while soft-deleted.
	if _, err := s.Store.DeleteCert("emulator", "web", 90); err != nil {
		t.Fatal(err)
	}
	if w := createTestCert(t, s, "web", `{}`); w.Code != http.StatusConflict {
		t.Fatalf("create over deleted = %d", w.Code)
	}
}

func TestCertGetPolicyOperationErrors(t *testing.T) {
	s, _ := newService(t, "")
	if w := do(s.getCertificate, "GET", "/x", "", map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d", w.Code)
	}
	if w := do(s.getCertificatePolicy, "GET", "/x", "", map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("policy missing = %d", w.Code)
	}
	if w := do(s.getCertificateOperation, "GET", "/x", "", map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("operation missing = %d", w.Code)
	}
	createTestCert(t, s, "c", `{"policy":{"x509_props":{"subject":"CN=c"}}}`)
	if w := do(s.getCertificate, "GET", "/x", "", map[string]string{"name": "c"}); w.Code != http.StatusOK {
		t.Fatalf("get = %d", w.Code)
	}
	w := do(s.getCertificatePolicy, "GET", "/x", "", map[string]string{"name": "c"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "x509_props") {
		t.Fatalf("policy = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.getCertificateOperation, "GET", "/x", "", map[string]string{"name": "c"}); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "completed") {
		t.Fatalf("operation = %d %s", w.Code, w.Body.Bytes())
	}
	// List + versions.
	createTestCert(t, s, "c", `{}`) // second version
	w = do(s.listCertificateVersions, "GET", "/x?api-version=7.5", "", map[string]string{"name": "c"})
	var page struct{ Value []map[string]any }
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Value) != 2 {
		t.Fatalf("versions = %s", w.Body.Bytes())
	}
	w = do(s.listCertificates, "GET", "/certificates?api-version=7.5", "", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Value) != 1 {
		t.Fatalf("list = %s", w.Body.Bytes())
	}
	// Never-existed name lists empty (200); soft-deleted 404s.
	if w := do(s.listCertificateVersions, "GET", "/x?api-version=7.5", "", map[string]string{"name": "nope"}); w.Code != http.StatusOK {
		t.Fatalf("versions of never-existed = %d", w.Code)
	}
	if _, err := s.Store.DeleteCert("emulator", "c", 90); err != nil {
		t.Fatal(err)
	}
	if w := do(s.listCertificateVersions, "GET", "/x", "", map[string]string{"name": "c"}); w.Code != http.StatusNotFound {
		t.Fatalf("versions of soft-deleted = %d", w.Code)
	}
}

func TestImportErrors(t *testing.T) {
	s, _ := newService(t, "")
	for _, body := range []string{`{`, `{}`, `{"value":"not-base64-not-pem-@@@"}`, `{"value":"aGVsbG8="}`} {
		if w := do(s.importCertificate, "POST", "/x", body, map[string]string{"name": "i"}); w.Code != http.StatusBadRequest {
			t.Fatalf("import %q = %d", body, w.Code)
		}
	}
}

func TestCertSoftDeleteHandlers(t *testing.T) {
	s, _ := newService(t, "")
	createTestCert(t, s, "d", `{}`)
	nv := map[string]string{"name": "d"}
	missing := map[string]string{"name": "nope"}

	for name, w := range map[string]*httptest.ResponseRecorder{
		"delete missing":  do(s.deleteCertificate, "DELETE", "/x", "", missing),
		"getdel missing":  do(s.getDeletedCertificate, "GET", "/x", "", missing),
		"recover missing": do(s.recoverCertificate, "POST", "/x", "", missing),
		"purge missing":   do(s.purgeCertificate, "DELETE", "/x", "", missing),
	} {
		if w.Code != http.StatusNotFound {
			t.Errorf("%s = %d; want 404", name, w.Code)
		}
	}
	if w := do(s.deleteCertificate, "DELETE", "/x", "", nv); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "scheduledPurgeDate") {
		t.Fatalf("delete = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.getDeletedCertificate, "GET", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("get deleted = %d", w.Code)
	}
	if w := do(s.listDeletedCertificates, "GET", "/deletedcertificates?api-version=7.5", "", nil); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "recoveryId") {
		t.Fatalf("list deleted = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.recoverCertificate, "POST", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("recover = %d", w.Code)
	}
	do(s.deleteCertificate, "DELETE", "/x", "", nv)
	if w := do(s.purgeCertificate, "DELETE", "/x", "", nv); w.Code != http.StatusNoContent {
		t.Fatalf("purge = %d", w.Code)
	}
}

func TestCertStorageFailure500s(t *testing.T) {
	dir := t.TempDir()
	s, st := newService(t, dir)
	createTestCert(t, s, "a", `{}`)
	createTestCert(t, s, "del", `{}`)
	if _, err := st.DeleteCert("emulator", "del", 90); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE cert_versions`); err != nil {
		t.Fatal(err)
	}

	nv := map[string]string{"name": "a", "version": "v"}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"get":          do(s.getCertificate, "GET", "/x", "", nv),
		"policy":       do(s.getCertificatePolicy, "GET", "/x", "", map[string]string{"name": "a"}),
		"list":         do(s.listCertificates, "GET", "/certificates", "", nil),
		"versions":     do(s.listCertificateVersions, "GET", "/x", "", nv),
		"delete":       do(s.deleteCertificate, "DELETE", "/x", "", nv),
		"list deleted": do(s.listDeletedCertificates, "GET", "/deletedcertificates", "", nil),
	} {
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with no table = %d; want 500", name, w.Code)
		}
	}

	// Dropping deleted_certs makes purge/recover error at the lookup → 500.
	if _, err := db.Exec(`DROP TABLE deleted_certs`); err != nil {
		t.Fatal(err)
	}
	if w := do(s.purgeCertificate, "DELETE", "/x", "", map[string]string{"name": "del"}); w.Code != http.StatusInternalServerError {
		t.Errorf("purge with no deleted table = %d; want 500", w.Code)
	}
	if w := do(s.recoverCertificate, "POST", "/x", "", map[string]string{"name": "del"}); w.Code != http.StatusInternalServerError {
		t.Errorf("recover with no deleted table = %d; want 500", w.Code)
	}
}
