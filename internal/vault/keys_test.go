package vault

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// createTestKey drives createKey and returns the version id.
func createTestKey(t *testing.T, s *Service, name, body string) string {
	t.Helper()
	w := do(s.createKey, "POST", "/x", body, map[string]string{"name": name})
	if w.Code != http.StatusOK {
		t.Fatalf("createKey %s = %d %s", name, w.Code, w.Body.Bytes())
	}
	var b struct {
		Key struct {
			KID string `json:"kid"`
		} `json:"key"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return b.Key.KID[strings.LastIndexByte(b.Key.KID, '/')+1:]
}

func TestCreateKeyBranches(t *testing.T) {
	s, _ := newService(t, "")

	for _, body := range []string{`{`, `{}`, `{"kty":"RSA","key_size":123}`, `{"kty":"EC","crv":"P-999"}`, `{"kty":"AES"}`} {
		if w := do(s.createKey, "POST", "/x", body, map[string]string{"name": "k"}); w.Code != http.StatusBadRequest {
			t.Fatalf("createKey %q = %d", body, w.Code)
		}
	}
	// RSA with explicit ops + attributes + tags.
	v := createTestKey(t, s, "rsa", `{"kty":"RSA","key_size":2048,"key_ops":["sign","verify"],"attributes":{"enabled":true},"tags":{"a":"b"}}`)
	if v == "" {
		t.Fatal("no version")
	}
	// EC default curve.
	createTestKey(t, s, "ec", `{"kty":"EC"}`)
	// HSM kty normalizes to the software type.
	w := do(s.createKey, "POST", "/x", `{"kty":"RSA-HSM"}`, map[string]string{"name": "hsm"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"kty":"RSA"`) {
		t.Fatalf("RSA-HSM = %d %s", w.Code, w.Body.Bytes())
	}
	// Conflict while soft-deleted.
	if _, err := s.Store.DeleteKey("emulator", "rsa", 90); err != nil {
		t.Fatal(err)
	}
	if w := do(s.createKey, "POST", "/x", `{"kty":"RSA"}`, map[string]string{"name": "rsa"}); w.Code != http.StatusConflict {
		t.Fatalf("create over deleted = %d", w.Code)
	}
}

func TestKeyGetUpdateListErrors(t *testing.T) {
	s, _ := newService(t, "")
	if w := do(s.getKey, "GET", "/x", "", map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d", w.Code)
	}
	if w := do(s.updateKey, "PATCH", "/x", `{}`, map[string]string{"name": "nope", "version": "v"}); w.Code != http.StatusNotFound {
		t.Fatalf("update missing = %d", w.Code)
	}
	v := createTestKey(t, s, "k", `{"kty":"RSA"}`)
	pv := map[string]string{"name": "k", "version": v}
	if w := do(s.updateKey, "PATCH", "/x", `{`, pv); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed update = %d", w.Code)
	}
	// Update ops + disable.
	w := do(s.updateKey, "PATCH", "/x", `{"key_ops":["sign"],"attributes":{"enabled":false},"tags":{"t":"1"}}`, pv)
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d %s", w.Code, w.Body.Bytes())
	}
	// Disabled key: get 403.
	if w := do(s.getKey, "GET", "/x", "", map[string]string{"name": "k"}); w.Code != http.StatusForbidden {
		t.Fatalf("disabled get = %d", w.Code)
	}
	// Versions list; missing name 404.
	createTestKey(t, s, "multi", `{"kty":"RSA"}`)
	createTestKey(t, s, "multi", `{"kty":"RSA"}`)
	w = do(s.listKeyVersions, "GET", "/x?api-version=7.5", "", map[string]string{"name": "multi"})
	var page struct{ Value []map[string]any }
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != http.StatusOK || len(page.Value) != 2 {
		t.Fatalf("versions = %d %s", w.Code, w.Body.Bytes())
	}
	w = do(s.listKeys, "GET", "/keys?api-version=7.5", "", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Value) < 2 {
		t.Fatalf("list keys = %s", w.Body.Bytes())
	}
	// Never-existed name lists empty (200); soft-deleted 404s.
	w = do(s.listKeyVersions, "GET", "/x?api-version=7.5", "", map[string]string{"name": "nope"})
	if w.Code != http.StatusOK {
		t.Fatalf("versions of never-existed = %d", w.Code)
	}
	if _, err := s.Store.DeleteKey("emulator", "multi", 90); err != nil {
		t.Fatal(err)
	}
	if w := do(s.listKeyVersions, "GET", "/x", "", map[string]string{"name": "multi"}); w.Code != http.StatusNotFound {
		t.Fatalf("versions of soft-deleted = %d", w.Code)
	}
}

func TestKeySoftDeleteHandlers(t *testing.T) {
	s, _ := newService(t, "")
	createTestKey(t, s, "d", `{"kty":"RSA"}`)
	nv := map[string]string{"name": "d"}
	missing := map[string]string{"name": "nope"}

	for name, w := range map[string]*httptest.ResponseRecorder{
		"delete missing":  do(s.deleteKey, "DELETE", "/x", "", missing),
		"getdel missing":  do(s.getDeletedKey, "GET", "/x", "", missing),
		"recover missing": do(s.recoverKey, "POST", "/x", "", missing),
		"purge missing":   do(s.purgeKey, "DELETE", "/x", "", missing),
	} {
		if w.Code != http.StatusNotFound {
			t.Errorf("%s = %d; want 404", name, w.Code)
		}
	}
	if w := do(s.deleteKey, "DELETE", "/x", "", nv); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "scheduledPurgeDate") {
		t.Fatalf("delete = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.getDeletedKey, "GET", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("get deleted = %d", w.Code)
	}
	w := do(s.listDeletedKeys, "GET", "/deletedkeys?api-version=7.5", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"recoveryId"`) {
		t.Fatalf("list deleted = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.recoverKey, "POST", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("recover = %d", w.Code)
	}
	do(s.deleteKey, "DELETE", "/x", "", nv)
	if w := do(s.purgeKey, "DELETE", "/x", "", nv); w.Code != http.StatusNoContent {
		t.Fatalf("purge = %d", w.Code)
	}
	if w := do(s.getKey, "GET", "/x", "", nv); w.Code != http.StatusNotFound {
		t.Fatalf("purged get = %d", w.Code)
	}
}

func TestCryptoOpErrors(t *testing.T) {
	s, _ := newService(t, "")
	v := createTestKey(t, s, "k", `{"kty":"RSA"}`)
	pv := map[string]string{"name": "k", "version": v}

	sign := s.cryptoOp("sign")
	if w := do(sign, "POST", "/x", "", map[string]string{"name": "nope", "version": "v"}); w.Code != http.StatusNotFound {
		t.Fatalf("op on missing key = %d", w.Code)
	}
	for _, body := range []string{`{`, `{}`, `{"alg":"RS256"}`, `{"alg":"RS256","value":"!!!"}`} {
		if w := do(sign, "POST", "/x", body, pv); w.Code != http.StatusBadRequest {
			t.Fatalf("sign %q = %d", body, w.Code)
		}
	}
	// Wrong digest length for RS256.
	shortDigest := base64.RawURLEncoding.EncodeToString([]byte("short"))
	if w := do(sign, "POST", "/x", `{"alg":"RS256","value":"`+shortDigest+`"}`, pv); w.Code != http.StatusBadRequest {
		t.Fatalf("bad digest length = %d", w.Code)
	}
	// EC alg on an RSA key.
	digest := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if w := do(sign, "POST", "/x", `{"alg":"ES256","value":"`+digest+`"}`, pv); w.Code != http.StatusBadRequest {
		t.Fatalf("EC alg on RSA = %d", w.Code)
	}
	// verify with bad digest base64.
	verifyOp := s.cryptoOp("verify")
	if w := do(verifyOp, "POST", "/x", `{"alg":"RS256","value":"`+digest+`","digest":"!!!"}`, pv); w.Code != http.StatusBadRequest {
		t.Fatalf("verify bad digest = %d", w.Code)
	}
	// decrypt garbage ciphertext fails at the crypto layer.
	dec := s.cryptoOp("decrypt")
	if w := do(dec, "POST", "/x", `{"alg":"RSA-OAEP-256","value":"`+digest+`"}`, pv); w.Code != http.StatusBadRequest {
		t.Fatalf("decrypt garbage = %d", w.Code)
	}
}

func TestKeyStorageFailure500s(t *testing.T) {
	dir := t.TempDir()
	s, st := newService(t, dir)
	createTestKey(t, s, "a", `{"kty":"RSA"}`)
	createTestKey(t, s, "del", `{"kty":"RSA"}`)
	if _, err := st.DeleteKey("emulator", "del", 90); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE key_versions`); err != nil {
		t.Fatal(err)
	}

	nv := map[string]string{"name": "a", "version": "v"}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"create":       do(s.createKey, "POST", "/x", `{"kty":"RSA"}`, map[string]string{"name": "b"}),
		"get":          do(s.getKey, "GET", "/x", "", nv),
		"list":         do(s.listKeys, "GET", "/keys", "", nil),
		"versions":     do(s.listKeyVersions, "GET", "/x", "", nv),
		"delete":       do(s.deleteKey, "DELETE", "/x", "", nv),
		"list deleted": do(s.listDeletedKeys, "GET", "/deletedkeys", "", nil),
	} {
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with no table = %d; want 500", name, w.Code)
		}
	}
}
