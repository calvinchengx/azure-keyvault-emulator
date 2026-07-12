package vault

// Direct handler tests: bypass withAuth (covered by the server e2e) and
// drive handlers with SetPathValue; storage failures injected by dropping
// tables under a live on-disk store.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/clock"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/config"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

func newService(t *testing.T, dataDir string) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(dataDir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{EntraIssuer: "https://e/t/v2.0", DefaultVault: "emulator", SoftDeleteRetentionDays: 90}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	return New(cfg, st, nil), st
}

func do(h handler, method, path, body string, pathVals map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range pathVals {
		r.SetPathValue(k, v)
	}
	w := httptest.NewRecorder()
	h(w, r, "emulator")
	return w
}

func seed(t *testing.T, st *store.Store, name, value string) *store.SecretVersion {
	t.Helper()
	v := &store.SecretVersion{Vault: "emulator", Name: name, Value: value, Enabled: true}
	if err := st.SetSecret(v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVaultNameResolution(t *testing.T) {
	s, _ := newService(t, "")
	cases := map[string]string{
		"myvault.vault.azure.net":      "myvault",
		"myvault.vault.azure.net:8444": "myvault",
		"localhost:8444":               "emulator",
		"127.0.0.1:8444":               "emulator",
		"vault.azure.net":              "emulator", // no vault segment
		"a.b.vault.azure.net":          "emulator", // nested = not a vault name
	}
	for host, want := range cases {
		r := httptest.NewRequest("GET", "/secrets", nil)
		r.Host = host
		if got := s.vaultName(r); got != want {
			t.Errorf("vaultName(%q) = %q; want %q", host, got, want)
		}
	}
	r := httptest.NewRequest("GET", "/secrets", nil)
	r.Host = "myvault.vault.azure.net"
	if got := s.baseURL(r); got != "https://myvault.vault.azure.net" {
		t.Errorf("baseURL = %q", got)
	}
}

func TestSetGetErrors(t *testing.T) {
	s, st := newService(t, "")

	for _, body := range []string{`{`, `{}`, `{"value":""}`} {
		if w := do(s.setSecret, "PUT", "/secrets/a", body, map[string]string{"name": "a"}); w.Code != http.StatusBadRequest {
			t.Fatalf("set %q = %d", body, w.Code)
		}
	}
	if w := do(s.getSecret, "GET", "/secrets/a", "", map[string]string{"name": "a"}); w.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d", w.Code)
	}
	if w := do(s.getSecretVersion, "GET", "/x", "", map[string]string{"name": "a", "version": "v"}); w.Code != http.StatusNotFound {
		t.Fatalf("get missing version = %d", w.Code)
	}
	// Full attribute set on PUT; disabled version 403s on both gets.
	body := `{"value":"x","attributes":{"enabled":false,"nbf":100,"exp":200},"tags":{"a":"b"}}`
	w := do(s.setSecret, "PUT", "/secrets/a", body, map[string]string{"name": "a"})
	if w.Code != http.StatusOK {
		t.Fatalf("set = %d %s", w.Code, w.Body.Bytes())
	}
	var bundle struct {
		ID         string
		Attributes struct {
			Enabled *bool
			NBF     *int64 `json:"nbf"`
		}
		Tags map[string]string
	}
	_ = json.Unmarshal(w.Body.Bytes(), &bundle)
	if bundle.Attributes.Enabled == nil || *bundle.Attributes.Enabled || *bundle.Attributes.NBF != 100 || bundle.Tags["a"] != "b" {
		t.Fatalf("bundle = %s", w.Body.Bytes())
	}
	if w := do(s.getSecret, "GET", "/x", "", map[string]string{"name": "a"}); w.Code != http.StatusForbidden {
		t.Fatalf("disabled get = %d", w.Code)
	}
	version := bundle.ID[strings.LastIndexByte(bundle.ID, '/')+1:]
	if w := do(s.getSecretVersion, "GET", "/x", "", map[string]string{"name": "a", "version": version}); w.Code != http.StatusForbidden {
		t.Fatalf("disabled get version = %d", w.Code)
	}

	// PUT on a soft-deleted name conflicts.
	seed(t, st, "gone", "x")
	if _, err := st.DeleteSecret("emulator", "gone", 90); err != nil {
		t.Fatal(err)
	}
	if w := do(s.setSecret, "PUT", "/x", `{"value":"y"}`, map[string]string{"name": "gone"}); w.Code != http.StatusConflict {
		t.Fatalf("set on deleted = %d", w.Code)
	}
}

func TestUpdateSecretBranches(t *testing.T) {
	s, st := newService(t, "")
	v := seed(t, st, "u", "one")
	pv := map[string]string{"name": "u", "version": v.Version}

	if w := do(s.updateSecret, "PATCH", "/x", `{`, pv); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed patch = %d", w.Code)
	}
	if w := do(s.updateSecret, "PATCH", "/x", `{}`, map[string]string{"name": "u", "version": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("patch missing version = %d", w.Code)
	}
	body := `{"contentType":"text/plain","attributes":{"enabled":false,"nbf":5,"exp":9},"tags":{"t":"1"}}`
	w := do(s.updateSecret, "PATCH", "/x", body, pv)
	if w.Code != http.StatusOK {
		t.Fatalf("patch = %d %s", w.Code, w.Body.Bytes())
	}
	if strings.Contains(w.Body.String(), `"value"`) {
		t.Fatal("update response leaked the value")
	}
	got, _ := st.GetSecretVersion("emulator", "u", v.Version)
	if got.ContentType != "text/plain" || got.Enabled || *got.NBF != 5 || *got.Exp != 9 {
		t.Fatalf("update not applied: %+v", got)
	}
}

func TestPaging(t *testing.T) {
	s, st := newService(t, "")
	for _, n := range []string{"a", "b", "c"} {
		seed(t, st, n, "v")
	}
	// maxresults=2 → nextLink with $skiptoken=2; second page has 1 + null next.
	w := do(s.listSecrets, "GET", "/secrets?api-version=7.5&maxresults=2", "", nil)
	var page struct {
		Value    []map[string]any
		NextLink *string
	}
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Value) != 2 || page.NextLink == nil || !strings.Contains(*page.NextLink, "$skiptoken=2") {
		t.Fatalf("page1 = %s", w.Body.Bytes())
	}
	w = do(s.listSecrets, "GET", "/secrets?api-version=7.5&maxresults=2&$skiptoken=2", "", nil)
	page.NextLink = nil
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Value) != 1 || page.NextLink != nil {
		t.Fatalf("page2 = %s", w.Body.Bytes())
	}
	// Out-of-range skiptoken → empty page.
	w = do(s.listSecrets, "GET", "/secrets?$skiptoken=99", "", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Value) != 0 {
		t.Fatalf("overflow page = %s", w.Body.Bytes())
	}
	// listSecretVersions: never-existed names list empty (200); soft-deleted
	// names 404.
	w = do(s.listSecretVersions, "GET", "/x?api-version=7.5", "", map[string]string{"name": "nope"})
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != http.StatusOK || len(page.Value) != 0 {
		t.Fatalf("versions of missing = %d %s", w.Code, w.Body.Bytes())
	}
	if _, err := st.DeleteSecret("emulator", "a", 90); err != nil {
		t.Fatal(err)
	}
	if w := do(s.listSecretVersions, "GET", "/x", "", map[string]string{"name": "a"}); w.Code != http.StatusNotFound {
		t.Fatalf("versions of soft-deleted = %d", w.Code)
	}
}

func TestSoftDeleteHandlers(t *testing.T) {
	s, st := newService(t, "")
	seed(t, st, "d", "x")
	nv := map[string]string{"name": "d"}
	missing := map[string]string{"name": "nope"}

	if w := do(s.deleteSecret, "DELETE", "/x", "", missing); w.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d", w.Code)
	}
	w := do(s.deleteSecret, "DELETE", "/x", "", nv)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "scheduledPurgeDate") ||
		!strings.Contains(w.Body.String(), "recoveryId") {
		t.Fatalf("delete = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.getDeletedSecret, "GET", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("get deleted = %d", w.Code)
	}
	if w := do(s.getDeletedSecret, "GET", "/x", "", missing); w.Code != http.StatusNotFound {
		t.Fatalf("get deleted missing = %d", w.Code)
	}
	w = do(s.listDeletedSecrets, "GET", "/deletedsecrets?api-version=7.5", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"recoveryId"`) {
		t.Fatalf("list deleted = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.recoverSecret, "POST", "/x", "", missing); w.Code != http.StatusNotFound {
		t.Fatalf("recover missing = %d", w.Code)
	}
	if w := do(s.recoverSecret, "POST", "/x", "", nv); w.Code != http.StatusOK {
		t.Fatalf("recover = %d", w.Code)
	}
	// Delete again, purge, verify gone.
	do(s.deleteSecret, "DELETE", "/x", "", nv)
	if w := do(s.purgeSecret, "DELETE", "/x", "", missing); w.Code != http.StatusNotFound {
		t.Fatalf("purge missing = %d", w.Code)
	}
	if w := do(s.purgeSecret, "DELETE", "/x", "", nv); w.Code != http.StatusNoContent {
		t.Fatalf("purge = %d", w.Code)
	}
	if w := do(s.getSecret, "GET", "/x", "", nv); w.Code != http.StatusNotFound {
		t.Fatalf("purged get = %d", w.Code)
	}
}

func TestBackupRestoreBranches(t *testing.T) {
	s, st := newService(t, "")
	seed(t, st, "b", "one")
	seed(t, st, "b", "two")

	if w := do(s.backupSecret, "POST", "/x", "", map[string]string{"name": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("backup missing = %d", w.Code)
	}
	w := do(s.backupSecret, "POST", "/x", "", map[string]string{"name": "b"})
	if w.Code != http.StatusOK {
		t.Fatalf("backup = %d", w.Code)
	}
	var blob struct{ Value string }
	_ = json.Unmarshal(w.Body.Bytes(), &blob)

	// Restore into a vault that still has the name → 409.
	if w := do(s.restoreSecret, "POST", "/x", `{"value":"`+blob.Value+`"}`, nil); w.Code != http.StatusConflict {
		t.Fatalf("restore over live = %d", w.Code)
	}
	// Purge, restore, verify both versions.
	if _, err := st.DeleteSecret("emulator", "b", 90); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeSecret("emulator", "b"); err != nil {
		t.Fatal(err)
	}
	if w := do(s.restoreSecret, "POST", "/x", `{"value":"`+blob.Value+`"}`, nil); w.Code != http.StatusOK {
		t.Fatalf("restore = %d %s", w.Code, w.Body.Bytes())
	}
	vs, _ := st.ListSecretVersions("emulator", "b")
	if len(vs) != 2 {
		t.Fatalf("restored versions = %d", len(vs))
	}
	// Malformed restore bodies.
	for _, body := range []string{`{`, `{}`, `{"value":"!!!"}`, `{"value":"bm90LWpzb24"}`} {
		if w := do(s.restoreSecret, "POST", "/x", body, nil); w.Code != http.StatusBadRequest {
			t.Fatalf("restore %q = %d", body, w.Code)
		}
	}
}

func TestChallengeAndFaults(t *testing.T) {
	s, _ := newService(t, "")
	h := s.withAuth("secrets/get", func(w http.ResponseWriter, r *http.Request, vault string) {
		w.WriteHeader(http.StatusOK)
	})
	// No Authorization → 401 with the challenge (nil validator never reached).
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/secrets/x", nil))
	if w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), `authorization="https://e/t"`) ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), `resource="https://vault.azure.net"`) {
		t.Fatalf("challenge = %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w.Header().Get("x-ms-request-id") == "" {
		t.Fatal("missing x-ms-request-id")
	}
	// Faults fire before auth: throttle, then (separately) reject.
	s.SetFaults(1, 0)
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/secrets/x", nil))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("throttle = %d", w.Code)
	}
	s.SetFaults(0, 1)
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/secrets/x", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("reject = %d", w.Code)
	}
	// Negative SetFaults leaves state as-is (both exhausted → challenge again).
	s.SetFaults(-1, -1)
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/secrets/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("after faults = %d", w.Code)
	}
}

func TestStorageFailure500s(t *testing.T) {
	dir := t.TempDir()
	s, st := newService(t, dir)
	seed(t, st, "a", "x")
	seed(t, st, "del", "x")
	if _, err := st.DeleteSecret("emulator", "del", 90); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE secret_versions`); err != nil {
		t.Fatal(err)
	}

	nv := map[string]string{"name": "a", "version": "v"}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"set":          do(s.setSecret, "PUT", "/x", `{"value":"y"}`, nv),
		"get":          do(s.getSecret, "GET", "/x", "", nv),
		"get version":  do(s.getSecretVersion, "GET", "/x", "", nv),
		"list":         do(s.listSecrets, "GET", "/secrets", "", nil),
		"versions":     do(s.listSecretVersions, "GET", "/x", "", nv),
		"delete":       do(s.deleteSecret, "DELETE", "/x", "", nv),
		"get deleted":  do(s.getDeletedSecret, "GET", "/x", "", map[string]string{"name": "del"}),
		"list deleted": do(s.listDeletedSecrets, "GET", "/deletedsecrets", "", nil),
		"purge":        do(s.purgeSecret, "DELETE", "/x", "", map[string]string{"name": "del"}),
	} {
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s with no table = %d; want 500", name, w.Code)
		}
	}
}
