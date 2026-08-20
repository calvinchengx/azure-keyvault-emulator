package server

// Control-surface unit tests (no entra needed): clock GET/POST shapes,
// malformed bodies, and fault wiring.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/config"
)

func newControlServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{EntraIssuer: "https://unused/t/v2.0", DefaultVault: "emulator", SoftDeleteRetentionDays: 90}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (s *Server) hit(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rd)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestControlSurface(t *testing.T) {
	s := newControlServer(t)

	if w := s.hit(t, "GET", "/health", ""); w.Code != http.StatusOK {
		t.Fatalf("health = %d", w.Code)
	}
	if w := s.hit(t, "GET", "/_emulator/clock", ""); w.Code != http.StatusOK {
		t.Fatalf("clock get = %d", w.Code)
	}
	// Offset + freeze + advance in one body.
	w := s.hit(t, "POST", "/_emulator/clock", `{"offset":100,"freeze":true,"advance":5}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"frozen":true`) {
		t.Fatalf("clock post = %d %s", w.Code, w.Body.String())
	}
	// Unfreeze.
	w = s.hit(t, "POST", "/_emulator/clock", `{"freeze":false}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"frozen":false`) {
		t.Fatalf("unfreeze = %d %s", w.Code, w.Body.String())
	}
	// Malformed bodies 400.
	if w := s.hit(t, "POST", "/_emulator/clock", `{nope`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad clock body = %d", w.Code)
	}
	if w := s.hit(t, "POST", "/_emulator/faults", `{nope`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad faults body = %d", w.Code)
	}
	// Faults accept partial fields; throttle then reject fire on the vault.
	if w := s.hit(t, "POST", "/_emulator/faults", `{"throttleNextRequests":1}`); w.Code != http.StatusOK {
		t.Fatalf("faults = %d", w.Code)
	}
	if w := s.hit(t, "GET", "/secrets?api-version=7.5", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request = %d; want 429", w.Code)
	}
	if w := s.hit(t, "POST", "/_emulator/faults", `{"rejectNextRequests":1}`); w.Code != http.StatusOK {
		t.Fatalf("faults combo = %d", w.Code)
	}
	if w := s.hit(t, "GET", "/secrets?api-version=7.5", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("rejected request = %d; want 500", w.Code)
	}
	// Purge protection: toggle on, toggle off, malformed body 400.
	if w := s.hit(t, "POST", "/_emulator/purge-protection", `{"enabled":true}`); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatalf("purge-protection on = %d %s", w.Code, w.Body.String())
	}
	if w := s.hit(t, "POST", "/_emulator/purge-protection", `{"enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("purge-protection off = %d", w.Code)
	}
	if w := s.hit(t, "POST", "/_emulator/purge-protection", `{}`); w.Code != http.StatusBadRequest {
		t.Fatalf("purge-protection empty body = %d; want 400", w.Code)
	}
	if w := s.hit(t, "POST", "/_emulator/purge-protection", `{nope`); w.Code != http.StatusBadRequest {
		t.Fatalf("purge-protection bad body = %d; want 400", w.Code)
	}
	// Access policies: the real document compiles; unknown names and bad
	// bodies are refused; an empty list restores full access.
	ap := `{"accessPolicies":[{"objectId":"p1","permissions":{"secrets":["get","list"]}}]}`
	if w := s.hit(t, "POST", "/_emulator/access-policy", ap); w.Code != http.StatusOK {
		t.Fatalf("access-policy = %d %s", w.Code, w.Body.String())
	}
	if w := s.hit(t, "POST", "/_emulator/access-policy",
		`{"accessPolicies":[{"objectId":"p1","permissions":{"secrets":["frobnicate"]}}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad permission accepted = %d", w.Code)
	}
	if w := s.hit(t, "POST", "/_emulator/access-policy", `{nope`); w.Code != http.StatusBadRequest {
		t.Fatalf("access-policy bad body = %d", w.Code)
	}
	if w := s.hit(t, "POST", "/_emulator/access-policy", `{"accessPolicies":[]}`); w.Code != http.StatusOK {
		t.Fatalf("access-policy reset = %d", w.Code)
	}
	// RBAC: built-in roles assign; unknown roles and bad bodies are refused.
	rb := `{"assignments":[{"principalId":"p1","role":"Key Vault Secrets User"}]}`
	if w := s.hit(t, "POST", "/_emulator/rbac", rb); w.Code != http.StatusOK {
		t.Fatalf("rbac = %d %s", w.Code, w.Body.String())
	}
	if w := s.hit(t, "POST", "/_emulator/rbac",
		`{"assignments":[{"principalId":"p1","role":"Duke of Vaults"}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown role accepted = %d", w.Code)
	}
	if w := s.hit(t, "POST", "/_emulator/rbac", `{nope`); w.Code != http.StatusBadRequest {
		t.Fatalf("rbac bad body = %d", w.Code)
	}
	if w := s.hit(t, "POST", "/_emulator/rbac", `{"assignments":[]}`); w.Code != http.StatusOK {
		t.Fatalf("rbac reset = %d", w.Code)
	}
}

// TestARMSourceWiring: with ARMURL configured the server builds a feed
// consumer, applies it before serving, and stops its poller on Close.
func TestARMSourceWiring(t *testing.T) {
	const scope = "/subscriptions/s/resourceGroups/g/providers/Microsoft.KeyVault/vaults/emulator"
	hits := make(chan struct{}, 16)
	arm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hits <- struct{}{}:
		default:
		}
		if got := r.URL.Query().Get("scope"); got != scope {
			t.Errorf("feed scope = %q", got)
		}
		_, _ = w.Write([]byte(`{"scope":"` + scope + `","generated":1,"assignments":[
			{"principalId":"sp-1","roleName":"Key Vault Secrets User",
			 "dataActions":["Microsoft.KeyVault/vaults/secrets/getSecret/action"]}],
			"accessPolicies":[],"enableRbacAuthorization":true}`))
	}))
	defer arm.Close()

	cfg := &config.Config{
		EntraIssuer: "https://e/t/v2.0", DefaultVault: "emulator",
		SoftDeleteRetentionDays: 90,
		ARMURL:                  arm.URL, ARMScope: scope, ARMPollSeconds: 1,
	}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, arm.Client())
	if err != nil {
		t.Fatal(err)
	}
	if s.ARM == nil {
		t.Fatal("ARM source not wired")
	}
	// The startup refresh already applied the feed.
	select {
	case <-hits:
	default:
		t.Fatal("no feed request at startup")
	}
	if !s.Vault.Allowed("sp-1", "secrets/get", "") || s.Vault.Allowed("sp-1", "secrets/set", "") {
		t.Fatal("ARM feed did not govern the served vault")
	}
	// A principal with no assignment is denied, not waved through.
	if s.Vault.Allowed("nobody", "secrets/get", "") {
		t.Fatal("an unassigned principal was allowed under ARM governance")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Close is idempotent (the poller channel is only closed once).
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestARMSourceUnreachable: a server configured against a dead ARM still
// starts — the emulator must not be unusable because a sibling is down.
func TestARMSourceUnreachable(t *testing.T) {
	cfg := &config.Config{
		EntraIssuer: "https://e/t/v2.0", DefaultVault: "emulator",
		SoftDeleteRetentionDays: 90,
		ARMURL:                  "https://127.0.0.1:1", ARMPollSeconds: 1,
		ARMSubscription: "s", ARMResourceGroup: "g",
	}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("server.New with a dead ARM: %v", err)
	}
	defer func() { _ = s.Close() }()
	// Authorization was never applied, so the un-configured posture holds.
	if !s.Vault.Allowed("anyone", "secrets/get", "") {
		t.Fatal("a failed startup refresh left the vault locked down")
	}
}
