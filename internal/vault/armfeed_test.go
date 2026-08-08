package vault

// The ARM feed consumer: dataAction mapping, the access-policy/RBAC either-or,
// and the poller's behaviour against a stub feed.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOpsForDataAction(t *testing.T) {
	cases := map[string][]string{
		"Microsoft.KeyVault/vaults/secrets/getSecret/action": {"secrets/get"},
		"Microsoft.KeyVault/vaults/keys/sign/action":         {"keys/sign"},
		"microsoft.keyvault/vaults/keys/read":                {"keys/get", "keys/list"},
		"Microsoft.KeyVault/vaults/*":                        {"*"},
		"*":                                                  {"*"},
	}
	for action, want := range cases {
		got := opsForDataAction(action)
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("opsForDataAction(%q) = %v; missing %q", action, got, w)
			}
		}
	}
	// A type wildcard expands to that type's operations and no others.
	secrets := opsForDataAction("Microsoft.KeyVault/vaults/secrets/*")
	if !slices.Contains(secrets, "secrets/purge") || slices.Contains(secrets, "keys/sign") {
		t.Fatalf("secrets wildcard = %v", secrets)
	}
	// Unknown and empty actions grant nothing.
	if got := opsForDataAction("Microsoft.Storage/blobs/read"); len(got) != 0 {
		t.Fatalf("foreign action granted %v", got)
	}
	if got := opsForDataAction("   "); len(got) != 0 {
		t.Fatalf("empty action granted %v", got)
	}
}

func TestAccessPolicyOps(t *testing.T) {
	if got := accessPolicyOps("secrets", []string{"Get", "list"}); !slices.Contains(got, "secrets/get") ||
		!slices.Contains(got, "secrets/list") {
		t.Fatalf("secrets perms = %v", got)
	}
	if got := accessPolicyOps("keys", []string{"all"}); !slices.Contains(got, "keys/sign") {
		t.Fatalf("keys all = %v", got)
	}
	if got := accessPolicyOps("certificates", []string{"managecontacts"}); !slices.Contains(got, "certificates/setcontacts") {
		t.Fatalf("certificates managecontacts = %v", got)
	}
	// Unknown object type and unknown permission grant nothing.
	if got := accessPolicyOps("storage", []string{"get"}); len(got) != 0 {
		t.Fatalf("storage perms = %v", got)
	}
	if got := accessPolicyOps("secrets", []string{"frobnicate"}); len(got) != 0 {
		t.Fatalf("unknown perm = %v", got)
	}
}

// feedJSON builds a feed document the way arm-emulator serves it.
func feedJSON(t *testing.T, rbacOnly bool) string {
	t.Helper()
	doc := map[string]any{
		"scope":     "/subscriptions/s/resourceGroups/g/providers/Microsoft.KeyVault/vaults/v",
		"generated": 1700000000,
		"assignments": []map[string]any{{
			"principalId": "sp-1",
			"roleName":    "Key Vault Secrets User",
			"dataActions": []string{
				"Microsoft.KeyVault/vaults/secrets/getSecret/action",
				"Microsoft.KeyVault/vaults/secrets/readMetadata/action",
			},
			"notDataActions": []string{},
		}, {
			"principalId":    "sp-2",
			"roleName":       "Key Vault Crypto Officer",
			"dataActions":    []string{"Microsoft.KeyVault/vaults/keys/*"},
			"notDataActions": []string{"Microsoft.KeyVault/vaults/keys/purge/action"},
		}},
		"accessPolicies": []map[string]any{{
			"objectId": "legacy-1",
			"permissions": map[string]any{
				"secrets": []string{"get", "set"},
				"keys":    []string{"sign"},
			},
		}},
		"enableRbacAuthorization": rbacOnly,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCompileFeed(t *testing.T) {
	var f armFeed
	if err := json.Unmarshal([]byte(feedJSON(t, false)), &f); err != nil {
		t.Fatal(err)
	}
	perms := compileFeed(&f)

	// Role assignments map onto ops.
	if !slices.Contains(perms["sp-1"], "secrets/get") || !slices.Contains(perms["sp-1"], "secrets/list") {
		t.Fatalf("sp-1 = %v", perms["sp-1"])
	}
	if slices.Contains(perms["sp-1"], "secrets/set") {
		t.Fatalf("Secrets User granted a write: %v", perms["sp-1"])
	}
	// A wildcard role grants the type, minus its notDataActions.
	if !slices.Contains(perms["sp-2"], "keys/sign") {
		t.Fatalf("sp-2 missing keys/sign: %v", perms["sp-2"])
	}
	if slices.Contains(perms["sp-2"], "keys/purge") {
		t.Fatalf("notDataActions not subtracted: %v", perms["sp-2"])
	}
	// Access policies apply when the vault is not RBAC-only.
	if !slices.Contains(perms["legacy-1"], "secrets/set") || !slices.Contains(perms["legacy-1"], "keys/sign") {
		t.Fatalf("access policy = %v", perms["legacy-1"])
	}

	// With enableRbacAuthorization the access policies are ignored, exactly
	// as real Key Vault ignores them in RBAC mode.
	var rf armFeed
	if err := json.Unmarshal([]byte(feedJSON(t, true)), &rf); err != nil {
		t.Fatal(err)
	}
	rbac := compileFeed(&rf)
	if _, ok := rbac["legacy-1"]; ok {
		t.Fatalf("access policy honoured in RBAC mode: %v", rbac["legacy-1"])
	}
	if !slices.Contains(rbac["sp-1"], "secrets/get") {
		t.Fatalf("assignments lost in RBAC mode: %v", rbac["sp-1"])
	}

	// An empty feed grants nothing to anyone — and an empty map means "full
	// access" to the allowlist, which is the documented un-configured posture.
	empty := compileFeed(&armFeed{})
	if len(empty) != 0 {
		t.Fatalf("empty feed = %v", empty)
	}
}

func TestARMSourceRefresh(t *testing.T) {
	body := feedJSON(t, false)
	var gotScope string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotScope = r.URL.Query().Get("scope")
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	s, _ := newService(t, "")
	const scope = "/subscriptions/s/resourceGroups/g/providers/Microsoft.KeyVault/vaults/v"
	src := NewARMSource(s, srv.URL, scope, srv.Client(), 0)
	if src.TTL != 5*time.Second {
		t.Fatalf("default TTL = %v", src.TTL)
	}
	if err := src.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if gotScope != scope {
		t.Fatalf("feed queried scope %q", gotScope)
	}
	// The compiled map governs the live allowlist.
	if !s.allowed("sp-1", "secrets/get", "") || s.allowed("sp-1", "secrets/set", "") {
		t.Fatal("ARM feed did not govern authorization")
	}

	// A non-200 feed is an error and leaves the last-known map in place.
	status = http.StatusInternalServerError
	if err := src.Refresh(); err == nil {
		t.Fatal("Refresh accepted a 500")
	}
	if !s.allowed("sp-1", "secrets/get", "") {
		t.Fatal("a failed refresh dropped the last-known permissions")
	}

	// Malformed JSON is an error too.
	status = http.StatusOK
	body = "{not json"
	if err := src.Refresh(); err == nil {
		t.Fatal("Refresh accepted malformed JSON")
	}

	// An unreachable ARM is an error, not a panic.
	srv.Close()
	if err := src.Refresh(); err == nil {
		t.Fatal("Refresh against a dead ARM succeeded")
	}

	// A nil client falls back to the default, and Run stops when signalled.
	src2 := NewARMSource(s, "http://127.0.0.1:1", scope, nil, 10*time.Millisecond)
	if src2.Client == nil {
		t.Fatal("nil client not defaulted")
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() { src2.Run(done); close(stopped) }()
	time.Sleep(30 * time.Millisecond) // let at least one failing tick run
	close(done)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop when signalled")
	}
}

// TestARMSourceAppliesVaultConfig: the vault RESOURCE's own configuration —
// purge protection and the soft-delete window — comes from ARM, because in
// Azure those are properties of the ARM resource rather than of the process
// serving the data plane.
func TestARMSourceAppliesVaultConfig(t *testing.T) {
	body := `{"scope":"/s","generated":1,"assignments":[],"accessPolicies":[],
		"enableRbacAuthorization":true,
		"vault":{"exists":true,"enablePurgeProtection":true,"softDeleteRetentionInDays":7}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	s, st := newService(t, "")
	if s.retention() != 90 {
		t.Fatalf("default retention = %d", s.retention())
	}
	src := NewARMSource(s, srv.URL, "/s", srv.Client(), time.Second)
	if err := src.Refresh(); err != nil {
		t.Fatal(err)
	}
	// Both properties now come from the resource.
	if !s.purgeProtected() {
		t.Fatal("purge protection from ARM was not applied")
	}
	if s.retention() != 7 {
		t.Fatalf("retention from ARM = %d; want 7", s.retention())
	}
	// And they show up where callers see them.
	seed(t, st, "s1", "v")
	w := do(s.getSecret, "GET", "/x", "", map[string]string{"name": "s1"})
	if !strings.Contains(w.Body.String(), `"recoverableDays":7`) ||
		!strings.Contains(w.Body.String(), `"Recoverable"`) {
		t.Fatalf("attributes did not follow ARM: %s", w.Body.Bytes())
	}

	// A vault resource that does not exist must NOT reconfigure a running
	// emulator — absence is not an instruction.
	body = `{"scope":"/s","generated":2,"assignments":[],"accessPolicies":[],
		"vault":{"exists":false,"enablePurgeProtection":false}}`
	if err := src.Refresh(); err != nil {
		t.Fatal(err)
	}
	if !s.purgeProtected() || s.retention() != 7 {
		t.Fatal("an absent vault resource silently reconfigured the emulator")
	}

	// An out-of-range window is ignored rather than applied.
	body = `{"scope":"/s","generated":3,"assignments":[],"accessPolicies":[],
		"vault":{"exists":true,"softDeleteRetentionInDays":9999}}`
	if err := src.Refresh(); err != nil {
		t.Fatal(err)
	}
	if s.retention() != 7 {
		t.Fatalf("out-of-range retention applied: %d", s.retention())
	}
}
