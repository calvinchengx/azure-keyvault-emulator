package vault

// P6 parity tests: key validity enforcement on crypto, the certificate
// delete cascade, sealed backup blobs, the rotation engine, and the
// access-policy / RBAC compilers.

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/auth"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

func TestKeyValidityEnforcedOnCrypto(t *testing.T) {
	s, st := newService(t, "")
	now := st.Now()
	sign := `{"alg":"RS256","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`

	expired := map[string]string{"name": "old"}
	do(s.createKey, "POST", "/x", fmt.Sprintf(`{"kty":"RSA","attributes":{"exp":%d}}`, now-10), expired)
	if w := do(s.cryptoOp("sign"), "POST", "/x", sign, expired); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "expired") {
		t.Fatalf("sign with expired key = %d %s", w.Code, w.Body.Bytes())
	}

	future := map[string]string{"name": "later"}
	do(s.createKey, "POST", "/x", fmt.Sprintf(`{"kty":"RSA","attributes":{"nbf":%d}}`, now+3600), future)
	if w := do(s.cryptoOp("sign"), "POST", "/x", sign, future); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "not yet valid") {
		t.Fatalf("sign with not-yet-valid key = %d %s", w.Code, w.Body.Bytes())
	}

	// Inside the window: works. Reads of the expired key stay permissive.
	live := map[string]string{"name": "live"}
	do(s.createKey, "POST", "/x", fmt.Sprintf(`{"kty":"RSA","attributes":{"nbf":%d,"exp":%d}}`, now-10, now+3600), live)
	if w := do(s.cryptoOp("sign"), "POST", "/x", sign, live); w.Code != http.StatusOK {
		t.Fatalf("sign inside window = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.getKey, "GET", "/x", "", expired); w.Code != http.StatusOK {
		t.Fatalf("get expired key = %d; reads must stay permissive", w.Code)
	}
}

func TestCertDeleteCascade(t *testing.T) {
	s, st := newService(t, "")
	createTestCert(t, s, "web", `{}`)
	if _, err := st.GetKey("emulator", "web"); err != nil {
		t.Fatal("linked key missing after create")
	}

	// Delete cascades to the linked key and secret.
	if w := do(s.deleteCertificate, "DELETE", "/x", "", map[string]string{"name": "web"}); w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body.Bytes())
	}
	if _, err := st.GetDeletedKey("emulator", "web"); err != nil {
		t.Fatal("linked key not soft-deleted with the certificate")
	}
	if _, err := st.GetDeletedSecret("emulator", "web"); err != nil {
		t.Fatal("linked secret not soft-deleted with the certificate")
	}

	// Recover restores all three.
	if w := do(s.recoverCertificate, "POST", "/x", "", map[string]string{"name": "web"}); w.Code != http.StatusOK {
		t.Fatalf("recover = %d %s", w.Code, w.Body.Bytes())
	}
	if _, err := st.GetKey("emulator", "web"); err != nil {
		t.Fatal("linked key not recovered with the certificate")
	}
	if _, err := st.GetSecret("emulator", "web"); err != nil {
		t.Fatal("linked secret not recovered with the certificate")
	}

	// Purge carries them away entirely.
	do(s.deleteCertificate, "DELETE", "/x", "", map[string]string{"name": "web"})
	if w := do(s.purgeCertificate, "DELETE", "/x", "", map[string]string{"name": "web"}); w.Code != http.StatusNoContent {
		t.Fatalf("purge = %d %s", w.Code, w.Body.Bytes())
	}
	if _, err := st.GetDeletedKey("emulator", "web"); err == nil {
		t.Fatal("linked key survived the purge")
	}
	if _, err := st.GetDeletedSecret("emulator", "web"); err == nil {
		t.Fatal("linked secret survived the purge")
	}
}

func TestBackupBlobsAreSealed(t *testing.T) {
	s, st := newService(t, "")
	seed(t, st, "s1", "top-secret")

	w := do(s.backupSecret, "POST", "/x", "", map[string]string{"name": "s1"})
	if w.Code != http.StatusOK {
		t.Fatalf("backup = %d %s", w.Code, w.Body.Bytes())
	}
	var out struct{ Value string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)

	// Opaque: the blob must not decode to readable JSON carrying the value.
	raw, err := base64.RawURLEncoding.DecodeString(out.Value)
	if err != nil {
		t.Fatalf("blob is not base64url: %v", err)
	}
	if strings.Contains(string(raw), "top-secret") {
		t.Fatal("backup blob leaks the secret value in cleartext")
	}

	// A tampered blob is refused.
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	body := fmt.Sprintf(`{"value":%q}`, base64.RawURLEncoding.EncodeToString(tampered))
	if w := do(s.restoreSecret, "POST", "/x", body, nil); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "not produced by this vault") {
		t.Fatalf("tampered restore = %d %s", w.Code, w.Body.Bytes())
	}

	// The genuine blob round-trips after the original is purged.
	if _, err := st.DeleteSecret("emulator", "s1", 90); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeSecret("emulator", "s1"); err != nil {
		t.Fatal(err)
	}
	body = fmt.Sprintf(`{"value":%q}`, out.Value)
	if w := do(s.restoreSecret, "POST", "/x", body, nil); w.Code != http.StatusOK {
		t.Fatalf("restore = %d %s", w.Code, w.Body.Bytes())
	}
	v, err := st.GetSecret("emulator", "s1")
	if err != nil || v.Value != "top-secret" {
		t.Fatalf("restored value = %v, %v", v, err)
	}
}

func TestParseISODuration(t *testing.T) {
	cases := map[string]struct {
		secs int64
		ok   bool
	}{
		"P7D": {7 * 86400, true}, "P90D": {90 * 86400, true},
		"P1Y": {365 * 86400, true}, "P1M": {30 * 86400, true},
		"P2W": {14 * 86400, true}, "PT12H": {12 * 3600, true},
		"P1DT6H": {86400 + 6*3600, true},
		"":       {0, false}, "P": {0, false}, "PT": {0, false},
		"7D": {0, false}, "P7X": {0, false},
	}
	for in, want := range cases {
		got, ok := parseISODuration(in)
		if ok != want.ok || (ok && got != want.secs) {
			t.Errorf("parseISODuration(%q) = %d,%v; want %d,%v", in, got, ok, want.secs, want.ok)
		}
	}
}

func TestAutoRotation(t *testing.T) {
	s, st := newService(t, "")
	st.Clock.Freeze()
	defer st.Clock.Unfreeze()
	nv := map[string]string{"name": "auto"}
	do(s.createKey, "POST", "/x", `{"kty":"RSA","key_ops":["sign","verify"]}`, nv)

	policy := `{"lifetimeActions":[{"trigger":{"timeAfterCreate":"P7D"},"action":{"type":"Rotate"}}],"attributes":{"expiryTime":"P30D"}}`
	if w := do(s.setKeyRotationPolicy, "PUT", "/x", policy, nv); w.Code != http.StatusOK {
		t.Fatalf("set policy = %d %s", w.Code, w.Body.Bytes())
	}

	// Before the trigger: no rotation.
	do(s.getKey, "GET", "/x", "", nv)
	if vs, _ := st.ListKeyVersions("emulator", "auto"); len(vs) != 1 {
		t.Fatalf("rotated early: %d versions", len(vs))
	}

	// Cross the trigger on the emulator clock: the next read rotates once.
	st.Clock.Advance(8 * 86400)
	w := do(s.getKey, "GET", "/x", "", nv)
	if w.Code != http.StatusOK {
		t.Fatalf("get after trigger = %d %s", w.Code, w.Body.Bytes())
	}
	vs, _ := st.ListKeyVersions("emulator", "auto")
	if len(vs) != 2 {
		t.Fatalf("versions after trigger = %d; want 2", len(vs))
	}
	// The new version carries the policy's expiry and inherited key_ops.
	cur, _ := st.GetKey("emulator", "auto")
	if cur.Exp == nil || *cur.Exp != st.Now()+30*86400 {
		t.Fatalf("rotated exp = %v; want now+30d", cur.Exp)
	}
	if !slices.Contains(keyOps(cur), "sign") || len(keyOps(cur)) != 2 {
		t.Fatalf("rotated key_ops = %v", keyOps(cur))
	}
	// Idempotent within the window: an immediate second read does not rotate.
	do(s.getKey, "GET", "/x", "", nv)
	if vs, _ := st.ListKeyVersions("emulator", "auto"); len(vs) != 2 {
		t.Fatalf("second read rotated again: %d versions", len(vs))
	}
	// A non-rotate policy never rotates.
	notify := map[string]string{"name": "notify"}
	do(s.createKey, "POST", "/x", `{"kty":"EC"}`, notify)
	do(s.setKeyRotationPolicy, "PUT", "/x",
		`{"lifetimeActions":[{"trigger":{"timeBeforeExpiry":"P7D"},"action":{"type":"Notify"}}]}`, notify)
	st.Clock.Advance(30 * 86400)
	do(s.getKey, "GET", "/x", "", notify)
	if vs, _ := st.ListKeyVersions("emulator", "notify"); len(vs) != 1 {
		t.Fatalf("notify policy rotated: %d versions", len(vs))
	}
}

// TestP6ErrorPaths drives the failure branches of the new machinery: an
// unwritable data dir breaks seal-key creation (backup 500s), a dropped table
// breaks the delete cascade, and corrupt key material breaks rotation.
func TestP6ErrorPaths(t *testing.T) {
	// Overflowing duration digits.
	if _, ok := parseISODuration("P99999999999999999999D"); ok {
		t.Fatal("overflowing duration parsed")
	}

	// chmod cannot write-protect a directory on Windows, so the seal-key
	// failure path is only reachable on POSIX runners.
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		s, st := newService(t, dir)
		seed(t, st, "s1", "v")
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if w := do(s.backupSecret, "POST", "/x", "", map[string]string{"name": "s1"}); w.Code != http.StatusInternalServerError {
			t.Fatalf("backup with unwritable data dir = %d %s", w.Code, w.Body.Bytes())
		}
		if w := do(s.restoreSecret, "POST", "/x", `{"value":"aGVsbG8"}`, nil); w.Code != http.StatusInternalServerError {
			t.Fatalf("restore with unwritable data dir = %d %s", w.Code, w.Body.Bytes())
		}
		_ = os.Chmod(dir, 0o700)
	}

	// Cascade failure: the key table gone under a live cert delete.
	s2dir := t.TempDir()
	s2, _ := newService(t, s2dir)
	createTestCert(t, s2, "web", `{}`)
	db, err := sql.Open("sqlite", filepath.Join(s2dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE deleted_keys`); err != nil {
		t.Fatal(err)
	}
	if w := do(s2.deleteCertificate, "DELETE", "/x", "", map[string]string{"name": "web"}); w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with broken cascade = %d %s", w.Code, w.Body.Bytes())
	}

	// Recover/purge cascade failures: the key table gone after a cascaded
	// delete makes both surface 500 rather than half-restoring.
	s4dir := t.TempDir()
	s4, _ := newService(t, s4dir)
	createTestCert(t, s4, "c2", `{}`)
	do(s4.deleteCertificate, "DELETE", "/x", "", map[string]string{"name": "c2"})
	db4, err := sql.Open("sqlite", filepath.Join(s4dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db4.Close()
	if _, err := db4.Exec(`DROP TABLE key_versions`); err != nil {
		t.Fatal(err)
	}
	// Recovery flips markers only, so it survives the missing versions table…
	if w := do(s4.recoverCertificate, "POST", "/x", "", map[string]string{"name": "c2"}); w.Code != http.StatusOK {
		t.Fatalf("recover after marker flip = %d %s", w.Code, w.Body.Bytes())
	}
	// …but a fresh cascaded delete needs it and surfaces the failure.
	if w := do(s4.deleteCertificate, "DELETE", "/x", "", map[string]string{"name": "c2"}); w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with dropped key table = %d %s", w.Code, w.Body.Bytes())
	}

	// Purge cascade failure: soft-delete everything first, then break the
	// key-versions table so PurgeKey errors under a successful PurgeCert.
	s5dir := t.TempDir()
	s5, _ := newService(t, s5dir)
	createTestCert(t, s5, "c3", `{}`)
	do(s5.deleteCertificate, "DELETE", "/x", "", map[string]string{"name": "c3"})
	db5, err := sql.Open("sqlite", filepath.Join(s5dir, "azure-keyvault-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db5.Close()
	if _, err := db5.Exec(`DROP TABLE key_versions`); err != nil {
		t.Fatal(err)
	}
	if w := do(s5.purgeCertificate, "DELETE", "/x", "", map[string]string{"name": "c3"}); w.Code != http.StatusInternalServerError {
		t.Fatalf("purge with broken cascade = %d %s", w.Code, w.Body.Bytes())
	}

	// Closed-DB sweep over the cert lifecycle handlers' first storage reads.
	s6, st6 := newService(t, "")
	st6.Close()
	for name, h := range map[string]handler{
		"recover": s6.recoverCertificate, "purge": s6.purgeCertificate,
		"delete": s6.deleteCertificate, "getDeleted": s6.getDeletedCertificate,
	} {
		if w := do(h, "POST", "/x", "", map[string]string{"name": "x"}); w.Code != http.StatusInternalServerError {
			t.Fatalf("%s on closed DB = %d %s", name, w.Code, w.Body.Bytes())
		}
	}

	// Rotation over corrupt private material surfaces the parse error.
	s3, st3 := newService(t, "")
	if err := st3.SetKey(&store.KeyVersion{Vault: "emulator", Name: "bad", Kty: "RSA",
		PrivateDER: "bm90LWRlcg", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if w := do(s3.rotateKey, "POST", "/x", "", map[string]string{"name": "bad"}); w.Code != http.StatusInternalServerError {
		t.Fatalf("rotate corrupt key = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestCompileAccessPolicies(t *testing.T) {
	entries := []AccessPolicyEntry{{ObjectID: "p1"}}
	entries[0].Permissions.Secrets = []string{"Get", "list"}
	entries[0].Permissions.Keys = []string{"sign", "wrapKey"}
	entries[0].Permissions.Certificates = []string{"manageissuers"}
	perms, err := CompileAccessPolicies(entries)
	if err != nil {
		t.Fatal(err)
	}
	got := perms["p1"]
	for _, want := range []string{"secrets/get", "secrets/list", "keys/sign", "keys/wrapkey",
		"certificates/setissuers", "certificates/deleteissuers"} {
		if !slices.Contains(got, want) {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
	// "all" expands the full set; unknown names and missing objectId fail.
	entries[0].Permissions.Secrets = []string{"all"}
	if perms, err = CompileAccessPolicies(entries); err != nil ||
		!slices.Contains(perms["p1"], "secrets/purge") {
		t.Fatalf("all: %v %v", perms, err)
	}
	entries[0].Permissions.Secrets = []string{"frobnicate"}
	if _, err := CompileAccessPolicies(entries); err == nil {
		t.Fatal("unknown permission accepted")
	}
	if _, err := CompileAccessPolicies([]AccessPolicyEntry{{}}); err == nil {
		t.Fatal("missing objectId accepted")
	}
}

func TestCompileRBAC(t *testing.T) {
	perms, err := CompileRBAC([]RoleAssignment{
		{PrincipalID: "p1", Role: "Key Vault Secrets User"},
		{PrincipalID: "p1", Role: "Key Vault Crypto User"},
		{PrincipalID: "p2", Role: "Key Vault Administrator"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"secrets/get", "keys/sign"} {
		if !slices.Contains(perms["p1"], want) {
			t.Fatalf("merged roles missing %s: %v", want, perms["p1"])
		}
	}
	if !slices.Contains(perms["p2"], "*") {
		t.Fatalf("administrator = %v", perms["p2"])
	}
	if slices.Contains(perms["p1"], "secrets/set") {
		t.Fatal("Secrets User must not write")
	}
	if _, err := CompileRBAC([]RoleAssignment{{PrincipalID: "p", Role: "Duke of Vaults"}}); err == nil {
		t.Fatal("unknown role accepted")
	}
	if _, err := CompileRBAC([]RoleAssignment{{Role: "Key Vault Reader"}}); err == nil {
		t.Fatal("missing principalId accepted")
	}

	// The compiled map drives the live allowed() gate.
	s, _ := newService(t, "")
	s.SetPermissions(perms)
	if !s.allowed("p1", "secrets/get", "") || s.allowed("p1", "secrets/set", "") || !s.allowed("p2", "keys/rotate", "") {
		t.Fatal("compiled RBAC map not enforced by allowed()")
	}
}

func TestObjectScopedRBAC(t *testing.T) {
	perms, err := CompileRBAC([]RoleAssignment{
		{PrincipalID: "p1", Role: "Key Vault Crypto User", Scope: "/keys/signing-key"},
		{PrincipalID: "p2", Role: "Key Vault Administrator", Scope: "/secrets/one"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newService(t, "")
	s.SetPermissions(perms)

	// p1 may sign with the named key only; list (no object) needs vault scope.
	if !s.allowed("p1", "keys/sign", "signing-key") {
		t.Fatal("scoped grant refused on its own object")
	}
	if s.allowed("p1", "keys/sign", "other-key") {
		t.Fatal("scoped grant leaked to another object")
	}
	if s.allowed("p1", "keys/list", "") {
		t.Fatal("object-scoped assignment granted a vault-level operation")
	}
	// Administrator scoped to one secret touches that secret only.
	if !s.allowed("p2", "secrets/get", "one") || s.allowed("p2", "secrets/get", "two") ||
		s.allowed("p2", "keys/sign", "signing-key") {
		t.Fatal("scoped administrator not confined to its object")
	}

	// Malformed and empty-result scopes are refused.
	if _, err := CompileRBAC([]RoleAssignment{{PrincipalID: "p", Role: "Key Vault Reader", Scope: "/nope/x"}}); err == nil {
		t.Fatal("bad scope type accepted")
	}
	if _, err := CompileRBAC([]RoleAssignment{{PrincipalID: "p", Role: "Key Vault Reader", Scope: "/keys/"}}); err == nil {
		t.Fatal("empty scope name accepted")
	}
	if _, err := CompileRBAC([]RoleAssignment{{PrincipalID: "p", Role: "Key Vault Secrets User", Scope: "/keys/k"}}); err == nil {
		t.Fatal("type-mismatched scope produced an empty grant silently")
	}

	// The raw allowlist accepts op:object entries directly.
	s.SetPermissions(map[string][]string{"p3": {"secrets/get:pin"}})
	if !s.allowed("p3", "secrets/get", "pin") || s.allowed("p3", "secrets/get", "other") {
		t.Fatal("scoped allowlist entry not honoured")
	}
}

func TestGroupPrincipalAuthorization(t *testing.T) {
	s, _ := newService(t, "")
	const groupID = "54a9d08c-889d-489e-b534-336fe19dbfce"
	// The grant is bound to a GROUP, not to any user.
	s.SetManagedPermissions(map[string][]string{groupID: {"secrets/get"}})

	member := &auth.Principal{ID: "alice-oid", Type: "User", Groups: []string{groupID}}
	stranger := &auth.Principal{ID: "carol-oid", Type: "User"}
	otherGroup := &auth.Principal{ID: "dave-oid", Type: "User", Groups: []string{"some-other-group"}}

	if !s.allowedPrincipal(member, "secrets/get", "") {
		t.Fatal("a group member was denied its group's grant")
	}
	if s.allowedPrincipal(member, "secrets/set", "") {
		t.Fatal("the group grant leaked to an operation it does not cover")
	}
	if s.allowedPrincipal(stranger, "secrets/get", "") {
		t.Fatal("a non-member was allowed")
	}
	if s.allowedPrincipal(otherGroup, "secrets/get", "") {
		t.Fatal("membership of an unrelated group granted access")
	}

	// A direct grant to the principal still works alongside group grants, and
	// object scoping applies to group grants too.
	s.SetManagedPermissions(map[string][]string{
		"alice-oid": {"keys/sign"},
		groupID:     {"secrets/get:shared"},
	})
	if !s.allowedPrincipal(member, "keys/sign", "") {
		t.Fatal("a direct grant was lost")
	}
	if !s.allowedPrincipal(member, "secrets/get", "shared") {
		t.Fatal("a scoped group grant was denied on its object")
	}
	if s.allowedPrincipal(member, "secrets/get", "other") {
		t.Fatal("a scoped group grant leaked to another object")
	}
}
