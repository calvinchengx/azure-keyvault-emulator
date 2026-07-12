package store

import (
	"errors"
	"regexp"
	"testing"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/clock"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewVersionIDShape(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for range 50 {
		id := NewVersionID()
		if !re.MatchString(id) || seen[id] {
			t.Fatalf("NewVersionID() = %q (dup=%v)", id, seen[id])
		}
		seen[id] = true
	}
}

func TestSecretVersioning(t *testing.T) {
	s := newTestStore(t)
	v1 := &SecretVersion{Vault: "emulator", Name: "db", Value: "one", Enabled: true}
	if err := s.SetSecret(v1); err != nil {
		t.Fatal(err)
	}
	v2 := &SecretVersion{Vault: "emulator", Name: "db", Value: "two", Enabled: true, ContentType: "text/plain"}
	if err := s.SetSecret(v2); err != nil {
		t.Fatal(err)
	}
	if v1.Version == v2.Version {
		t.Fatal("PUT did not create a new version")
	}
	cur, err := s.GetSecret("emulator", "db")
	if err != nil || cur.Value != "two" {
		t.Fatalf("current = %+v, %v; want value two", cur, err)
	}
	old, err := s.GetSecretVersion("emulator", "db", v1.Version)
	if err != nil || old.Value != "one" {
		t.Fatalf("old version = %+v, %v", old, err)
	}
	vs, err := s.ListSecretVersions("emulator", "db")
	if err != nil || len(vs) != 2 || vs[0].Value != "one" {
		t.Fatalf("versions = %d, %v", len(vs), err)
	}
	// Update attributes only.
	nbf := int64(1000)
	old.NBF = &nbf
	old.Enabled = false
	if err := s.UpdateSecretVersion(old); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetSecretVersion("emulator", "db", v1.Version)
	if got.NBF == nil || *got.NBF != 1000 || got.Enabled {
		t.Fatalf("updated = %+v", got)
	}
	// Vault isolation + list newest-per-name.
	other := &SecretVersion{Vault: "other", Name: "db", Value: "x", Enabled: true}
	if err := s.SetSecret(other); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListSecrets("emulator")
	if err != nil || len(list) != 1 || list[0].Value != "two" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if _, err := s.GetSecret("nope", "db"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-vault get err = %v", err)
	}
}

func TestSoftDeleteLifecycleOnTheClock(t *testing.T) {
	s := newTestStore(t)
	s.Clock.Freeze()
	if err := s.SetSecret(&SecretVersion{Vault: "v", Name: "s", Value: "x", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// Delete: recoverable, name unusable, reads absent.
	d, err := s.DeleteSecret("v", "s", 90)
	if err != nil || d.PurgeAt != d.DeletedAt+90*86400 {
		t.Fatalf("delete = %+v, %v", d, err)
	}
	if _, err := s.GetSecret("v", "s"); !errors.Is(err, ErrNotFound) {
		t.Fatal("soft-deleted secret still readable")
	}
	if err := s.SetSecret(&SecretVersion{Vault: "v", Name: "s", Value: "y", Enabled: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("reuse of deleted name err = %v; want ErrConflict", err)
	}
	if _, err := s.ListSecretVersions("v", "s"); !errors.Is(err, ErrNotFound) {
		t.Fatal("versions of deleted name listed")
	}
	// The deleted record still exposes the latest version (for the bundle).
	if v, err := s.LatestVersionIncludingDeleted("v", "s"); err != nil || v.Value != "x" {
		t.Fatalf("latest incl deleted = %+v, %v", v, err)
	}

	// Recover restores reads.
	if err := s.RecoverSecret("v", "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSecret("v", "s"); err != nil {
		t.Fatalf("recovered secret unreadable: %v", err)
	}

	// Delete again, advance past the window: lazily purged.
	if _, err := s.DeleteSecret("v", "s", 7); err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(7*86400 + 1)
	if _, err := s.GetDeletedSecret("v", "s"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted record survived its purge deadline")
	}
	if v, err := s.LatestVersionIncludingDeleted("v", "s"); err == nil {
		t.Fatalf("versions survived lazy purge: %+v", v)
	}
	// Name is reusable after purge.
	if err := s.SetSecret(&SecretVersion{Vault: "v", Name: "s", Value: "fresh", Enabled: true}); err != nil {
		t.Fatalf("reuse after purge: %v", err)
	}
}

func TestListDeletedLazyPurge(t *testing.T) {
	s := newTestStore(t)
	s.Clock.Freeze()
	for _, name := range []string{"a", "b"} {
		if err := s.SetSecret(&SecretVersion{Vault: "v", Name: name, Value: "x", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteSecret("v", "a", 7); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSecret("v", "b", 90); err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(8 * 86400) // a lapses, b remains
	ds, err := s.ListDeletedSecrets("v")
	if err != nil || len(ds) != 1 || ds[0].Name != "b" {
		t.Fatalf("deleted list = %+v, %v", ds, err)
	}
}

func TestNotFoundAndClosedDB(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetSecret("v", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSecret = %v", err)
	}
	if _, err := s.GetSecretVersion("v", "x", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSecretVersion = %v", err)
	}
	if err := s.UpdateSecretVersion(&SecretVersion{Vault: "v", Name: "x", Version: "1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateSecretVersion = %v", err)
	}
	if _, err := s.DeleteSecret("v", "x", 90); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteSecret = %v", err)
	}
	if err := s.RecoverSecret("v", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecoverSecret = %v", err)
	}

	closed, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if err := closed.SetSecret(&SecretVersion{Vault: "v", Name: "s", Value: "x"}); err == nil {
		t.Error("SetSecret on closed DB succeeded")
	}
	if _, err := closed.GetSecret("v", "s"); err == nil {
		t.Error("GetSecret on closed DB succeeded")
	}
	if _, err := closed.ListSecrets("v"); err == nil {
		t.Error("ListSecrets on closed DB succeeded")
	}
	if _, err := closed.ListDeletedSecrets("v"); err == nil {
		t.Error("ListDeletedSecrets on closed DB succeeded")
	}
	if err := closed.PurgeSecret("v", "s"); err == nil {
		t.Error("PurgeSecret on closed DB succeeded")
	}
}
