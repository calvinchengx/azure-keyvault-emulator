package store

import (
	"errors"
	"testing"
)

func rsaKey(vault, name string) *KeyVersion {
	return &KeyVersion{Vault: vault, Name: name, Kty: "RSA", PrivateDER: "der", Enabled: true}
}

func TestKeyVersioningAndLists(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetKey(rsaKey("v", "k")); err != nil {
		t.Fatal(err)
	}
	k2 := rsaKey("v", "k")
	if err := s.SetKey(k2); err != nil {
		t.Fatal(err)
	}
	cur, err := s.GetKey("v", "k")
	if err != nil || cur.Version != k2.Version {
		t.Fatalf("current = %+v, %v", cur, err)
	}
	if _, err := s.GetKeyVersion("v", "k", k2.Version); err != nil {
		t.Fatal(err)
	}
	vs, err := s.ListKeyVersions("v", "k")
	if err != nil || len(vs) != 2 {
		t.Fatalf("versions = %d, %v", len(vs), err)
	}
	// Update attributes.
	cur.Enabled = false
	nbf := int64(5)
	cur.NBF = &nbf
	if err := s.UpdateKeyVersion(cur); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetKeyVersion("v", "k", cur.Version)
	if got.Enabled || *got.NBF != 5 {
		t.Fatalf("update not applied: %+v", got)
	}
	// Vault isolation on list.
	if err := s.SetKey(rsaKey("other", "k")); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListKeys("v")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
	if _, err := s.GetKey("nope", "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-vault get = %v", err)
	}
}

func TestKeySoftDeleteOnClock(t *testing.T) {
	s := newTestStore(t)
	s.Clock.Freeze()
	if err := s.SetKey(rsaKey("v", "k")); err != nil {
		t.Fatal(err)
	}

	d, err := s.DeleteKey("v", "k", 90)
	if err != nil || d.PurgeAt != d.DeletedAt+90*86400 {
		t.Fatalf("delete = %+v, %v", d, err)
	}
	if _, err := s.GetKey("v", "k"); !errors.Is(err, ErrNotFound) {
		t.Fatal("soft-deleted key still readable")
	}
	if err := s.SetKey(rsaKey("v", "k")); !errors.Is(err, ErrConflict) {
		t.Fatalf("reuse of deleted name = %v", err)
	}
	if _, err := s.ListKeyVersions("v", "k"); !errors.Is(err, ErrNotFound) {
		t.Fatal("versions of deleted name listed")
	}
	if k, err := s.LatestKeyIncludingDeleted("v", "k"); err != nil || k == nil {
		t.Fatalf("latest incl deleted = %v", err)
	}
	if err := s.RecoverKey("v", "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetKey("v", "k"); err != nil {
		t.Fatalf("recovered key unreadable: %v", err)
	}

	// Delete again, advance past window → lazily purged.
	if _, err := s.DeleteKey("v", "k", 7); err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(7*86400 + 1)
	if _, err := s.GetDeletedKey("v", "k"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted key survived purge deadline")
	}
	if err := s.SetKey(rsaKey("v", "k")); err != nil {
		t.Fatalf("reuse after purge: %v", err)
	}
}

func TestListDeletedKeysLazyPurge(t *testing.T) {
	s := newTestStore(t)
	s.Clock.Freeze()
	for _, name := range []string{"a", "b"} {
		if err := s.SetKey(rsaKey("v", name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteKey("v", "a", 7); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteKey("v", "b", 90); err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(8 * 86400)
	ds, err := s.ListDeletedKeys("v")
	if err != nil || len(ds) != 1 || ds[0].Name != "b" {
		t.Fatalf("deleted keys = %+v, %v", ds, err)
	}
}

func TestKeyStoreNotFoundAndClosed(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetKey("v", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetKey = %v", err)
	}
	if _, err := s.GetKeyVersion("v", "x", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetKeyVersion = %v", err)
	}
	if err := s.UpdateKeyVersion(&KeyVersion{Vault: "v", Name: "x", Version: "1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateKeyVersion = %v", err)
	}
	if _, err := s.DeleteKey("v", "x", 90); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteKey = %v", err)
	}
	if err := s.RecoverKey("v", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecoverKey = %v", err)
	}

	closed := newTestStore(t)
	closed.Close()
	if err := closed.SetKey(rsaKey("v", "k")); err == nil {
		t.Error("SetKey on closed DB succeeded")
	}
	if _, err := closed.GetKey("v", "k"); err == nil {
		t.Error("GetKey on closed DB succeeded")
	}
	if _, err := closed.ListKeys("v"); err == nil {
		t.Error("ListKeys on closed DB succeeded")
	}
	if _, err := closed.ListDeletedKeys("v"); err == nil {
		t.Error("ListDeletedKeys on closed DB succeeded")
	}
	if err := closed.PurgeKey("v", "k"); err == nil {
		t.Error("PurgeKey on closed DB succeeded")
	}
}
