package store

import (
	"errors"
	"testing"
)

func cert(vault, name string) *CertVersion {
	return &CertVersion{Vault: vault, Name: name, CerDER: "cer", PrivateDER: "key", Thumbprint: "tp", Enabled: true}
}

func TestCertVersioningUpdateAndLists(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetCert(cert("v", "c")); err != nil {
		t.Fatal(err)
	}
	c2 := cert("v", "c")
	if err := s.SetCert(c2); err != nil {
		t.Fatal(err)
	}
	cur, err := s.GetCert("v", "c")
	if err != nil || cur.Version != c2.Version {
		t.Fatalf("current = %+v, %v", cur, err)
	}
	if _, err := s.GetCertVersion("v", "c", c2.Version); err != nil {
		t.Fatal(err)
	}
	// Update attributes (disable + tags).
	cur.Enabled = false
	cur.TagsJSON = `{"t":"1"}`
	if err := s.UpdateCertVersion(cur); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetCertVersion("v", "c", cur.Version)
	if got.Enabled {
		t.Fatal("update not applied")
	}
	if err := s.UpdateCertVersion(&CertVersion{Vault: "v", Name: "c", Version: "nope"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing = %v", err)
	}
	vs, _ := s.ListCertVersions("v", "c")
	if len(vs) != 2 {
		t.Fatalf("versions = %d", len(vs))
	}
	if err := s.SetCert(cert("other", "c")); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListCerts("v")
	if len(list) != 1 {
		t.Fatalf("list = %d", len(list))
	}
}

func TestCertSoftDeleteOnClock(t *testing.T) {
	s := newTestStore(t)
	s.Clock.Freeze()
	if err := s.SetCert(cert("v", "c")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteCert("v", "c", 90); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCert("v", "c"); !errors.Is(err, ErrNotFound) {
		t.Fatal("soft-deleted cert readable")
	}
	if err := s.SetCert(cert("v", "c")); !errors.Is(err, ErrConflict) {
		t.Fatalf("reuse = %v", err)
	}
	if _, err := s.ListCertVersions("v", "c"); !errors.Is(err, ErrNotFound) {
		t.Fatal("versions of deleted listed")
	}
	if _, err := s.LatestCertIncludingDeleted("v", "c"); err != nil {
		t.Fatalf("latest incl deleted: %v", err)
	}
	if err := s.RecoverCert("v", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCert("v", "c"); err != nil {
		t.Fatalf("recovered unreadable: %v", err)
	}
	// Delete, advance past window → lazily purged.
	if _, err := s.DeleteCert("v", "c", 7); err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(7*86400 + 1)
	if _, err := s.GetDeletedCert("v", "c"); !errors.Is(err, ErrNotFound) {
		t.Fatal("survived purge deadline")
	}
	// ListDeletedCerts lazy purge.
	if err := s.SetCert(cert("v", "d")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteCert("v", "d", 7); err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(8 * 86400)
	if ds, err := s.ListDeletedCerts("v"); err != nil || len(ds) != 0 {
		t.Fatalf("deleted = %+v, %v", ds, err)
	}
}

func TestCertStoreNotFoundAndClosed(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetCert("v", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCert = %v", err)
	}
	if _, err := s.DeleteCert("v", "x", 90); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteCert = %v", err)
	}
	if err := s.RecoverCert("v", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecoverCert = %v", err)
	}

	closed := newTestStore(t)
	closed.Close()
	if err := closed.SetCert(cert("v", "c")); err == nil {
		t.Error("SetCert on closed DB succeeded")
	}
	if _, err := closed.ListCerts("v"); err == nil {
		t.Error("ListCerts on closed DB succeeded")
	}
	if _, err := closed.ListDeletedCerts("v"); err == nil {
		t.Error("ListDeletedCerts on closed DB succeeded")
	}
	if err := closed.PurgeCert("v", "c"); err == nil {
		t.Error("PurgeCert on closed DB succeeded")
	}
}

// Version getters short-circuit to NotFound while the name is soft-deleted.
func TestVersionGettersRespectSoftDelete(t *testing.T) {
	s := newTestStore(t)
	sv := &SecretVersion{Vault: "v", Name: "s", Value: "x", Enabled: true}
	if err := s.SetSecret(sv); err != nil {
		t.Fatal(err)
	}
	kv := rsaKey("v", "k")
	if err := s.SetKey(kv); err != nil {
		t.Fatal(err)
	}
	cv := cert("v", "c")
	if err := s.SetCert(cv); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSecret("v", "s", 90); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteKey("v", "k", 90); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteCert("v", "c", 90); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSecretVersion("v", "s", sv.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSecretVersion soft-deleted = %v", err)
	}
	if _, err := s.GetKeyVersion("v", "k", kv.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetKeyVersion soft-deleted = %v", err)
	}
	if _, err := s.GetCertVersion("v", "c", cv.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCertVersion soft-deleted = %v", err)
	}
}
