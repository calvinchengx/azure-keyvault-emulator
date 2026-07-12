package store

import (
	"errors"
	"testing"
)

func TestKeyRotationPolicyStore(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetKeyRotationPolicy("v", "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing policy err = %v", err)
	}
	if err := s.SetKeyRotationPolicy("v", "k", `{"a":1}`); err != nil {
		t.Fatal(err)
	}
	// Upsert overwrites.
	if err := s.SetKeyRotationPolicy("v", "k", `{"a":2}`); err != nil {
		t.Fatal(err)
	}
	js, err := s.GetKeyRotationPolicy("v", "k")
	if err != nil || js != `{"a":2}` {
		t.Fatalf("get policy = %q %v", js, err)
	}
}

func TestCertIssuerStore(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetCertIssuer("v", "i"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing issuer err = %v", err)
	}
	if _, err := s.DeleteCertIssuer("v", "i"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing err = %v", err)
	}
	if err := s.SetCertIssuer("v", "i", `{"provider":"P"}`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCertIssuer("v", "j", `{"provider":"Q"}`); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListCertIssuers("v")
	if err != nil || len(list) != 2 || list[0].Name != "i" {
		t.Fatalf("list = %+v %v", list, err)
	}
	js, err := s.DeleteCertIssuer("v", "i")
	if err != nil || js != `{"provider":"P"}` {
		t.Fatalf("delete = %q %v", js, err)
	}
	if _, err := s.GetCertIssuer("v", "i"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
}

func TestCertContactsStore(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetCertContacts("v"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing contacts err = %v", err)
	}
	if _, err := s.DeleteCertContacts("v"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing err = %v", err)
	}
	if err := s.SetCertContacts("v", `{"contacts":[]}`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCertContacts("v", `{"contacts":[1]}`); err != nil {
		t.Fatal(err) // upsert
	}
	js, err := s.GetCertContacts("v")
	if err != nil || js != `{"contacts":[1]}` {
		t.Fatalf("get = %q %v", js, err)
	}
	if js, err := s.DeleteCertContacts("v"); err != nil || js != `{"contacts":[1]}` {
		t.Fatalf("delete = %q %v", js, err)
	}
}

func TestUpdateCertPolicyStore(t *testing.T) {
	s := newTestStore(t)
	// No such certificate.
	if err := s.UpdateCertPolicy("v", "c", `{}`); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing cert err = %v", err)
	}
	cv := &CertVersion{Vault: "v", Name: "c", CerDER: "x", PrivateDER: "y", Enabled: true}
	if err := s.SetCert(cv); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateCertPolicy("v", "c", `{"issuer":{"name":"Self"}}`); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetCert("v", "c")
	if got.PolicyJSON != `{"issuer":{"name":"Self"}}` {
		t.Fatalf("policy = %s", got.PolicyJSON)
	}
}

func TestPendingCertStore(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetPendingCert("v", "c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing pending err = %v", err)
	}
	p := &PendingCert{Vault: "v", Name: "c", PrivateDER: "k", CSRDER: "r", Kty: "RSA", Issuer: "DigiCert"}
	if err := s.SetPendingCert(p); err != nil {
		t.Fatal(err)
	}
	// Upsert.
	p.CSRDER = "r2"
	if err := s.SetPendingCert(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPendingCert("v", "c")
	if err != nil || got.CSRDER != "r2" || got.Issuer != "DigiCert" || got.PolicyJSON != "{}" {
		t.Fatalf("get pending = %+v %v", got, err)
	}
	if err := s.DeletePendingCert("v", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPendingCert("v", "c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
}

// TestParityClosedDB sweeps the parity store methods against a closed database
// so their error-return branches are exercised.
func TestParityClosedDB(t *testing.T) {
	c := newTestStore(t)
	c.Close()
	checks := map[string]func() error{
		"GetKeyRotationPolicy": func() error { _, e := c.GetKeyRotationPolicy("v", "k"); return e },
		"SetKeyRotationPolicy": func() error { return c.SetKeyRotationPolicy("v", "k", "{}") },
		"GetCertIssuer":        func() error { _, e := c.GetCertIssuer("v", "i"); return e },
		"SetCertIssuer":        func() error { return c.SetCertIssuer("v", "i", "{}") },
		"ListCertIssuers":      func() error { _, e := c.ListCertIssuers("v"); return e },
		"GetCertContacts":      func() error { _, e := c.GetCertContacts("v"); return e },
		"SetCertContacts":      func() error { return c.SetCertContacts("v", "{}") },
		"GetPendingCert":       func() error { _, e := c.GetPendingCert("v", "c"); return e },
		"SetPendingCert":       func() error { return c.SetPendingCert(&PendingCert{Vault: "v", Name: "c"}) },
	}
	for name, fn := range checks {
		if err := fn(); err == nil {
			t.Errorf("%s on closed DB succeeded", name)
		}
	}
}
