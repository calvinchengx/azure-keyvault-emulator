package server

// Portal tests: the SPA is served under /_emulator/portal/ and the data
// endpoints aggregate store state across vaults.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

func TestPortalSPAServing(t *testing.T) {
	s := newControlServer(t)

	// The SPA shell is served at the portal root and for unknown deep links.
	for _, path := range []string{"/_emulator/portal/", "/_emulator/portal/#keys"} {
		w := s.hit(t, "GET", path, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<div id=\"app\">") {
			t.Fatalf("portal %q = %d, body head %q", path, w.Code, w.Body.String()[:min(80, w.Body.Len())])
		}
	}
	// Bare path redirects to the trailing-slash root.
	if w := s.hit(t, "GET", "/_emulator/portal", ""); w.Code != http.StatusMovedPermanently {
		t.Fatalf("bare portal path = %d", w.Code)
	}
}

func TestPortalDataEndpoints(t *testing.T) {
	s := newControlServer(t)

	// Seed one of each object plus a soft-deleted secret.
	if err := s.Store.SetSecret(&store.SecretVersion{Vault: "emulator", Name: "s1", Value: "v", Enabled: true, ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.SetKey(&store.KeyVersion{Vault: "emulator", Name: "k1", Kty: "EC", Crv: "P-256", PrivateDER: "x", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	exp := int64(999)
	if err := s.Store.SetCert(&store.CertVersion{Vault: "other", Name: "c1", CerDER: "d", PrivateDER: "p", Thumbprint: "abc123", Enabled: true, Exp: &exp}); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.SetSecret(&store.SecretVersion{Vault: "emulator", Name: "gone", Value: "v", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DeleteSecret("emulator", "gone", 90); err != nil {
		t.Fatal(err)
	}

	ow := s.hit(t, "GET", "/_emulator/portal/data/overview", "")
	if ow.Code != http.StatusOK {
		t.Fatalf("overview = %d", ow.Code)
	}
	var overview map[string]any
	if err := json.Unmarshal(ow.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	counts := overview["counts"].(map[string]any)
	if counts["secrets"].(float64) != 1 || counts["keys"].(float64) != 1 ||
		counts["certificates"].(float64) != 1 || counts["deletedSecrets"].(float64) != 1 {
		t.Fatalf("overview counts = %v", counts)
	}
	// Aggregates across both vaults.
	if vs := overview["vaults"].([]any); len(vs) != 2 {
		t.Fatalf("vaults = %v", vs)
	}

	if v := listValue(t, s, "/_emulator/portal/data/secrets"); len(v) != 1 || v[0]["name"] != "s1" {
		t.Fatalf("secrets = %v", v)
	}
	if v := listValue(t, s, "/_emulator/portal/data/keys"); len(v) != 1 || v[0]["kty"] != "EC P-256" {
		t.Fatalf("keys = %v", v)
	}
	if v := listValue(t, s, "/_emulator/portal/data/certificates"); len(v) != 1 || v[0]["vault"] != "other" {
		t.Fatalf("certificates = %v", v)
	}
	if v := listValue(t, s, "/_emulator/portal/data/deleted"); len(v) != 1 || v[0]["type"] != "secret" {
		t.Fatalf("deleted = %v", v)
	}
}

// TestPortalStorageFailure closes the store so every portal data endpoint
// takes its 500 path (Vaults() fails).
func TestPortalStorageFailure(t *testing.T) {
	s := newControlServer(t)
	s.Store.Close()
	for _, path := range []string{
		"/_emulator/portal/data/overview",
		"/_emulator/portal/data/secrets",
		"/_emulator/portal/data/keys",
		"/_emulator/portal/data/certificates",
		"/_emulator/portal/data/deleted",
	} {
		if w := s.hit(t, "GET", path, ""); w.Code != http.StatusInternalServerError {
			t.Errorf("%s with closed store = %d; want 500", path, w.Code)
		}
	}
}

func listValue(t *testing.T, s *Server, path string) []map[string]any {
	t.Helper()
	w := s.hit(t, "GET", path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("%s = %d", path, w.Code)
	}
	var body struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Value
}
