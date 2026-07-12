package server

// The operator portal: a read-only Svelte SPA plus the JSON endpoints that
// feed it. Unlike the Key Vault data plane (which owns the root path namespace
// and is bearer-authenticated), the portal lives under /_emulator/portal/ and
// reads store state directly through this local-tooling escape hatch — it
// never impersonates a principal. It aggregates across every vault, since
// objects are Host-routed and more than one vault can exist locally.

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-keyvault-emulator/portal"
)

const portalPrefix = "/_emulator/portal/"

func (s *Server) registerPortal() {
	s.mux.HandleFunc("GET /_emulator/portal/data/overview", s.portalOverview)
	s.mux.HandleFunc("GET /_emulator/portal/data/secrets", s.portalSecrets)
	s.mux.HandleFunc("GET /_emulator/portal/data/keys", s.portalKeys)
	s.mux.HandleFunc("GET /_emulator/portal/data/certificates", s.portalCertificates)
	s.mux.HandleFunc("GET /_emulator/portal/data/deleted", s.portalDeleted)

	assets, err := portal.Dist()
	if err != nil {
		return // no embedded portal (should not happen with a committed dist)
	}
	files := http.StripPrefix(portalPrefix, http.FileServerFS(assets))
	spa := func(w http.ResponseWriter, r *http.Request) {
		// Serve a real embedded asset as-is; anything else falls back to the
		// SPA shell so deep links (hash routes) resolve to index.html.
		p := strings.TrimPrefix(r.URL.Path, portalPrefix)
		if p != "" {
			if _, err := fs.Stat(assets, p); err == nil {
				files.ServeHTTP(w, r)
				return
			}
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = portalPrefix
		files.ServeHTTP(w, r2)
	}
	s.mux.HandleFunc("GET /_emulator/portal/{path...}", spa)
	// Bare /_emulator/portal → canonical trailing-slash root.
	s.mux.HandleFunc("GET /_emulator/portal", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, portalPrefix, http.StatusMovedPermanently)
	})
}

// vaultsOr500 lists vaults, writing a 500 and returning ok=false on failure.
func (s *Server) vaultsOr500(w http.ResponseWriter) ([]string, bool) {
	vaults, err := s.Store.Vaults()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return nil, false
	}
	return vaults, true
}

func (s *Server) portalOverview(w http.ResponseWriter, r *http.Request) {
	vaults, ok := s.vaultsOr500(w)
	if !ok {
		return
	}
	var secrets, keys, certs, delSecrets, delKeys, delCerts int
	for _, v := range vaults {
		if xs, err := s.Store.ListSecrets(v); err == nil {
			secrets += len(xs)
		}
		if xs, err := s.Store.ListKeys(v); err == nil {
			keys += len(xs)
		}
		if xs, err := s.Store.ListCerts(v); err == nil {
			certs += len(xs)
		}
		if xs, err := s.Store.ListDeletedSecrets(v); err == nil {
			delSecrets += len(xs)
		}
		if xs, err := s.Store.ListDeletedKeys(v); err == nil {
			delKeys += len(xs)
		}
		if xs, err := s.Store.ListDeletedCerts(v); err == nil {
			delCerts += len(xs)
		}
	}
	offset, frozen, now := s.Clock.State()
	writeJSON(w, http.StatusOK, map[string]any{
		"vaults":       vaults,
		"defaultVault": s.Cfg.DefaultVault,
		"counts": map[string]int{
			"secrets": secrets, "keys": keys, "certificates": certs,
			"deletedSecrets": delSecrets, "deletedKeys": delKeys, "deletedCertificates": delCerts,
		},
		"clock": map[string]any{"offset": offset, "frozen": frozen, "now": now},
	})
}

func (s *Server) portalSecrets(w http.ResponseWriter, r *http.Request) {
	vaults, ok := s.vaultsOr500(w)
	if !ok {
		return
	}
	items := []map[string]any{}
	for _, v := range vaults {
		xs, err := s.Store.ListSecrets(v)
		if err != nil {
			continue
		}
		for _, x := range xs {
			items = append(items, map[string]any{
				"vault": v, "name": x.Name, "version": x.Version, "enabled": x.Enabled,
				"contentType": x.ContentType, "updated": x.UpdatedAt,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}

func (s *Server) portalKeys(w http.ResponseWriter, r *http.Request) {
	vaults, ok := s.vaultsOr500(w)
	if !ok {
		return
	}
	items := []map[string]any{}
	for _, v := range vaults {
		xs, err := s.Store.ListKeys(v)
		if err != nil {
			continue
		}
		for _, x := range xs {
			kty := x.Kty
			if x.Crv != "" {
				kty += " " + x.Crv
			}
			items = append(items, map[string]any{
				"vault": v, "name": x.Name, "version": x.Version, "enabled": x.Enabled,
				"kty": kty, "updated": x.UpdatedAt,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}

func (s *Server) portalCertificates(w http.ResponseWriter, r *http.Request) {
	vaults, ok := s.vaultsOr500(w)
	if !ok {
		return
	}
	items := []map[string]any{}
	for _, v := range vaults {
		xs, err := s.Store.ListCerts(v)
		if err != nil {
			continue
		}
		for _, x := range xs {
			var exp int64
			if x.Exp != nil {
				exp = *x.Exp
			}
			items = append(items, map[string]any{
				"vault": v, "name": x.Name, "version": x.Version, "enabled": x.Enabled,
				"thumbprint": x.Thumbprint, "expires": exp, "updated": x.UpdatedAt,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}

func (s *Server) portalDeleted(w http.ResponseWriter, r *http.Request) {
	vaults, ok := s.vaultsOr500(w)
	if !ok {
		return
	}
	items := []map[string]any{}
	add := func(vault, kind, name string, deletedAt, purgeAt int64) {
		items = append(items, map[string]any{
			"vault": vault, "type": kind, "name": name,
			"deletedDate": deletedAt, "scheduledPurgeDate": purgeAt,
		})
	}
	for _, v := range vaults {
		if ds, err := s.Store.ListDeletedSecrets(v); err == nil {
			for _, d := range ds {
				add(v, "secret", d.Name, d.DeletedAt, d.PurgeAt)
			}
		}
		if ds, err := s.Store.ListDeletedKeys(v); err == nil {
			for _, d := range ds {
				add(v, "key", d.Name, d.DeletedAt, d.PurgeAt)
			}
		}
		if ds, err := s.Store.ListDeletedCerts(v); err == nil {
			for _, d := range ds {
				add(v, "certificate", d.Name, d.DeletedAt, d.PurgeAt)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}
