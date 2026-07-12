// Package server assembles the emulator: the vault data plane, /health, and
// the /_emulator control surface (clock + faults — local plumbing, not part
// of the Key Vault contract).
package server

import (
	"encoding/json"
	"net/http"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/auth"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/clock"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/config"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/vault"
)

// Server owns the emulator's components.
type Server struct {
	Cfg   *config.Config
	Store *store.Store
	Clock *clock.Clock
	Vault *vault.Service
	mux   *http.ServeMux
}

// New wires the emulator. jwksClient overrides the JWKS-fetching HTTP client
// when non-nil (in-process tests against entra-emulator's test listener).
func New(cfg *config.Config, jwksClient *http.Client) (*Server, error) {
	ck := clock.New()
	st, err := store.Open(cfg.DataDir, ck)
	if err != nil {
		return nil, err
	}
	v := auth.New(cfg.EntraIssuer, cfg.EntraJWKSURL, cfg.EntraTLSInsecure, ck.Now, jwksClient)
	kv := vault.New(cfg, st, v)

	s := &Server{Cfg: cfg, Store: st, Clock: ck, Vault: kv, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "now": ck.Now()})
	})
	s.registerControl()
	s.registerPortal()
	s.mux.Handle("/", kv)
	return s, nil
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Close releases resources.
func (s *Server) Close() error { return s.Store.Close() }

func (s *Server) registerControl() {
	s.mux.HandleFunc("GET /_emulator/clock", func(w http.ResponseWriter, r *http.Request) {
		offset, frozen, now := s.Clock.State()
		writeJSON(w, http.StatusOK, map[string]any{"offset": offset, "frozen": frozen, "now": now})
	})
	s.mux.HandleFunc("POST /_emulator/clock", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Advance *int64 `json:"advance"`
			Offset  *int64 `json:"offset"`
			Freeze  *bool  `json:"freeze"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		if body.Offset != nil {
			s.Clock.SetOffset(*body.Offset)
		}
		if body.Advance != nil {
			s.Clock.Advance(*body.Advance)
		}
		if body.Freeze != nil {
			if *body.Freeze {
				s.Clock.Freeze()
			} else {
				s.Clock.Unfreeze()
			}
		}
		offset, frozen, now := s.Clock.State()
		writeJSON(w, http.StatusOK, map[string]any{"offset": offset, "frozen": frozen, "now": now})
	})
	// Fault injection: throttle (429 + Retry-After — real AKV throttles
	// aggressively and SDK retry behavior is otherwise untestable offline)
	// or reject (500) the next N requests.
	s.mux.HandleFunc("POST /_emulator/faults", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ThrottleNextRequests *int `json:"throttleNextRequests"`
			RejectNextRequests   *int `json:"rejectNextRequests"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		throttle, reject := -1, -1
		if body.ThrottleNextRequests != nil {
			throttle = *body.ThrottleNextRequests
		}
		if body.RejectNextRequests != nil {
			reject = *body.RejectNextRequests
		}
		s.Vault.SetFaults(throttle, reject)
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	// Per-principal operation allowlist ({"<principal-oid>": ["secrets/get",
	// "keys/sign", "*"]}). Empty body or {} restores full access — honest to
	// access-policy semantics without pretending to be ARM.
	s.mux.HandleFunc("POST /_emulator/permissions", func(w http.ResponseWriter, r *http.Request) {
		var perms map[string][]string
		if err := json.NewDecoder(r.Body).Decode(&perms); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed JSON"})
			return
		}
		s.Vault.SetPermissions(perms)
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
