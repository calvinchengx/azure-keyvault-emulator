// Package vault serves the Key Vault data plane: the challenge-based
// authentication handshake (the emulator's reason to exist — the 401
// advertises entra-emulator's real authority) and the secrets surface with
// soft-delete semantics on the controllable clock.
package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/auth"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/config"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

// Service is the data-plane handler.
type Service struct {
	Store *store.Store
	Auth  *auth.Validator
	Cfg   *config.Config
	mux   *http.ServeMux

	// Fault switches (set via /_emulator/faults).
	mu           sync.Mutex
	throttleNext int // 429 + Retry-After
	rejectNext   int // 500
}

// New wires the service.
func New(cfg *config.Config, st *store.Store, v *auth.Validator) *Service {
	s := &Service{Store: st, Auth: v, Cfg: cfg, mux: http.NewServeMux()}
	s.mux.HandleFunc("PUT /secrets/{name}", s.withAuth(s.setSecret))
	s.mux.HandleFunc("GET /secrets/{name}", s.withAuth(s.getSecret))
	// The Azure SDK requests the unversioned get as /secrets/{name}/ — an
	// empty version segment with a trailing slash.
	s.mux.HandleFunc("GET /secrets/{name}/{$}", s.withAuth(s.getSecret))
	s.mux.HandleFunc("GET /secrets/{name}/{version}", s.withAuth(s.getSecretVersion))
	s.mux.HandleFunc("PATCH /secrets/{name}/{version}", s.withAuth(s.updateSecret))
	s.mux.HandleFunc("GET /secrets", s.withAuth(s.listSecrets))
	s.mux.HandleFunc("GET /secrets/{name}/versions", s.withAuth(s.listSecretVersions))
	s.mux.HandleFunc("DELETE /secrets/{name}", s.withAuth(s.deleteSecret))
	s.mux.HandleFunc("POST /secrets/{name}/backup", s.withAuth(s.backupSecret))
	s.mux.HandleFunc("POST /secrets/restore", s.withAuth(s.restoreSecret))
	s.mux.HandleFunc("GET /deletedsecrets/{name}", s.withAuth(s.getDeletedSecret))
	s.mux.HandleFunc("GET /deletedsecrets", s.withAuth(s.listDeletedSecrets))
	s.mux.HandleFunc("DELETE /deletedsecrets/{name}", s.withAuth(s.purgeSecret))
	s.mux.HandleFunc("POST /deletedsecrets/{name}/recover", s.withAuth(s.recoverSecret))
	return s
}

// SetFaults configures fault switches; negative values leave a field as-is.
func (s *Service) SetFaults(throttleNext, rejectNext int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if throttleNext >= 0 {
		s.throttleNext = throttleNext
	}
	if rejectNext >= 0 {
		s.rejectNext = rejectNext
	}
}

// vaultName resolves the vault from the Host header: {name}.vault.azure.net
// addresses that vault; anything else (localhost, ips) is the default vault.
func (s *Service) vaultName(r *http.Request) string {
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if rest, ok := strings.CutSuffix(host, ".vault.azure.net"); ok && rest != "" && !strings.Contains(rest, ".") {
		return rest
	}
	return s.Cfg.DefaultVault
}

// baseURL is the vault origin used in object ids — always the canonical
// https://{vault}.vault.azure.net form, as in real Key Vault.
func (s *Service) baseURL(r *http.Request) string {
	return "https://" + s.vaultName(r) + ".vault.azure.net"
}

type handler func(w http.ResponseWriter, r *http.Request, vault string)

// withAuth implements challenge-based authentication: a tokenless request
// gets 401 + WWW-Authenticate advertising the (emulated) Entra authority;
// a token is validated against that issuer's JWKS with the vault audience.
func (s *Service) withAuth(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-ms-request-id", store.NewVersionID())
		s.mu.Lock()
		switch {
		case s.rejectNext > 0:
			s.rejectNext--
			s.mu.Unlock()
			writeKVErr(w, http.StatusInternalServerError, "InternalServerError", "Injected fault.")
			return
		case s.throttleNext > 0:
			s.throttleNext--
			s.mu.Unlock()
			w.Header().Set("Retry-After", "1")
			writeKVErr(w, http.StatusTooManyRequests, "Throttled", "Injected throttling; retry the request.")
			return
		}
		s.mu.Unlock()

		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer authorization=%q, resource=%q`, s.Cfg.EntraAuthority, "https://vault.azure.net"))
			writeKVErr(w, http.StatusUnauthorized, "Unauthorized", "AKV10000: Request is missing a Bearer or PoP token.")
			return
		}
		if _, err := s.Auth.ValidateRequest(r); err != nil {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer authorization=%q, resource=%q`, s.Cfg.EntraAuthority, "https://vault.azure.net"))
			writeKVErr(w, http.StatusUnauthorized, "Unauthorized", err.Error())
			return
		}
		h(w, r, s.vaultName(r))
	}
}

// ServeHTTP dispatches to the data-plane mux.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// ---- wire shapes ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeKVErr emits the Key Vault error envelope.
func writeKVErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
