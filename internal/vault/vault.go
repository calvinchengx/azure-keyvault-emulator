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
	// certMux serves the reserved certificate sub-resources (issuers,
	// contacts). Their fixed path segments overlap with the {name}/pending
	// and {name}/policy certificate-operation patterns, which Go's ServeMux
	// treats as an unresolvable conflict — so they get their own mux,
	// dispatched by path prefix in ServeHTTP.
	certMux *http.ServeMux

	// Fault switches (set via /_emulator/faults).
	mu           sync.Mutex
	throttleNext int // 429 + Retry-After
	rejectNext   int // 500
	// perms is the optional per-principal operation allowlist
	// (/_emulator/permissions): principal id → allowed ops. A principal
	// absent from a non-empty map (or with an empty list) is denied; an
	// empty map means full access for everyone (the default dev posture).
	perms map[string][]string
}

// New wires the service.
func New(cfg *config.Config, st *store.Store, v *auth.Validator) *Service {
	s := &Service{Store: st, Auth: v, Cfg: cfg, mux: http.NewServeMux(), certMux: http.NewServeMux()}
	s.mux.HandleFunc("PUT /secrets/{name}", s.withAuth("secrets/set", s.setSecret))
	s.mux.HandleFunc("GET /secrets/{name}", s.withAuth("secrets/get", s.getSecret))
	// The Azure SDK requests the unversioned get as /secrets/{name}/ — an
	// empty version segment with a trailing slash.
	s.mux.HandleFunc("GET /secrets/{name}/{$}", s.withAuth("secrets/get", s.getSecret))
	s.mux.HandleFunc("GET /secrets/{name}/{version}", s.withAuth("secrets/get", s.getSecretVersion))
	s.mux.HandleFunc("PATCH /secrets/{name}/{version}", s.withAuth("secrets/update", s.updateSecret))
	s.mux.HandleFunc("GET /secrets", s.withAuth("secrets/list", s.listSecrets))
	s.mux.HandleFunc("GET /secrets/{name}/versions", s.withAuth("secrets/list", s.listSecretVersions))
	s.mux.HandleFunc("DELETE /secrets/{name}", s.withAuth("secrets/delete", s.deleteSecret))
	s.mux.HandleFunc("POST /secrets/{name}/backup", s.withAuth("secrets/backup", s.backupSecret))
	s.mux.HandleFunc("POST /secrets/restore", s.withAuth("secrets/restore", s.restoreSecret))
	s.mux.HandleFunc("GET /deletedsecrets/{name}", s.withAuth("secrets/get", s.getDeletedSecret))
	s.mux.HandleFunc("GET /deletedsecrets", s.withAuth("secrets/list", s.listDeletedSecrets))
	s.mux.HandleFunc("DELETE /deletedsecrets/{name}", s.withAuth("secrets/purge", s.purgeSecret))
	s.mux.HandleFunc("POST /deletedsecrets/{name}/recover", s.withAuth("secrets/recover", s.recoverSecret))

	s.mux.HandleFunc("POST /keys/{name}/create", s.withAuth("keys/create", s.createKey))
	// PUT /keys/{name} imports a caller-supplied JWK.
	s.mux.HandleFunc("PUT /keys/{name}", s.withAuth("keys/import", s.importKey))
	s.mux.HandleFunc("GET /keys/{name}", s.withAuth("keys/get", s.getKey))
	s.mux.HandleFunc("GET /keys/{name}/{$}", s.withAuth("keys/get", s.getKey))
	s.mux.HandleFunc("GET /keys/{name}/{version}", s.withAuth("keys/get", s.getKey))
	s.mux.HandleFunc("PATCH /keys/{name}/{version}", s.withAuth("keys/update", s.updateKey))
	s.mux.HandleFunc("PATCH /keys/{name}", s.withAuth("keys/update", s.updateKeyLatest))
	s.mux.HandleFunc("GET /keys", s.withAuth("keys/list", s.listKeys))
	s.mux.HandleFunc("GET /keys/{name}/versions", s.withAuth("keys/list", s.listKeyVersions))
	s.mux.HandleFunc("DELETE /keys/{name}", s.withAuth("keys/delete", s.deleteKey))
	s.mux.HandleFunc("POST /keys/{name}/backup", s.withAuth("keys/backup", s.backupKey))
	s.mux.HandleFunc("POST /keys/restore", s.withAuth("keys/restore", s.restoreKey))
	s.mux.HandleFunc("GET /keys/{name}/rotationpolicy", s.withAuth("keys/get", s.getKeyRotationPolicy))
	s.mux.HandleFunc("PUT /keys/{name}/rotationpolicy", s.withAuth("keys/update", s.setKeyRotationPolicy))
	s.mux.HandleFunc("GET /deletedkeys/{name}", s.withAuth("keys/get", s.getDeletedKey))
	s.mux.HandleFunc("GET /deletedkeys", s.withAuth("keys/list", s.listDeletedKeys))
	s.mux.HandleFunc("DELETE /deletedkeys/{name}", s.withAuth("keys/purge", s.purgeKey))
	s.mux.HandleFunc("POST /deletedkeys/{name}/recover", s.withAuth("keys/recover", s.recoverKey))
	// GetRandomBytes: vault-level, not tied to a key name.
	s.mux.HandleFunc("POST /rng", s.withAuth("keys/rng", s.getRandomBytes))
	// Crypto operations, versioned and unversioned (the SDK's unversioned
	// form reaches these via the double-slash rewrite in ServeHTTP).
	for _, op := range []string{"sign", "verify", "encrypt", "decrypt", "wrapkey", "unwrapkey"} {
		s.mux.HandleFunc("POST /keys/{name}/{version}/"+op, s.withAuth("keys/"+op, s.cryptoOp(op)))
		s.mux.HandleFunc("POST /keys/{name}/"+op, s.withAuth("keys/"+op, s.cryptoOp(op)))
	}
	// Secure Key Release (versioned + unversioned via the double-slash rewrite).
	s.mux.HandleFunc("POST /keys/{name}/{version}/release", s.withAuth("keys/release", s.releaseKey))
	s.mux.HandleFunc("POST /keys/{name}/release", s.withAuth("keys/release", s.releaseKey))

	s.mux.HandleFunc("POST /certificates/{name}/create", s.withAuth("certificates/create", s.createCertificate))
	s.mux.HandleFunc("POST /certificates/{name}/import", s.withAuth("certificates/import", s.importCertificate))
	s.mux.HandleFunc("POST /certificates/{name}/pending/merge", s.withAuth("certificates/merge", s.mergeCertificate))
	s.mux.HandleFunc("POST /certificates/{name}/backup", s.withAuth("certificates/backup", s.backupCertificate))
	s.mux.HandleFunc("POST /certificates/restore", s.withAuth("certificates/restore", s.restoreCertificate))
	s.mux.HandleFunc("GET /certificates/{name}/pending", s.withAuth("certificates/get", s.getCertificateOperation))
	s.mux.HandleFunc("GET /certificates/{name}/policy", s.withAuth("certificates/get", s.getCertificatePolicy))
	s.mux.HandleFunc("PATCH /certificates/{name}/policy", s.withAuth("certificates/update", s.updateCertificatePolicy))
	s.mux.HandleFunc("GET /certificates/{name}/versions", s.withAuth("certificates/list", s.listCertificateVersions))
	// Certificate issuers and contacts (vault-scoped sub-resources) live on
	// certMux — see the field comment for why they can't share s.mux.
	s.certMux.HandleFunc("GET /certificates/issuers", s.withAuth("certificates/list", s.listCertIssuers))
	s.certMux.HandleFunc("GET /certificates/issuers/{$}", s.withAuth("certificates/list", s.listCertIssuers))
	s.certMux.HandleFunc("PUT /certificates/issuers/{name}", s.withAuth("certificates/setissuers", s.setCertIssuer))
	s.certMux.HandleFunc("GET /certificates/issuers/{name}", s.withAuth("certificates/getissuers", s.getCertIssuer))
	s.certMux.HandleFunc("PATCH /certificates/issuers/{name}", s.withAuth("certificates/setissuers", s.setCertIssuer))
	s.certMux.HandleFunc("DELETE /certificates/issuers/{name}", s.withAuth("certificates/deleteissuers", s.deleteCertIssuer))
	s.certMux.HandleFunc("PUT /certificates/contacts", s.withAuth("certificates/setcontacts", s.setCertContacts))
	s.certMux.HandleFunc("GET /certificates/contacts", s.withAuth("certificates/getcontacts", s.getCertContacts))
	s.certMux.HandleFunc("DELETE /certificates/contacts", s.withAuth("certificates/deletecontacts", s.deleteCertContacts))
	s.mux.HandleFunc("GET /certificates/{name}", s.withAuth("certificates/get", s.getCertificate))
	s.mux.HandleFunc("GET /certificates/{name}/{$}", s.withAuth("certificates/get", s.getCertificate))
	s.mux.HandleFunc("GET /certificates/{name}/{version}", s.withAuth("certificates/get", s.getCertificate))
	s.mux.HandleFunc("PATCH /certificates/{name}/{version}", s.withAuth("certificates/update", s.updateCertificate))
	s.mux.HandleFunc("PATCH /certificates/{name}", s.withAuth("certificates/update", s.updateCertificate))
	s.mux.HandleFunc("GET /certificates", s.withAuth("certificates/list", s.listCertificates))
	s.mux.HandleFunc("DELETE /certificates/{name}", s.withAuth("certificates/delete", s.deleteCertificate))
	s.mux.HandleFunc("GET /deletedcertificates/{name}", s.withAuth("certificates/get", s.getDeletedCertificate))
	s.mux.HandleFunc("GET /deletedcertificates", s.withAuth("certificates/list", s.listDeletedCertificates))
	s.mux.HandleFunc("DELETE /deletedcertificates/{name}", s.withAuth("certificates/purge", s.purgeCertificate))
	s.mux.HandleFunc("POST /deletedcertificates/{name}/recover", s.withAuth("certificates/recover", s.recoverCertificate))
	return s
}

// SetPermissions replaces the per-principal operation allowlist (nil or
// empty = full access for every valid token).
func (s *Service) SetPermissions(perms map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perms = perms
}

// allowed reports whether the principal may perform op.
func (s *Service) allowed(principalID, op string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.perms) == 0 {
		return true
	}
	for _, got := range s.perms[principalID] {
		if got == op || got == "*" {
			return true
		}
	}
	return false
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
// gets 401 + WWW-Authenticate advertising the (emulated) Entra authority; a
// token is validated against that issuer's JWKS with the vault audience, and
// the optional permission map gates the named operation.
func (s *Service) withAuth(op string, h handler) http.HandlerFunc {
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
		p, err := s.Auth.ValidateRequest(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer authorization=%q, resource=%q`, s.Cfg.EntraAuthority, "https://vault.azure.net"))
			writeKVErr(w, http.StatusUnauthorized, "Unauthorized", err.Error())
			return
		}
		if !s.allowed(p.ID, op) {
			writeKVErr(w, http.StatusForbidden, "Forbidden",
				fmt.Sprintf("The principal is not permitted to perform %s on this vault.", op))
			return
		}
		h(w, r, s.vaultName(r))
	}
}

// ServeHTTP dispatches to the data-plane mux. The Azure SDK emits an empty
// version segment for unversioned crypto operations (/keys/{name}//sign);
// collapse doubled slashes so those reach the version-less patterns instead
// of ServeMux's 301 redirect (which POSTs must not follow).
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "//") {
		r.URL.Path = strings.ReplaceAll(r.URL.Path, "//", "/")
	}
	// Reserved certificate sub-resources route to certMux (they can't share
	// s.mux — see the certMux field comment).
	p := r.URL.Path
	if p == "/certificates/issuers" || strings.HasPrefix(p, "/certificates/issuers/") ||
		p == "/certificates/contacts" {
		s.certMux.ServeHTTP(w, r)
		return
	}
	s.mux.ServeHTTP(w, r)
}

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
