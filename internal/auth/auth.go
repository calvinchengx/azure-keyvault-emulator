// Package auth validates Entra bearer tokens the way real Key Vault does:
// signature against the issuer's JWKS, issuer match, Fabric audience set, and
// expiry — with expiry checked against the emulator's controllable clock so
// token-lifetime scenarios are testable. No claims are trusted before the
// signature verifies.
package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
)

// VaultAudiences are the audiences Key Vault accepts (Azure keeps the
// trailing-slash variant when a client requests it).
var VaultAudiences = []string{
	"https://vault.azure.net",
	"https://vault.azure.net/",
}

// Principal is the validated caller identity.
type Principal struct {
	ID   string // oid claim (falls back to sub)
	Type string // "User" | "ServicePrincipal"
	App  string // appid claim when present
	// Groups is the token's groups claim — the object ids of the groups the
	// caller belongs to. Real Entra emits it when the app's
	// groupMembershipClaims (or an optional claim) asks for it; RBAC binds
	// assignments to groups as often as to principals, so authorization
	// matches against these too.
	Groups []string
}

// issuerSet is one trusted issuer with its JWKS cache.
type issuerSet struct {
	issuer  string
	jwksURL string
	keys    map[string]*rsa.PublicKey // kid → key
}

// Validator verifies RS256 bearer tokens against one or more trusted
// issuers' JWKS. The key that verifies a token's signature is bound to its
// issuer: the token's iss claim must name the issuer that key came from.
type Validator struct {
	Audiences []string
	Now       func() int64 // emulator clock

	client *http.Client

	mu      sync.RWMutex
	issuers []*issuerSet
}

// New builds a single-issuer Validator fetching keys from jwksURL. insecure
// skips TLS verification (entra-emulator's self-signed cert on a compose
// network). client overrides the HTTP client when non-nil (in-process tests).
func New(issuer, jwksURL string, insecure bool, now func() int64, client *http.Client) *Validator {
	return NewMulti([][2]string{{issuer, jwksURL}}, insecure, now, client)
}

// NewMulti builds a Validator trusting several issuers — ordered
// {issuer, jwksURL} pairs, as real Key Vault trusts any issuer of its tenant.
func NewMulti(pairs [][2]string, insecure bool, now func() int64, client *http.Client) *Validator {
	if client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		client = &http.Client{Transport: tr}
	}
	v := &Validator{Audiences: VaultAudiences, Now: now, client: client}
	for _, p := range pairs {
		v.issuers = append(v.issuers, &issuerSet{issuer: p[0], jwksURL: p[1], keys: map[string]*rsa.PublicKey{}})
	}
	return v
}

// Errors distinguished for the API's 401 bodies.
var (
	ErrNoToken  = errors.New("missing bearer token")
	ErrBadToken = errors.New("invalid token")
)

// ValidateRequest extracts and validates the Authorization header.
func (v *Validator) ValidateRequest(r *http.Request) (*Principal, error) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return nil, ErrNoToken
	}
	return v.Validate(strings.TrimSpace(h[len(prefix):]))
}

// Validate verifies the compact JWS and returns the principal.
func (v *Validator) Validate(token string) (*Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrBadToken)
	}
	headB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrBadToken)
	}
	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headB, &head); err != nil || head.Alg != "RS256" {
		return nil, fmt.Errorf("%w: unsupported alg", ErrBadToken)
	}
	key, keyIssuer, err := v.key(head.Kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadToken, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrBadToken)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("%w: signature", ErrBadToken)
	}

	payloadB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrBadToken)
	}
	var claims struct {
		Iss    string          `json:"iss"`
		Aud    json.RawMessage `json:"aud"`
		Exp    int64           `json:"exp"`
		Nbf    int64           `json:"nbf"`
		Oid    string          `json:"oid"`
		Groups []string        `json:"groups"`
		Sub    string          `json:"sub"`
		AppID  string          `json:"appid"`
		IdTyp  string          `json:"idtyp"`
	}
	if err := json.Unmarshal(payloadB, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims", ErrBadToken)
	}
	if claims.Iss != keyIssuer {
		return nil, fmt.Errorf("%w: issuer %q not trusted", ErrBadToken, claims.Iss)
	}
	if !audMatch(claims.Aud, v.Audiences) {
		return nil, fmt.Errorf("%w: audience not accepted", ErrBadToken)
	}
	now := v.Now()
	const skew = 60
	if claims.Exp != 0 && now > claims.Exp+skew {
		return nil, fmt.Errorf("%w: expired", ErrBadToken)
	}
	if claims.Nbf != 0 && now < claims.Nbf-skew {
		return nil, fmt.Errorf("%w: not yet valid", ErrBadToken)
	}

	p := &Principal{ID: claims.Oid, App: claims.AppID, Type: "User", Groups: claims.Groups}
	if p.ID == "" {
		p.ID = claims.Sub
	}
	// App-only tokens: idtyp=app when present; otherwise the v2 shape is an
	// appid with no user oid.
	if claims.IdTyp == "app" || (claims.Oid == "" && claims.AppID != "") {
		p.Type = "ServicePrincipal"
	}
	if p.ID == "" {
		return nil, fmt.Errorf("%w: no principal claim", ErrBadToken)
	}
	return p, nil
}

// aud may be a string or an array of strings.
func audMatch(raw json.RawMessage, accepted []string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		for _, a := range accepted {
			if one == a {
				return true
			}
		}
		return false
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, got := range many {
			for _, a := range accepted {
				if got == a {
					return true
				}
			}
		}
	}
	return false
}

// key returns the RSA key for kid and the issuer it belongs to, refetching
// each issuer's JWKS once on a miss (key rotation, first use).
func (v *Validator) key(kid string) (*rsa.PublicKey, string, error) {
	v.mu.RLock()
	for _, set := range v.issuers {
		if k := set.keys[kid]; k != nil {
			v.mu.RUnlock()
			return k, set.issuer, nil
		}
	}
	v.mu.RUnlock()
	var lastErr error
	for _, set := range v.issuers {
		if err := v.refresh(set); err != nil {
			lastErr = err
		}
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, set := range v.issuers {
		if k := set.keys[kid]; k != nil {
			return k, set.issuer, nil
		}
	}
	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", fmt.Errorf("no key %q in any trusted issuer's JWKS", kid)
}

func (v *Validator) refresh(set *issuerSet) error {
	resp, err := v.client.Get(set.jwksURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}
	fresh := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nB, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eB, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		fresh[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nB),
			E: int(new(big.Int).SetBytes(eB).Int64()),
		}
	}
	if len(fresh) == 0 {
		return errors.New("JWKS contained no RSA keys")
	}
	v.mu.Lock()
	set.keys = fresh
	v.mu.Unlock()
	return nil
}
