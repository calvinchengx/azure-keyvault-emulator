// Package config resolves runtime configuration from KV_* environment
// variables with flag overrides applied by cmd. The docker-compose contract
// (KV_ENTRA_ISSUER, KV_ENTRA_TLS_INSECURE) is the canonical wiring to
// entra-emulator.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config is the resolved emulator configuration.
type Config struct {
	// Addr is the listen address, e.g. ":8444".
	Addr string
	// DataDir holds SQLite and TLS state. Empty means in-memory DB and
	// ephemeral TLS keys.
	DataDir string

	// EntraIssuer is the exact iss expected in bearer tokens, e.g.
	// https://entra-emulator:8443/{tenant}/v2.0 — or a real Entra issuer.
	// A comma-separated list trusts several issuers (each validated against
	// its own JWKS); the 401 challenge advertises the first.
	EntraIssuer string
	// EntraJWKSURL is where signing keys are fetched; derived from the
	// issuer when unset.
	EntraJWKSURL string
	// EntraAuthority is what the 401 challenge advertises
	// ({origin}/{tenant}); derived from the issuer.
	EntraAuthority string
	// EntraTLSInsecure skips TLS verification when fetching JWKS.
	EntraTLSInsecure bool

	// DefaultVault is the vault served on non-vault hosts (localhost).
	DefaultVault string
	// SoftDeleteRetentionDays is the recovery window (7–90, default 90).
	SoftDeleteRetentionDays int
	// PurgeProtection mirrors real Key Vault's vault property: purge is
	// refused and recoveryLevel reports "Recoverable" while enabled. Also
	// toggleable at runtime via POST /_emulator/purge-protection.
	PurgeProtection bool

	// DisableTLS serves plain HTTP.
	DisableTLS bool
}

// FromEnvPartial reads the environment without validating — cmd applies flag
// overrides first, then calls Finish.
func FromEnvPartial() *Config {
	retention := 90
	if v, err := strconv.Atoi(os.Getenv("KV_SOFT_DELETE_RETENTION_DAYS")); err == nil {
		retention = v
	}
	return &Config{
		Addr:                    envOr("KV_ADDR", ":8444"),
		DataDir:                 os.Getenv("KV_DATA_DIR"),
		EntraIssuer:             os.Getenv("KV_ENTRA_ISSUER"),
		EntraJWKSURL:            os.Getenv("KV_ENTRA_JWKS_URL"),
		EntraTLSInsecure:        boolEnv("KV_ENTRA_TLS_INSECURE"),
		DefaultVault:            envOr("KV_DEFAULT_VAULT", "emulator"),
		SoftDeleteRetentionDays: retention,
		PurgeProtection:         boolEnv("KV_PURGE_PROTECTION"),
		DisableTLS:              boolEnv("KV_DISABLE_TLS"),
	}
}

// FromEnv builds a validated Config.
func FromEnv() (*Config, error) {
	c := FromEnvPartial()
	return c, c.Finish()
}

// Issuers returns the trusted issuers in order (EntraIssuer split on commas).
func (c *Config) Issuers() []string {
	var out []string
	for _, s := range strings.Split(c.EntraIssuer, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// IssuerJWKS returns ordered {issuer, jwksURL} pairs. An explicit
// KV_ENTRA_JWKS_URL applies to the first issuer only; the rest derive their
// JWKS from their own issuer URL.
func (c *Config) IssuerJWKS() [][2]string {
	var out [][2]string
	for i, iss := range c.Issuers() {
		base := strings.TrimSuffix(strings.TrimSuffix(iss, "/"), "/v2.0")
		jwks := base + "/discovery/v2.0/keys"
		if i == 0 && c.EntraJWKSURL != "" {
			jwks = c.EntraJWKSURL
		}
		out = append(out, [2]string{iss, jwks})
	}
	return out
}

// Finish validates and derives dependent fields. Call after flag overrides.
func (c *Config) Finish() error {
	issuers := c.Issuers()
	if len(issuers) == 0 {
		return fmt.Errorf("KV_ENTRA_ISSUER is required: the issuer bearer tokens must carry (an entra-emulator or real Entra v2.0 issuer URL)")
	}
	first := strings.TrimSuffix(strings.TrimSuffix(issuers[0], "/"), "/v2.0")
	if c.EntraJWKSURL == "" {
		c.EntraJWKSURL = first + "/discovery/v2.0/keys"
	}
	if c.EntraAuthority == "" {
		c.EntraAuthority = first
	}
	for _, iss := range issuers {
		if u, err := url.Parse(iss); err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("KV_ENTRA_ISSUER %q is not a URL", iss)
		}
	}
	if c.SoftDeleteRetentionDays < 7 || c.SoftDeleteRetentionDays > 90 {
		return fmt.Errorf("KV_SOFT_DELETE_RETENTION_DAYS must be 7-90 (got %d)", c.SoftDeleteRetentionDays)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func boolEnv(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
