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
		DisableTLS:              boolEnv("KV_DISABLE_TLS"),
	}
}

// FromEnv builds a validated Config.
func FromEnv() (*Config, error) {
	c := FromEnvPartial()
	return c, c.Finish()
}

// Finish validates and derives dependent fields. Call after flag overrides.
func (c *Config) Finish() error {
	if c.EntraIssuer == "" {
		return fmt.Errorf("KV_ENTRA_ISSUER is required: the issuer bearer tokens must carry (an entra-emulator or real Entra v2.0 issuer URL)")
	}
	base := strings.TrimSuffix(strings.TrimSuffix(c.EntraIssuer, "/"), "/v2.0")
	if c.EntraJWKSURL == "" {
		c.EntraJWKSURL = base + "/discovery/v2.0/keys"
	}
	if c.EntraAuthority == "" {
		c.EntraAuthority = base
	}
	if u, err := url.Parse(c.EntraIssuer); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("KV_ENTRA_ISSUER %q is not a URL", c.EntraIssuer)
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
