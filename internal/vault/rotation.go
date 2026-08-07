package vault

// The rotation engine: the stored rotation policy acts. When a lifetime
// action's Rotate trigger (timeAfterCreate, ISO-8601) has elapsed on the
// emulator clock, the next read of the key lazily mints a new version — the
// same lazy clock-driven pattern as soft-delete retention. The policy's
// attributes.expiryTime drives the new version's exp.

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/store"
)

// isoDurationRE matches ISO-8601 durations (P90D, P1Y6M, PT12H, …).
var isoDurationRE = regexp.MustCompile(
	`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`)

// parseISODuration returns the duration in seconds. Calendar units use the
// conventional approximations (Y=365d, M=30d) — rotation windows are
// day-granular in practice.
func parseISODuration(s string) (int64, bool) {
	m := isoDurationRE.FindStringSubmatch(s)
	if m == nil || s == "P" || s == "PT" {
		return 0, false
	}
	units := []int64{365 * 86400, 30 * 86400, 7 * 86400, 86400, 3600, 60, 1}
	var total int64
	any := false
	for i, u := range units {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.ParseInt(m[i+1], 10, 64)
		if err != nil {
			return 0, false
		}
		total += n * u
		any = true
	}
	return total, any
}

// rotationPolicy is the subset of the stored policy the engine reads.
type rotationPolicy struct {
	LifetimeActions []struct {
		Trigger struct {
			TimeAfterCreate string `json:"timeAfterCreate"`
		} `json:"trigger"`
		Action struct {
			Type string `json:"type"`
		} `json:"action"`
	} `json:"lifetimeActions"`
	Attributes struct {
		ExpiryTime string `json:"expiryTime"`
	} `json:"attributes"`
}

// policyFor loads and parses the key's rotation policy; nil when unset or
// unparseable (a policy the engine cannot read simply does not rotate).
func (s *Service) policyFor(vault, name string) (*rotationPolicy, error) {
	js, err := s.Store.GetKeyRotationPolicy(vault, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pol rotationPolicy
	if json.Unmarshal([]byte(js), &pol) != nil {
		return nil, nil
	}
	return &pol, nil
}

// mintRotation generates a fresh version of cur — same type, size and curve,
// key_ops and tags carried over.
func mintRotation(cur *store.KeyVersion) (*store.KeyVersion, error) {
	priv, err := parseKey(cur.PrivateDER)
	if err != nil {
		return nil, err
	}
	size := 0
	if rk, ok := priv.(*rsa.PrivateKey); ok {
		size = rk.N.BitLen()
	}
	der, crv, err := generateKey(cur.Kty, size, cur.Crv)
	if err != nil {
		return nil, err
	}
	return &store.KeyVersion{
		Vault: cur.Vault, Name: cur.Name, Kty: cur.Kty, Crv: crv, PrivateDER: der,
		Enabled: true, KeyOpsJSON: cur.KeyOpsJSON, TagsJSON: cur.TagsJSON,
		Exportable: cur.Exportable, ReleasePolicyJSON: cur.ReleasePolicyJSON,
	}, nil
}

// applyRotationExpiry sets the new version's exp from the policy's
// attributes.expiryTime, when present.
func (s *Service) applyRotationExpiry(nv *store.KeyVersion, pol *rotationPolicy) {
	if pol == nil {
		return
	}
	if d, ok := parseISODuration(pol.Attributes.ExpiryTime); ok && d > 0 {
		e := s.Store.Now() + d
		nv.Exp = &e
	}
}

// maybeAutoRotate applies the stored rotation policy lazily: if a Rotate
// trigger's timeAfterCreate has elapsed since the newest version was created,
// one fresh version is minted. Absent key, absent policy, or a non-rotate
// policy are all no-ops; only storage failures surface.
func (s *Service) maybeAutoRotate(vault, name string) error {
	pol, err := s.policyFor(vault, name)
	if err != nil {
		return err
	}
	if pol == nil {
		return nil
	}
	after := int64(-1)
	for _, la := range pol.LifetimeActions {
		if strings.EqualFold(la.Action.Type, "Rotate") {
			if d, ok := parseISODuration(la.Trigger.TimeAfterCreate); ok && d > 0 {
				after = d
			}
		}
	}
	if after < 0 {
		return nil
	}
	cur, err := s.Store.GetKey(vault, name)
	if err != nil {
		// Absent or soft-deleted: nothing to rotate. Real storage failures
		// will surface on the read that follows.
		return nil
	}
	if s.Store.Now() < cur.CreatedAt+after {
		return nil
	}
	nv, err := mintRotation(cur)
	if err != nil {
		return err
	}
	s.applyRotationExpiry(nv, pol)
	return s.Store.SetKey(nv)
}
