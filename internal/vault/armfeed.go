package vault

// The ARM feed consumer: when arm-emulator is wired in, authorization stops
// being configured through this emulator's own control surface and starts
// coming from where Azure keeps it — role assignments and vault access
// policies written over ARM's real wire.
//
// Division of authority, as in Azure: ARM owns roles, assignments and access
// policies; this data plane owns its operation vocabulary and decides what a
// dataAction permits. The mapping below is that decision, and it is the whole
// integration — everything downstream is the allowlist engine that already
// exists.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// dataActionMap translates Key Vault dataActions to this emulator's ops.
// Wildcards are handled separately; these are the exact documented actions.
var dataActionMap = map[string][]string{
	"microsoft.keyvault/vaults/secrets/getsecret/action":    {"secrets/get"},
	"microsoft.keyvault/vaults/secrets/readmetadata/action": {"secrets/list"},
	"microsoft.keyvault/vaults/secrets/setsecret/action":    {"secrets/set"},
	"microsoft.keyvault/vaults/secrets/delete":              {"secrets/delete"},
	"microsoft.keyvault/vaults/secrets/backup/action":       {"secrets/backup"},
	"microsoft.keyvault/vaults/secrets/restore/action":      {"secrets/restore"},
	"microsoft.keyvault/vaults/secrets/recover/action":      {"secrets/recover"},
	"microsoft.keyvault/vaults/secrets/purge/action":        {"secrets/purge"},

	"microsoft.keyvault/vaults/keys/read":           {"keys/get", "keys/list"},
	"microsoft.keyvault/vaults/keys/create":         {"keys/create"},
	"microsoft.keyvault/vaults/keys/update/action":  {"keys/update"},
	"microsoft.keyvault/vaults/keys/import/action":  {"keys/import"},
	"microsoft.keyvault/vaults/keys/delete":         {"keys/delete"},
	"microsoft.keyvault/vaults/keys/backup/action":  {"keys/backup"},
	"microsoft.keyvault/vaults/keys/restore/action": {"keys/restore"},
	"microsoft.keyvault/vaults/keys/recover/action": {"keys/recover"},
	"microsoft.keyvault/vaults/keys/purge/action":   {"keys/purge"},
	"microsoft.keyvault/vaults/keys/encrypt/action": {"keys/encrypt"},
	"microsoft.keyvault/vaults/keys/decrypt/action": {"keys/decrypt"},
	"microsoft.keyvault/vaults/keys/wrap/action":    {"keys/wrapkey"},
	"microsoft.keyvault/vaults/keys/unwrap/action":  {"keys/unwrapkey"},
	"microsoft.keyvault/vaults/keys/sign/action":    {"keys/sign"},
	"microsoft.keyvault/vaults/keys/verify/action":  {"keys/verify"},
	"microsoft.keyvault/vaults/keys/rotate/action":  {"keys/rotate"},
	"microsoft.keyvault/vaults/keys/release/action": {"keys/release"},
	"microsoft.keyvault/vaults/keys/rng/action":     {"keys/rng"},

	"microsoft.keyvault/vaults/certificates/read":            {"certificates/get", "certificates/list"},
	"microsoft.keyvault/vaults/certificates/create/action":   {"certificates/create", "certificates/merge"},
	"microsoft.keyvault/vaults/certificates/update/action":   {"certificates/update"},
	"microsoft.keyvault/vaults/certificates/import/action":   {"certificates/import"},
	"microsoft.keyvault/vaults/certificates/delete":          {"certificates/delete"},
	"microsoft.keyvault/vaults/certificates/backup/action":   {"certificates/backup"},
	"microsoft.keyvault/vaults/certificates/restore/action":  {"certificates/restore"},
	"microsoft.keyvault/vaults/certificates/recover/action":  {"certificates/recover"},
	"microsoft.keyvault/vaults/certificates/purge/action":    {"certificates/purge"},
	"microsoft.keyvault/vaults/certificates/issuers/read":    {"certificates/getissuers"},
	"microsoft.keyvault/vaults/certificates/issuers/write":   {"certificates/setissuers"},
	"microsoft.keyvault/vaults/certificates/issuers/delete":  {"certificates/deleteissuers"},
	"microsoft.keyvault/vaults/certificates/contacts/read":   {"certificates/getcontacts"},
	"microsoft.keyvault/vaults/certificates/contacts/write":  {"certificates/setcontacts"},
	"microsoft.keyvault/vaults/certificates/contacts/delete": {"certificates/deletecontacts"},
}

// opsForDataAction expands one dataAction, including the wildcard forms real
// role definitions use ("Microsoft.KeyVault/vaults/*",
// "Microsoft.KeyVault/vaults/secrets/*").
func opsForDataAction(action string) []string {
	a := strings.ToLower(strings.TrimSpace(action))
	if a == "" {
		return nil
	}
	if a == "*" || a == "microsoft.keyvault/vaults/*" || a == "microsoft.keyvault/*" {
		return []string{"*"}
	}
	if strings.HasSuffix(a, "/*") {
		prefix := strings.TrimSuffix(a, "*")
		var out []string
		for k, ops := range dataActionMap {
			if strings.HasPrefix(k, prefix) {
				out = append(out, ops...)
			}
		}
		return out
	}
	return dataActionMap[a]
}

// accessPolicyOps expands an access-policy permission list ("get", "list",
// "all", …) for one object type onto this emulator's ops. It reuses the same
// tables the /_emulator/access-policy surface compiles with, so both routes
// to a permission mean exactly the same thing.
func accessPolicyOps(kind string, names []string) []string {
	var table map[string][]string
	switch kind {
	case "secrets":
		table = secretPerms
	case "keys":
		table = keyPerms
	case "certificates":
		table = certPerms
	default:
		return nil
	}
	var out []string
	for _, n := range names {
		key := strings.ToLower(strings.TrimSpace(n))
		if key == "all" {
			out = append(out, allOf(table)...)
			continue
		}
		if ops, ok := table[key]; ok {
			out = append(out, ops...)
		}
		// An unrecognised permission name grants nothing — the feed is not a
		// user-facing API, so a silent skip is right here; the control-surface
		// route still refuses typos loudly.
	}
	return out
}

// armFeed is the shape arm-emulator serves at /_family/authorization.
type armFeed struct {
	Scope       string `json:"scope"`
	Generated   int64  `json:"generated"`
	Assignments []struct {
		PrincipalID    string   `json:"principalId"`
		RoleName       string   `json:"roleName"`
		DataActions    []string `json:"dataActions"`
		NotDataActions []string `json:"notDataActions"`
	} `json:"assignments"`
	AccessPolicies []struct {
		ObjectID    string `json:"objectId"`
		Permissions struct {
			Keys         []string `json:"keys"`
			Secrets      []string `json:"secrets"`
			Certificates []string `json:"certificates"`
		} `json:"permissions"`
	} `json:"accessPolicies"`
	EnableRbacAuthorization bool `json:"enableRbacAuthorization"`
}

// compileFeed turns a feed document into the per-principal allowlist. A vault
// with enableRbacAuthorization honours role assignments only; otherwise
// access policies apply too — the same either/or real Key Vault enforces.
func compileFeed(f *armFeed) map[string][]string {
	perms := map[string][]string{}
	add := func(principal string, ops []string) {
		if principal == "" || len(ops) == 0 {
			return
		}
		for _, op := range ops {
			if !contains(perms[principal], op) {
				perms[principal] = append(perms[principal], op)
			}
		}
	}
	for _, a := range f.Assignments {
		var ops []string
		for _, da := range a.DataActions {
			ops = append(ops, opsForDataAction(da)...)
		}
		// notDataActions subtract from what the role grants.
		if len(a.NotDataActions) > 0 {
			var denied []string
			for _, nda := range a.NotDataActions {
				denied = append(denied, opsForDataAction(nda)...)
			}
			var kept []string
			for _, op := range ops {
				if !contains(denied, op) {
					kept = append(kept, op)
				}
			}
			ops = kept
		}
		add(a.PrincipalID, ops)
	}
	if !f.EnableRbacAuthorization {
		for _, p := range f.AccessPolicies {
			var ops []string
			ops = append(ops, accessPolicyOps("secrets", p.Permissions.Secrets)...)
			ops = append(ops, accessPolicyOps("keys", p.Permissions.Keys)...)
			ops = append(ops, accessPolicyOps("certificates", p.Permissions.Certificates)...)
			add(p.ObjectID, ops)
		}
	}
	return perms
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// ARMSource polls arm-emulator's family feed and keeps this service's
// allowlist in step with it.
type ARMSource struct {
	BaseURL string // arm-emulator origin
	Scope   string // this vault's ARM resource id
	Client  *http.Client
	TTL     time.Duration

	svc  *Service
	mu   sync.Mutex
	last int64
}

// NewARMSource wires a feed consumer for the vault at scope.
func NewARMSource(svc *Service, baseURL, scope string, client *http.Client, ttl time.Duration) *ARMSource {
	if client == nil {
		client = http.DefaultClient
	}
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &ARMSource{BaseURL: strings.TrimSuffix(baseURL, "/"), Scope: scope,
		Client: client, TTL: ttl, svc: svc}
}

// Refresh fetches the feed once and applies it to the service's allowlist.
func (a *ARMSource) Refresh() error {
	url := fmt.Sprintf("%s/_family/authorization?scope=%s", a.BaseURL, a.Scope)
	resp, err := a.Client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch ARM authorization feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch ARM authorization feed: status %d", resp.StatusCode)
	}
	var f armFeed
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil {
		return fmt.Errorf("parse ARM authorization feed: %w", err)
	}
	a.svc.SetManagedPermissions(compileFeed(&f))
	a.mu.Lock()
	a.last = f.Generated
	a.mu.Unlock()
	return nil
}

// Run refreshes until ctx-less stop is signalled by closing done. The caller
// owns the goroutine; Refresh is safe to call directly in tests.
func (a *ARMSource) Run(done <-chan struct{}) {
	t := time.NewTicker(a.TTL)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			_ = a.Refresh() // a transient ARM outage leaves the last-known map in place
		}
	}
}
