package vault

// Authorization documents: the real vault access-policy shape and the real
// RBAC built-in roles, each compiled onto the emulator's per-principal
// operation allowlist (the same store /_emulator/permissions writes). No ARM
// is pretended — assignment happens through the control surface — but the
// documents and role names are the ones real code uses.

import (
	"fmt"
	"strings"
)

// permission-name → emulator ops, per object type. Names follow the vault
// access-policy schema (case-insensitive); "all" grants the type's full set.
var (
	secretPerms = map[string][]string{
		"get": {"secrets/get"}, "list": {"secrets/list"}, "set": {"secrets/set"},
		"delete": {"secrets/delete"}, "backup": {"secrets/backup"},
		"restore": {"secrets/restore"}, "recover": {"secrets/recover"},
		"purge": {"secrets/purge"},
	}
	keyPerms = map[string][]string{
		// rng rides with get: random bytes are not key material.
		"get": {"keys/get", "keys/rng"}, "list": {"keys/list"},
		"create": {"keys/create"}, "import": {"keys/import"},
		"update": {"keys/update"}, "delete": {"keys/delete"},
		"backup": {"keys/backup"}, "restore": {"keys/restore"},
		"recover": {"keys/recover"}, "purge": {"keys/purge"},
		"encrypt": {"keys/encrypt"}, "decrypt": {"keys/decrypt"},
		"sign": {"keys/sign"}, "verify": {"keys/verify"},
		"wrapkey": {"keys/wrapkey"}, "unwrapkey": {"keys/unwrapkey"},
		"rotate":            {"keys/rotate"},
		"getrotationpolicy": {"keys/get"}, "setrotationpolicy": {"keys/update"},
		"release": {"keys/release"},
	}
	certPerms = map[string][]string{
		"get": {"certificates/get"}, "list": {"certificates/list"},
		// create covers merge, as completing an operation does in real KV.
		"create": {"certificates/create", "certificates/merge"},
		"import": {"certificates/import"}, "update": {"certificates/update"},
		"delete": {"certificates/delete"}, "backup": {"certificates/backup"},
		"restore": {"certificates/restore"}, "recover": {"certificates/recover"},
		"purge":          {"certificates/purge"},
		"managecontacts": {"certificates/setcontacts", "certificates/getcontacts", "certificates/deletecontacts"},
		"getissuers":     {"certificates/getissuers"},
		"listissuers":    {"certificates/list"},
		"setissuers":     {"certificates/setissuers"},
		"deleteissuers":  {"certificates/deleteissuers"},
		"manageissuers":  {"certificates/setissuers", "certificates/deleteissuers"},
	}
)

func allOf(m map[string][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ops := range m {
		for _, op := range ops {
			if !seen[op] {
				seen[op] = true
				out = append(out, op)
			}
		}
	}
	return out
}

// AccessPolicyEntry is one entry of the real vault access-policy document.
type AccessPolicyEntry struct {
	ObjectID    string `json:"objectId"`
	Permissions struct {
		Secrets      []string `json:"secrets"`
		Keys         []string `json:"keys"`
		Certificates []string `json:"certificates"`
	} `json:"permissions"`
}

// CompileAccessPolicies turns the access-policy document into the
// per-principal op allowlist. Unknown permission names are refused so a typo
// cannot silently widen or narrow access.
func CompileAccessPolicies(entries []AccessPolicyEntry) (map[string][]string, error) {
	out := map[string][]string{}
	expand := func(kind string, table map[string][]string, names []string) ([]string, error) {
		var ops []string
		for _, n := range names {
			key := strings.ToLower(strings.TrimSpace(n))
			if key == "all" {
				ops = append(ops, allOf(table)...)
				continue
			}
			mapped, ok := table[key]
			if !ok {
				return nil, fmt.Errorf("unknown %s permission %q", kind, n)
			}
			ops = append(ops, mapped...)
		}
		return ops, nil
	}
	for _, e := range entries {
		if e.ObjectID == "" {
			return nil, fmt.Errorf("access policy entry missing objectId")
		}
		var ops []string
		for _, part := range []struct {
			kind  string
			table map[string][]string
			names []string
		}{
			{"secret", secretPerms, e.Permissions.Secrets},
			{"key", keyPerms, e.Permissions.Keys},
			{"certificate", certPerms, e.Permissions.Certificates},
		} {
			got, err := expand(part.kind, part.table, part.names)
			if err != nil {
				return nil, err
			}
			ops = append(ops, got...)
		}
		out[e.ObjectID] = append(out[e.ObjectID], ops...)
	}
	return out, nil
}

// builtinRoles are the real Key Vault data-plane built-in roles, expanded to
// the emulator's op sets per their documented data actions.
var builtinRoles = map[string][]string{
	"key vault administrator": {"*"},
	"key vault reader": {
		"secrets/list", "keys/list", "certificates/list", "certificates/get",
	},
	"key vault secrets user":    {"secrets/get", "secrets/list"},
	"key vault secrets officer": allOf(secretPerms),
	"key vault crypto user": {
		"keys/get", "keys/list", "keys/sign", "keys/verify", "keys/encrypt",
		"keys/decrypt", "keys/wrapkey", "keys/unwrapkey", "keys/rng",
	},
	"key vault crypto officer": allOf(keyPerms),
	"key vault crypto service encryption user": {
		"keys/get", "keys/wrapkey", "keys/unwrapkey",
	},
	"key vault certificate user": {
		"certificates/get", "certificates/list", "secrets/get",
	},
	"key vault certificates officer": allOf(certPerms),
}

// RoleAssignment assigns a built-in role to a principal, optionally scoped
// to one object ("/keys/{name}", "/secrets/{name}", "/certificates/{name}"),
// as data-plane RBAC assignments can be.
type RoleAssignment struct {
	PrincipalID string `json:"principalId"`
	Role        string `json:"role"`
	Scope       string `json:"scope"`
}

// CompileRBAC expands role assignments to the op allowlist; assignments for
// the same principal merge, as role assignments do. A scoped assignment
// keeps only the role's operations of the scope's object type, each bound to
// the object name — operations without an object (list, restore) need a
// vault-level (unscoped) assignment, as in real RBAC.
func CompileRBAC(assignments []RoleAssignment) (map[string][]string, error) {
	out := map[string][]string{}
	for _, a := range assignments {
		if a.PrincipalID == "" {
			return nil, fmt.Errorf("role assignment missing principalId")
		}
		ops, ok := builtinRoles[strings.ToLower(strings.TrimSpace(a.Role))]
		if !ok {
			known := make([]string, 0, len(builtinRoles))
			for r := range builtinRoles {
				known = append(known, r)
			}
			return nil, fmt.Errorf("unknown role %q (known roles: %s)", a.Role, strings.Join(known, ", "))
		}
		if a.Scope != "" {
			scoped, err := scopeOps(ops, a.Scope)
			if err != nil {
				return nil, err
			}
			ops = scoped
		}
		out[a.PrincipalID] = append(out[a.PrincipalID], ops...)
	}
	return out, nil
}

// scopeOps binds a role's operations to one object. "*" (administrator)
// expands to every operation of the scope's type first.
func scopeOps(ops []string, scope string) ([]string, error) {
	parts := strings.Split(strings.Trim(scope, "/"), "/")
	if len(parts) != 2 || parts[1] == "" {
		return nil, fmt.Errorf("scope %q is not /keys|secrets|certificates/{name}", scope)
	}
	objType, name := parts[0], parts[1]
	var table map[string][]string
	switch objType {
	case "keys":
		table = keyPerms
	case "secrets":
		table = secretPerms
	case "certificates":
		table = certPerms
	default:
		return nil, fmt.Errorf("scope %q is not /keys|secrets|certificates/{name}", scope)
	}
	expanded := ops
	if len(ops) == 1 && ops[0] == "*" {
		expanded = allOf(table)
	}
	var out []string
	for _, op := range expanded {
		if strings.HasPrefix(op, objType+"/") {
			out = append(out, op+":"+name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("role grants no %s operations; a %s-scoped assignment would be empty", objType, objType)
	}
	return out, nil
}
