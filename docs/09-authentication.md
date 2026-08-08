# 09 — Authentication

Authentication *is the point* of this emulator. Where a pass-through emulator
accepts any token, this one advertises a real Entra authority and validates
every token — so `DefaultAzureCredential` walks the same path it walks in
production, and the credential path itself is under test.

## The challenge handshake

```
 Azure SDK (SecretClient / azsecrets / …)
      │ 1. request with no token
      ▼
 keyvault-emulator ── 401 WWW-Authenticate: Bearer
      │                 authorization="{entra-origin}/{tenant}",
      │                 resource="https://vault.azure.net"
      │ 2. SDK acquires a token from the advertised authority
      ▼
 entra-emulator ── mints aud = https://vault.azure.net
      │ 3. SDK retries with the token
      ▼
 keyvault-emulator ── validate (sig + iss + aud + exp) against entra JWKS → 200
```

1. **Challenge.** Any request without an `Authorization` header gets `401` with
   `WWW-Authenticate: Bearer authorization="…", resource="https://vault.azure.net"`.
   The authority is the configured Entra issuer's origin+tenant — entra-emulator
   or a real tenant.
2. **Acquire.** The SDK's credential fetches a vault-audience token from that
   authority. `DefaultAzureCredential`/`ClientSecretCredential` do this
   transparently.
3. **Validate.** The retried token is checked for real: RS256 signature against
   the issuer's JWKS (fetched once, cached by `kid`), issuer match, audience ∈
   {`https://vault.azure.net`, `https://vault.azure.net/`}, and `exp`/`nbf`
   against the [controllable clock](10-testing.md). A bad token → `401`; a
   valid token missing a granted operation → `403` (see below).

## Any Entra credential path works

Because validation is real and issuer-anchored, **every** way of getting a
vault-audience token from entra-emulator works end to end:

- **Client credentials** — `ClientSecretCredential`, or a raw
  `grant_type=client_credentials&scope=https://vault.azure.net/.default`.
  Resolves with no resource-app seed since entra-emulator v0.2.1 treats
  `https://vault.azure.net` as a well-known Azure resource.
- **Managed identity** — the App Service-style endpoint
  (`GET {entra}/msi/token?resource=https://vault.azure.net`, guarded by
  `X-IDENTITY-HEADER`). No secret in the workload; the endpoint echoes the
  requested resource as the audience.
- **Fabric workspace identity** — a token entra mints for a provisioned
  workspace identity (the basis of the [family chain](11-family-integration.md)).
- **Forged tokens** — entra-emulator's token forge, for negative tests
  (wrong audience, already expired). The vault rejects them exactly as
  production would.

Wrong-audience (e.g. a Fabric token) and clock-expired tokens are asserted
rejected in the CI e2e.

## Authorization (optional)

By default a valid vault-audience token has **full data-plane access** — the
common dev posture, and enough for most tests. To exercise
authorization-denied paths, set a per-principal operation allowlist over the
control surface:

```bash
curl -sk -X POST https://localhost:8444/_emulator/permissions \
  -d '{"<principal-oid>": ["secrets/get", "keys/sign"]}'
```

Now that principal may only `GET` secrets and `sign` with keys; anything else
is `403 Forbidden`. Operation names are `{type}/{op}` (`secrets/set`,
`keys/create`, `certificates/delete`, …); `*` grants all. An empty map `{}`
restores full access. This models access-policy *semantics* without pretending
to be ARM ([Architecture § Authorization](03-architecture.md)).

Two higher-level front-ends compile onto the same allowlist (last writer
wins), using the documents real code uses:

```bash
# The real vault access-policy shape (per-type permission names, "all" works):
curl -sk -X POST https://localhost:8444/_emulator/access-policy \
  -d '{"accessPolicies":[{"objectId":"<oid>","permissions":{"secrets":["get","list"],"keys":["sign","verify"]}}]}'

# The real RBAC built-in roles by name:
curl -sk -X POST https://localhost:8444/_emulator/rbac \
  -d '{"assignments":[{"principalId":"<oid>","role":"Key Vault Secrets User"}]}'
```

Known roles: Key Vault Administrator, Reader, Secrets User/Officer, Crypto
User/Officer, Crypto Service Encryption User, Certificate User, Certificates
Officer. Unknown permission or role names are refused (400), so a typo cannot
silently widen access. `{"accessPolicies": []}` / `{"assignments": []}`
restore full access.

### Authorization from ARM (the real route)

Point the emulator at [arm-emulator](https://github.com/calvinchengx/arm-emulator)
and authorization stops being configured here at all — it comes from where
Azure keeps it:

```bash
azure-keyvault-emulator -arm-url https://localhost:8445 \
  -arm-subscription 00000000-0000-0000-0000-000000000001 \
  -arm-resource-group my-rg
```

Now `az role assignment create --role "Key Vault Secrets User"` (or the real
management SDKs) writes the assignment over ARM's wire, this emulator polls
ARM's family feed, and the grant governs the data plane within a poll
interval. Access policies set with `az keyvault set-policy` work the same way,
and a vault with `enableRbacAuthorization` ignores them exactly as real Key
Vault does.

Two behaviours worth knowing:

- **Under ARM governance, no assignment means no access** (`403`) — real
  Azure's posture. Without `-arm-url`, an unconfigured emulator still grants
  full access, which is the convenient local default.
- ARM being unreachable is not fatal: the last-known grants stay in force, and
  a vault that never reached ARM starts in the permissive default.

#### Driving it with the real `az` CLI

`az cloud register` exists so the CLI can target non-public ARM endpoints
(sovereign clouds, Stack Hub). Register the family as one and every
authorization command works unmodified:

```bash
az cloud register --name EmulatorCloud \
  --endpoint-resource-manager https://localhost:8445 \
  --endpoint-active-directory https://localhost:8443 \
  --endpoint-active-directory-resource-id https://management.azure.com/ \
  --suffix-keyvault-dns .vault.azure.net
az cloud set --name EmulatorCloud
az config set core.instance_discovery=false   # private cloud: skip MSAL's
                                              # login.microsoftonline.com probe
export REQUESTS_CA_BUNDLE=/path/to/emulator-certs.pem

az login --service-principal -u <client-id> -p <secret> --tenant <tenant> --allow-no-subscriptions
az group create --name my-rg --location westeurope
az keyvault create --name emulator --resource-group my-rg --location westeurope
az role assignment create --role "Key Vault Secrets User" \
  --assignee-object-id <oid> --assignee-principal-type ServicePrincipal --scope <vault-id>
```

`e2e/az-cli/run.py` runs exactly this in CI and asserts the data plane flips
between `403` and authorized after each command.

**Group assignments resolve for members.** A role assigned to a group
(`principalType: Group`) authorizes any caller whose token carries that group
in its `groups` claim — the user is never named in the assignment, exactly as
data-plane RBAC resolves group membership. entra-emulator emits the claim when
the app's `groupMembershipClaims` asks for it (its seeded *Engineering* group
has Alice and Bob in it).

The ops a role's dataActions map to are listed in
`internal/vault/armfeed.go` — that mapping is this data plane's decision, as
it is in Azure, where ARM stores the actions and the service interprets them.

Assignments scope to a single object, as data-plane RBAC supports — add
`"scope": "/keys/{name}"` (or `/secrets/…`, `/certificates/…`) to an
assignment, or use `{type}/{op}:{object}` entries in the raw allowlist.
Operations without an object of their own (list, restore, rng) require a
vault-level (unscoped) grant, exactly as in real RBAC.

## localhost vs DNS-pinned

The SDK's challenge-resource verification expects the vault host to end in
`vault.azure.net`. On `localhost` it won't, so set
`DisableChallengeResourceVerification`; DNS-pin `{vault}.vault.azure.net` to
`127.0.0.1` to avoid the override. Both are covered in
[TLS and vaults](05-tls-and-vaults.md).
