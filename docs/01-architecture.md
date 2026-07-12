# 01 — Architecture

azure-keyvault-emulator is a **data-plane contract emulator** for Azure Key
Vault: the `https://{vault}.vault.azure.net` REST surface that applications,
SDKs, and Fabric AKV-references actually call. The ARM control plane (vault
CRUD, `Microsoft.KeyVault/vaults`) is out of scope — vaults are emulator
configuration, not API resources.

## Version grounding

Azure Key Vault's data plane is versioned by the **`api-version` query
parameter** (GA `7.5`; the emulator accepts any `7.x` and echoes shapes per
7.5). The docs corpus is evergreen; for clean-room reproducibility we pin
commits, not versions:

> `MicrosoftDocs/azure-security-docs @ cf2b4befe` (2026-07-10) —
> `articles/key-vault/{general,secrets,keys,certificates}`
> `james-gould/azure-keyvault-emulator @ 210582e` (2026-06-09) —
> behavioral reference for SDK compatibility

Re-audit by diffing the grounding files against those SHAs and bumping the pin
(same procedure as fabric-emulator's).

## The trust model — why this emulator exists

Key Vault authenticates every request with an Entra bearer token, discovered
through **challenge-based authentication**
(`general/authentication-requests-and-responses.md`): the SDK's first call
carries no token; the vault answers `401` with
`WWW-Authenticate: Bearer authorization="<authority>", resource="https://vault.azure.net"`;
the SDK acquires a token from that authority and retries.

The emulator implements this faithfully **across services**:

- The `401` challenge advertises **entra-emulator's authority**
  (`{entra-origin}/{tenant}`) — not a built-in fake OAuth surface.
- The retried token is validated for real: RS256 signature against
  entra-emulator's JWKS, issuer match, audience ∈
  {`https://vault.azure.net`, `https://vault.azure.net/`}, `exp`/`nbf` on the
  emulator's controllable clock.
- Any entra-emulator credential path therefore works end-to-end exactly as in
  production: client credentials, the App Service-style managed-identity
  endpoint (`/msi/token`), Fabric workspace-identity tokens, or forged
  negative-test tokens.

This is the deliberate contrast with the james-gould emulator, whose
authentication accepts any token by design. Both are valid tools; this one is
for testing the **credential path**, not only the storage path.

### entra-emulator prerequisite

entra-emulator mints an audience when the requested scope resolves to a known
resource. `https://vault.azure.net/.default` resolves once a resource app with
`appIdUri = https://vault.azure.net` exists — either seeded via entra's admin
API at startup (the docker-compose does this) or, preferably, a small
entra-emulator enhancement adding Key Vault to its known-resource carve-outs
(like the Fabric one, roadmap item there). The MSI endpoint needs nothing: it
already echoes arbitrary `resource=` values as the audience.

## Design principle: mirror the family

| Concern | Choice (same as entra-emulator / fabric-emulator) |
|---|---|
| Language / HTTP | Go, stdlib `net/http` |
| Storage | `modernc.org/sqlite` (pure-Go, no CGO) |
| Determinism | Controllable **clock** (drives `nbf`/`exp` attributes, soft-delete retention, token expiry) + fault injection via `/_emulator` |
| TLS | Self-signed cert covering `localhost`, `*.vault.azure.net` |
| Distribution | GoReleaser: binaries, distroless Docker (GHCR), Homebrew, winget |
| Docs | `/docs` = source of truth → Astro Starlight on GitHub Pages |
| Tests | Unit/integration + **real-SDK e2e** (azsecrets + azidentity against entra) + ≥90% coverage floor |
| License | Apache-2.0, clean-room |

The clock is the quiet payoff again: secret `exp`/`nbf` windows, the 7–90-day
soft-delete retention, and certificate lifetimes are all testable in
milliseconds by advancing virtual time.

## Vault addressing

Real Key Vault is DNS-per-vault. The emulator is **Host-routed** like
fabric-emulator's OneLake plane:

- `Host: {vault}.vault.azure.net` → that vault (auto-created on first use, or
  restricted to declared vaults via config).
- Any other host (e.g. `localhost:8443`) → the **default seeded vault**
  (`emulator`), so quick curl/local use needs no DNS games.

Full-fidelity SDK use pins DNS (`{vault}.vault.azure.net → 127.0.0.1`, the
cert covers it — same trick as fabric-emulator's fabric-cicd harness). Plain
`https://localhost:{port}` works too but needs the SDK's
`DisableChallengeResourceVerification` option, since the challenge resource
won't match the host — both paths documented in the quickstart.

## Data model (SQLite)

```
vault           (name)                       -- host-derived; default seeded
secret          (vault, name, current_version)
secret_version  (vault, name, version, value, content_type, enabled,
                 nbf, exp, tags_json, created_at, updated_at)
deleted_secret  (vault, name, deleted_at, scheduled_purge_at, payload_json)
key / key_version / deleted_key              -- P1 (real crypto, see roadmap)
certificate / …                              -- P2
```

Object identifiers are full URLs, as on the wire:
`https://{vault}.vault.azure.net/secrets/{name}/{version}`.

## Semantics that must be faithful

- **Attributes** (`secrets/about-secrets.md`): `enabled` gates retrieval;
  `nbf`/`exp` are **informational** — a `get` outside the window still
  succeeds (documented for recovery/test purposes), so the emulator must NOT
  reject expired secrets. Read-only `created`/`updated` stamped from the
  clock.
- **Soft delete** (`general/soft-delete-overview.md`): DELETE moves the object
  to the deleted state with a retention window (default 90 days, 7–90
  configurable); it is recoverable until purged or the window lapses on the
  clock; the name cannot be reused while soft-deleted; purge is a separate,
  permission-gated second step.
- **Versioning**: every `PUT secrets/{name}` creates a new version; the
  unversioned GET returns the current one; versions are listable.
- **Error envelope**: `{"error":{"code":…,"message":…}}` with the
  `x-ms-request-id` header (`general/common-error-codes.md`).
- **Paging**: `maxresults` + `nextLink`, the AKV list shape.

## Authorization model

Real Key Vault has two data-plane authorization models (legacy access
policies; Azure RBAC roles like *Key Vault Secrets User*), both administered
through ARM — which we don't emulate. The emulator's model:

- A valid vault-audience token grants **full data-plane access** by default
  (the common dev posture).
- An optional per-principal permission map (config/`/_emulator`) can restrict
  principals to operation sets (`get`, `list`, `set`, `delete`, `purge`, …) to
  test authorization-denied paths — honest to access-policy *semantics*
  without pretending to be ARM.

## Non-goals

The ARM control plane, Managed HSM, private endpoints/firewall enforcement,
customer-managed-key encryption theater, certificate *issuance* against real
CAs (self-signed only), and key types requiring an HSM. The emulator is a
contract emulator for local dev/CI, not a security boundary.

## Composition

`docker-compose.yml` brings up entra-emulator + this emulator with the
challenge authority pre-wired and the vault resource app seeded. Adding
fabric-emulator gives the full offline story — its **AKV-reference
connections** (a fabric-emulator roadmap item) resolve secrets here, so a
Fabric pipeline connection can be tested with zero cloud dependencies:
`workspace identity → entra token → vault secret → connection`.
