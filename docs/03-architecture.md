# 03 — Architecture

azure-keyvault-emulator is a **data-plane contract emulator** for Azure Key
Vault: the `https://{vault}.vault.azure.net` REST surface that applications,
SDKs, and Fabric AKV-references actually call. The ARM control plane (vault
CRUD, `Microsoft.KeyVault/vaults`) is out of scope — vaults are emulator
configuration, not API resources.

## The trust model — why this emulator exists

Key Vault authenticates every request with an Entra bearer token, discovered
through **challenge-based authentication**: the SDK's first call carries no
token; the vault answers `401` with
`WWW-Authenticate: Bearer authorization="<authority>", resource="https://vault.azure.net"`;
the SDK acquires a token from that authority and retries.

The emulator implements this faithfully **across services**:

- The `401` challenge advertises **entra-emulator's authority**
  (`{entra-origin}/{tenant}`) — not a built-in fake OAuth surface.
- The retried token is validated for real: RS256 signature against
  entra-emulator's JWKS, issuer match, audience ∈
  {`https://vault.azure.net`, `https://vault.azure.net/`}, and `exp`/`nbf` on
  the emulator's controllable clock.
- Any entra-emulator credential path therefore works end to end exactly as in
  production: client credentials, the App Service-style managed-identity
  endpoint (`/msi/token`), Fabric workspace-identity tokens, or forged
  negative-test tokens.

This is the deliberate contrast with the excellent
[james-gould/azure-keyvault-emulator](https://github.com/james-gould/azure-keyvault-emulator),
whose authentication accepts any token by design. Both are valid tools; this
one is for testing the **credential path**, not only the storage path. See
[Authentication](09-authentication.md) for the handshake in depth.

### entra-emulator prerequisite

entra-emulator mints a vault-audience token when the requested scope resolves
to a known resource. Since **entra-emulator v0.2.1**, `https://vault.azure.net`
is a built-in well-known Azure resource (alongside Storage and ARM), so
`https://vault.azure.net/.default` resolves with **no resource-app seed step** —
the compose wiring works out of the box. The MSI endpoint needs nothing: it
echoes the requested `resource=` as the audience.

## Design principle: mirror the family

| Concern | Choice (same as entra-emulator / fabric-emulator) |
|---|---|
| Language / HTTP | Go, stdlib `net/http` |
| Storage | `modernc.org/sqlite` (pure-Go, no CGO) |
| Determinism | Controllable **clock** (drives `nbf`/`exp`, soft-delete retention, token expiry) + fault injection via `/_emulator` |
| TLS | Self-signed cert covering `localhost`, `*.vault.azure.net` |
| Distribution | GoReleaser: binaries, distroless Docker (GHCR), Homebrew, winget |
| Docs | `/docs` = source of truth → Astro Starlight on GitHub Pages |
| Tests | Unit/integration + **real-SDK e2e** (azsecrets / azkeys / azcertificates against entra) + ≥90% coverage floor |
| License | Apache-2.0, clean-room |

The clock is the quiet payoff: secret `exp`/`nbf` windows, the 7–90-day
soft-delete retention, and certificate lifetimes are all testable in
milliseconds by advancing virtual time ([Testing](10-testing.md)).

## Vault addressing

Real Key Vault is DNS-per-vault. The emulator is **Host-routed**:

- `Host: {vault}.vault.azure.net` → that vault (created on first write).
- Any other host (e.g. `localhost:8444`) → the **default vault** (`emulator`,
  configurable), so quick curl/local use needs no DNS games.

Full-fidelity SDK use pins DNS (`{vault}.vault.azure.net → 127.0.0.1`; the cert
covers it). Plain `https://localhost:{port}` also works but needs the SDK's
`DisableChallengeResourceVerification` option, since the challenge resource
won't match the host. Both paths are in the [Quickstart](01-quickstart.md);
details in [TLS and vaults](05-tls-and-vaults.md).

## Object model

Three object types, each with the same versioning + soft-delete skeleton and
full-URL identifiers on the wire
(`https://{vault}.vault.azure.net/{secrets|keys|certificates}/{name}/{version}`):

- **[Secrets](06-secrets.md)** — opaque values with attributes and tags.
- **[Keys](07-keys.md)** — RSA/EC keys with **real** sign/verify/encrypt/wrap.
- **[Certificates](08-certificates.md)** — self-signed issuance + PFX/PEM
  import; the linked key and secret materialize under the same name.

Private key material (PKCS#8) never leaves the store; handlers derive the
public JWK or DER cert per request.

## Semantics that must be faithful

- **Attributes**: `enabled` gates retrieval (`403` when false); `nbf`/`exp` are
  **informational** — a `get` outside the window still succeeds (documented for
  recovery/test use), so the emulator does **not** reject expired objects.
  `created`/`updated` are stamped from the clock.
- **Soft delete**: `DELETE` moves the object to the deleted state with a
  retention window (default 90 days, 7–90 configurable); recoverable until
  purged or the window lapses on the clock; the name is unusable while
  soft-deleted; purge is a separate, permission-gated step.
- **Versioning**: every write creates a new version; the unversioned `GET`
  returns the current one; versions are listable. Version ids are 32-hex.
- **Error envelope**: `{"error":{"code":…,"message":…}}` with an
  `x-ms-request-id` header on every response.
- **Paging**: `maxresults` + `nextLink`, the AKV list shape.

## Authorization model

Real Key Vault has two data-plane authorization models (legacy access
policies; Azure RBAC roles like *Key Vault Secrets User*), both administered
through ARM — which the emulator does not model. Instead:

- A valid vault-audience token grants **full data-plane access** by default
  (the common dev posture).
- An optional **per-principal permission map** (`/_emulator/permissions`)
  restricts principals to operation sets (`secrets/get`, `keys/sign`, `*`, …)
  to test authorization-denied paths — honest to access-policy *semantics*
  without pretending to be ARM.

## Operator portal

A read-only Svelte 5 SPA ships **inside the binary** (`go:embed` over a
committed `portal/dist`) and is served at `/_emulator/portal/` — separate from
the bearer-authenticated data plane, which owns the root path namespace. It
shows the dashboard and per-type object lists (secrets, keys, certificates,
deleted), and drives the clock and fault-injection controls. It reads state
through the unauthenticated `/_emulator/portal/data/*` endpoints (a
local-tooling escape hatch, never impersonating a principal) and aggregates
across every vault. CI builds it from source, guards `portal/dist` against
drift, and runs a Playwright mount smoke.

## Non-goals

The ARM control plane, Managed HSM, private endpoints / firewall enforcement,
customer-managed-key encryption theater, certificate *issuance* against real
CAs (self-signed only), and key types requiring an HSM. The emulator is a
contract emulator for local dev/CI, **not a security boundary** — run it on
`localhost` only.

## Clean-room grounding

Built only from public documentation and behavioral study — no Microsoft
source. Pinned for reproducibility:

> `MicrosoftDocs/azure-security-docs @ cf2b4befe` (2026-07-10) —
> `articles/key-vault/{general,secrets,keys,certificates}`
> `james-gould/azure-keyvault-emulator @ 210582e` (2026-06-09) —
> behavioral reference for SDK compatibility

The data plane is versioned by the `api-version` query parameter (GA `7.5`; the
emulator accepts any `7.x`). Re-audit by diffing the grounding files against
those SHAs and bumping the pin.
