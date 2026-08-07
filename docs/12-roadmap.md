# 12 — Roadmap

Same discipline as fabric-emulator: each phase independently useful, real-SDK
e2e-verified, ≥90% coverage floor in CI from the first commit.

## P0 — secrets + the real auth handshake

The core value: an Azure SDK acquires a token from entra-emulator via the
challenge flow and round-trips secrets.

- [x] Foundations: clock, config (`KV_*` env + flags), store (vault, secret,
      secret_version, deleted_secret), self-signed TLS (`*.vault.azure.net`),
      Host-routed vault resolution + default seeded vault.
- [x] Auth: challenge `401` advertising the entra authority; RS256 validation
      against entra JWKS (issuer, vault audience, clock-based expiry).
      Reuses the validator pattern from fabric-emulator's `internal/auth`.
- [x] Secrets: set/get/get-version/patch/list/list-versions (paged),
      new-version-per-PUT, `enabled` gating, informational `nbf`/`exp`,
      backup/restore.
- [x] Soft delete: delete → deleted state with `scheduledPurgeDate` on the
      clock; recover; purge; name-reuse conflict while deleted.
- [x] `/_emulator` clock + faults (incl. 429 throttling injection).
- [x] Docker (distroless) + docker-compose with entra-emulator (challenge
      authority pre-wired; vault resource app seeded via entra's admin API).
- [x] e2e (in-process entra, like fabric-emulator's fixture): **azsecrets +
      azidentity.ClientSecretCredential** complete the challenge flow
      unmodified; managed-identity path via entra's `/msi/token`
      (`IDENTITY_ENDPOINT`/`IDENTITY_HEADER`); forged wrong-audience /
      expired tokens rejected; clock-advance expires a live token.

## P1 — keys (real crypto) + hardening

- [x] Keys CRUD/versions/soft-delete; RSA + EC generation (software-protected).
- [x] sign/verify, encrypt/decrypt, wrap/unwrap with real Go crypto — output
      verifiable against the returned JWK.
- [x] Optional per-principal permission map (`/_emulator/permissions`) for
      authorization-denied paths.
- [x] e2e: azkeys SDK sign → local JWK verify; encrypt → decrypt round trip.

## P2 — certificates

- [x] Certificates CRUD + policy; self-signed issuance; PFX/PEM import;
      linked key/secret materialization under the same name.
- [x] e2e: azcertificates SDK create-self-signed → fetch → TLS-use the cert.

## P3 — family integration

- [x] fabric-emulator **AKV-reference connections** resolve against this
      emulator (its roadmap item, built on the fabric side): `workspace
      identity → entra token → vault secret → connection`, fully offline.
- [x] e2e: the **secret-as-SP-credential chain** — the canonical "SP secret
      lives in Key Vault" pattern across all three emulators
      (`e2e/chain/run.py`, in CI): a client-credentials call stores an SP
      secret in the vault, a **managed-identity** token (entra `/msi/token`,
      no credential in the workload) reads it back, that secret authenticates
      the SP to entra for a Fabric-audience token, and the token calls
      fabric-emulator. Three real processes; a wrong secret breaks the chain
      exactly where it would in Azure.
- [x] entra-emulator enhancement (shipped in **entra v0.2.1**): recognize
      `https://vault.azure.net` (+ Storage, ARM) as well-known Azure
      resources, so client-credentials/MSI resolve the vault audience without
      seeding a resource app.
- [x] Compose file with all three emulators (`docker-compose.yml`, `full`
      profile adds fabric).

## P4 — SDK parity surface *(shipped in v0.2.0)*

Round out the secondary operations the Azure SDKs expose beyond core CRUD, so a
test written against `azkeys` / `azcertificates` never hits an endpoint the
emulator lacks. Measured against the
[Key Vault REST API reference](https://learn.microsoft.com/en-us/rest/api/keyvault/)
and what the real SDKs call; we keep our real-auth and real-crypto posture
throughout. With these, the emulator reaches **full parity** on the
SDK-observable surface.

- [x] Keys: **import** a caller-supplied JWK (`PUT /keys/{name}`, real RSA/EC
      material — a subsequent sign/verify round-trips), update-latest
      (`PATCH /keys/{name}`), **backup/restore**, and **rotation policy**
      get/set.
- [x] **GetRandomBytes** (`POST /rng`).
- [x] Certificates: **backup/restore**, update attributes/policy
      (`PATCH /certificates/{name}`), policy update
      (`PATCH /certificates/{name}/policy`), **issuers**
      (`GET`/`PUT`/`PATCH`/`DELETE /certificates/issuers/{name}` + list) and
      **contacts** (`GET`/`PUT`/`DELETE /certificates/contacts`).
- [x] **Secure Key Release** (`POST /keys/{name}/{version}/release`) — a
      genuine signed JWS carrying the released public JWK. No HSM attestation
      (there is no enclave to attest), so any enabled key is releasable; the
      call path and token shape are emulated.
- [x] **Certificate CSR merge** (`POST /certificates/{name}/pending/merge`) —
      a named issuer creates a pending operation with a real PKCS#10 CSR; you
      sign it with your own CA and merge the chain back, completing the
      async-issuance path fully offline. A live third-party CA remains the only
      certificate non-goal (the emulator never phones out).

## P5 — real-service fidelity *(shipped in v0.4.0)*

Close the remaining implementable gaps against real Key Vault, each landed
with its witness (Go test + the multi-language SDK suites where the SDKs
surface the operation):

- [x] **Rotate key** (`POST /keys/{name}/rotate`) — a new version with fresh
      material of the same type and size; `key_ops`/tags carry over.
- [x] **`key_ops` enforcement** — operations outside the key's list get
      `403 Forbidden`; the JWK's `key_ops` also drives SDK-local refusal.
- [x] **Certificate operation cancel + delete** (`PATCH`/`DELETE`
      `/certificates/{name}/pending`) — cancelled operations refuse merge;
      deleted operations read absent until the next create.
- [x] **Purge protection** (`-purge-protection`, `KV_PURGE_PROTECTION`,
      `/_emulator/purge-protection`) — purge `403`s, `recoveryLevel` reports
      `Recoverable`.
- [x] **`oct`/`oct-HSM` refused faithfully** — vaults hold RSA/EC only;
      symmetric keys (and their AES algorithms) are Managed HSM territory.
- [x] **`api-version` required + validated** — 7.x and the date-based versions
      current SDKs send; the create-operation LRO now reports
      `inProgress` → `completed` as the real service does.

## P6 — remaining distance to full parity *(shipped in v0.4.0)*

The whole remaining gap between the emulator and real Key Vault, in three
honesty grades. Everything not listed here is either already 🟢 in
[parity.md](parity.md) or a declared scope boundary (ARM, Managed HSM,
networking, attestation, live CAs) where full parity *means keeping the
refusal faithful*.

**Closable for real** (the emulator genuinely does the work):

- [x] **`nbf`/`exp` enforced on key crypto operations** — sign/verify/
      encrypt/decrypt/wrap/unwrap with an expired or not-yet-valid key returns
      `403 Forbidden`, as real Key Vault refuses; deterministic on the
      controllable clock. Object retrieval stays permissive (as in real KV,
      where reads return the object and its attributes).
- [x] **Certificate delete cascade** — closing the documented divergence:
      deleting a certificate soft-deletes its linked key and secret; recover
      and purge carry them along too.
- [x] **Opaque backup blobs** — backup output becomes a sealed blob (AEAD
      under an emulator-held key persisted in the data dir), restorable only
      by the same emulator instance — the honest analog of real Key Vault's
      same-subscription/geography restore rule. Transparent-JSON blobs from
      earlier versions stop restoring.
- [x] **Multiple trusted issuers** — `KV_ENTRA_ISSUER` accepts a
      comma-separated list; tokens from any listed issuer validate against
      that issuer's JWKS. The 401 challenge advertises the first.
- [x] **Auto-rotation from the rotation policy** — the stored policy acts:
      when a `lifetimeActions` rotate trigger (`timeAfterCreate`, ISO-8601)
      elapses on the emulator clock, the next read of the key lazily mints a
      new version, with `attributes.expiryTime` driving the new version's
      `exp` — the same lazy clock-driven pattern as soft-delete retention.

**Emulatable contract** (real document shapes + real enforcement, no ARM):

- [x] **Access policies** — `POST /_emulator/access-policy` accepts the real
      vault access-policy document (`objectId` +
      `permissions: {secrets, keys, certificates}`) and compiles it onto the
      internal per-principal op allowlist.
- [x] **RBAC built-in roles** — `POST /_emulator/rbac` assigns the real
      built-in roles (Key Vault Administrator, Secrets User/Officer, Crypto
      User/Officer, Certificates User/Officer, Reader) by name, expanded to
      their documented data-plane operation sets on the same allowlist.

Sequencing: enforcement first (nbf/exp, cascade — small, immediately
SDK-witnessable), then sealing + multi-issuer, then the rotation engine, then
authorization. Each lands with Go tests inside the ≥90% floor; the Python
suite witnesses the expiry refusal with a real SDK.

## P7 — full parity *(shipped in v0.4.0)*

The final stretch: everything still short of 🟢 that can move without faking
a trust property.

- [x] **BYOK for real** — `PUT /keys/{name}` accepts the `.byok` transfer
      blob (`key_hsm`): the KEK lives in this vault, and the emulator
      genuinely undoes `CKM_RSA_AES_KEY_WRAP` — RSA-OAEP(SHA-1) unwraps the
      ephemeral AES-256 key, AES-KWP (RFC 5649, clean-room) unwraps the
      target key. The round-trip test proves possession by verifying a
      vault-produced signature against the original public key. The KEK is
      software-held, per the documented HSM normalisation.
- [x] **Exportable + release policy** — only a key created
      `attributes.exportable: true` may be released, as real Key Vault
      enforces; `release_policy` is stored, echoed on the bundle, and carried
      through rotation. Attestation remains the honest boundary.
- [x] **Issuer registry drives issuance** — a named issuer must be
      registered under `/certificates/issuers` before it can issue
      (`Unknown` remains the external-CSR escape hatch), as the real service
      requires.
- [x] **Object-scoped authorization** — allowlist entries accept
      `{type}/{op}:{object}`, and RBAC assignments accept
      `scope: "/keys/{name}"` — the same object-level scoping data-plane
      RBAC supports. Operations without an object (list, restore) need
      vault-level grants, as in real RBAC.
- [x] **Soft-delete regraded** — the delete→recover→purge state machine and
      clock-driven retention were always real enforced logic; lazy purge on
      observation is indistinguishable from a background job to any caller.
      The parity map now grades them accordingly.

## Cross-cutting (throughout)

- [x] CI: vet/build/test + 90% coverage floor + the three-emulator chain e2e.
- [x] Starlight docs site on GitHub Pages (`/docs` = source of truth),
      live at <https://calvinchengx.github.io/azure-keyvault-emulator/>.
- [x] GoReleaser: binaries + distroless Docker (GHCR) + Homebrew + winget.
      **v0.1.0** shipped P0–P3; **v0.2.0** adds the full P4 parity surface
      (import, backup/restore, rng, rotation policy, key release, issuers,
      contacts, certificate CSR merge) and the operator portal.
- [x] **Svelte operator portal** *(v0.2.0)* — dashboard,
      secrets/keys/certificates/deleted views, clock + fault-injection
      controls. Svelte 5, built to a committed `portal/dist`, embedded via
      `go:embed`, served at `/_emulator/portal/`, with a CI drift guard +
      Playwright mount smoke. Mirrors the family pattern.

## Sequencing note

Build the **challenge handshake before any storage** — it is this emulator's
reason to exist, every SDK call path runs through it, and it defines the
integration contract with entra-emulator. Secrets storage is straightforward
once auth is honest.
