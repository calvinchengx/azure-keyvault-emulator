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

## P4 — SDK parity surface

Round out the secondary operations the Azure SDKs expose beyond core CRUD, so a
test written against `azkeys` / `azcertificates` never hits an endpoint the
emulator lacks. Measured against the reference
[james-gould emulator](https://github.com/james-gould/azure-keyvault-emulator);
we keep our real-auth and real-crypto posture throughout.

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
- Intentional non-goals (documented, not gaps): **key release** (SKR needs an
      attestation authority) and **certificate CSR merge** (a CA-signed flow) —
      both out of scope for a self-signed, offline emulator, matching the
      existing "Self issuer only" boundary.

## Cross-cutting (throughout)

- [x] CI: vet/build/test + 90% coverage floor + the three-emulator chain e2e.
- [x] Starlight docs site on GitHub Pages (`/docs` = source of truth),
      live at <https://calvinchengx.github.io/azure-keyvault-emulator/>.
- [x] GoReleaser: binaries + distroless Docker (GHCR) + Homebrew + winget
      (released as **v0.1.0**).
- [ ] Svelte portal (vaults/secrets/deleted/clock views) — after the API
      stabilizes, mirroring the family pattern.

## Sequencing note

Build the **challenge handshake before any storage** — it is this emulator's
reason to exist, every SDK call path runs through it, and it defines the
integration contract with entra-emulator. Secrets storage is straightforward
once auth is honest.
