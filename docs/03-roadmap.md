# 03 — Roadmap

Same discipline as fabric-emulator: each phase independently useful, real-SDK
e2e-verified, ≥90% coverage floor in CI from the first commit.

## P0 — secrets + the real auth handshake

The core value: an Azure SDK acquires a token from entra-emulator via the
challenge flow and round-trips secrets.

- [ ] Foundations: clock, config (`KV_*` env + flags), store (vault, secret,
      secret_version, deleted_secret), self-signed TLS (`*.vault.azure.net`),
      Host-routed vault resolution + default seeded vault.
- [ ] Auth: challenge `401` advertising the entra authority; RS256 validation
      against entra JWKS (issuer, vault audience, clock-based expiry).
      Reuses the validator pattern from fabric-emulator's `internal/auth`.
- [ ] Secrets: set/get/get-version/patch/list/list-versions (paged),
      new-version-per-PUT, `enabled` gating, informational `nbf`/`exp`,
      backup/restore.
- [ ] Soft delete: delete → deleted state with `scheduledPurgeDate` on the
      clock; recover; purge; name-reuse conflict while deleted.
- [ ] `/_emulator` clock + faults (incl. 429 throttling injection).
- [ ] Docker (distroless) + docker-compose with entra-emulator (challenge
      authority pre-wired; vault resource app seeded via entra's admin API).
- [ ] e2e (in-process entra, like fabric-emulator's fixture): **azsecrets +
      azidentity.ClientSecretCredential** complete the challenge flow
      unmodified; managed-identity path via entra's `/msi/token`
      (`IDENTITY_ENDPOINT`/`IDENTITY_HEADER`); forged wrong-audience /
      expired tokens rejected; clock-advance expires a live token.

## P1 — keys (real crypto) + hardening

- [ ] Keys CRUD/versions/soft-delete; RSA + EC generation (software-protected).
- [ ] sign/verify, encrypt/decrypt, wrap/unwrap with real Go crypto — output
      verifiable against the returned JWK.
- [ ] Optional per-principal permission map (`/_emulator/permissions`) for
      authorization-denied paths.
- [ ] e2e: azkeys SDK sign → local JWK verify; encrypt → decrypt round trip.

## P2 — certificates

- [ ] Certificates CRUD + policy; self-signed issuance; PFX/PEM import;
      linked key/secret materialization under the same name.
- [ ] e2e: azcertificates SDK create-self-signed → fetch → TLS-use the cert.

## P3 — family integration

- [ ] fabric-emulator **AKV-reference connections** resolve against this
      emulator (its roadmap item): `workspace identity → entra token →
      vault secret → connection`, fully offline.
- [ ] e2e: the **secret-as-SP-credential chain** — the canonical "SP secret
      lives in Key Vault" pattern, across all three emulators: an app uses
      managed identity (entra `/msi/token`) to read a client_secret from this
      vault, exchanges it via client credentials at entra for a
      Fabric-audience token, and calls fabric-emulator. Every hop uses the
      production trust relationship; a wrong or expired vault secret breaks
      the chain exactly where it would in Azure.
- [ ] entra-emulator enhancement: add `https://vault.azure.net` to its
      known-resource carve-outs so client-credentials scope resolution works
      without seeding a resource app.
- [ ] Compose file with all three emulators.

## Cross-cutting (throughout)

- [ ] CI: vet/build/test + 90% coverage floor from the first code commit.
- [ ] Starlight docs site on GitHub Pages (`/docs` = source of truth).
- [ ] GoReleaser: binaries + distroless Docker (GHCR) + Homebrew + winget.
- [ ] Svelte portal (vaults/secrets/deleted/clock views) — after the API
      stabilizes, mirroring the family pattern.

## Sequencing note

Build the **challenge handshake before any storage** — it is this emulator's
reason to exist, every SDK call path runs through it, and it defines the
integration contract with entra-emulator. Secrets storage is straightforward
once auth is honest.
