# azure-keyvault-emulator

A clean-room, local emulator of the **Azure Key Vault data plane** — the third
member of an emulator family built on one principle: **the same trust
relationships as production**.

- [entra-emulator](https://github.com/calvinchengx/entra-emulator) — the STS:
  issues the tokens.
- [fabric-emulator](https://github.com/calvinchengx/fabric-emulator) — the
  Microsoft Fabric control + data plane: consumes them.
- **azure-keyvault-emulator** — the secret store: consumes them too, at
  `https://{vault}.vault.azure.net` wire fidelity.

```
 Azure SDK (azsecrets / SecretClient)
      │ 1. unauthenticated probe
      ▼
 azure-keyvault-emulator ── 401 WWW-Authenticate: Bearer
      │                        authorization="{entra authority}",
      │                        resource="https://vault.azure.net"
      │ 2. SDK acquires token from the advertised authority
      ▼
 entra-emulator ── mints aud=https://vault.azure.net
      │ 3. SDK retries with the token
      ▼
 azure-keyvault-emulator ── validates sig/iss/aud against entra's JWKS → 200
```

## Why another Key Vault emulator?

[james-gould/azure-keyvault-emulator](https://github.com/james-gould/azure-keyvault-emulator)
is excellent and proves the SDK-compatibility ground: full `SecretClient` /
`KeyClient` / `CertificateClient` support. But its authentication is
deliberately a pass-through — any token is accepted (`ValidateIssuer=false`,
`ValidateAudience=false`, a signature validator that decodes without
verifying), with a built-in fake OAuth surface to satisfy the SDK challenge
dance.

This project makes the opposite trade: **authentication is the point.** Tokens
are validated for real — signature against entra-emulator's JWKS, issuer,
`https://vault.azure.net` audience, expiry on a controllable clock — and the
401 challenge advertises *entra-emulator's* authority, so
`DefaultAzureCredential` walks the same two-step it walks in production. Your
tests exercise the credential path, not just the storage path: a
managed-identity token from entra's MSI endpoint, a client-credentials token, a
Fabric workspace-identity token — each either works or fails exactly as it
would against real Azure.

## Status

**Working** — secrets, keys (real RSA/EC cryptography), and certificates
(self-signed + PFX/PEM import) are shipped, each verified end-to-end by the
real Azure SDK (`azsecrets` / `azkeys` / `azcertificates`) completing
challenge-based authentication against an in-process entra-emulator. Soft
delete, versioning, backup/restore, and an optional per-principal permission
map are in. Every package covers itself; 90%+ total with a CI floor.

Install: `go install github.com/calvinchengx/azure-keyvault-emulator/cmd/azure-keyvault-emulator@latest`,
`brew install calvinchengx/tap/azure-keyvault-emulator`,
`winget install calvinchengx.azure-keyvault-emulator`, or the
`ghcr.io/calvinchengx/azure-keyvault-emulator` image (see
[`docker-compose.yml`](docker-compose.yml) for the entra-emulator pairing).

See [docs/01-architecture.md](docs/01-architecture.md),
[docs/02-api-surface.md](docs/02-api-surface.md), and
[docs/03-roadmap.md](docs/03-roadmap.md).

## License

Apache-2.0. Clean-room: grounded in Microsoft's public documentation
([`MicrosoftDocs/azure-security-docs`](https://github.com/MicrosoftDocs/azure-security-docs),
the Key Vault REST reference) and behavioral study of the MIT-licensed
james-gould emulator — no Microsoft source.
