# azure-keyvault-emulator

[![CI](https://github.com/calvinchengx/azure-keyvault-emulator/actions/workflows/ci.yml/badge.svg)](https://github.com/calvinchengx/azure-keyvault-emulator/actions/workflows/ci.yml)
[![Docs](https://github.com/calvinchengx/azure-keyvault-emulator/actions/workflows/docs-site.yml/badge.svg)](https://calvinchengx.github.io/azure-keyvault-emulator/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A clean-room, local emulator of the **Azure Key Vault data plane** — secrets,
keys doing real RSA/EC cryptography, and X.509 certificates — the third member
of an emulator family built on one principle: **the same trust relationships as
production**.

![azure-keyvault-emulator demo: the 401 challenge every Azure SDK follows, a real Entra token answering it, a secret round-tripped, and a real RS256 signature](docs/demo/demo.gif)

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

A read-only **operator portal** (dashboard, object browsers, clock + fault
controls) is embedded in the binary and served at
`http://localhost:8444/_emulator/portal/` — no extra process.

## Parity at a glance

| | Rows | Meaning |
|---|---|---|
| 🟢 **Real** | 32 | Genuine work — real RSA/EC cryptography, real X.509 issuance, real token validation |
| 🟡 **Emulated** | 13 | Faithful API contract and persisted state, but no engine behind it |
| 🟠 **Partial** | 2 | The common path works; the edges are not there yet |
| 🔴 **Not implemented** | 21 | The infrastructure *around* the vault — ARM, the HSM, private networking — which no localhost process can honestly provide |

The real Azure SDKs (`azsecrets` / `azkeys` / `azcertificates`) drive it as
borrowed oracles. Full detail: [parity map](docs/parity.md).

## Quick start

Same three verbs on Linux, macOS and Windows — see
[platform setup](docs/14-platform-setup.md) for the prerequisites:

```bash
make doctor   # toolchain + docker context check — run this first
make up       # entra-emulator :8443 + keyvault-emulator :8444
make status   # is the pair usable? (containers, endpoints, the 401 challenge)
```

`make up PROFILE="--profile full"` adds fabric-emulator for the
secret-as-SP-credential chain.

The rest:

```bash
make help     # every target with a one-line description
make ps       # container states
make logs     # tail logs (SVC=<service> to narrow to one)
make down     # stop and remove containers — volumes SURVIVE
make clean    # stop and remove containers AND delete the data volumes
make restart  # clean, then up
make test     # go build, vet and unit tests
make chain    # the secret-as-SP-credential chain, end to end
```

Docs: <https://calvinchengx.github.io/azure-keyvault-emulator/> — start with
the [Quickstart](docs/01-quickstart.md), then
[Architecture](docs/03-architecture.md), the data-plane reference
([Secrets](docs/06-secrets.md) / [Keys](docs/07-keys.md) /
[Certificates](docs/08-certificates.md)), and
[Authentication](docs/09-authentication.md).

## License

Apache-2.0. Clean-room: grounded in Microsoft's public documentation
([`MicrosoftDocs/azure-security-docs`](https://github.com/MicrosoftDocs/azure-security-docs),
the Key Vault REST reference) and behavioral study of the MIT-licensed
james-gould emulator — no Microsoft source.
