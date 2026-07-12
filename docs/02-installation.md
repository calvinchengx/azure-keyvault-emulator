# 02 — Installation

A single static Go binary (pure-Go SQLite, no CGO). Pick whichever channel
fits; all ship the same binary.

## Docker / compose (recommended)

The emulator needs entra-emulator to validate tokens, so the compose file is
the simplest start:

```bash
docker compose up                 # entra :8443 + keyvault :8444
docker compose --profile full up  # adds fabric-emulator :9443 (the whole family)
```

Or run the image directly against an existing entra:

```bash
docker run --rm -p 8444:8444 \
  -e KV_ENTRA_ISSUER="https://entra:8443/11111111-1111-1111-1111-111111111111/v2.0" \
  -e KV_ENTRA_TLS_INSECURE=true \
  ghcr.io/calvinchengx/azure-keyvault-emulator:latest
```

The image is distroless; its `HEALTHCHECK` runs the binary's own
`healthcheck` subcommand (no shell in the container).

## Homebrew (macOS / Linux)

```bash
brew install calvinchengx/tap/azure-keyvault-emulator
```

## winget (Windows)

```powershell
winget install calvinchengx.azure-keyvault-emulator
```

## go install

```bash
go install github.com/calvinchengx/azure-keyvault-emulator/cmd/azure-keyvault-emulator@latest
```

## Release binaries

Prebuilt archives for linux/darwin/windows × amd64/arm64 are attached to each
[GitHub release](https://github.com/calvinchengx/azure-keyvault-emulator/releases),
with `checksums.txt`.

## Run it

The one required setting is the Entra issuer to validate tokens against
(entra-emulator or a real tenant):

```bash
azure-keyvault-emulator \
  --entra-issuer "https://localhost:8443/11111111-1111-1111-1111-111111111111/v2.0" \
  --entra-tls-insecure
```

`azure-keyvault-emulator version` prints the build; `healthcheck` probes
`/health` and exits 0 when live. Full settings in
[Configuration](04-configuration.md).
