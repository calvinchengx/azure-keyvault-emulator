# 01 — Quickstart

Bring up the vault next to entra-emulator, then read and write a secret with
the real Azure SDK — the challenge handshake and token validation happen for
real, offline, in about a minute.

## 1. Start the pair

```bash
docker compose up            # entra-emulator :8443, keyvault-emulator :8444
```

The [`docker-compose.yml`](https://github.com/calvinchengx/azure-keyvault-emulator/blob/main/docker-compose.yml)
wires the vault's `401` challenge to entra-emulator's authority and points
token validation at entra's JWKS. No cloud tenant, no configuration.

## 2. Acquire a token and use a secret (Azure SDK)

`DefaultAzureCredential` walks the exact production path: the vault answers the
SDK's first, tokenless call with a `401` challenge naming entra-emulator's
authority; the SDK acquires a token there and retries.

```python
import os
from azure.identity import DefaultAzureCredential, DefaultAzureCredentialOptions
from azure.keyvault.secrets import SecretClient

# entra-emulator's seeded confidential app (public dev values).
os.environ["AZURE_TENANT_ID"] = "11111111-1111-1111-1111-111111111111"
os.environ["AZURE_CLIENT_ID"] = "cccccccc-0000-0000-0000-000000000002"
os.environ["AZURE_CLIENT_SECRET"] = "daemon-app-secret"
os.environ["AZURE_AUTHORITY_HOST"] = "https://localhost:8443"

cred = DefaultAzureCredential(
    DefaultAzureCredentialOptions(disable_instance_discovery=True))

client = SecretClient(
    vault_url="https://localhost:8444",
    credential=cred,
    # localhost ≠ *.vault.azure.net, so relax the challenge-resource check.
    # DNS-pinned {name}.vault.azure.net use does not need this (see below).
    disable_challenge_resource_verification=True,
    connection_verify=False,  # self-signed cert — local only
)

client.set_secret("db-password", "hunter2")
print(client.get_secret("db-password").value)   # -> hunter2
```

Any Azure Key Vault SDK works the same way — `azsecrets` (Go), `SecretClient`
(.NET/JS), etc. See [Authentication](09-authentication.md) for the handshake in
detail.

## 3. Or just curl it

The default vault (`emulator`) is served on any non-vault host, so `localhost`
works with no DNS setup. Mint a token, then use it:

```bash
TOKEN=$(curl -sk -X POST \
  "https://localhost:8443/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=cccccccc-0000-0000-0000-000000000002&client_secret=daemon-app-secret&scope=https://vault.azure.net/.default" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -sk -X PUT "https://localhost:8444/secrets/db-password?api-version=7.5" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"value":"hunter2"}'

curl -sk "https://localhost:8444/secrets/db-password?api-version=7.5" \
  -H "Authorization: Bearer $TOKEN"
```

A request with no token returns the `401` challenge; a wrong-audience or
expired token is rejected — the point of this emulator (see
[Architecture](03-architecture.md)).

## DNS-pinned mode (full fidelity)

To exercise the SDK's default challenge-resource verification, point the vault
hostname at the emulator (the TLS cert covers `*.vault.azure.net`):

```bash
# /etc/hosts:  127.0.0.1  myvault.vault.azure.net
# then use vault_url="https://myvault.vault.azure.net:8444" with no
# disable_challenge_resource_verification.
```

## Next

- [Installation](02-installation.md) — brew, winget, `go install`, Docker, compose.
- [Secrets](06-secrets.md) · [Keys](07-keys.md) · [Certificates](08-certificates.md) — the full data-plane reference.
- [Testing](10-testing.md) — freeze the clock, inject throttling, restrict permissions.
