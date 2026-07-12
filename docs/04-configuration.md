# 04 — Configuration

Every setting has a `KV_*` environment variable and a flag; the flag wins when
both are set. Only the Entra issuer is required.

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--addr` | `KV_ADDR` | `:8444` | Listen address. |
| `--data-dir` | `KV_DATA_DIR` | *(empty)* | State directory (SQLite + persisted TLS cert). Empty = in-memory DB and ephemeral TLS keys. |
| `--entra-issuer` | `KV_ENTRA_ISSUER` | *(required)* | The exact `iss` bearer tokens must carry, e.g. `https://localhost:8443/{tenant}/v2.0`. An entra-emulator or real Entra v2.0 issuer. |
| `--entra-jwks-url` | `KV_ENTRA_JWKS_URL` | *(derived)* | Where signing keys are fetched. Derived from the issuer when unset (`{issuer − /v2.0}/discovery/v2.0/keys`). |
| `--entra-tls-insecure` | `KV_ENTRA_TLS_INSECURE` | `false` | Skip TLS verification when fetching JWKS — for entra-emulator's self-signed cert on a compose network. |
| `--default-vault` | `KV_DEFAULT_VAULT` | `emulator` | The vault served on non-vault hosts (`localhost`, IPs). |
| `--soft-delete-retention-days` | `KV_SOFT_DELETE_RETENTION_DAYS` | `90` | Soft-delete recovery window (7–90). Rejected outside that range. |
| `--disable-tls` | `KV_DISABLE_TLS` | `false` | Serve plain HTTP (behind a TLS-terminating proxy, or for curl exploration). |

## Derived fields

`--entra-jwks-url` and the challenge authority are both derived from
`--entra-issuer` when unset:

```
issuer   https://localhost:8443/{tenant}/v2.0
jwks     https://localhost:8443/{tenant}/discovery/v2.0/keys
authority (advertised in the 401 challenge)
         https://localhost:8443/{tenant}
```

Point `--entra-issuer` at a **real** Entra tenant and nothing else changes —
the vault validates real tokens.

## Docker environment

The distroless image sets `KV_DATA_DIR=/data` and exposes `8444`; mount `/data`
to persist state and the TLS cert across restarts. See
[Installation](02-installation.md) for the compose contract.

## What is *not* configured here

- Vaults are created on first write (Host-routed) — there is no vault-CRUD API
  ([Architecture § Non-goals](03-architecture.md)).
- Runtime knobs used only in tests — the controllable clock, fault injection,
  and the permission map — are set over HTTP through `/_emulator`
  ([Testing](10-testing.md)), not via config.
