# 04 — Configuration

Every setting has a `KV_*` environment variable and a flag; the flag wins when
both are set. Only the Entra issuer is required.

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--addr` | `KV_ADDR` | `:8444` | Listen address. |
| `--data-dir` | `KV_DATA_DIR` | `./data` | State directory (SQLite + persisted TLS cert), so secrets, keys and certificates survive a restart. Set it to the **empty string** to opt back into an in-memory DB and ephemeral TLS keys — *unset* and *set-empty* differ deliberately, and the compose files use the empty form so a throwaway stack leaves nothing behind. |
| `--entra-issuer` | `KV_ENTRA_ISSUER` | *(required)* | The exact `iss` bearer tokens must carry, e.g. `https://localhost:8443/{tenant}/v2.0`. An entra-emulator or real Entra v2.0 issuer. A comma-separated list trusts several issuers, each validated against its own JWKS; the 401 challenge advertises the first. |
| `--entra-jwks-url` | `KV_ENTRA_JWKS_URL` | *(derived)* | Where signing keys are fetched. Derived from the issuer when unset (`{issuer − /v2.0}/discovery/v2.0/keys`). |
| `--entra-tls-insecure` | `KV_ENTRA_TLS_INSECURE` | `false` | Skip TLS verification when fetching JWKS — for entra-emulator's self-signed cert on a compose network. |
| `--default-vault` | `KV_DEFAULT_VAULT` | `emulator` | The vault served on non-vault hosts (`localhost`, IPs). |
| `--soft-delete-retention-days` | `KV_SOFT_DELETE_RETENTION_DAYS` | `90` | Soft-delete recovery window (7–90). Rejected outside that range. |
| `--arm-url` | `KV_ARM_URL` | *(unset)* | arm-emulator's origin. When set, authorization comes from ARM (role assignments + vault access policies) instead of the `/_emulator` surface. |
| `--arm-scope` | `KV_ARM_SCOPE` | derived | This vault's ARM resource id. Derived from the subscription, resource group and default vault name when unset. |
| `--arm-subscription` | `KV_ARM_SUBSCRIPTION` | `6082bfda-…-9feb` | Used to derive the scope. |
| `--arm-resource-group` | `KV_ARM_RESOURCE_GROUP` | `emulator-rg` | Used to derive the scope. |
| — | `KV_ARM_POLL_SECONDS` | `5` | How often the ARM authorization feed is refreshed. |
| `--purge-protection` | `KV_PURGE_PROTECTION` | off | Refuse purge (`403`) and report `recoveryLevel: Recoverable`, as a purge-protected vault does. Also toggleable at runtime: `POST /_emulator/purge-protection {"enabled": true}`. |
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

## When ARM governs, the vault resource wins

With `--arm-url` set, the vault's own settings come from the
`Microsoft.KeyVault/vaults` resource in ARM, because that is where they live in
Azure — not from this process's flags:

| Setting | Flag (standalone) | ARM property (when `--arm-url` is set) |
|---|---|---|
| Purge protection | `--purge-protection` | `properties.enablePurgeProtection` |
| Soft-delete window | `--soft-delete-retention-days` | `properties.softDeleteRetentionInDays` |
| Authorization model | *(control surface)* | `properties.enableRbacAuthorization` |
| Who may do what | `/_emulator/*` | role assignments + access policies |

So `az keyvault update --enable-purge-protection true` changes the running
emulator's behaviour, exactly as it changes a real vault's. Two guards:

- **An absent vault resource changes nothing.** If ARM has no vault at the
  configured scope, the flags stay in force — absence is not an instruction.
- **An out-of-range window is ignored** rather than applied, the same 7–90
  validation the flag gets.

This is the default: `docker compose up` starts arm-emulator and points the
vault at it. The stack also seeds what Azure gives you when you create a vault
in the portal — the `Microsoft.KeyVault/vaults` resource and a **Key Vault
Secrets Officer** assignment for the principal that created it — because ARM's
rule is *no assignment means no access*, and a default stack whose first
request is a `403` would be worse than no default at all.

```bash
docker compose up                 # ARM governs
KV_ARM_URL= docker compose up     # opt out; or: make up NOARM=1
```

The seed is `scripts/seed-arm.py`, deliberately readable: it is also the
documentation for doing the same thing by hand against a real vault.
