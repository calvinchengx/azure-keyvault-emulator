# 05 — TLS and vaults

## Self-signed TLS

The emulator serves HTTPS with a self-signed certificate covering `localhost`,
`keyvault-emulator`, `vault.azure.net`, and the wildcard `*.vault.azure.net`.
With `--data-dir` set, the cert is persisted under `{data-dir}/tls/` so its
fingerprint is stable across restarts; without it, an ephemeral cert is
generated per run.

Because the cert isn't in any trust store, clients must trust it explicitly:

- **Azure SDKs** — pass a transport/`connection_verify=False` (dev only), or
  add the cert to the OS/language trust store.
- **curl** — `-k`.
- **Node** — `NODE_EXTRA_CA_CERTS=/path/to/cert.pem`.

`--disable-tls` serves plain HTTP instead — useful behind a TLS-terminating
proxy or for quick curl exploration; the SDKs still expect HTTPS.

## Vault addressing (Host-routed)

Real Key Vault gives every vault its own DNS name
(`{vault}.vault.azure.net`). The emulator routes on the `Host` header:

| Request `Host` | Resolves to |
|---|---|
| `{vault}.vault.azure.net[:port]` | the vault named `{vault}` |
| anything else (`localhost`, `127.0.0.1`, …) | the **default vault** (`--default-vault`, `emulator`) |

Vaults are created implicitly on first write — there is no vault-management
API. Object ids are always the canonical
`https://{vault}.vault.azure.net/{type}/{name}/{version}` form on the wire,
regardless of how you reached the emulator.

### Two ways to point an SDK at a vault

**Localhost (simplest).** Use `vault_url = https://localhost:8444`. The vault
resolves to the default vault, but the SDK's challenge-resource check sees
`localhost` ≠ `*.vault.azure.net` and complains — so set
`DisableChallengeResourceVerification` (the option exists precisely for
non-standard endpoints):

```python
SecretClient("https://localhost:8444", cred,
             disable_challenge_resource_verification=True,
             connection_verify=False)
```

**DNS-pinned (full fidelity).** Map the real hostname to the emulator so the
challenge resource matches and no SDK override is needed:

```
# /etc/hosts
127.0.0.1  myvault.vault.azure.net
```

```python
SecretClient("https://myvault.vault.azure.net:8444", cred,
             connection_verify=False)  # still self-signed
```

The wildcard cert covers `myvault.vault.azure.net`, so only the self-signed
trust needs handling. This is the same DNS-pin trick fabric-emulator uses for
its `api.fabric.microsoft.com` harness.
