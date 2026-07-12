# 13 — The entra-emulator companion

This emulator does not authenticate anyone itself — it **validates** tokens
issued by [entra-emulator](https://github.com/calvinchengx/entra-emulator), the
family's identity provider, exactly as real Key Vault validates against
Microsoft Entra. entra-emulator is a required companion (or a real Entra
tenant).

## What entra-emulator provides

- **JWKS + issuer.** The vault fetches signing keys from the configured
  issuer's `discovery/v2.0/keys` and checks every token's signature, issuer,
  audience, and expiry against it.
- **The authority the `401` challenge advertises** — `{origin}/{tenant}`, so
  `DefaultAzureCredential` knows where to acquire a vault-audience token.
- **Every credential path** — client credentials, the managed-identity endpoint
  (`/msi/token`), Fabric workspace-identity tokens, and a token forge for
  negative tests. All produce tokens this vault accepts or rejects on their
  merits ([Authentication](09-authentication.md)).

## The vault carve-out (entra v0.2.1)

entra-emulator resolves a requested scope to a token audience. Since **v0.2.1**
it recognizes `https://vault.azure.net` (and Storage, ARM) as a well-known
Azure resource, so `https://vault.azure.net/.default` resolves with no
resource-app registration. Pin entra-emulator ≥ v0.2.1 (the compose file uses
`:latest`).

## Wiring

The vault needs one thing: the issuer to trust.

```bash
azure-keyvault-emulator \
  --entra-issuer "https://<entra-host>/<tenant>/v2.0" \
  --entra-tls-insecure          # for entra's self-signed cert on a dev network
```

`--entra-jwks-url` and the challenge authority derive from the issuer
([Configuration](04-configuration.md)). Point `--entra-issuer` at a real Entra
tenant and the vault validates real tokens — the coupling is HTTP-only (JWKS +
the issuer URL), no shared process.

## Pointing at a real tenant

Because validation is issuer-anchored, you can run this vault against a real
Entra tenant: set `--entra-issuer` to `https://login.microsoftonline.com/{tenant}/v2.0`,
drop `--entra-tls-insecure`, and real `DefaultAzureCredential` tokens with
`aud=https://vault.azure.net` are accepted. (The data plane is still the
emulator — this is for exercising real-token acquisition, not real vault
storage.)

## See also

- [Architecture](03-architecture.md) — the cross-service trust model.
- [Family integration](11-family-integration.md) — composing all three
  emulators.
