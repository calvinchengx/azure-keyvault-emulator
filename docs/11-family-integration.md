# 11 — Family integration

azure-keyvault-emulator is the third member of an emulator family built on one
principle: **the same trust relationships as production**. entra-emulator
issues tokens; the fabric and keyvault emulators validate them against entra's
JWKS. The payoff is that they compose into a faithful offline Azure environment.

- [entra-emulator](https://github.com/calvinchengx/entra-emulator) — the STS.
- [fabric-emulator](https://github.com/calvinchengx/fabric-emulator) — the
  Microsoft Fabric control + data plane.
- **azure-keyvault-emulator** — the secret store.

## The secret-as-SP-credential chain

The canonical "an SP's secret lives in Key Vault" pattern, exercised across all
three emulators as three real processes — [`e2e/chain/run.py`](https://github.com/calvinchengx/azure-keyvault-emulator/blob/main/e2e/chain/run.py),
run in CI:

```
 vault secret ──▶ managed identity ──▶ entra token ──▶ fabric
```

1. A client-credentials call stores a service principal's `client_secret` in
   the vault.
2. A workload reads it back with a **managed-identity token** (entra's
   `/msi/token`) — no credential in the workload.
3. That recovered secret authenticates the SP to entra (client credentials) for
   a **Fabric-audience** token.
4. The token calls fabric-emulator and is accepted.

Every hop uses the production trust relationship. A wrong secret breaks the
chain exactly where it would in Azure — which is what a pass-through-auth
emulator cannot test.

Bring up the whole trio for this flow:

```bash
docker compose --profile full up   # entra + keyvault + fabric
```

## AKV-reference connections (fabric side)

Microsoft Fabric lets a connection point at a Key Vault secret instead of
embedding a credential (its "Azure Key Vault references" feature).
fabric-emulator models this with an `AzureKeyVaultReference` connection
credential type that **resolves the secret from this emulator** at connection
create — reproducing the feature end to end offline:

```
 workspace identity ──▶ entra token ──▶ vault secret ──▶ connection
```

The secret material is resolved and used but **never echoed back** — fabric
stores the reference, not the value. This is a fabric-emulator feature that
consumes this emulator; see fabric-emulator's connection docs.

## Why three emulators, not one

Each emulates a distinct product with a distinct protocol, and each is
independently useful and released. Folding them together would blur the trust
boundary that makes the composition faithful: the vault trusts *Entra*, not a
built-in fake — so any real Entra credential (client secret, managed identity,
workspace identity) flows through unchanged. See
[Architecture](03-architecture.md).
