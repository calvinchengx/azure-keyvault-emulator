# 11 — Family integration

azure-keyvault-emulator is one of six emulators built on a single principle:
**the same trust relationships as production**. entra-emulator issues tokens;
every other member validates them against entra's JWKS. The payoff is that they
compose into a faithful offline Azure environment.

- [entra-emulator](https://github.com/calvinchengx/entra-emulator) — the STS. Everything below validates
  the tokens it issues.
- [arm-emulator](https://github.com/calvinchengx/arm-emulator) — ARM control plane and RBAC. Governs this
  vault: role assignments decide who may read what.
- **azure-keyvault-emulator** — the secret store.
- [fabric-emulator](https://github.com/calvinchengx/fabric-emulator) — the Microsoft Fabric control + data
  plane.
- [azure-apim-emulator](https://github.com/calvinchengx/azure-apim-emulator) — API Management. Takes named
  values and certificates from here.
- [databricks-emulator](https://github.com/calvinchengx/databricks-emulator) — a Databricks workspace.

Run them together with [azure-emulators](https://github.com/calvinchengx/azure-emulators), which holds the
family compose file and the pinned versions they are certified against.

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

## Vault-backed connection credentials (fabric side)

Microsoft Fabric lets a connection point at a Key Vault secret instead of
embedding a credential. It is **not** a credential type of its own: the owning
type carries a `KeyVaultSecretReference`, so a key backed by a vault is

```json
{"credentialType": "Key",
 "keyReference": {"connectionId": "<an AzureKeyVault connection>",
                  "secretName": "contoso-pos-api-key"}}
```

and `connectionId` names a **connection to the vault** — not a `vaultUri`. So
the vault is itself a connection (`type: AzureKeyVault`, parameter
`accountName`), and binding one takes two creates.

> **Changed in fabric-emulator 0.22.0.** This page previously documented a
> `credentialType: "AzureKeyVaultReference"`, which fabric-emulator accepted and
> real Fabric has never had. It is now rejected. Measured against a tenant on
> 2026-08-11, along with the rest of the Create Connection contract.

fabric-emulator **resolves the secret from this emulator** at connection create,
reproducing the feature end to end offline:

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
