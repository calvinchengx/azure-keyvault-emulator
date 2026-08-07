# 10 — Testing

The `/_emulator` control surface makes time, failures, and authorization
deterministic — so behavior that would take days or aggressive load in real
Key Vault is testable in milliseconds. These routes are **local plumbing**, not
part of the Key Vault contract, and take no auth.

## Controllable clock

Every timestamp the emulator stamps — secret `nbf`/`exp` windows, soft-delete
`scheduledPurgeDate`, certificate validity, and token `exp`/`nbf` checks —
flows through one clock you control.

```bash
# freeze, then jump past a 90-day purge deadline instantly
curl -sk -X POST https://localhost:8444/_emulator/clock -d '{"freeze": true}'
curl -sk -X POST https://localhost:8444/_emulator/clock -d '{"advance": 7776000}'   # +90 days
curl -sk      https://localhost:8444/_emulator/clock                                 # {offset, frozen, now}
```

Fields: `advance` (± seconds), `offset` (absolute seconds from real time),
`freeze` (bool). Uses:

- **Soft-delete purge** — delete a secret, advance past `scheduledPurgeDate`,
  confirm it's gone and the name is reusable.
- **Token expiry** — mint a token, advance past its lifetime, confirm the vault
  now `401`s the same token (validation runs on this clock).
- **Certificate lifetime** — issue with a short validity, advance, inspect.

## Fault injection

```bash
# make the next request 429 with Retry-After (test SDK retry/backoff)
curl -sk -X POST https://localhost:8444/_emulator/faults -d '{"throttleNextRequests": 1}'

# make the next request a 500
curl -sk -X POST https://localhost:8444/_emulator/faults -d '{"rejectNextRequests": 1}'
```

Throttling injection matters because real Key Vault throttles aggressively, and
an SDK's retry/backoff behavior is otherwise untestable offline. Faults fire
*before* auth, so they exercise the transport path regardless of token state.

## Permission map

Restrict a principal to an operation set to test authorization-denied paths —
see [Authentication § Authorization](09-authentication.md).

```bash
curl -sk -X POST https://localhost:8444/_emulator/permissions \
  -d '{"<principal-oid>": ["secrets/get"]}'   # {} restores full access
```

## In your own tests

- **Any language** — point the SDK at the emulator (localhost or DNS-pinned),
  drive the clock/faults over `/_emulator` with a plain HTTP call.
- **Go, in-process** — the emulator's own e2e starts entra-emulator in-process
  and drives the real `azsecrets`/`azkeys`/`azcertificates` SDKs against the
  vault; see `internal/server/*_test.go` for the fixture pattern.

## What the project itself verifies

- Real-SDK e2e for all three object types (`azsecrets`, `azkeys`,
  `azcertificates`) completing challenge-based auth against in-process
  entra-emulator.
- The real-SDK witness matrix (`e2e/sdk/run.py`): Microsoft's **Python**
  (`azure-keyvault-*`), **JavaScript** (`@azure/keyvault-*`) and **.NET**
  (`Azure.Security.KeyVault.*`) SDKs, pinned, each completing challenge auth
  and exercising secrets (soft-delete → recover → purge), RSA crypto through
  `CryptographyClient` (with a tampered-signature negative), and the
  self-signed certificate LRO — on Linux, macOS and Windows in CI.
- The [three-emulator chain](11-family-integration.md) (`e2e/chain/run.py`).
- A ≥90% coverage floor, enforced in CI.
- Every 🟢 claim in the [parity map](parity.md) names its witness, enforced by
  `scripts/check_witnesses.py --strict` in CI.
