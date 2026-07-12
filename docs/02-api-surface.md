# 02 — Emulated API surface

Grounded in the Key Vault REST reference (data plane, `api-version=7.5`) and
the endpoint set the james-gould emulator proved sufficient for full Azure SDK
client support. All routes are relative to the vault origin
(`https://{vault}.vault.azure.net`), require `api-version`, and speak
`application/json`.

## Authentication handshake (every route)

1. Request without a token →
   `401` + `WWW-Authenticate: Bearer authorization="{entra-origin}/{tenant}", resource="https://vault.azure.net"`.
2. Request with a token → RS256 validation against entra-emulator JWKS:
   issuer, vault audience, `exp`/`nbf` on the emulator clock. Failures are
   `401` with the AKV error envelope; a valid token lacking a granted
   operation (when the optional permission map is on) is `403 Forbidden`.

## Secrets (P0)

| Method + path | Purpose |
|---|---|
| `PUT /secrets/{name}` | set — creates a **new version**; body `{value, contentType?, attributes?, tags?}` → 200 secret bundle |
| `GET /secrets/{name}` | get current version (404 `SecretNotFound` if missing/disabled-by-delete) |
| `GET /secrets/{name}/{version}` | get a specific version |
| `PATCH /secrets/{name}/{version}` | update attributes/tags (not the value) |
| `GET /secrets?maxresults=&$skiptoken=` | list current versions (paged, `nextLink`) |
| `GET /secrets/{name}/versions` | list all versions (paged) |
| `DELETE /secrets/{name}` | soft-delete → deleted-secret bundle with `scheduledPurgeDate` |
| `POST /secrets/{name}/backup` | opaque backup blob `{value: base64}` |
| `POST /secrets/restore` | restore from a backup blob |

**Secret bundle** (the wire shape):

```json
{
  "id": "https://emulator.vault.azure.net/secrets/db-password/4387e9f3d6e14c459867679a90fd0f79",
  "value": "hunter2",
  "contentType": "text/plain",
  "attributes": {
    "enabled": true, "nbf": 1493938410, "exp": 1493938410,
    "created": 1493938410, "updated": 1493938410,
    "recoveryLevel": "Recoverable+Purgeable", "recoverableDays": 90
  },
  "tags": { "env": "dev" }
}
```

Fidelity notes (from `secrets/about-secrets.md`): `enabled=false` blocks
retrieval (403); `nbf`/`exp` are **informational** — gets outside the window
still succeed; `PUT` of an existing name creates a version, never overwrites;
version ids are 32-hex like real AKV.

## Deleted secrets — soft delete (P0)

| Method + path | Purpose |
|---|---|
| `GET /deletedsecrets/{name}` | inspect a soft-deleted secret |
| `GET /deletedsecrets` | list (paged) |
| `DELETE /deletedsecrets/{name}` | **purge** — permanent, permission-gated |
| `POST /deletedsecrets/{name}/recover` | recover to the active state |

Retention: `--soft-delete-retention-days` (7–90, default 90). The purge
deadline is enforced on the **controllable clock** — advance past
`scheduledPurgeDate` and the object is gone; the name is unusable while
soft-deleted (409 `Conflict` on `PUT`), both testable without waiting.

## Keys (P1)

Same CRUD/versioning/soft-delete skeleton as secrets
(`/keys/{name}[/{version}]`, `/deletedkeys/…`), plus the crypto operations —
implemented with **real Go crypto** (RSA 2048/3072/4096, EC P-256/384/521),
software-protected only:

| Method + path | Purpose |
|---|---|
| `POST /keys/{name}/create` | create (kty, key_size/crv, key_ops) |
| `GET /keys/{name}/{version}` | JWK public material |
| `POST /keys/{name}/{version}/sign` \| `/verify` | RS256/ES256 family |
| `POST /keys/{name}/{version}/encrypt` \| `/decrypt` | RSA-OAEP(+256), RSA1_5 |
| `POST /keys/{name}/{version}/wrapkey` \| `/unwrapkey` | key wrapping |

Signatures verify against the JWK the API returns — real interop, not stubs.

## Certificates (P2)

`/certificates` CRUD, policy get/set, and self-signed issuance only (`issuer:
"Self"`); import of caller-supplied PFX/PEM. Real CA integration (DigiCert,
etc.) is a non-goal. The certificate's key/secret pair materializes in
`/keys` and `/secrets` under the same name, as in real AKV.

## Control surface (`/_emulator`, no auth — local plumbing)

| Route | Purpose |
|---|---|
| `GET/POST /_emulator/clock` | freeze/advance/offset virtual time (attribute windows, purge deadlines, token expiry) |
| `POST /_emulator/faults` | inject `429 Retry-After` throttling, 500s, per-operation failures |
| `POST /_emulator/permissions` | optional per-principal operation map (authorization-denied testing) |

Throttling injection matters: real AKV throttles aggressively
(`general/overview-throttling.md` guidance) and SDK retry behavior is
otherwise untestable offline.

## Error envelope

```json
{ "error": { "code": "SecretNotFound", "message": "A secret with (name/id) db-password was not found in this key vault." } }
```

With `x-ms-request-id` on every response (`general/common-error-codes.md`).
