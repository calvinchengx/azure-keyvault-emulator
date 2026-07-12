# 06 — Secrets

Opaque values with attributes, tags, versioning, and soft delete. All routes
are relative to the vault origin (`https://{vault}.vault.azure.net`), require
`api-version`, speak `application/json`, and require a valid bearer token
([Authentication](09-authentication.md)).

## Endpoints

| Method + path | Purpose |
|---|---|
| `PUT /secrets/{name}` | set — creates a **new version**; body `{value, contentType?, attributes?, tags?}` → 200 bundle |
| `GET /secrets/{name}` | get the current version |
| `GET /secrets/{name}/{version}` | get a specific version |
| `PATCH /secrets/{name}/{version}` | update attributes/tags (never the value) |
| `GET /secrets?maxresults=&$skiptoken=` | list current versions (paged) |
| `GET /secrets/{name}/versions` | list all versions of a name (paged) |
| `DELETE /secrets/{name}` | soft-delete → deleted-secret bundle with `scheduledPurgeDate` |
| `POST /secrets/{name}/backup` | opaque backup blob `{value: base64}` |
| `POST /secrets/restore` | restore from a backup blob |

### Deleted secrets (soft delete)

| Method + path | Purpose |
|---|---|
| `GET /deletedsecrets/{name}` | inspect a soft-deleted secret |
| `GET /deletedsecrets` | list (paged) |
| `POST /deletedsecrets/{name}/recover` | recover to the active state |
| `DELETE /deletedsecrets/{name}` | **purge** — permanent, permission-gated |

## Secret bundle

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

`PATCH` responses omit `value`, like real Key Vault — a secret's value is never
echoed on an attributes-only update.

## Behavior that matters

- **Versioning.** Every `PUT` of a name creates a new 32-hex version and never
  overwrites; the unversioned `GET` returns the newest.
- **`enabled`.** `enabled: false` blocks retrieval with `403 Forbidden`.
- **`nbf` / `exp` are informational.** A `GET` outside the not-before /
  expiry window still succeeds — matching AKV's documented behavior (retrieving
  an expired secret is a supported recovery/test scenario). The emulator never
  rejects a secret for being expired.
- **Soft delete on the clock.** `DELETE` retains all versions and stamps a
  `scheduledPurgeDate` from the retention window
  (`--soft-delete-retention-days`, 7–90, default 90). While soft-deleted the
  name reads as absent (`404 SecretNotFound`) and cannot be reused
  (`409 Conflict` on `PUT`). `recover` restores it; `purge` removes it
  permanently. Advance the [clock](10-testing.md) past `scheduledPurgeDate`
  and it is purged automatically — no waiting.
- **Backup/restore.** `backup` returns an opaque base64 blob of every version;
  `restore` recreates the name in a vault that doesn't already have it.

## SDK example (Go)

```go
client, _ := azsecrets.NewClient(vaultURL, cred, opts)
client.SetSecret(ctx, "db-password", azsecrets.SetSecretParameters{
    Value: to.Ptr("hunter2"),
}, nil)
got, _ := client.GetSecret(ctx, "db-password", "", nil)   // *got.Value == "hunter2"
```

Verified end to end against the real `azsecrets` SDK in CI.
