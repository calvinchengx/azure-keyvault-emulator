# 07 — Keys

RSA and EC keys with the same versioning + soft-delete skeleton as
[secrets](06-secrets.md), plus cryptographic operations backed by **real Go
crypto** — signatures verify against the JWK the API returns, not stubs.
Software-protected only (no HSM).

## Endpoints

| Method + path | Purpose |
|---|---|
| `POST /keys/{name}/create` | create — `{kty, key_size?/crv?, key_ops?, attributes?, tags?}` → key bundle |
| `PUT /keys/{name}` | **import** a caller-supplied JWK (`{key:{kty,…private members}, attributes?, tags?}`) |
| `GET /keys/{name}` \| `/keys/{name}/{version}` | get the public JWK |
| `PATCH /keys/{name}/{version}` \| `/keys/{name}` | update `key_ops`/attributes/tags (versioned or latest) |
| `GET /keys` \| `/keys/{name}/versions` | list (paged) |
| `DELETE /keys/{name}` | soft-delete |
| `POST /keys/{name}/backup` · `POST /keys/restore` | opaque backup blob (all versions) → restore into an empty name |
| `GET` \| `PUT /keys/{name}/rotationpolicy` | rotation policy (round-tripped; unset returns the disabled-rotation default) |
| `GET/DELETE /deletedkeys/{name}`, `GET /deletedkeys`, `POST /deletedkeys/{name}/recover` | deleted-key lifecycle |
| `POST /rng` | `{count}` (1–128) → `{value}` cryptographically-random base64url bytes |

**Import** reconstructs a real key from the JWK's private members (RSA
`n/e/d/p/q`, EC `crv/x/y/d`); the material is validated (RSA CRT check, EC
on-curve check) and a subsequent `sign` verifies against the returned public
JWK — the same interop guarantee as generated keys.

### Cryptographic operations

Versioned and unversioned; wire values are base64url. The caller hashes (Key
Vault signs a digest), matching AKV semantics.

| Method + path | Algorithms |
|---|---|
| `POST /keys/{name}/{version}/sign` \| `/verify` | `RS256/384/512`, `PS256/384/512`, `ES256/384/512` |
| `POST /keys/{name}/{version}/encrypt` \| `/decrypt` | `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256` |
| `POST /keys/{name}/{version}/wrapKey` \| `/unwrapKey` | `RSA-OAEP`, `RSA-OAEP-256`, `RSA1_5` |

## Supported key types

- **RSA** — key sizes 2048 / 3072 / 4096.
- **EC** — curves P-256 / P-384 / P-521.

`RSA-HSM` / `EC-HSM` `kty` values are accepted and normalized to their
software equivalents (there is no HSM). The **private key never leaves the
store**; every response derives the public JWK (`n`/`e` for RSA, `crv`/`x`/`y`
for EC).

## The interop guarantee

A signature the emulator produces verifies against the public JWK it returned —
proven both through the SDK's `Verify` and by independent reconstruction of the
public key in the CI e2e (RSA via `n`/`e`, EC via the raw `r‖s` encoding Azure
emits). A tampered signature fails; a disabled key `403`s on crypto ops.

## SDK example (Go)

```go
kc, _ := azkeys.NewClient(vaultURL, cred, opts)
key, _ := kc.CreateKey(ctx, "signer", azkeys.CreateKeyParameters{
    Kty: to.Ptr(azkeys.KeyTypeRSA), KeySize: to.Ptr(int32(2048)),
}, nil)

digest := sha256.Sum256([]byte("attest me"))
sig, _ := kc.Sign(ctx, "signer", "", azkeys.SignParameters{
    Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256), Value: digest[:],
}, nil)

// Verifies through the SDK — and locally against key.Key (n, e).
ok, _ := kc.Verify(ctx, "signer", "", azkeys.VerifyParameters{
    Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256),
    Digest: digest[:], Signature: sig.Result,
}, nil)   // *ok.Value == true
```

Verified end to end against the real `azkeys` SDK in CI.
