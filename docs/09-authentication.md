# 09 — Authentication

Authentication *is the point* of this emulator. Where a pass-through emulator
accepts any token, this one advertises a real Entra authority and validates
every token — so `DefaultAzureCredential` walks the same path it walks in
production, and the credential path itself is under test.

## The challenge handshake

```
 Azure SDK (SecretClient / azsecrets / …)
      │ 1. request with no token
      ▼
 keyvault-emulator ── 401 WWW-Authenticate: Bearer
      │                 authorization="{entra-origin}/{tenant}",
      │                 resource="https://vault.azure.net"
      │ 2. SDK acquires a token from the advertised authority
      ▼
 entra-emulator ── mints aud = https://vault.azure.net
      │ 3. SDK retries with the token
      ▼
 keyvault-emulator ── validate (sig + iss + aud + exp) against entra JWKS → 200
```

1. **Challenge.** Any request without an `Authorization` header gets `401` with
   `WWW-Authenticate: Bearer authorization="…", resource="https://vault.azure.net"`.
   The authority is the configured Entra issuer's origin+tenant — entra-emulator
   or a real tenant.
2. **Acquire.** The SDK's credential fetches a vault-audience token from that
   authority. `DefaultAzureCredential`/`ClientSecretCredential` do this
   transparently.
3. **Validate.** The retried token is checked for real: RS256 signature against
   the issuer's JWKS (fetched once, cached by `kid`), issuer match, audience ∈
   {`https://vault.azure.net`, `https://vault.azure.net/`}, and `exp`/`nbf`
   against the [controllable clock](10-testing.md). A bad token → `401`; a
   valid token missing a granted operation → `403` (see below).

## Any Entra credential path works

Because validation is real and issuer-anchored, **every** way of getting a
vault-audience token from entra-emulator works end to end:

- **Client credentials** — `ClientSecretCredential`, or a raw
  `grant_type=client_credentials&scope=https://vault.azure.net/.default`.
  Resolves with no resource-app seed since entra-emulator v0.2.1 treats
  `https://vault.azure.net` as a well-known Azure resource.
- **Managed identity** — the App Service-style endpoint
  (`GET {entra}/msi/token?resource=https://vault.azure.net`, guarded by
  `X-IDENTITY-HEADER`). No secret in the workload; the endpoint echoes the
  requested resource as the audience.
- **Fabric workspace identity** — a token entra mints for a provisioned
  workspace identity (the basis of the [family chain](11-family-integration.md)).
- **Forged tokens** — entra-emulator's token forge, for negative tests
  (wrong audience, already expired). The vault rejects them exactly as
  production would.

Wrong-audience (e.g. a Fabric token) and clock-expired tokens are asserted
rejected in the CI e2e.

## Authorization (optional)

By default a valid vault-audience token has **full data-plane access** — the
common dev posture, and enough for most tests. To exercise
authorization-denied paths, set a per-principal operation allowlist over the
control surface:

```bash
curl -sk -X POST https://localhost:8444/_emulator/permissions \
  -d '{"<principal-oid>": ["secrets/get", "keys/sign"]}'
```

Now that principal may only `GET` secrets and `sign` with keys; anything else
is `403 Forbidden`. Operation names are `{type}/{op}` (`secrets/set`,
`keys/create`, `certificates/delete`, …); `*` grants all. An empty map `{}`
restores full access. This models access-policy *semantics* without pretending
to be ARM ([Architecture § Authorization](03-architecture.md)).

## localhost vs DNS-pinned

The SDK's challenge-resource verification expects the vault host to end in
`vault.azure.net`. On `localhost` it won't, so set
`DisableChallengeResourceVerification`; DNS-pin `{vault}.vault.azure.net` to
`127.0.0.1` to avoid the override. Both are covered in
[TLS and vaults](05-tls-and-vaults.md).
