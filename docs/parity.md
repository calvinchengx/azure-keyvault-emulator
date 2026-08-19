# Feature parity: azure-keyvault-emulator vs. real Azure Key Vault

How the emulator's surface maps to real Key Vault (as documented at
[learn.microsoft.com/azure/key-vault](https://learn.microsoft.com/en-us/azure/key-vault/)),
and — the point of this table — **whether real work happens or just the API shape**.

The design bet is that the durable, testable surface is *protocol + real
cryptography + identity*, and those are done for real: real RS256 token
validation, real RSA/EC keys doing real signing and encryption, real X.509
issuance. What is left out is the **infrastructure** around the vault — ARM, the
HSM, private networking — which no localhost process can honestly provide.

**"Real via our own wire-protocol implementation."** A row is 🟢 **Real** not
only when real cryptography does the work, but also when the emulator itself
implements Key Vault's wire protocol and the logic behind it — so a real,
unmodified SDK gets byte- and behaviour-identical responses. The Entra
challenge handshake, the object model and the error envelope are all in this
category.

:::note[Absent means 404, not 501]
Unlike its sibling emulators, this one has **no `501` stubs**: a feature that
isn't implemented simply has no route, so the SDK sees a **404**. A 🔴 below
therefore means "absent", not "honestly refused".
:::

## Legend

| | Meaning |
|---|---|
| 🟢 **Real** | Genuine work: real signed JWTs verified, real crypto, real X.509, real logic enforced — no pretending. |
| 🟡 **Emulated** | Faithful API contract + persisted state, but no engine — clock-derived or management-only. |
| 🟠 **Bring-your-own-engine** | Real when you attach a real external engine; contract-only otherwise. |
| 🔴 **Not implemented** | Absent (404). |

## Authentication & identity (`authentication/`)

| Key Vault feature | Emulator | Type |
|---|---|---|
| Entra bearer challenge (`401` + `WWW-Authenticate`) | Tokenless request returns the real challenge — `Bearer authorization="…", resource="https://vault.azure.net"` with AKV code `AKV10000`; unmodified `azidentity` walks it | 🟢 Real |
| Token validation (RS256 / JWKS / issuer / audience / expiry) | Signature verified **before any claim is read**; issuer + audience (string or array) + `exp`/`nbf` with 60s skew, on the emulator's controllable clock; JWKS cached by `kid`, refetched once on miss. `ci:host-routed` drives the JWKS, issuer and audience halves with Microsoft's SDK: a token from an unlisted issuer and a valid token minted for `https://management.azure.com` are each refused 401. **`exp`/`nbf` remain witnessed by Go tests alone** — expiry needs the controllable clock, which no external client can reach. | 🟢 Real |
| Principal derivation (`oid` → `sub`; `idtyp=app` → service principal) | Full | 🟢 Real |
| Group membership in authorization | A grant to a group authorizes any caller carrying that group in its `groups` claim — the member is never named, as data-plane RBAC resolves it | 🟢 Real |
| Multiple trusted issuers | `KV_ENTRA_ISSUER` accepts a comma-separated list; each issuer validates against its **own** JWKS, and the verifying key is bound to the token's `iss`. `ci:host-routed` runs **two separate entra-emulator instances** with different signing keys and accepts a token from each; dropping one from the list makes the suite fail naming the missing JWKS key. | 🟢 Real |

## Secrets (`secrets/`)

| Key Vault feature | Emulator | Type |
|---|---|---|
| Set / get / list / list-versions, get by version | Full; real bytes persisted | 🟢 Real |
| Versioning (32-hex version per write) | Full — every write mints a new version | 🟢 Real |
| Attributes `enabled` | Enforced — a disabled object is refused | 🟢 Real |
| Attributes `nbf` / `exp` | Stored and returned; retrieval stays permissive — exactly real Key Vault's behaviour (expired secrets still read; consuming code decides) | 🟢 Real |
| Backup / restore | An **opaque sealed blob** (AEAD under an emulator-held key), restorable only by the same emulator instance — the honest analog of the same-subscription/geography rule | 🟢 Real |

## Keys (`keys/`)

| Key Vault feature | Emulator | Type |
|---|---|---|
| Create key — **RSA** 2048/3072/4096, **EC** P-256/P-384/P-521 | Real `crypto/rsa` + `crypto/ecdsa` keygen | 🟢 Real |
| Sign / verify — RS256/384/512, PS256/384/512, ES256/384/512 | Real PKCS#1v15 / PSS / ECDSA; ES\* uses Azure's raw `r‖s` encoding | 🟢 Real |
| Encrypt / decrypt — RSA1_5, RSA-OAEP, RSA-OAEP-256 | Real RSA | 🟢 Real |
| Wrap / unwrap key | Real — the same RSA path as encrypt/decrypt | 🟢 Real |
| Import key (JWK) | Real: RSA `n/e/d/p/q` precomputed + validated; EC `crv/x/y/d` checked on-curve | 🟢 Real |
| Get random bytes | Real `crypto/rand`, 1–128 enforced | 🟢 Real |
| Public JWK exposure (private material never leaves) | Full — private PKCS#8 stays in the store | 🟢 Real |
| `RSA-HSM` / `EC-HSM` key types | **Refused** (`400`) as a Standard-tier vault refuses them — HSM-backed keys need Premium, whose guarantee is hardware. Accepting one and returning software material would tell a caller their keys are HSM-backed when they are not; same boundary as `oct` below | 🟢 Real |
| Secure Key Release (`/release`) | `exportable` is **enforced** (a non-exportable key refuses release, as real KV) and `release_policy` is stored and returned; the JWS is genuinely signed — but **no attestation** (there is no enclave to attest) | 🟡 Emulated |
| Key rotation **policy** (get/set) | Stored, round-tripped, and **acting**: a `Rotate` trigger's `timeAfterCreate` rotates lazily on the emulator clock; `expiryTime` drives the new version's `exp` | 🟢 Real |
| `nbf` / `exp` enforced for cryptographic use | Crypto with an expired or not-yet-valid key returns `403`, as real Key Vault refuses; reads stay permissive | 🟢 Real |
| Rotate key (`POST /keys/{name}/rotate`) | Real: a new version with fresh material of the same type and size; `key_ops` and tags carry over | 🟢 Real |
| `key_ops` enforcement | Enforced — an operation outside the key's `key_ops` gets `403 Forbidden`, and the JWK's `key_ops` drives SDK-local refusal too | 🟢 Real |
| `oct` / `oct-HSM` symmetric keys (and their AES algorithms) | Refused with the real error — vaults hold RSA/EC only; symmetric keys require **Managed HSM**, which is out of scope below | 🟢 Real |
| **BYOK** (KEK-wrapped import) | Real: the `.byok` transfer blob's `CKM_RSA_AES_KEY_WRAP` is genuinely undone — RSA-OAEP(SHA-1) to the vault-held KEK, then AES-KWP (RFC 5649) — and possession is proven by signature. The KEK is software-held, per the HSM normalisation above | 🟢 Real |
| Key backup / restore | An opaque sealed blob (AEAD, emulator-held key) — private material never rides in a readable blob | 🟢 Real |

## Certificates (`certificates/`)

| Key Vault feature | Emulator | Type |
|---|---|---|
| Create self-signed certificate | Real `x509.CreateCertificate` — random 128-bit serial, KeyUsage/ExtKeyUsage/BasicConstraints, SAN DNS names | 🟢 Real |
| Certificate policy (`key_props`, `x509_props`, `issuer`) | Honoured — key type/size/curve, subject, SANs, validity months | 🟢 Real |
| Import — PKCS#12 (PFX) and PEM (PKCS#8 / PKCS#1 / SEC1) | Real parsing; cert-only PEM supported | 🟢 Real |
| Linked key + secret materialised under the same name | Full on create, as real Key Vault | 🟢 Real |
| Certificate signing request (PKCS#10) for a named issuer | Real CSR; the operation reports `inProgress` with the CSR bytes | 🟢 Real |
| Merge a signed chain | Real — and the leaf's public key is **verified to match the pending key** before merge (400 otherwise) | 🟢 Real |
| **Issuance by a real CA** | The emulator generates the key and a real CSR and merges the chain **your** CA signs — real X.509 only when you attach that CA | 🟠 BYO-engine |
| Delete cascade to the linked key/secret | Deletion, recovery and purge carry the linked key and secret, as the three-views-of-one-object model requires | 🟢 Real |
| Issuers / contacts | The issuer registry **drives issuance**: a named issuer must be registered before it can issue (`Unknown` = external-CSR escape hatch), as real KV requires; contacts round-trip. Live CA integration is the BYO-engine row above | 🟢 Real |
| Certificate backup / restore | An opaque sealed blob (AEAD, emulator-held key) | 🟢 Real |
| Cancel / delete a certificate operation | Cancel marks an in-progress operation `cancelled` (merge is then refused); delete removes the operation until the next create restores it | 🟢 Real |
| Create operation LRO shape (`inProgress` on create → `completed` on poll) | As real Key Vault reports it — the shape the SDK pollers depend on | 🟢 Real |

## Soft-delete & recovery

| Key Vault feature | Emulator | Type |
|---|---|---|
| Soft-delete → list-deleted → recover → purge (secrets, keys, certificates) | Real enforced state machine, retention validated 7–90 days — every transition and refusal is genuine logic, nothing pretended | 🟢 Real |
| Retention window expiry | Genuinely clock-driven: an object past `purgeAt` purges lazily on observation — indistinguishable from a background job to any caller, and deterministic on the controllable clock. The window itself comes from the ARM vault resource when ARM governs | 🟢 Real |
| Name reuse while soft-deleted → `409 Conflict` | Enforced | 🟢 Real |
| Purge protection / non-purgeable `recoveryLevel` | Purge returns `403 Forbidden` and `recoveryLevel` reports `Recoverable`. When ARM governs, the setting comes from the **vault resource** (`az keyvault update --enable-purge-protection`), as in Azure; standalone it is `-purge-protection` | 🟢 Real |

## Vault addressing, TLS & the object model

| Key Vault feature | Emulator | Type |
|---|---|---|
| Host-routed vaults (`{name}.vault.azure.net`) | Full — host selects the vault; anything else falls back to the default vault. `ci:host-routed` reaches the vault at `https://contoso.vault.azure.net` with **`verify_challenge_resource` left ON**, which the localhost suites have to disable: the SDK refuses to send a token unless the host matches the `https://vault.azure.net` challenge. | 🟢 Real |
| Canonical object IDs (`https://{vault}.vault.azure.net/...`) | Always rendered canonically regardless of the listen address | 🟢 Real |
| TLS with a cert covering `*.vault.azure.net` | Real self-signed material, persisted so fingerprints are stable. `ci:host-routed` verifies the chain rather than skipping it (`connection_verify` points at the vault's own `cert.pem`), so the wildcard SAN is load-bearing: removing it fails the suite with `certificate is not valid for 'contoso.vault.azure.net'`. | 🟢 Real |
| Paging (`maxresults`, `nextLink`) | Full, capped at 25 | 🟢 Real |
| Key Vault error envelope + `x-ms-request-id` | On every response | 🟢 Real |
| `api-version` validation | Required and validated: the 7.x line and the date-based versions current SDKs send (e.g. `2025-07-01`) are accepted; anything else gets the real `400` envelope. Behaviour is not version-differentiated | 🟢 Real |

## Authorization

| Key Vault feature | Emulator | Type |
|---|---|---|
| Data-plane authorization | **ARM governs by default**: assignments and access policies decide, and no assignment means no access, as in Azure. Opted out (`KV_ARM_URL=`), a per-principal allowlist stands in (`POST /_emulator/permissions`, ops `{type}/{op}`, optional `:{object}` scope, `*` wildcard) and an empty one permits everything — a posture Azure has no equivalent of, which is why it is no longer the default | 🟢 Real |
| RBAC data-plane roles (Key Vault Secrets User, …) | Real, and wired in by default: `az role assignment create` writes the assignment over **ARM's real wire** and this data plane enforces it, no-assignment-means-no-access included. Standalone, the same roles assign over `POST /_emulator/rbac` with object-level scopes | 🟢 Real |
| Access policies (the classic vault access-policy document) | Real via ARM the same way (`az keyvault set-policy`), including a vault's `enableRbacAuthorization` making them ignored. Standalone, the real document shape is accepted at `POST /_emulator/access-policy` | 🟢 Real |
| Role/policy **assignment** with ARM opted out | The `/_emulator` control surface stands in — real documents and enforcement, but not ARM's wire. Reachable only by setting `KV_ARM_URL=` | 🟡 Emulated |

## Emulator-only (no Key Vault equivalent — these exist for testing)

| Feature | Purpose |
|---|---|
| Clock control (`/_emulator/clock`) | Freeze/advance/offset — makes token expiry and soft-delete retention deterministic |
| Fault injection (`/_emulator/faults`) | Force `429` + `Retry-After` or `500` for the next N requests, to exercise SDK retry paths |
| Permissions (`/_emulator/permissions`) | The authorization allowlist above |
| Read-only portal (`/_emulator/portal/`) | Inspect vault state in a browser |

## Ecosystem conformance: real clients as witnesses

| Real client (pinned) | Surface exercised | Status |
|---|---|---|
| `azsecrets` (Azure Go SDK) | Secrets, versions, soft-delete | 🟢 CI `test` |
| `azkeys` (Azure Go SDK) | Keys, sign/verify, encrypt/decrypt, wrap/unwrap | 🟢 CI `test` |
| `azcertificates` (Azure Go SDK) | Certificate create/import/merge | 🟢 CI `test` |
| `azidentity` (`ClientSecretCredential`) | The Entra challenge handshake, against an in-process real **entra-emulator** | 🟢 CI `test` |
| Three-emulator chain (vault secret → managed identity → Entra → Fabric) | The family integration, incl. a negative test | 🟢 CI `chain` (stdlib HTTP, not an SDK) |
| `azure-keyvault-secrets`/`-keys`/`-certificates` + `azure-identity` (**Python**) | Challenge auth; secret lifecycle incl. soft-delete → recover → purge; RSA crypto via `CryptographyClient` with a tamper negative; on-demand rotation; a `key_ops` refusal; self-signed certificate LRO | 🟢 CI `python-sdk` (3 OSes) |
| `@azure/keyvault-secrets`/`-keys`/`-certificates` + `@azure/identity` (**JavaScript**) | Same surface as the Python suite | 🟢 CI `js-sdk` (3 OSes) |
| `Azure.Security.KeyVault.{Secrets,Keys,Certificates}` + `Azure.Identity` (**.NET**) | Same surface as the Python suite | 🟢 CI `dotnet-sdk` (3 OSes) |

The Go SDK tests are the real oracle: they reconstruct an `*rsa.PublicKey` from
the returned JWK and verify an SDK-produced signature **outside** the SDK, with a
tampered-signature negative alongside.

## Scope boundary: the vault, not the infrastructure around it

| Azure feature | Why out of scope | Type |
|---|---|---|
| **ARM control plane** (create/delete vaults, `Microsoft.KeyVault/vaults`) | A different plane: subscriptions, resource groups, deployments. The emulator serves the **data plane** a vault client talks to | 🔴 |
| **Managed HSM** (`managedhsm.azure.net`) | A distinct service and a hardware trust boundary — a localhost process cannot honestly emulate an HSM's guarantees | 🔴 |
| **Private endpoints / firewall / network ACLs** | Network topology, not vault behaviour | 🔴 |
| **Customer-managed-key encryption of the vault itself** | Infrastructure-level | 🔴 |
| **Real CA issuance** (DigiCert / GlobalSign integrations) | Needs a real CA — hence the BYO-engine CSR/merge path above | 🔴 |
| **Diagnostic logs / Event Grid notifications / metrics** | Azure Monitor surface | 🔴 |
