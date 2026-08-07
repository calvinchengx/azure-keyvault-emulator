# 08 — Certificates

Self-signed issuance, PFX/PEM import, and the **external-issuer CSR/merge
flow** — all producing genuine X.509. A live third-party CA is still a non-goal
(the emulator never phones out), but a named issuer produces a real CSR you can
sign yourself and merge back, so the SDK's async-issuance path works end to
end. Same versioning + soft-delete skeleton as
[secrets](06-secrets.md)/[keys](07-keys.md).

## Endpoints

| Method + path | Purpose |
|---|---|
| `POST /certificates/{name}/create` | `Self` issuer → self-signed cert; a named issuer → pending operation with a CSR. A named issuer must be **registered** under `/certificates/issuers` first (`Unknown` = external-CSR escape hatch), as real KV requires |
| `POST /certificates/{name}/import` | import a base64 PKCS#12 (PFX) or PEM bundle |
| `POST /certificates/{name}/pending/merge` | complete a pending operation with the signed chain (`{x5c}`) |
| `GET /certificates/{name}/pending` | the certificate operation (poll) — `inProgress`+CSR, `cancelled`, or `completed` |
| `PATCH /certificates/{name}/pending` | cancel an in-progress operation (`{"cancellation_requested": true}`); cancelled operations refuse merge |
| `DELETE /certificates/{name}/pending` | delete the operation — it reads absent until the next create restores it |
| `GET /certificates/{name}` \| `/certificates/{name}/{version}` | get the certificate bundle |
| `PATCH /certificates/{name}` \| `/certificates/{name}/{version}` | update attributes/tags (and policy if supplied) |
| `GET` \| `PATCH /certificates/{name}/policy` | get / update the certificate policy |
| `GET /certificates` \| `/certificates/{name}/versions` | list (paged) |
| `DELETE /certificates/{name}` | soft-delete — **cascades** to the linked key and secret (recover and purge carry them too) |
| `POST /certificates/{name}/backup` · `POST /certificates/restore` | opaque backup blob → restore into an empty name |
| `GET/DELETE /deletedcertificates/{name}`, `GET /deletedcertificates`, `POST /deletedcertificates/{name}/recover` | deleted-certificate lifecycle |

### Issuers and contacts (vault-scoped)

| Method + path | Purpose |
|---|---|
| `GET /certificates/issuers` | list issuers (paged) |
| `GET` \| `PUT` \| `PATCH` \| `DELETE /certificates/issuers/{name}` | manage a named issuer (opaque document round-tripped) |
| `GET` \| `PUT` \| `DELETE /certificates/contacts` | manage the vault's contact list |

These are administrative side objects the SDK manages alongside certificates;
the emulator round-trips the SDK's own document shape. They do **not** drive
issuance — only the `Self` issuer produces certificates (see below).

## Issuance

`create` reads the policy's `key_props` (RSA/EC, size/curve), `x509_props`
(subject, subject-alternative DNS names, validity months), and `issuer`.

- **`Self` (or unset) issuer → self-signed.** Issuance is synchronous
  internally, but the create response reports `status: inProgress` — as real
  Key Vault does — and the `/pending` poll reports `completed`. (The Python
  SDK's poller depends on that two-step; an already-completed create response
  makes it resolve to nothing.)
- **A named issuer → asynchronous (pending) operation.** The emulator
  generates the key and a real PKCS#10 **CSR**, and the operation reports
  `status: inProgress` with the `csr`. You sign that CSR with your own CA and
  return the chain via **merge** (below) — the classic external-issuance flow,
  fully offline. The emulator never contacts a real CA.

The **CER is a real, parseable X.509**: the CI e2e creates a cert via the SDK
and parses `got.CER` with `x509.ParseCertificate`, asserting the requested
subject CN and SAN.

## Merge (completing an external issuance)

`POST /certificates/{name}/pending/merge` takes the signed chain (`x5c`, a list
of DER certs, leaf first) and completes the pending operation. The emulator
**verifies the leaf's public key matches the pending key** (mismatch → 400),
binds the stored private key to the signed certificate, and materializes the
linked key/secret. The CI e2e drives the full loop against the real
`azcertificates` SDK: `CreateCertificate` with a named issuer → read the CSR
off the operation → sign it with a throwaway CA → `MergeCertificate` → `GetCertificate`.

## Import

`import` accepts, in the base64 `value` field:

- a **PKCS#12 / PFX** blob (with optional password), or
- a **PEM** bundle — a `CERTIFICATE` block plus a `PRIVATE KEY` (PKCS#8),
  `RSA PRIVATE KEY` (PKCS#1), or `EC PRIVATE KEY` block.

A certificate-only PEM (no key) imports too.

## Linked key and secret

Creating or importing a certificate **materializes** the linked key and secret
under the same name, exactly as real Key Vault does:

- `GET /keys/{name}` → the certificate's public key.
- `GET /secrets/{name}` → the PFX-equivalent bundle (private key + cert),
  base64, `contentType: application/x-pkcs12`.

So `GetCertificate`, `GetKey`, and `GetSecret` on the same name all resolve.

## SDK example (Go)

```go
cc, _ := azcertificates.NewClient(vaultURL, cred, opts)
op, _ := cc.CreateCertificate(ctx, "web", azcertificates.CreateCertificateParameters{
    CertificatePolicy: &azcertificates.CertificatePolicy{
        IssuerParameters: &azcertificates.IssuerParameters{Name: to.Ptr("Self")},
        X509CertificateProperties: &azcertificates.X509CertificateProperties{
            Subject: to.Ptr("CN=emulator.example.com"),
        },
    },
}, nil)   // op.Status == "completed"

got, _ := cc.GetCertificate(ctx, "web", "", nil)
cert, _ := x509.ParseCertificate(got.CER)   // a real X.509
```

Verified end to end against the real `azcertificates` SDK in CI (self-signed +
PKCS#12 + PEM import).
