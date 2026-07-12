# 08 — Certificates

Self-signed issuance and PFX/PEM import, producing genuine X.509. Real CA
integration (DigiCert, etc.) is a **non-goal** — only the `Self` issuer is
supported. Same versioning + soft-delete skeleton as
[secrets](06-secrets.md)/[keys](07-keys.md).

## Endpoints

| Method + path | Purpose |
|---|---|
| `POST /certificates/{name}/create` | issue self-signed from a policy → certificate operation |
| `POST /certificates/{name}/import` | import a base64 PKCS#12 (PFX) or PEM bundle |
| `GET /certificates/{name}/pending` | the certificate operation (poll) |
| `GET /certificates/{name}` \| `/certificates/{name}/{version}` | get the certificate bundle |
| `GET /certificates/{name}/policy` | the certificate policy |
| `GET /certificates` \| `/certificates/{name}/versions` | list (paged) |
| `DELETE /certificates/{name}` | soft-delete |
| `GET/DELETE /deletedcertificates/{name}`, `GET /deletedcertificates`, `POST /deletedcertificates/{name}/recover` | deleted-certificate lifecycle |

## Issuance

`create` reads the policy's `key_props` (RSA/EC, size/curve), `x509_props`
(subject, subject-alternative DNS names, validity months), and `issuer`. Since
self-signed issuance is synchronous, the returned operation reports
`status: completed` immediately — the SDK polls `/pending` once and proceeds to
`GET`. A non-`Self` issuer is rejected (`IssuerNotSupported`).

The **CER is a real, parseable X.509**: the CI e2e creates a cert via the SDK
and parses `got.CER` with `x509.ParseCertificate`, asserting the requested
subject CN and SAN.

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
