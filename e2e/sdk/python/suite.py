"""Real Microsoft Python SDK (azure-keyvault-*) against the emulator pair.

ClientSecretCredential walks the challenge handshake against a real
entra-emulator; then SecretClient / KeyClient / CryptographyClient /
CertificateClient exercise the data plane. Env: KV_URL, AZURE_TENANT_ID,
AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, ENTRA_AUTHORITY_HOST.

Self-signed emulator TLS: connection_verify=False (harness only). The vault
URL is localhost, not *.vault.azure.net, so verify_challenge_resource=False —
the same switch real SDK users flip for any non-public vault domain.
"""

import datetime
import os
import sys

from azure.identity import ClientSecretCredential
from azure.keyvault.certificates import CertificateClient, CertificatePolicy
from azure.keyvault.keys import KeyClient, KeyRotationPolicy
from azure.keyvault.keys.crypto import (CryptographyClient,
                                        EncryptionAlgorithm,
                                        SignatureAlgorithm)
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

KV_URL = os.environ["KV_URL"]

failures = 0


def check(name, cond, extra=""):
    global failures
    if cond:
        print(f"  ok  {name}")
    else:
        print(f"  FAIL {name} {extra}")
        failures += 1


def main():
    cred = ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
        authority=os.environ["ENTRA_AUTHORITY_HOST"],
        disable_instance_discovery=True,
        connection_verify=False,
    )
    kw = {"verify_challenge_resource": False, "connection_verify": False}

    # --- Secrets: set → versions → soft delete → recover → purge ---
    print("SecretClient")
    sc = SecretClient(KV_URL, cred, **kw)
    sc.set_secret("py-e2e", "v1")
    latest = sc.set_secret("py-e2e", "v2")
    check("set/get latest", sc.get_secret("py-e2e").value == "v2")
    versions = list(sc.list_properties_of_secret_versions("py-e2e"))
    check("two versions listed", len(versions) == 2, f"got {len(versions)}")
    check("get by version", sc.get_secret("py-e2e", latest.properties.version).value == "v2")

    sc.begin_delete_secret("py-e2e").wait()
    check("deleted secret visible", sc.get_deleted_secret("py-e2e").name == "py-e2e")
    sc.begin_recover_deleted_secret("py-e2e").wait()
    check("recovered", sc.get_secret("py-e2e").value == "v2")
    sc.begin_delete_secret("py-e2e").wait()
    sc.purge_deleted_secret("py-e2e")
    try:
        sc.get_deleted_secret("py-e2e")
        check("purged is gone", False)
    except ResourceNotFoundError:
        check("purged is gone", True)

    # --- Secret attributes: enabled, nbf/exp ---------------------------------
    # Real Key Vault refuses a GET on a disabled secret, and on one whose nbf
    # has not arrived, with 403 — not 404. The distinction matters to callers.
    sc.set_secret("py-e2e-attrs", "v1", enabled=False)
    try:
        sc.get_secret("py-e2e-attrs")
        check("disabled secret refused", False)
    except HttpResponseError as e:
        check("disabled secret refused", e.status_code == 403, f"got {e.status_code}")

    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    sc.set_secret("py-e2e-nbf", "v1", not_before=future)
    try:
        sc.get_secret("py-e2e-nbf")
        check("not-yet-valid secret refused", False)
    except HttpResponseError as e:
        check("not-yet-valid secret refused", e.status_code == 403, f"got {e.status_code}")

    # --- Canonical object ids, error envelope, paging ------------------------
    ident = sc.set_secret("py-e2e-id", "v1")
    check("canonical object id",
          ident.id.startswith("https://") and "/secrets/py-e2e-id/" in ident.id,
          ident.id)

    try:
        sc.get_secret("py-e2e-does-not-exist")
        check("error envelope + request id", False)
    except ResourceNotFoundError as e:
        hdr = (e.response.headers or {})
        rid = hdr.get("x-ms-request-id") or hdr.get("x-ms-keyvault-request-id")
        check("error envelope + request id",
              e.status_code == 404 and bool(rid) and "SecretNotFound" in str(e),
              f"rid={rid}")

    for i in range(7):
        sc.set_secret(f"py-e2e-page-{i}", "v")
    pages = list(sc.list_properties_of_secrets(max_page_size=3).by_page())
    total = sum(len(list(pg)) for pg in pages)
    check("paging via maxresults/nextLink", len(pages) >= 3 and total >= 7,
          f"{len(pages)} pages, {total} items")

    # --- Soft-delete semantics ----------------------------------------------
    sc.set_secret("py-e2e-reuse", "v1")
    sc.begin_delete_secret("py-e2e-reuse").wait()
    try:
        sc.set_secret("py-e2e-reuse", "v2")
        check("name reuse while soft-deleted conflicts", False)
    except HttpResponseError as e:
        check("name reuse while soft-deleted conflicts", e.status_code == 409,
              f"got {e.status_code}")
    lvl = sc.get_deleted_secret("py-e2e-reuse").properties.recovery_level or ""
    check("recoveryLevel reported", "Recoverable" in lvl, lvl)

    # --- Keys: real RSA crypto through CryptographyClient ---
    print("KeyClient + CryptographyClient")
    kc = KeyClient(KV_URL, cred, **kw)
    key = kc.create_rsa_key("py-e2e-rsa", size=2048)
    check("rsa key created", key.key_type == "RSA")
    # key.id carries the canonical https://{vault}.vault.azure.net host (as
    # real Key Vault would); CryptographyClient dials the id's host, so hand
    # it the same key via the emulator's localhost address instead.
    cc = CryptographyClient(f"{KV_URL}/keys/{key.name}/{key.properties.version}",
                            cred, **kw)

    plain = b"the py sdk is the oracle"
    enc = cc.encrypt(EncryptionAlgorithm.rsa_oaep, plain)
    dec = cc.decrypt(EncryptionAlgorithm.rsa_oaep, enc.ciphertext)
    check("encrypt/decrypt round-trip", dec.plaintext == plain)

    import hashlib
    digest = hashlib.sha256(b"sign me").digest()
    sig = cc.sign(SignatureAlgorithm.rs256, digest)
    check("sign/verify", cc.verify(SignatureAlgorithm.rs256, digest, sig.signature).is_valid)
    tampered = hashlib.sha256(b"tampered").digest()
    check("tampered digest rejected",
          not cc.verify(SignatureAlgorithm.rs256, tampered, sig.signature).is_valid)

    rotated = kc.rotate_key("py-e2e-rsa")
    check("rotate mints a new version",
          rotated.properties.version != key.properties.version and rotated.key_type == "RSA")

    restricted = kc.create_rsa_key("py-e2e-signonly", size=2048,
                                   key_operations=["sign", "verify"])
    rcc = CryptographyClient(
        f"{KV_URL}/keys/{restricted.name}/{restricted.properties.version}", cred, **kw)
    try:
        rcc.encrypt(EncryptionAlgorithm.rsa_oaep, b"nope")
        check("key_ops enforced", False)
    except HttpResponseError as e:
        check("key_ops enforced", e.status_code == 403, f"got {e.status_code}")

    past = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    stale = kc.create_rsa_key("py-e2e-expired", size=2048, expires_on=past)
    ecc = CryptographyClient(
        f"{KV_URL}/keys/{stale.name}/{stale.properties.version}", cred, **kw)
    try:
        ecc.sign(SignatureAlgorithm.rs256, digest)
        check("expired key refused for crypto", False)
    except HttpResponseError as e:
        check("expired key refused for crypto", e.status_code == 403, f"got {e.status_code}")

    # --- Key backup/restore, rotation policy, oct rejection ------------------
    blob = kc.backup_key("py-e2e-rsa")
    check("key backup returns an opaque blob", isinstance(blob, bytes) and len(blob) > 0)
    kc.begin_delete_key("py-e2e-rsa").wait()
    kc.purge_deleted_key("py-e2e-rsa")
    restored = kc.restore_key_backup(blob)
    check("key restored from backup", restored.name == "py-e2e-rsa")

    from azure.keyvault.keys import KeyRotationLifetimeAction, KeyRotationPolicyAction
    policy = kc.update_key_rotation_policy(
        "py-e2e-rsa",
        KeyRotationPolicy(
            lifetime_actions=[KeyRotationLifetimeAction(
                KeyRotationPolicyAction.rotate, time_after_create="P30D")],
            expires_in="P90D"))
    check("rotation policy set", policy.expires_in == "P90D", str(policy.expires_in))
    check("rotation policy read back",
          kc.get_key_rotation_policy("py-e2e-rsa").expires_in == "P90D")

    # HSM-backed key types need Premium; a Standard vault refuses them rather
    # than quietly handing back a software key.
    for hsm_kty in ("RSA-HSM", "EC-HSM"):
        try:
            kc.create_key(f"py-e2e-{hsm_kty.lower()}", hsm_kty)
            check(f"{hsm_kty} refused (Standard tier)", False)
        except HttpResponseError as e:
            check(f"{hsm_kty} refused (Standard tier)",
                  e.status_code == 400, f"got {e.status_code}")

    # oct keys are a Managed HSM feature; a vault refuses them, and so do we.
    try:
        kc.create_key("py-e2e-oct", "oct")
        check("oct key refused (Managed HSM boundary)", False)
    except HttpResponseError as e:
        check("oct key refused (Managed HSM boundary)",
              e.status_code in (400, 403), f"got {e.status_code}")

    # --- Certificates: self-signed issuance via the LRO poller ---
    print("CertificateClient")
    cert_client = CertificateClient(KV_URL, cred, **kw)
    poller = cert_client.begin_create_certificate(
        "py-e2e-cert",
        CertificatePolicy(issuer_name="Self", subject="CN=py-e2e",
                          validity_in_months=12))
    cert = poller.result()
    check("self-signed cert issued", cert.name == "py-e2e-cert" and bool(cert.cer))
    check("linked key materialised",
          kc.get_key("py-e2e-cert").key_type in ("RSA", "EC"))

    # --- Certificate operation: CSR from a named issuer, then cancel/delete --
    # A non-"Self" issuer starts a genuinely asynchronous operation: the vault
    # generates the key and a PKCS#10 CSR and waits for the external signer.
    # That is the state real Key Vault leaves cancellable, and it is what makes
    # the CSR observable.
    cert_client.create_issuer("py-e2e-ca", provider="Test")
    cert_client.begin_create_certificate(
        "py-e2e-pending",
        CertificatePolicy(issuer_name="py-e2e-ca", subject="CN=py-e2e-pending",
                          validity_in_months=12),
        _polling_interval=1)
    op = cert_client.get_certificate_operation("py-e2e-pending")
    check("named issuer yields a PKCS#10 CSR",
          bool(op.csr) and op.issuer_name == "py-e2e-ca",
          f"csr={bool(op.csr)} issuer={op.issuer_name}")

    cert_client.cancel_certificate_operation("py-e2e-pending")
    check("certificate operation cancelled",
          cert_client.get_certificate_operation("py-e2e-pending").cancellation_requested)
    cert_client.delete_certificate_operation("py-e2e-pending")
    try:
        cert_client.get_certificate_operation("py-e2e-pending")
        check("certificate operation deleted", False)
    except (ResourceNotFoundError, HttpResponseError):
        check("certificate operation deleted", True)

    # --- Certificate backup, and delete cascading to key + secret -----------
    cblob = cert_client.backup_certificate("py-e2e-cert")
    check("certificate backup returns a blob", isinstance(cblob, bytes) and len(cblob) > 0)

    cert_client.begin_delete_certificate("py-e2e-cert").wait()
    try:
        kc.get_key("py-e2e-cert")
        check("delete cascades to the linked key", False)
    except ResourceNotFoundError:
        check("delete cascades to the linked key", True)
    try:
        sc.get_secret("py-e2e-cert")
        check("delete cascades to the linked secret", False)
    except (ResourceNotFoundError, HttpResponseError):
        check("delete cascades to the linked secret", True)

    if failures:
        sys.exit(f"{failures} check(s) failed")
    print("python suite: all checks passed")


if __name__ == "__main__":
    main()
