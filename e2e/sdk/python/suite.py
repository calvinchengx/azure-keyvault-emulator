"""Real Microsoft Python SDK (azure-keyvault-*) against the emulator pair.

ClientSecretCredential walks the challenge handshake against a real
entra-emulator; then SecretClient / KeyClient / CryptographyClient /
CertificateClient exercise the data plane. Env: KV_URL, AZURE_TENANT_ID,
AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, ENTRA_AUTHORITY_HOST.

Self-signed emulator TLS: connection_verify=False (harness only). The vault
URL is localhost, not *.vault.azure.net, so verify_challenge_resource=False —
the same switch real SDK users flip for any non-public vault domain.
"""

import os
import sys

from azure.identity import ClientSecretCredential
from azure.keyvault.certificates import CertificateClient, CertificatePolicy
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import (CryptographyClient,
                                        EncryptionAlgorithm,
                                        SignatureAlgorithm)
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError

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

    if failures:
        sys.exit(f"{failures} check(s) failed")
    print("python suite: all checks passed")


if __name__ == "__main__":
    main()
