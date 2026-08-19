"""Runs INSIDE the client container. Microsoft's own SDK, the vault's real name.

What this suite exists to prove is not that the SDK works -- e2e/sdk already
shows that -- but that it works with the two checks the other suites have to
turn off:

  connection_verify        pointed at the vault's own cert instead of False, so
                           TLS is actually verified, and the cert has to cover
                           `*.vault.azure.net` for the handshake to succeed.
  verify_challenge_resource left ON, which the localhost suites cannot do: the
                           WWW-Authenticate challenge names
                           https://vault.azure.net, and the SDK refuses to send
                           a token to a host that does not match it.

Together those two are the external witness for host-routed vaults and for the
TLS cert, because neither can pass unless the vault really answers to
`contoso.vault.azure.net` and really presents a cert covering that name.

The credential's own hop to entra stays unverified (`connection_verify=False`
on ClientSecretCredential). That is entra's self-signed cert, a different
repo's claim; verifying it here would make this suite fail for a reason that
has nothing to do with Key Vault.
"""

from __future__ import annotations

import sys

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

TENANT = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
SP_CLIENT = "00d88624-f0d7-46f6-a641-6232c2608928"
SP_SECRET = "daemon-app-secret"

VAULT = "https://contoso.vault.azure.net"
KV_CERT = "/kvdata/tls/cert.pem"

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"   {'ok  ' if ok else 'FAIL'}  {label}{'' if ok else ': ' + detail}")
    if not ok:
        failures.append(label)


def credential(authority_host: str) -> ClientSecretCredential:
    return ClientSecretCredential(
        tenant_id=TENANT,
        client_id=SP_CLIENT,
        client_secret=SP_SECRET,
        authority=authority_host,
        # entra's cert, not the vault's. See the module docstring.
        connection_verify=False,
        # The authority is not one of Azure's public clouds, so MSAL's
        # instance-discovery lookup cannot validate it. Every SDK suite here
        # sets this; it is about entra's identity, not the vault's, and the two
        # checks this suite exists to keep on are on the SecretClient below.
        disable_instance_discovery=True,
        additionally_allowed_tenants=["*"],
    )


def client(cred: ClientSecretCredential) -> SecretClient:
    return SecretClient(
        vault_url=VAULT,
        credential=cred,
        # BOTH left on. This is the whole point of the suite.
        connection_verify=KV_CERT,
        verify_challenge_resource=True,
    )


def main() -> int:
    # 1 + 2. A trusted issuer, over verified TLS, at the vault's real name.
    c = client(credential("https://entra-a:8443"))
    c.set_secret("host-routed", "from-entra-a")
    got = c.get_secret("host-routed")
    check("entra-a token accepted at contoso.vault.azure.net", got.value == "from-entra-a",
          f"read back {got.value!r}")
    # The id the vault hands back is its own canonical URL, so a vault that
    # answered on the alias but described itself as localhost is caught here.
    check("secret id carries the vault's real host", ".vault.azure.net" in (got.id or ""),
          f"id={got.id!r}")

    # 3. The SECOND trusted issuer. A different entra, different signing keys.
    c2 = client(credential("https://entra-b:8443"))
    got2 = c2.get_secret("host-routed")
    check("entra-b token accepted on the same vault", got2.value == "from-entra-a",
          f"read back {got2.value!r}")

    # 4. The issuer that was never trusted. Well-formed, correctly signed,
    #    wrong origin -- so a pass here would mean the issuer list is decorative.
    try:
        client(credential("https://entra-untrusted:8443")).get_secret("host-routed")
        check("untrusted issuer refused", False, "the vault accepted a token from an unlisted issuer")
    except (ClientAuthenticationError, HttpResponseError) as exc:
        status = getattr(exc, "status_code", None)
        check(f"untrusted issuer refused ({status or type(exc).__name__})", True)

    # 5. A REAL token from a TRUSTED issuer, minted for the wrong resource.
    #    Everything about it is valid except who it is for, which isolates the
    #    audience check from the issuer check above.
    class WrongAudience:
        def __init__(self, inner):
            self._inner = inner

        def get_token(self, *_scopes, **kwargs):
            return self._inner.get_token("https://management.azure.com/.default", **kwargs)

    try:
        SecretClient(
            vault_url=VAULT,
            credential=WrongAudience(credential("https://entra-a:8443")),
            connection_verify=KV_CERT,
            verify_challenge_resource=True,
        ).get_secret("host-routed")
        check("ARM-audience token refused", False,
              "the vault accepted a token minted for https://management.azure.com")
    except (ClientAuthenticationError, HttpResponseError) as exc:
        status = getattr(exc, "status_code", None)
        check(f"ARM-audience token refused ({status or type(exc).__name__})", True)

    if failures:
        print(f"\nFAILED: {', '.join(failures)}")
        return 1
    print("\nMicrosoft's SDK reached the vault by its real name over verified TLS, "
          "with challenge-resource verification ON; two issuers accepted, a third refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
