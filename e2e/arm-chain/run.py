#!/usr/bin/env python3
"""Authorization written over ARM's real wire, enforced by the data plane.

    1. entra-emulator mints an ARM-audience token.
    2. arm-emulator creates a resource group and a Microsoft.KeyVault/vaults
       resource — real ARM calls, real resource ids.
    3. With no role assignment, the vault refuses the service principal's
       data-plane call (403).
    4. A Key Vault Secrets User role assignment is created over ARM.
    5. The same call now succeeds — the vault picked the grant up from ARM.
    6. Deleting the assignment takes the access away again.
    7. An access policy (the classic, non-RBAC route) grants it once more.

Every hop is a real HTTP call between three separate processes on the
production trust relationships. Self-contained and stdlib-only.
"""

import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORK = Path(os.environ.get("TMPDIR", "/tmp")) / "kv-arm-chain-e2e"
ENTRA_PORT = int(os.environ.get("ENTRA_PORT", "18743"))
KV_PORT = int(os.environ.get("KV_PORT", "18744"))
ARM_PORT = int(os.environ.get("ARM_PORT", "18745"))
TENANT = "11111111-1111-1111-1111-111111111111"
SP_CLIENT = "cccccccc-0000-0000-0000-000000000002"
SP_SECRET = "daemon-app-secret"
# entra-emulator's seeded user and the group she belongs to. A ROPC token for
# Alice carries the groups claim once the app asks for it, which is how a
# group-scoped role assignment reaches a real caller.
ALICE_UPN = "alice@entraemulator.dev"
ALICE_PASSWORD = "Password1!"
ENG_GROUP = "bbbbbbbb-0000-0000-0000-000000000001"
# The daemon service principal's object id in entra-emulator's seed — the
# principal the vault sees in the token's oid claim.
ENTRA_VERSION = os.environ.get("ENTRA_VERSION", "v0.3.1")
# /metadata/endpoints and the vault provider need arm >= v0.1.1.
ARM_VERSION = os.environ.get("ARM_VERSION", "v0.1.1")

E = f"https://localhost:{ENTRA_PORT}"
KV = f"https://localhost:{KV_PORT}"
ARM = f"https://localhost:{ARM_PORT}"
ISSUER = f"{E}/{TENANT}/v2.0"
SUB = "00000000-0000-0000-0000-000000000001"
RG = "kv-rg"
VAULT = "emulator"
SCOPE = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.KeyVault/vaults/{VAULT}"
SECRETS_USER = "4633458b-17de-408a-b874-0445c86b69e6"
ROLE_ID = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{SECRETS_USER}"
ARM_API = "2022-04-01"
KV_API = "7.5"
EXE = ".exe" if os.name == "nt" else ""

TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE

procs: list[subprocess.Popen] = []


def http(method, url, headers=None, data=None):
    """Return (status, body_bytes); status 0 when unreachable (still booting)."""
    if isinstance(data, str):
        data = data.encode()
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, context=TLS, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, ConnectionError, OSError):
        return 0, b""


def token(scope):
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": SP_CLIENT,
        "client_secret": SP_SECRET, "scope": scope,
    })
    status, raw = http("POST", f"{E}/{TENANT}/oauth2/v2.0/token",
                       {"Content-Type": "application/x-www-form-urlencoded"}, body)
    if status != 200:
        sys.exit(f"FAIL: token for {scope} = {status} {raw[:200]}")
    return json.loads(raw)["access_token"]


def ropc_token(username, password, scope):
    """A user token via resource-owner password credentials."""
    body = urllib.parse.urlencode({
        "grant_type": "password", "client_id": SP_CLIENT, "client_secret": SP_SECRET,
        "username": username, "password": password, "scope": scope,
    })
    status, raw = http("POST", f"{E}/{TENANT}/oauth2/v2.0/token",
                       {"Content-Type": "application/x-www-form-urlencoded"}, body)
    if status != 200:
        sys.exit(f"FAIL: ROPC token for {username} = {status} {raw[:300]}")
    return json.loads(raw)["access_token"]


def claims_of(jwt):
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    import base64
    return json.loads(base64.urlsafe_b64decode(payload))


def groups_of(jwt):
    return claims_of(jwt).get("groups", [])


def principal_of(jwt):
    """The oid the vault will see — read from the token the SP just got."""
    claims = claims_of(jwt)
    return claims.get("oid") or claims.get("sub")


def bearer(tok):
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def go_install(bin_name, path):
    print(f"    go install {path}", file=sys.stderr)
    env = {**os.environ, "GOBIN": str(WORK), "GOTOOLCHAIN": "auto"}
    subprocess.run(["go", "install", path], check=True, env=env)
    return WORK / (bin_name + EXE)


def start(name, argv, env_extra=None):
    log = open(WORK / f"{name}.log", "w")
    p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                         env={**os.environ, **(env_extra or {})})
    procs.append(p)
    return p


def wait_healthy():
    deadline = time.time() + 30
    while time.time() < deadline:
        if all(http("GET", f"{b}/health")[0] == 200 for b in (E, KV, ARM)):
            return
        time.sleep(0.2)
    for n in ("entra", "arm", "kv"):
        log = WORK / f"{n}.log"
        if log.exists():
            print(f"---- {n}.log ----\n{log.read_text()}", file=sys.stderr)
    sys.exit("emulators did not become healthy in time")


def secret_read_status(tok):
    """The data-plane call whose authorization we are proving."""
    return http("GET", f"{KV}/secrets/probe?api-version={KV_API}", bearer(tok))[0]


def wait_for(predicate, what, timeout=15):
    """The vault polls ARM, so a grant takes effect within a poll interval."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.3)
    sys.exit(f"FAIL: timed out waiting for {what}")


def driver():
    print("-- 1. ARM-audience token from entra")
    arm_tok = token("https://management.azure.com/.default")
    kv_tok = token("https://vault.azure.net/.default")
    principal = principal_of(kv_tok)
    print(f"   service principal oid: {principal}")

    print("-- 2. create the resource group and the vault over ARM")
    status, raw = http("PUT", f"{ARM}/subscriptions/{SUB}/resourcegroups/{RG}?api-version={ARM_API}",
                       bearer(arm_tok), '{"location":"westeurope"}')
    if status != 201:
        sys.exit(f"FAIL: create resource group = {status} {raw[:300]}")
    status, raw = http("PUT", f"{ARM}{SCOPE}?api-version=2024-11-01", bearer(arm_tok),
                       json.dumps({"location": "westeurope",
                                   "properties": {"tenantId": TENANT, "accessPolicies": [],
                                                  "enableRbacAuthorization": True}}))
    if status != 200:
        sys.exit(f"FAIL: create vault = {status} {raw[:300]}")
    print(f"   vault resource created at {SCOPE}")

    print("-- 3. with no assignment, the data plane refuses the principal")
    # A secret the principal cannot read; 403 is authorization, 404 would be
    # the object simply not existing, so the distinction matters.
    wait_for(lambda: secret_read_status(kv_tok) == 403, "the vault to apply ARM's empty grant")
    print("   403 Forbidden, as an unassigned principal should get")

    print("-- 4. assign Key Vault Secrets User over ARM")
    assignment = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
    status, raw = http("PUT",
                       f"{ARM}{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{assignment}?api-version={ARM_API}",
                       bearer(arm_tok),
                       json.dumps({"properties": {"roleDefinitionId": ROLE_ID,
                                                  "principalId": principal,
                                                  "principalType": "ServicePrincipal"}}))
    if status != 201:
        sys.exit(f"FAIL: create role assignment = {status} {raw[:300]}")
    print("   assignment created over ARM's real wire")

    print("-- 5. the same data-plane call now passes authorization")
    # 404 (the secret does not exist) proves authorization passed; 403 would
    # mean it did not.
    wait_for(lambda: secret_read_status(kv_tok) == 404, "the ARM grant to reach the vault")
    print("   authorized: the vault picked the assignment up from ARM")

    print("-- 6. deleting the assignment takes the access away")
    status, _ = http("DELETE",
                     f"{ARM}{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{assignment}?api-version={ARM_API}",
                     bearer(arm_tok))
    if status != 200:
        sys.exit(f"FAIL: delete role assignment = {status}")
    wait_for(lambda: secret_read_status(kv_tok) == 403, "the revocation to reach the vault")
    print("   403 again — revocation propagates")

    print("-- 7. an access policy grants it again (the classic, non-RBAC route)")
    status, raw = http("PUT", f"{ARM}{SCOPE}?api-version=2024-11-01", bearer(arm_tok),
                       json.dumps({"location": "westeurope",
                                   "properties": {"tenantId": TENANT, "enableRbacAuthorization": False,
                                                  "accessPolicies": []}}))
    if status != 200:
        sys.exit(f"FAIL: switch the vault off RBAC = {status} {raw[:300]}")
    status, raw = http("PUT",
                       f"{ARM}{SCOPE}/accessPolicies/add?api-version=2024-11-01", bearer(arm_tok),
                       json.dumps({"properties": {"accessPolicies": [
                           {"tenantId": TENANT, "objectId": principal,
                            "permissions": {"secrets": ["get", "list"]}}]}}))
    if status != 200:
        sys.exit(f"FAIL: set access policy = {status} {raw[:300]}")
    wait_for(lambda: secret_read_status(kv_tok) == 404, "the access policy to reach the vault")
    print("   authorized via access policy")

    print("-- 8. a GROUP assignment reaches a member user")
    # Put the vault back in RBAC mode so only assignments count.
    status, raw = http("PUT", f"{ARM}{SCOPE}?api-version=2024-11-01", bearer(arm_tok),
                       json.dumps({"location": "westeurope",
                                   "properties": {"tenantId": TENANT, "enableRbacAuthorization": True,
                                                  "accessPolicies": []}}))
    if status != 200:
        sys.exit(f"FAIL: back to RBAC mode = {status} {raw[:300]}")

    # Ask the app for group membership claims, as an app registration does in
    # real Entra; then Alice's token carries her groups.
    status, raw = http("PATCH", f"{E}/admin/api/apps/{SP_CLIENT}",
                       {"Content-Type": "application/json"},
                       '{"groupMembershipClaims":"SecurityGroup"}')
    if status != 200:
        sys.exit(f"FAIL: enable group claims = {status} {raw[:300]}")

    # Alice signs in with her password; her token carries the groups claim.
    alice_tok = ropc_token(ALICE_UPN, ALICE_PASSWORD, "https://vault.azure.net/.default")
    groups = groups_of(alice_tok)
    if ENG_GROUP not in groups:
        sys.exit(f"FAIL: Alice's token carries no Engineering group: {groups}")
    print(f"   Alice's token carries groups: {groups}")

    # No assignment for Alice or her group yet.
    wait_for(lambda: secret_read_status(alice_tok) == 403, "Alice to start unauthorized")

    group_assignment = "7a0620ff-9c97-e122-c53e-11d15fd075aa"
    status, raw = http("PUT",
                       f"{ARM}{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{group_assignment}?api-version={ARM_API}",
                       bearer(arm_tok),
                       json.dumps({"properties": {"roleDefinitionId": ROLE_ID,
                                                  "principalId": ENG_GROUP,
                                                  "principalType": "Group"}}))
    if status != 201:
        sys.exit(f"FAIL: create group assignment = {status} {raw[:300]}")
    # Alice was never named — the grant reaches her through the group.
    wait_for(lambda: secret_read_status(alice_tok) == 404, "the group grant to reach a member")
    print("   Alice is authorized through her group, never named in the assignment")

    # The service principal is not in the group, so it stays refused.
    if secret_read_status(kv_tok) != 403:
        sys.exit("FAIL: a non-member was authorized by the group assignment")
    print("   a non-member is still refused")

    print("\nARM CHAIN E2E: PASS — ARM assignment (user, group and access policy) -> Key Vault enforcement")


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "kvdata").mkdir(parents=True)

    print("==> building/installing entra + arm + keyvault")
    # The delegated Azure-resource carve-out (a user token for
    # https://vault.azure.net) needs entra >= v0.3.1. A sibling checkout wins
    # so the family can be developed together; otherwise the pinned release.
    entra_repo = Path(os.environ.get("ENTRA_EMULATOR_REPO", REPO.parent / "entra-emulator"))
    entra_bin = WORK / ("entra-emulator" + EXE)
    if (entra_repo / "go.mod").exists():
        subprocess.run(["go", "build", "-C", str(entra_repo), "-o", str(entra_bin),
                        "./cmd/entra-emulator"], check=True,
                       env={**os.environ, "GOTOOLCHAIN": "auto"})
    else:
        entra_bin = go_install("entra-emulator",
                               f"github.com/calvinchengx/entra-emulator/cmd/entra-emulator@{ENTRA_VERSION}")
    kv_bin = WORK / ("azure-keyvault-emulator" + EXE)
    subprocess.run(["go", "build", "-C", str(REPO), "-o", str(kv_bin), "./cmd/azure-keyvault-emulator"],
                   check=True, env={**os.environ, "GOTOOLCHAIN": "auto"})
    arm_repo = Path(os.environ.get("ARM_EMULATOR_REPO", REPO.parent / "arm-emulator"))
    arm_bin = WORK / ("arm-emulator" + EXE)
    if (arm_repo / "go.mod").exists():
        subprocess.run(["go", "build", "-C", str(arm_repo), "-o", str(arm_bin), "./cmd/arm-emulator"],
                       check=True, env={**os.environ, "GOTOOLCHAIN": "auto"})
    else:
        arm_bin = go_install("arm-emulator",
                             f"github.com/calvinchengx/arm-emulator/cmd/arm-emulator@{ARM_VERSION}")

    print(f"==> starting entra-emulator on :{ENTRA_PORT}")
    start("entra", [str(entra_bin)], {
        "ORIGIN_MODE": "compat", "PORT": str(ENTRA_PORT), "PUBLIC_ORIGIN": E,
        "DB_PATH": str(WORK / "entra.sqlite"), "TLS_CERT_DIR": str(WORK / "entra-tls"),
    })
    print(f"==> starting arm-emulator on :{ARM_PORT}")
    start("arm", [str(arm_bin), "-addr", f":{ARM_PORT}", "-entra-issuer", ISSUER,
                  "-entra-tls-insecure", "-subscription-id", SUB, "-tenant-id", TENANT])
    print(f"==> starting azure-keyvault-emulator on :{KV_PORT} (authorized by ARM)")
    start("kv", [str(kv_bin), "-addr", f":{KV_PORT}", "-data-dir", str(WORK / "kvdata"),
                 "-entra-issuer", ISSUER, "-entra-tls-insecure",
                 "-arm-url", ARM, "-arm-scope", SCOPE])

    wait_healthy()
    print("==> running the ARM authorization chain")
    driver()


if __name__ == "__main__":
    try:
        main()
    finally:
        for p in procs:
            p.terminate()
