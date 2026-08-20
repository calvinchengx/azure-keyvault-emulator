#!/usr/bin/env python3
"""The flagship witness: Microsoft's own `az` CLI, unmodified, driving the
emulator family as a registered cloud.

`az cloud register` exists so the CLI can target non-public ARM endpoints —
sovereign clouds, Stack Hub. The family becomes one of those:

    az cloud register --name EmulatorCloud
        --endpoint-resource-manager       <arm-emulator>
        --endpoint-active-directory       <entra-emulator>
        --suffix-keyvault-dns             .vault.azure.net
    az login --service-principal ...      (against entra-emulator)
    az group create / az keyvault create  (arm-emulator)
    az role assignment create             (arm-emulator)
    az keyvault secret show               (azure-keyvault-emulator, authorized
                                           by the assignment that just landed)

Nothing is stubbed on the CLI's side: it discovers the cloud, acquires real
tokens with the right audiences, and speaks ARM and the vault data plane.

The CLI needs a CA it trusts, so the harness runs the emulators with a
generated CA and points REQUESTS_CA_BUNDLE at it — the same thing a developer
does locally, rather than disabling verification.
"""

import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORK = Path(os.environ.get("TMPDIR", "/tmp")) / "kv-az-cli-e2e"
ENTRA_PORT = int(os.environ.get("ENTRA_PORT", "18843"))
KV_PORT = int(os.environ.get("KV_PORT", "18844"))
ARM_PORT = int(os.environ.get("ARM_PORT", "18845"))
TENANT = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
SP_CLIENT = "00d88624-f0d7-46f6-a641-6232c2608928"
SP_SECRET = "daemon-app-secret"
ENTRA_VERSION = os.environ.get("ENTRA_VERSION", "v0.9.0")
ARM_VERSION = os.environ.get("ARM_VERSION", "v0.4.1")

E = f"https://localhost:{ENTRA_PORT}"
KV = f"https://localhost:{KV_PORT}"
ARM = f"https://localhost:{ARM_PORT}"
ISSUER = f"{E}/{TENANT}/v2.0"
SUB = "6082bfda-63d0-46f4-8272-ae9195139feb"
RG = "az-rg"
VAULT = "emulator"
SCOPE = (f"/subscriptions/{SUB}/resourceGroups/{RG}"
         f"/providers/Microsoft.KeyVault/vaults/{VAULT}")
CLOUD = os.environ.get("AZ_CLOUD_NAME", "EmulatorCloud")
EXE = ".exe" if os.name == "nt" else ""

TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE

procs: list[subprocess.Popen] = []
# A private CLI config dir so the harness never touches the developer's real
# az profile, cloud list or credentials.
AZ_ENV = {}


def http(method, url, headers=None, data=None):
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


def az(*args, check=True, capture=True):
    """Run the real az CLI against the emulator cloud."""
    cmd = ["az", *args]
    print(f"    $ {' '.join(cmd)}", file=sys.stderr)
    r = subprocess.run(cmd, env={**os.environ, **AZ_ENV},
                       capture_output=capture, text=True)
    if check and r.returncode != 0:
        sys.exit(f"FAIL: {' '.join(cmd)}\n{(r.stderr or r.stdout)[:2000]}")
    return r


def az_json(*args):
    r = az(*args, "-o", "json")
    return json.loads(r.stdout) if r.stdout.strip() else None


def go_install(bin_name, path):
    print(f"    go install {path}", file=sys.stderr)
    env = {**os.environ, "GOBIN": str(WORK), "GOTOOLCHAIN": "auto"}
    subprocess.run(["go", "install", path], check=True, env=env)
    return WORK / (bin_name + EXE)


def build_or_install(repo_env, sibling, bin_name, module, version):
    """Prefer a sibling checkout so the family develops together."""
    repo = Path(os.environ.get(repo_env, REPO.parent / sibling))
    out = WORK / (bin_name + EXE)
    if (repo / "go.mod").exists():
        subprocess.run(["go", "build", "-C", str(repo), "-o", str(out), f"./cmd/{bin_name}"],
                       check=True, env={**os.environ, "GOTOOLCHAIN": "auto"})
        return out
    return go_install(bin_name, f"{module}@{version}")


def start(name, argv, env_extra=None):
    log = open(WORK / f"{name}.log", "w")
    p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                         env={**os.environ, **(env_extra or {})})
    procs.append(p)
    return p


def wait_healthy():
    deadline = time.time() + 40
    while time.time() < deadline:
        if all(http("GET", f"{b}/health")[0] == 200 for b in (E, KV, ARM)):
            return
        time.sleep(0.3)
    for n in ("entra", "arm", "kv"):
        log = WORK / f"{n}.log"
        if log.exists():
            print(f"---- {n}.log ----\n{log.read_text()}", file=sys.stderr)
    sys.exit("emulators did not become healthy in time")


def collect_ca():
    """Gather the emulators' self-signed certs into one bundle the CLI trusts.

    Each emulator persists its cert under {data-dir}/tls/cert.pem. They are
    self-signed, so the cert is its own CA — concatenating them is exactly
    what `REQUESTS_CA_BUNDLE` wants.
    """
    bundle = WORK / "emulator-ca.pem"
    pems = []
    for sub in ("entra-tls", "armdata/tls", "kvdata/tls"):
        p = WORK / sub / "cert.pem"
        if not p.exists():
            p = WORK / sub.split("/")[0] / "tls" / "cert.pem"
        if p.exists():
            pems.append(p.read_text())
    if not pems:
        sys.exit("no emulator certificates found to trust")
    bundle.write_text("\n".join(pems))
    return bundle


def secret_read_status(token):
    return http("GET", f"{KV}/secrets/probe?api-version=7.5",
                {"Authorization": f"Bearer {token}"})[0]


def wait_for(predicate, what, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    sys.exit(f"FAIL: timed out waiting for {what}")


def driver():
    print("-- 1. register the emulator family as a cloud")
    # A stale registration from an earlier run would collide.
    az("cloud", "set", "--name", "AzureCloud", check=False)
    az("cloud", "unregister", "--name", CLOUD, check=False)
    az("cloud", "register", "--name", CLOUD,
       "--endpoint-resource-manager", ARM,
       "--endpoint-active-directory", E,
       "--endpoint-active-directory-resource-id", "https://management.azure.com/",
       "--endpoint-active-directory-graph-resource-id", f"{E}/",
       "--endpoint-management", ARM,
       "--suffix-keyvault-dns", ".vault.azure.net")
    az("cloud", "set", "--name", CLOUD)
    print(f"   {CLOUD} registered and selected")

    print("-- 2. az login --service-principal against entra-emulator")
    az("login", "--service-principal", "-u", SP_CLIENT, "-p", SP_SECRET,
       "--tenant", TENANT, "--allow-no-subscriptions")
    accounts = az_json("account", "list")
    print(f"   signed in; {len(accounts)} subscription(s) visible to the CLI")

    print("-- 3. az group create + az keyvault create (real ARM calls)")
    az("group", "create", "--name", RG, "--location", "westeurope",
       "--subscription", SUB)
    vault = az_json("keyvault", "create", "--name", VAULT, "--resource-group", RG,
                    "--location", "westeurope", "--subscription", SUB,
                    "--enable-rbac-authorization", "true")
    if not vault or vault.get("name") != VAULT:
        sys.exit(f"FAIL: az keyvault create returned {vault}")
    print(f"   vault created: {vault['properties']['vaultUri']}")

    print("-- 4. the service principal cannot read yet")
    sp_token = json.loads(http(
        "POST", f"{E}/{TENANT}/oauth2/v2.0/token",
        {"Content-Type": "application/x-www-form-urlencoded"},
        f"grant_type=client_credentials&client_id={SP_CLIENT}"
        f"&client_secret={SP_SECRET}&scope=https%3A%2F%2Fvault.azure.net%2F.default")[1])["access_token"]
    wait_for(lambda: secret_read_status(sp_token) == 403,
             "the vault to apply ARM's empty grant")
    print("   403 Forbidden")

    print("-- 5. az role assignment create")
    assignment = az_json("role", "assignment", "create",
                         "--role", "Key Vault Secrets User",
                         "--assignee-object-id", SP_CLIENT,
                         "--assignee-principal-type", "ServicePrincipal",
                         "--scope", SCOPE)
    if not assignment or "roleDefinitionId" not in json.dumps(assignment):
        sys.exit(f"FAIL: az role assignment create returned {assignment}")
    print(f"   assignment {assignment.get('name')} created by the real CLI")

    print("-- 6. the data plane honours it")
    wait_for(lambda: secret_read_status(sp_token) == 404,
             "the CLI's assignment to reach the vault")
    print("   authorized — az wrote the grant, the vault enforced it")

    print("-- 7. az role assignment delete revokes it")
    az("role", "assignment", "delete", "--ids", assignment["id"])
    wait_for(lambda: secret_read_status(sp_token) == 403,
             "the CLI's revocation to reach the vault")
    print("   403 again")

    print("-- 8. az keyvault set-policy (the classic access-policy route)")
    az("keyvault", "update", "--name", VAULT, "--resource-group", RG,
       "--subscription", SUB, "--enable-rbac-authorization", "false")
    az("keyvault", "set-policy", "--name", VAULT, "--resource-group", RG,
       "--subscription", SUB, "--object-id", SP_CLIENT,
       "--secret-permissions", "get", "list")
    wait_for(lambda: secret_read_status(sp_token) == 404,
             "the CLI's access policy to reach the vault")
    print("   authorized via az keyvault set-policy")

    print("\nAZ CLI E2E: PASS — the real Azure CLI drives the emulator family")


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    for d in ("kvdata", "armdata", "azconfig"):
        (WORK / d).mkdir(parents=True)

    AZ_ENV["AZURE_CONFIG_DIR"] = str(WORK / "azconfig")
    # MSAL validates an authority against login.microsoftonline.com unless
    # instance discovery is off — the switch the CLI documents for private
    # and disconnected clouds (ADFS, Stack Hub). Without it the CLI reaches
    # for the real internet before it ever talks to the emulator.
    AZ_ENV["AZURE_CORE_INSTANCE_DISCOVERY"] = "false"

    print("==> building/installing the three emulators")
    entra_bin = build_or_install("ENTRA_EMULATOR_REPO", "entra-emulator", "entra-emulator",
                                 "github.com/calvinchengx/entra-emulator/cmd/entra-emulator",
                                 ENTRA_VERSION)
    arm_bin = build_or_install("ARM_EMULATOR_REPO", "arm-emulator", "arm-emulator",
                               "github.com/calvinchengx/arm-emulator/cmd/arm-emulator",
                               ARM_VERSION)
    kv_bin = WORK / ("azure-keyvault-emulator" + EXE)
    subprocess.run(["go", "build", "-C", str(REPO), "-o", str(kv_bin),
                    "./cmd/azure-keyvault-emulator"],
                   check=True, env={**os.environ, "GOTOOLCHAIN": "auto"})

    print(f"==> starting entra :{ENTRA_PORT}, arm :{ARM_PORT}, keyvault :{KV_PORT}")
    start("entra", [str(entra_bin)], {
        "ORIGIN_MODE": "compat", "PORT": str(ENTRA_PORT), "PUBLIC_ORIGIN": E,
        "DB_PATH": str(WORK / "entra.sqlite"), "TLS_CERT_DIR": str(WORK / "entra-tls"),
    })
    start("arm", [str(arm_bin), "-addr", f":{ARM_PORT}", "-data-dir", str(WORK / "armdata"),
                  "-entra-issuer", ISSUER, "-entra-tls-insecure",
                  "-subscription-id", SUB, "-tenant-id", TENANT])
    start("kv", [str(kv_bin), "-addr", f":{KV_PORT}", "-data-dir", str(WORK / "kvdata"),
                 "-entra-issuer", ISSUER, "-entra-tls-insecure",
                 "-arm-url", ARM, "-arm-scope", SCOPE])
    wait_healthy()

    # The CLI verifies TLS like any real client; hand it the emulators' certs.
    bundle = collect_ca()
    AZ_ENV["REQUESTS_CA_BUNDLE"] = str(bundle)
    AZ_ENV["ADAL_PYTHON_SSL_NO_VERIFY"] = ""
    print(f"==> trusting the emulator certificates via {bundle}")

    try:
        driver()
    finally:
        az("cloud", "set", "--name", "AzureCloud", check=False)
        az("cloud", "unregister", "--name", CLOUD, check=False)


if __name__ == "__main__":
    try:
        main()
    finally:
        for p in procs:
            p.terminate()
