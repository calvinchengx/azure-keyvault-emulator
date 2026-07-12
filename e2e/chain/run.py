#!/usr/bin/env python3
"""The three-emulator chain, end to end on production trust relationships:

    1. A service principal's client_secret is stored in the vault.
    2. A workload reads it back using a MANAGED IDENTITY token (entra's MSI
       endpoint) — no credential in the workload.
    3. That secret authenticates the SP to entra (client credentials) for a
       Fabric-audience token.
    4. The token calls fabric-emulator and is accepted.

Every hop is a real HTTP call between three separate processes, each
validating tokens against entra-emulator's JWKS exactly as production does.
Self-contained and stdlib-only: installs entra + fabric (go install), builds
keyvault from this repo, runs the driver. No pip dependencies.
"""

import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORK = Path(os.environ.get("TMPDIR", "/tmp")) / "kv-chain-e2e"
ENTRA_PORT = int(os.environ.get("ENTRA_PORT", "18443"))
KV_PORT = int(os.environ.get("KV_PORT", "18444"))
FABRIC_PORT = int(os.environ.get("FABRIC_PORT", "19443"))
TENANT = "11111111-1111-1111-1111-111111111111"
# entra-emulator's seeded confidential daemon (public dev values).
SP_CLIENT = "cccccccc-0000-0000-0000-000000000002"
SP_SECRET = "daemon-app-secret"
# entra >= v0.2.1 has the https://vault.azure.net carve-out.
ENTRA_VERSION = os.environ.get("ENTRA_VERSION", "v0.2.1")
FABRIC_VERSION = os.environ.get("FABRIC_VERSION", "latest")

E = f"https://localhost:{ENTRA_PORT}"
KV = f"https://localhost:{KV_PORT}"
FAB = f"https://localhost:{FABRIC_PORT}"
ISSUER = f"{E}/{TENANT}/v2.0"
V = "7.5"

# Self-signed certs everywhere — harness only.
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


def form_token(secret, scope):
    """Client-credentials grant → access_token (or '' on failure)."""
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": SP_CLIENT,
        "client_secret": secret,
        "scope": scope,
    })
    status, raw = http("POST", f"{E}/{TENANT}/oauth2/v2.0/token",
                       {"Content-Type": "application/x-www-form-urlencoded"}, body)
    if status != 200:
        return ""
    import json
    return json.loads(raw).get("access_token", "")


def go_install(bin_name, path):
    print(f"    go install {path}", file=sys.stderr)
    # GOTOOLCHAIN=auto: let go fetch a newer toolchain if a dependency needs
    # one (CI may pin GOTOOLCHAIN=local, which would otherwise fail).
    env = {**os.environ, "GOBIN": str(WORK), "GOTOOLCHAIN": "auto"}
    subprocess.run(["go", "install", path], check=True, env=env)
    target = WORK / bin_name
    if not target.exists():
        sys.exit(f"install failed: {target} missing")
    return target


def start(name, argv, env_extra):
    log = open(WORK / f"{name}.log", "w")
    p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                         env={**os.environ, **env_extra})
    procs.append(p)
    return p


def wait_healthy():
    deadline = time.time() + 20
    while time.time() < deadline:
        if all(http("GET", f"{base}/health")[0] == 200 for base in (E, KV, FAB)):
            return
        time.sleep(0.2)
    sys.exit("emulators did not become healthy in time")


def bearer(tok):
    return {"Authorization": f"Bearer {tok}"}


def driver():
    print("-- 1. get a vault-audience token (client credentials, daemon SP)")
    kv_token = form_token(SP_SECRET, "https://vault.azure.net/.default")
    if not kv_token:
        sys.exit("FAIL: no vault token (carve-out?)")
    print(f"   vault token acquired ({len(kv_token)} chars, no resource-app seed)")

    print("-- 2. store the SP's client_secret in the vault")
    status, _ = http("PUT", f"{KV}/secrets/sp-credential?api-version={V}",
                     {**bearer(kv_token), "Content-Type": "application/json"},
                     f'{{"value":"{SP_SECRET}"}}')
    if status != 200:
        sys.exit(f"FAIL: store secret = {status}")
    print("   stored secret 'sp-credential'")

    print("-- 3. read it back with a MANAGED IDENTITY token (no secret in the workload)")
    import json
    status, raw = http("GET", f"{E}/msi/token?resource=https://vault.azure.net&api-version=2019-08-01",
                       {"X-IDENTITY-HEADER": "managed-identity-secret"})
    msi_token = json.loads(raw).get("access_token", "") if status == 200 else ""
    if not msi_token:
        sys.exit("FAIL: no MSI token")
    status, raw = http("GET", f"{KV}/secrets/sp-credential?api-version={V}", bearer(msi_token))
    recovered = json.loads(raw).get("value", "") if status == 200 else ""
    if recovered != SP_SECRET:
        sys.exit(f"FAIL: recovered '{recovered}' != '{SP_SECRET}'")
    print(f"   managed identity read the secret back: '{recovered}'")

    print("-- 4. use the recovered secret to authenticate the SP to entra for Fabric")
    fab_token = form_token(recovered, "https://api.fabric.microsoft.com/.default")
    if not fab_token:
        sys.exit("FAIL: no fabric token")
    print("   fabric-audience token acquired with the vault-sourced secret")

    print("-- 5. call fabric-emulator with it")
    status, _ = http("GET", f"{FAB}/v1/workspaces", bearer(fab_token))
    if status != 200:
        sys.exit(f"FAIL: fabric call = {status}")
    # A wrong secret breaks the chain exactly where it would in Azure.
    if form_token("wrong", "https://api.fabric.microsoft.com/.default"):
        sys.exit("FAIL: wrong secret was accepted")

    print("\nCHAIN E2E: PASS — vault secret -> managed identity -> entra token -> fabric")


def main():
    if WORK.exists():
        import shutil
        shutil.rmtree(WORK)
    (WORK / "kvdata").mkdir(parents=True)

    print("==> installing entra-emulator + fabric-emulator (pinned)")
    entra_bin = go_install("entra-emulator",
                           f"github.com/calvinchengx/entra-emulator/cmd/entra-emulator@{ENTRA_VERSION}")
    fabric_bin = go_install("fabric-emulator",
                            f"github.com/calvinchengx/fabric-emulator/cmd/fabric-emulator@{FABRIC_VERSION}")

    print(f"==> starting entra-emulator on :{ENTRA_PORT}")
    start("entra", [str(entra_bin)], {
        "ORIGIN_MODE": "compat", "PORT": str(ENTRA_PORT),
        "PUBLIC_ORIGIN": E, "DB_PATH": str(WORK / "entra.sqlite"),
        "TLS_CERT_DIR": str(WORK / "entra-tls"),
    })

    print(f"==> building + starting azure-keyvault-emulator on :{KV_PORT}")
    kv_bin = WORK / "azure-keyvault-emulator"
    subprocess.run(["go", "build", "-C", str(REPO), "-o", str(kv_bin),
                    "./cmd/azure-keyvault-emulator"],
                   check=True, env={**os.environ, "GOTOOLCHAIN": "auto"})
    start("kv", [str(kv_bin), "-addr", f":{KV_PORT}", "-data-dir", str(WORK / "kvdata"),
                 "-entra-issuer", ISSUER, "-entra-tls-insecure"], {})

    print(f"==> starting fabric-emulator on :{FABRIC_PORT}")
    start("fabric", [str(fabric_bin), "-addr", f":{FABRIC_PORT}",
                     "-entra-issuer", ISSUER, "-entra-tls-insecure"], {})

    wait_healthy()
    print("==> running the chain driver")
    driver()


if __name__ == "__main__":
    try:
        main()
    finally:
        for p in procs:
            p.terminate()
