#!/usr/bin/env python3
"""Real-Microsoft-SDK witness matrix: boots entra-emulator + this emulator,
then runs the per-language Azure Key Vault SDK suites against them.

    python3 e2e/sdk/run.py [python|js|dotnet ...]     (default: all three)

Each suite is an unmodified, pinned Microsoft SDK (azure-keyvault-* /
@azure/keyvault-* / Azure.Security.KeyVault.*) completing challenge-based
authentication against a real entra-emulator and then exercising secrets,
keys (real crypto) and certificates. This is the enforcement arm of
docs/parity.md: the SDKs are the oracle, not our own tests.

The runner itself is stdlib-only; suite dependencies are managed by the
language's own toolchain (uv / pnpm / dotnet).
"""

import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
WORK = Path(tempfile.gettempdir()) / "kv-sdk-e2e"
ENTRA_PORT = int(os.environ.get("ENTRA_PORT", "18543"))
KV_PORT = int(os.environ.get("KV_PORT", "18544"))
TENANT = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
# entra-emulator's seeded confidential daemon (public dev values).
SP_CLIENT = "00d88624-f0d7-46f6-a641-6232c2608928"
SP_SECRET = "daemon-app-secret"
# entra >= v0.2.1 has the https://vault.azure.net carve-out.
ENTRA_VERSION = os.environ.get("ENTRA_VERSION", "v0.4.0")

E = f"https://localhost:{ENTRA_PORT}"
KV = f"https://localhost:{KV_PORT}"
ISSUER = f"{E}/{TENANT}/v2.0"
EXE = ".exe" if os.name == "nt" else ""

# Self-signed certs everywhere — harness only.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE

procs: list[subprocess.Popen] = []


def http_status(url):
    try:
        with urllib.request.urlopen(url, context=TLS, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, ConnectionError, OSError):
        return 0


def go_install(bin_name, path):
    print(f"    go install {path}", file=sys.stderr)
    env = {**os.environ, "GOBIN": str(WORK), "GOTOOLCHAIN": "auto"}
    subprocess.run(["go", "install", path], check=True, env=env)
    target = WORK / (bin_name + EXE)
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
    deadline = time.time() + 30
    while time.time() < deadline:
        if all(http_status(f"{base}/health") == 200 for base in (E, KV)):
            return
        time.sleep(0.2)
    for name in ("entra", "kv"):
        log = WORK / f"{name}.log"
        if log.exists():
            print(f"---- {name}.log ----\n{log.read_text()}", file=sys.stderr)
    sys.exit("emulators did not become healthy in time")


def suite_env():
    return {
        **os.environ,
        "KV_URL": KV,
        "AZURE_TENANT_ID": TENANT,
        "AZURE_CLIENT_ID": SP_CLIENT,
        "AZURE_CLIENT_SECRET": SP_SECRET,
        "ENTRA_AUTHORITY_HOST": E,
    }


def run(cmd, cwd, env):
    print(f"    $ {' '.join(map(str, cmd))}", file=sys.stderr)
    return subprocess.run(cmd, cwd=cwd, env=env).returncode == 0


def which(tool):
    """shutil.which, exiting with guidance when missing (also resolves the
    .cmd/.exe shims Windows toolchains install)."""
    path = shutil.which(tool)
    if not path:
        sys.exit(f"{tool} is required for this suite and was not found on PATH")
    return path


def suite_python(env):
    d = HERE / "python"
    return run([which("uv"), "run", "--no-project",
                "--with-requirements", str(d / "requirements.txt"),
                "python", str(d / "suite.py")], d, env)


def suite_js(env):
    d = HERE / "js"
    if not (d / "node_modules").exists():
        subprocess.run([which("pnpm"), "install", "--frozen-lockfile"],
                       cwd=REPO, check=True)
    # Node has no per-request CA override the SDK exposes; the harness runs
    # against self-signed emulators, so TLS verification is off for this
    # process only.
    return run([which("node"), str(d / "suite.mjs")], d,
               {**env, "NODE_TLS_REJECT_UNAUTHORIZED": "0"})


def suite_dotnet(env):
    d = HERE / "dotnet"
    return run([which("dotnet"), "run", "-c", "Release", "--project", str(d)], d, env)


SUITES = {"python": suite_python, "js": suite_js, "dotnet": suite_dotnet}


def main(argv):
    suites = argv or list(SUITES)
    unknown = [s for s in suites if s not in SUITES]
    if unknown:
        sys.exit(f"unknown suite(s): {', '.join(unknown)}")

    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "kvdata").mkdir(parents=True)

    print("==> installing entra-emulator (pinned) + building azure-keyvault-emulator")
    entra_bin = go_install(
        "entra-emulator",
        f"github.com/calvinchengx/entra-emulator/cmd/entra-emulator@{ENTRA_VERSION}")
    kv_bin = WORK / ("azure-keyvault-emulator" + EXE)
    subprocess.run(["go", "build", "-C", str(REPO), "-o", str(kv_bin),
                    "./cmd/azure-keyvault-emulator"],
                   check=True, env={**os.environ, "GOTOOLCHAIN": "auto"})

    print(f"==> starting entra-emulator on :{ENTRA_PORT}")
    start("entra", [str(entra_bin)], {
        "ORIGIN_MODE": "compat", "PORT": str(ENTRA_PORT),
        "PUBLIC_ORIGIN": E, "DB_PATH": str(WORK / "entra.sqlite"),
        "TLS_CERT_DIR": str(WORK / "entra-tls"),
    })
    print(f"==> starting azure-keyvault-emulator on :{KV_PORT}")
    start("kv", [str(kv_bin), "-addr", f":{KV_PORT}",
                 "-data-dir", str(WORK / "kvdata"),
                 "-entra-issuer", ISSUER, "-entra-tls-insecure"], {})
    wait_healthy()

    env = suite_env()
    failed = []
    for name in suites:
        print(f"\n==> suite: {name}")
        if SUITES[name](env):
            print(f"==> suite {name}: PASS")
        else:
            print(f"==> suite {name}: FAIL")
            failed.append(name)

    if failed:
        print(f"\nSDK E2E: FAIL — {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"\nSDK E2E: PASS — {', '.join(suites)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    finally:
        for p in procs:
            p.terminate()
