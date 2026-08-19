#!/usr/bin/env python3
"""Boot the stack and run the SDK suite inside the client container.

Everything runs in compose because the point of this suite is the vault's NAME:
a compose network alias makes `contoso.vault.azure.net` resolve to the vault,
which no amount of host-side wiring can do without editing /etc/hosts.

The vault is BUILT from this checkout rather than pulled, so the suite witnesses
the code under review.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TENANT = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
COMPOSE = ["docker", "compose", "-f", str(HERE / "docker-compose.yml"), "-p", "kv-host-routed"]
# Pinned, like every other SDK suite here: a floating client would make a red
# run ambiguous between our regression and their release.
PINS = [
    "azure-identity==1.19.0",
    "azure-keyvault-secrets==4.9.0",
]


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["TENANT"] = TENANT
    return subprocess.run(COMPOSE + list(args), check=check, env=env)


def main() -> int:
    try:
        compose("up", "-d", "--build", "--wait")

        # Installed at run time rather than baked: this suite is about the
        # vault, and a Dockerfile here would be one more thing to keep pinned.
        subprocess.run(
            COMPOSE + ["exec", "-T", "client", "pip", "install", "--quiet", "--no-input", *PINS],
            check=True,
        )
        subprocess.run(
            COMPOSE + ["cp", str(HERE / "suite.py"), "client:/suite.py"], check=True
        )
        rc = subprocess.run(COMPOSE + ["exec", "-T", "client", "python", "/suite.py"]).returncode
        return rc
    finally:
        compose("down", "-v", check=False)


if __name__ == "__main__":
    sys.exit(main())
