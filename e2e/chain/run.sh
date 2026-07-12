#!/bin/sh
# The three-emulator chain, end to end on production trust relationships:
#
#   1. A service principal's client_secret is stored in the vault.
#   2. A workload reads it back using a MANAGED IDENTITY token (entra's MSI
#      endpoint) — no credential in the workload.
#   3. That secret authenticates the SP to entra (client credentials) for a
#      Fabric-audience token.
#   4. The token calls fabric-emulator and is accepted.
#
# Every hop is a real HTTP call between three separate processes, each
# validating tokens against entra-emulator's JWKS exactly as production does.
# Self-contained: installs entra + fabric (go install), builds keyvault from
# this repo, runs the curl driver.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
WORK="${TMPDIR:-/tmp}/kv-chain-e2e"
ENTRA_PORT="${ENTRA_PORT:-18443}"
KV_PORT="${KV_PORT:-18444}"
FABRIC_PORT="${FABRIC_PORT:-19443}"
TENANT=11111111-1111-1111-1111-111111111111
# entra-emulator's seeded confidential daemon (public dev values).
SP_CLIENT=cccccccc-0000-0000-0000-000000000002
SP_SECRET=daemon-app-secret

rm -rf "$WORK" && mkdir -p "$WORK/kvdata"
trap 'kill $(cat "$WORK"/*.pid 2>/dev/null) 2>/dev/null || true' EXIT INT TERM

# Let go fetch a newer toolchain if a dependency's go directive needs one —
# CI may pin GOTOOLCHAIN=local, which would otherwise fail the install.
export GOTOOLCHAIN=auto

# Always go install a pinned version — a PATH binary (e.g. an older Homebrew
# entra-emulator) may predate the Azure-resource carve-out this chain needs.
# Errors are surfaced (no output suppression) and the binary is verified.
install_bin() {
  # $1 = binary name, $2 = go install path with @version
  echo "    go install $2" >&2
  GOBIN="$WORK" go install "$2"
  test -x "$WORK/$1" || { echo "install failed: $WORK/$1 missing" >&2; exit 1; }
}

echo "==> installing entra-emulator + fabric-emulator (pinned)"
# entra >= v0.2.1 has the https://vault.azure.net carve-out.
install_bin entra-emulator "github.com/calvinchengx/entra-emulator/cmd/entra-emulator@${ENTRA_VERSION:-v0.2.1}"
install_bin fabric-emulator "github.com/calvinchengx/fabric-emulator/cmd/fabric-emulator@${FABRIC_VERSION:-latest}"
ENTRA_BIN="$WORK/entra-emulator"
FABRIC_BIN="$WORK/fabric-emulator"

echo "==> starting entra-emulator on :$ENTRA_PORT"
ORIGIN_MODE=compat PORT="$ENTRA_PORT" PUBLIC_ORIGIN="https://localhost:$ENTRA_PORT" \
  DB_PATH="$WORK/entra.sqlite" TLS_CERT_DIR="$WORK/entra-tls" \
  "$ENTRA_BIN" > "$WORK/entra.log" 2>&1 &
echo $! > "$WORK/entra.pid"

ISSUER="https://localhost:$ENTRA_PORT/$TENANT/v2.0"

echo "==> building + starting azure-keyvault-emulator on :$KV_PORT"
go build -C "$REPO" -o "$WORK/azure-keyvault-emulator" ./cmd/azure-keyvault-emulator
"$WORK/azure-keyvault-emulator" -addr ":$KV_PORT" -data-dir "$WORK/kvdata" \
  -entra-issuer "$ISSUER" -entra-tls-insecure > "$WORK/kv.log" 2>&1 &
echo $! > "$WORK/kv.pid"

echo "==> starting fabric-emulator on :$FABRIC_PORT"
"$FABRIC_BIN" -addr ":$FABRIC_PORT" -entra-issuer "$ISSUER" -entra-tls-insecure \
  > "$WORK/fabric.log" 2>&1 &
echo $! > "$WORK/fabric.pid"

for i in $(seq 1 50); do
  curl -sk "https://localhost:$ENTRA_PORT/health" >/dev/null 2>&1 &&
    curl -sk "https://localhost:$KV_PORT/health" >/dev/null 2>&1 &&
    curl -sk "https://localhost:$FABRIC_PORT/health" >/dev/null 2>&1 && break
  sleep 0.2
done

echo "==> running the chain driver"
ENTRA_PORT="$ENTRA_PORT" KV_PORT="$KV_PORT" FABRIC_PORT="$FABRIC_PORT" \
  TENANT="$TENANT" SP_CLIENT="$SP_CLIENT" SP_SECRET="$SP_SECRET" \
  sh "$DIR/driver.sh"
