#!/bin/sh
# Walks the secret-as-SP-credential chain across the three running emulators.
# All calls use -k (self-signed certs) — harness only.
set -eu

E="https://localhost:$ENTRA_PORT"
KV="https://localhost:$KV_PORT"
FAB="https://localhost:$FABRIC_PORT"
V=7.5

jqget() { # extract a JSON string field ($1) from stdin without jq
  sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'
}

echo "-- 1. get a vault-audience token (client credentials, daemon SP)"
KV_TOKEN=$(curl -sk -X POST "$E/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=$SP_CLIENT&client_secret=$SP_SECRET&scope=https://vault.azure.net/.default" \
  | jqget access_token)
[ -n "$KV_TOKEN" ] || { echo "FAIL: no vault token (carve-out?)"; exit 1; }
echo "   vault token acquired (${#KV_TOKEN} chars, no resource-app seed)"

echo "-- 2. store the SP's client_secret in the vault"
code=$(curl -sk -o /dev/null -w '%{http_code}' -X PUT \
  "$KV/secrets/sp-credential?api-version=$V" \
  -H "Authorization: Bearer $KV_TOKEN" -H "Content-Type: application/json" \
  -d "{\"value\":\"$SP_SECRET\"}")
[ "$code" = "200" ] || { echo "FAIL: store secret = $code"; exit 1; }
echo "   stored secret 'sp-credential'"

echo "-- 3. read it back with a MANAGED IDENTITY token (no secret in the workload)"
MSI_TOKEN=$(curl -sk "$E/msi/token?resource=https://vault.azure.net&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: managed-identity-secret" | jqget access_token)
[ -n "$MSI_TOKEN" ] || { echo "FAIL: no MSI token"; exit 1; }
RECOVERED=$(curl -sk "$KV/secrets/sp-credential?api-version=$V" \
  -H "Authorization: Bearer $MSI_TOKEN" | jqget value)
[ "$RECOVERED" = "$SP_SECRET" ] || { echo "FAIL: recovered '$RECOVERED' != '$SP_SECRET'"; exit 1; }
echo "   managed identity read the secret back: '$RECOVERED'"

echo "-- 4. use the recovered secret to authenticate the SP to entra for Fabric"
FAB_TOKEN=$(curl -sk -X POST "$E/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=$SP_CLIENT&client_secret=$RECOVERED&scope=https://api.fabric.microsoft.com/.default" \
  | jqget access_token)
[ -n "$FAB_TOKEN" ] || { echo "FAIL: no fabric token"; exit 1; }
echo "   fabric-audience token acquired with the vault-sourced secret"

echo "-- 5. call fabric-emulator with it"
code=$(curl -sk -o /dev/null -w '%{http_code}' "$FAB/v1/workspaces" \
  -H "Authorization: Bearer $FAB_TOKEN")
[ "$code" = "200" ] || { echo "FAIL: fabric call = $code"; exit 1; }
# And a wrong secret breaks the chain exactly where it would in Azure.
BAD=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$E/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=$SP_CLIENT&client_secret=wrong&scope=https://api.fabric.microsoft.com/.default")
[ "$BAD" = "200" ] && { echo "FAIL: wrong secret was accepted"; exit 1; }

echo ""
echo "CHAIN E2E: PASS — vault secret -> managed identity -> entra token -> fabric"
