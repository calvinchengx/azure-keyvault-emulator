# Regenerate the README demo GIF:  vhs docs/demo/demo.tape   (run from the repo root)
# Requires: vhs, ttyd, ffmpeg, go, curl, jq, openssl, entra-emulator on PATH.
#
# NOTE ON QUOTING: VHS's lexer has no escape sequence, so `Type "... \" ..."`
# fails to parse. Commands that need double quotes are delimited with backticks
# instead — inside those, both ' and " pass through literally.
Output docs/demo/demo.gif

Require go
Require curl
Require jq
Require openssl
Require entra-emulator

Set Shell bash
Set FontSize 19
Set Width 1240
Set Height 680
Set Padding 22
Set Margin 16
Set MarginFill "#1e1e2e"
Set BorderRadius 10
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
# 10ms, not the 18ms the entra demo uses: these commands are long (bearer
# headers, api-version query strings), so the typing animation — not the
# pauses — dominates the runtime. Slower typing here just makes a reader wait.
Set TypingSpeed 10ms

# --- setup (not shown) ---
# The vault validates real Entra tokens, so the issuer starts first. Odd ports
# so a dev stack on :8443/:8444 does not collide with the recording.
Hide
Type "go build -o /tmp/kv-demo ./cmd/azure-keyvault-emulator" Enter
Sleep 8s
Type "rm -rf /tmp/kv-demo-data /tmp/ee-kv.db && mkdir -p /tmp/kv-demo-data" Enter
Type "TLS_ENABLED=false PORT=18098 ORIGIN_MODE=compat DB_PATH=/tmp/ee-kv.db SEED_ON_START=true entra-emulator >/tmp/ee-kv.log 2>&1 &" Enter
Type "until curl -sf localhost:18098/health >/dev/null 2>&1; do sleep 0.3; done" Enter
Type "KV_ADDR=127.0.0.1:18444 KV_DISABLE_TLS=true KV_DATA_DIR=/tmp/kv-demo-data KV_ENTRA_ISSUER=http://localhost:18098/11111111-1111-1111-1111-111111111111/v2.0 /tmp/kv-demo >/tmp/kv-demo.log 2>&1 &" Enter
Type "until curl -sf localhost:18444/health >/dev/null 2>&1; do sleep 0.3; done" Enter
Sleep 2s
Type "PS1='$ '" Enter
Type "V=http://localhost:18444" Enter
Type "T=http://localhost:18098/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token" Enter
Type "C=cccccccc-0000-0000-0000-000000000002" Enter
Type "SEC=daemon-app-secret" Enter
Type "clear" Enter
Show

Sleep 500ms
Type "# azure-keyvault-emulator - Azure Key Vault, local, one Go binary" Enter
Sleep 600ms

Type "# 1. The 401 challenge - the handshake every Azure SDK follows" Enter
Sleep 500ms
Type `curl -s -i "$V/secrets/db-password?api-version=7.5" | grep -iE '^HTTP|^WWW-Authenticate'` Enter
Sleep 1400ms

Type "# 2. Answer it with a real Entra token for the vault audience" Enter
Sleep 500ms
Type "TOK=$(curl -s -X POST $T -d grant_type=client_credentials -d client_id=$C -d client_secret=$SEC -d scope=https://vault.azure.net/.default | jq -r .access_token)" Enter
Sleep 800ms
Type `A="Authorization: Bearer $TOK"` Enter
Sleep 400ms

Type "# 3. Set a secret, then read it back" Enter
Sleep 500ms
Type `curl -s -X PUT "$V/secrets/db-password?api-version=7.5" -H "$A" -d '{"value":"s3cr3t"}' | jq '{id, value}'` Enter
Sleep 1400ms

Type "# 4. Real RSA - a key the emulator generates, and a real RS256 signature" Enter
Sleep 500ms
Type `curl -s -X POST "$V/keys/demo-key/create?api-version=7.5" -H "$A" -d '{"kty":"RSA","key_size":2048}' | jq '{kid: .key.kid, kty: .key.kty}'` Enter
Sleep 1400ms
Type `D=$(printf 'ship it' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')` Enter
Sleep 600ms
Type `curl -s -X POST "$V/keys/demo-key/sign?api-version=7.5" -H "$A" -d '{"alg":"RS256","value":"'$D'"}' | jq '{kid, signature: (.value[0:44] + "...")}'` Enter
Sleep 1500ms

Type "" Enter
Type "# No vault to provision. Real tokens, real keys, real signatures." Enter
Sleep 1300ms

# --- teardown (not shown) ---
Hide
Type "kill %1 %2 2>/dev/null" Enter
Show
