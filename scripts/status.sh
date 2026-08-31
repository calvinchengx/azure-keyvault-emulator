#!/bin/sh
# One view of "is the pair actually usable?", because no single existing surface
# answers that. `docker compose ps` knows containers but not whether the vault
# serves; and a container can be up AND healthy while attached to NO network,
# which happens when a port bind fails during creation. Docker leaves the
# container running, compose reuses it because it looks healthy, and every peer
# then fails DNS resolution on its name.
#
# Exit 0 = everything checked is good, 1 = at least one problem (usable in CI).
set -eu

# The null device is not spelled the same everywhere. Under Git for Windows the
# SHELL understands /dev/null, but curl.exe is a native Windows binary that does
# not: `-o /dev/null` fails to open its output file and curl exits 23 AFTER
# already printing the status code, which corrupts any `curl … || fallback`.
# NUL is the Windows spelling and creates no file.
NULDEV=/dev/null
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) NULDEV=NUL ;;
esac

PROJECT="${COMPOSE_PROJECT_NAME:-azure-keyvault-emulator}"
VAULT="${VAULT_URL:-https://localhost:8444}"
ENTRA="${ENTRA_URL:-https://localhost:8443}"
TENANT="${TENANT_ID:-6f89cf12-978b-4d23-ac18-9ef0c127cf87}"
RC=0

say() { printf '%s\n' "$*"; }
bad() { RC=1; }

# HTTP probe: prints the status code, or "---" when unreachable. curl's exit
# status is deliberately not chained with `||` — it prints the code on stdout
# and can still exit non-zero for unrelated reasons (see NULDEV above), and
# inside `$(...)` a fallback would be APPENDED to the code, not replace it.
code() {
  # `|| true` is what makes the fallback below reachable. Under `set -e` an
  # assignment whose command substitution fails kills the whole script, so an
  # unreachable endpoint -- the one case this function exists to survive --
  # exited with curl's own status and printed nothing: no FAIL line, no
  # challenge check, no summary. CI reported `Error 35` and named neither the
  # endpoint nor the problem. `|| true` is deliberately OUTSIDE the
  # substitution so it cannot append to or discard what curl already printed,
  # which matters for the exit-23-after-printing case described above.
  c=$(curl -sk -o "$NULDEV" -w '%{http_code}' --max-time 5 "$1" 2>/dev/null) || true
  case "$c" in
    ''|000|*[!0-9]*) printf '%s' "---" ;;
    *)               printf '%s' "$c" ;;
  esac
}

check_http() { # url label expected
  c=$(code "$1")
  if [ "$c" = "$3" ]; then
    printf '  ok    %-24s %s\n' "$2" "HTTP $c"
  else
    printf '  FAIL  %-24s %s (want %s)\n' "$2" "HTTP $c" "$3"; bad
  fi
}

say "containers (project: $PROJECT)"
ids=$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null || true)
if [ -z "$ids" ]; then
  say "  FAIL  no containers. Start with: make up"; bad
else
  for id in $ids; do
    # One inspect per container, tab-separated, so the shell does no JSON parsing.
    line=$(docker inspect "$id" --format \
'{{index .Config.Labels "com.docker.compose.service"}}	{{.State.Status}}	{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}	{{len .NetworkSettings.Networks}}	{{if .State.ExitCode}}{{.State.ExitCode}}{{else}}0{{end}}')
    svc=$(printf '%s' "$line" | cut -f1)
    status=$(printf '%s' "$line" | cut -f2)
    health=$(printf '%s' "$line" | cut -f3)
    nets=$(printf '%s' "$line" | cut -f4)
    exitc=$(printf '%s' "$line" | cut -f5)

    note=""
    mark="ok  "
    case "$status" in
      running)
        case "$health" in
          healthy)   note="healthy" ;;
          starting)  note="health starting"; mark="warn" ;;
          unhealthy) note="UNHEALTHY"; mark="FAIL"; bad ;;
          none)      note="running (no healthcheck, serving unverified)"; mark="warn" ;;
        esac
        # The silent killer: up, but on no network, so its DNS name does not exist.
        if [ "$nets" = "0" ]; then
          note="$note; ON NO NETWORK (peers cannot resolve it) -> docker compose up -d --force-recreate $svc"
          mark="FAIL"; bad
        fi
        ;;
      exited)     note="exited $exitc"; mark="FAIL"; bad ;;
      restarting) note="restarting (crash loop)"; mark="FAIL"; bad ;;
      *)          note="$status"; mark="warn" ;;
    esac
    printf '  %-5s %-24s %s\n' "$mark" "$svc" "$note"
  done
fi

say ""
say "endpoints"
check_http "$ENTRA/$TENANT/v2.0/.well-known/openid-configuration" "entra discovery" 200
check_http "$VAULT/health" "vault /health" 200

# The one check that proves the PAIR is wired, not just that both processes are
# alive: a tokenless data-plane call must be refused with a 401 whose
# WWW-Authenticate names entra's authority. That challenge is what every Azure
# SDK follows to acquire a token, so if it is missing or points somewhere else,
# DefaultAzureCredential fails no matter how healthy both containers look.
say ""
say "challenge handshake (what the Azure SDKs actually follow)"
hdr=$(curl -skI --max-time 5 "$VAULT/secrets/_status_probe?api-version=7.4" 2>/dev/null || printf '')
auth=$(printf '%s' "$hdr" | grep -i '^www-authenticate:' || printf '')
if [ -z "$auth" ]; then
  printf '  FAIL  %-24s no WWW-Authenticate on an unauthenticated call\n' "401 challenge"; bad
else
  case "$auth" in
    *"$TENANT"*) printf '  ok    %-24s names the seeded tenant\n' "401 challenge" ;;
    *)           printf '  warn  %-24s present, but does not name %s\n' "401 challenge" "$TENANT" ;;
  esac
fi

say ""
if [ "$RC" = "0" ]; then say "pair OK"; else say "pair has problems (see FAIL above)"; fi
exit "$RC"
