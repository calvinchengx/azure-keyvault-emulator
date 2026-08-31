#!/bin/sh
# Block until the stack is actually usable, or give up loudly.
#
# `docker compose up -d` returns when containers are STARTED, which is earlier
# than serving: the vault's healthcheck is still in its start period and its
# TLS listener is not up. Every caller that ran `make up` and then talked to
# the vault raced it, including the sequence the README documents and the one
# CI runs.
#
# "Ready" is not redefined here. status.sh already decides what a usable pair
# means -- containers on a network, endpoints answering, and the 401 challenge
# naming the seeded tenant -- so this polls exactly that, and the two can never
# disagree about the definition.
set -eu

TIMEOUT="${WAIT_READY_TIMEOUT:-120}"
INTERVAL="${WAIT_READY_INTERVAL:-3}"
DIR=$(dirname "$0")

waited=0
while :; do
  if sh "$DIR/status.sh" >/dev/null 2>&1; then
    [ "$waited" -gt 0 ] && printf 'ready after %ss\n' "$waited"
    exit 0
  fi
  if [ "$waited" -ge "$TIMEOUT" ]; then
    # The last attempt runs VISIBLY, so the failure says which check failed
    # rather than only that the wait expired.
    printf 'not ready after %ss:\n' "$TIMEOUT" >&2
    sh "$DIR/status.sh" >&2 || true
    exit 1
  fi
  sleep "$INTERVAL"
  waited=$((waited + INTERVAL))
done
