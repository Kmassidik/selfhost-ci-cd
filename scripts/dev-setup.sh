#!/usr/bin/env bash
# Test harness: drives `cicd setup` non-interactively using .env.
#
# The product reads nothing from the environment; this script only fills the wizard's stdin
# so a fresh instance can be created in one command.
#
#   ./scripts/dev-setup.sh                      # create ./devdata from .env
#   CICD_TEST_RESET=1 ./scripts/dev-setup.sh    # delete ./devdata first
#   CICD_TEST_ROOT=/tmp/ci ./scripts/dev-setup.sh
#
# Requires: cargo build has produced ./target/debug/cicd
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE=${CICD_ENV_FILE:-.env}
if [ ! -f "$ENV_FILE" ]; then
  echo "error: $ENV_FILE not found — copy the template and fill in CICD_ADMIN_PASSWORD" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

if [ -z "${CICD_ADMIN_PASSWORD:-}" ]; then
  echo "error: CICD_ADMIN_PASSWORD is empty in $ENV_FILE" >&2
  exit 1
fi

if [ ! -x ./target/debug/cicd ]; then
  echo "error: ./target/debug/cicd missing — run: cargo build" >&2
  exit 1
fi

ROOT=${CICD_TEST_ROOT:-./devdata}
if [ -e "$ROOT" ]; then
  if [ "${CICD_TEST_RESET:-0}" = "1" ]; then
    rm -rf "$ROOT"
  else
    echo "error: $ROOT already exists — set CICD_TEST_RESET=1 to recreate" >&2
    exit 1
  fi
fi

case "${CICD_INGRESS:-lan}" in
  lan)        MODE=1 ;;
  cloudflare) MODE=2 ;;
  direct)     MODE=3 ;;
  *)          echo "error: CICD_INGRESS must be lan, cloudflare or direct" >&2; exit 1 ;;
esac

# Wizard prompt order: mode, name, bind, port, backends, targets, admin user, password,
# password repeat, confirm.
printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\ny\n' \
  "$MODE" \
  "${CICD_INSTANCE_NAME:-selfhost-ci-cd}" \
  "${CICD_BIND:-127.0.0.1}" \
  "${CICD_PORT:-8080}" \
  "${CICD_BACKENDS:-docker,nix}" \
  "${CICD_TARGETS:-linux}" \
  "${CICD_ADMIN_USER:-admin}" \
  "$CICD_ADMIN_PASSWORD" \
  "$CICD_ADMIN_PASSWORD" \
  | ./target/debug/cicd setup --root "$ROOT"
