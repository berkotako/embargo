#!/usr/bin/env bash
# Point a project at the Embargo gateway by setting `registry=` in its .npmrc.
# Idempotent: updates an existing registry= line rather than duplicating it.
#
#   scripts/onboard.sh                         # ./.npmrc → http://localhost:4873/
#   scripts/onboard.sh https://embargo.corp/   # custom gateway URL
#   scripts/onboard.sh https://embargo.corp/ /path/to/project
set -euo pipefail

REGISTRY="${1:-http://localhost:4873/}"
PROJECT_DIR="${2:-$PWD}"
NPMRC="${PROJECT_DIR%/}/.npmrc"

case "$REGISTRY" in
  http://*|https://*) ;;
  *) printf '\033[31m✗ registry must be an http(s) URL: %s\033[0m\n' "$REGISTRY" >&2; exit 1 ;;
esac

line="registry=${REGISTRY}"

if [ -f "$NPMRC" ] && grep -q '^registry=' "$NPMRC"; then
  # Replace the existing registry line in place (portable sed).
  tmp="$(mktemp)"
  sed "s|^registry=.*|${line}|" "$NPMRC" > "$tmp" && mv "$tmp" "$NPMRC"
  printf '\033[32m✓\033[0m updated registry in %s\n' "$NPMRC"
else
  [ -f "$NPMRC" ] || : > "$NPMRC"
  printf '%s\n' "$line" >> "$NPMRC"
  printf '\033[32m✓\033[0m set registry in %s\n' "$NPMRC"
fi

printf '  %s\n' "$line"
echo "Installs in this project now resolve through Embargo. Revert by removing that line."
