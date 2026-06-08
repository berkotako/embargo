#!/usr/bin/env bash
# One-command Embargo bootstrap: bring the full stack up, wait until the engine
# is healthy, and print how to point a client at the gateway.
#
#   scripts/quickstart.sh            # build + start, wait for health
#   EMBARGO_HOST=box.internal scripts/quickstart.sh   # advertise a non-local host
set -euo pipefail

cd "$(dirname "$0")/.."

HOST="${EMBARGO_HOST:-localhost}"
HEALTH_URL="http://localhost:9090/health/ready"
RETRIES="${EMBARGO_HEALTH_RETRIES:-60}"   # ~2 min at 2s each

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$1"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

# --- preflight ---
command -v docker >/dev/null 2>&1 || die "docker not found — install Docker first."
if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose";
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose";
else die "docker compose not found."; fi
docker info >/dev/null 2>&1 || die "docker daemon not reachable — is it running?"

bold "Building and starting the Embargo stack…"
$COMPOSE up --build -d

# --- wait for the engine to report ready ---
printf 'Waiting for the engine to become ready'
i=0
until curl -fsS "$HEALTH_URL" >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -ge "$RETRIES" ] && { echo; die "engine did not become ready — try: $COMPOSE logs engine"; }
  printf '.'; sleep 2
done
echo; ok "engine ready (self-seeded the default policy)"

cat <<EOF

$(bold "Embargo is up.")

  Console     http://${HOST}:4000     (sign in, pick a role)
  Gateway     http://${HOST}:4873     (point clients here)
  Admin API   http://${HOST}:8080/api
  Health      ${HEALTH_URL}

$(bold "Point a project at the firewall (one line):")

  scripts/onboard.sh                       # writes ./.npmrc for the current project
  # …or manually:
  echo 'registry=http://${HOST}:4873/' >> .npmrc

Then install as usual (npm / pnpm / yarn / bun) — held and denied versions are
stripped before your resolver sees them. Stop the stack with:  make down
EOF
