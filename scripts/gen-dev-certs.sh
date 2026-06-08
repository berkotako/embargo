#!/usr/bin/env sh
# Generate a dev mTLS chain: one CA that signs the engine's server cert and the
# gateway/admission/sandbox client certs. Idempotent — skips if the CA exists.
# POSIX sh so it runs in the alpine `certgen` compose service too.
#
#   scripts/gen-dev-certs.sh [out-dir]   (default: ./certs)
set -eu

DIR="${1:-certs}"
mkdir -p "$DIR"
cd "$DIR"

if [ ! -f ca.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ca.key -out ca.crt -subj "/CN=Embargo Dev CA" 2>/dev/null
  echo "generated CA"
fi

# issue <name> <CN> <server|client> [SAN]
issue() {
  local name="$1" cn="$2" kind="$3" san="${4:-}"
  [ -f "$name.crt" ] && return 0
  openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=$cn" 2>/dev/null
  local eku="clientAuth"
  [ "$kind" = "server" ] && eku="serverAuth,clientAuth"
  {
    echo "extendedKeyUsage=$eku"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 365 -out "$name.crt" -extfile "$name.ext" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
  echo "issued $name ($kind)"
}

issue engine   engine   server "DNS:engine,DNS:localhost,IP:127.0.0.1"
issue gateway  gateway  client
issue admission admission client
issue sandbox  sandbox  client

echo "certs in $(pwd):"
ls -1 *.crt
