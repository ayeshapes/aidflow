#!/usr/bin/env bash
# =============================================================================
#  TEMPORARY - DEVELOPMENT ONLY - NOT A CA-ISSUED CERTIFICATE
#
#  Creates a self-signed certificate for localhost so nginx can start before the
#  real CA-issued server certificate is ready. Nobody trusts it except a client
#  you explicitly tell to (curl --cacert secrets/server.crt ...).
#
#  - It is NOT evidence for SEC-10. Re-run the SEC-10 evidence commands with the
#    CA-issued certificate once it replaces this one.
#  - It is valid for 30 days, so it cannot be forgotten about for long.
#  - Its subject says "TEMPORARY" so nobody mistakes it for the real thing.
#
#  Usage: ./scripts/dev_self_signed_cert.sh [--force]
#  Output (same paths nginx mounts; override with TLS_CERT_PATH / TLS_KEY_PATH):
#     secrets/server.crt   secrets/server.key   (both git-ignored)
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."     # always run from the repo root

CERT="${TLS_CERT_PATH:-./secrets/server.crt}"
KEY="${TLS_KEY_PATH:-./secrets/server.key}"

if { [ -e "$CERT" ] || [ -e "$KEY" ]; } && [ "${1:-}" != "--force" ]; then
  echo "Refusing to overwrite an existing certificate or key:" >&2
  echo "  $CERT" >&2
  echo "  $KEY" >&2
  echo "If it is the CA-issued pair, keep it. To replace it anyway: $0 --force" >&2
  exit 1
fi

mkdir -p "$(dirname "$CERT")" "$(dirname "$KEY")"

# Create the key with owner-only permissions from the start.
umask 077
# EC P-256 key; SAN covers the names a browser/curl will use for the dev stack.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -sha256 -days 30 \
  -keyout "$KEY" -out "$CERT" \
  -subj "/O=AidFlow TEMPORARY DEV ONLY (self-signed)/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" \
  -addext "extendedKeyUsage=serverAuth" 2>/dev/null
chmod 644 "$CERT"     # a certificate is public; nginx (root in the container) reads the key
chmod 600 "$KEY"

cat <<MSG

*** TEMPORARY SELF-SIGNED CERTIFICATE CREATED - DEVELOPMENT ONLY ***
  certificate: $CERT
  private key: $KEY
  expires:     $(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)

Browsers will warn about it. To test with curl, trust THIS file explicitly:
  curl -v --cacert $CERT https://localhost/api/health

Replace both files with the CA-issued pair as soon as it is ready.
MSG
