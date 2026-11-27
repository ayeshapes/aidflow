#!/usr/bin/env bash
# Fails (exit 1) if any private-key marker is found in the repo.
# Usage: check_no_private_keys.sh [directory]   (default: repo root)

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
PATTERN='BEGIN PRIVATE KEY|BEGIN RSA PRIVATE KEY|BEGIN ENCRYPTED PRIVATE KEY'

# -r recursive, -I skip binary files, -E extended regex, -n show line numbers
if grep -rInE \
    --exclude-dir=.git \
    --exclude-dir=secrets \
    --exclude-dir=node_modules \
    --exclude-dir=.venv \
    --exclude=check_no_private_keys.sh \
    -e "$PATTERN" "$ROOT"; then
  echo "ERROR: private key found above. Remove it before committing." >&2
  exit 1
fi

echo "OK: no private keys found."
exit 0
