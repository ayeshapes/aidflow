#!/usr/bin/env bash
# Tests for check_no_private_keys.sh. Run: bash scripts/test_check_no_private_keys.sh

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check_no_private_keys.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
failed=0

# check <name> <expected exit code>
check() {
  bash "$SCRIPT" "$TMP" >/dev/null 2>&1
  code=$?
  if [ "$code" -eq "$2" ]; then
    echo "PASS: $1"
  else
    echo "FAIL: $1 (exit $code, expected $2)"
    failed=1
  fi
}

# Markers are split in two so this test file never matches itself.
markers=("BEGIN ""PRIVATE KEY" "BEGIN RSA ""PRIVATE KEY" "BEGIN ENCRYPTED ""PRIVATE KEY")

echo "hello" > "$TMP/clean.txt"
check "clean repo passes" 0

for m in "${markers[@]}"; do
  echo "-----$m-----" > "$TMP/leak.txt"
  check "detects: $m" 1
  rm "$TMP/leak.txt"
done

# Keys inside ignored folders must not trigger the check.
mkdir "$TMP/secrets" "$TMP/.git"
echo "-----${markers[0]}-----" > "$TMP/secrets/ca.key"
echo "-----${markers[0]}-----" > "$TMP/.git/x"
check "ignores secrets/ and .git/" 0

exit $failed
