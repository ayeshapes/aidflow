#!/usr/bin/env bash
# Checks the F-02 configuration rules. Run: bash scripts/test_f02_config.sh
cd "$(dirname "$0")/.." || exit 1
failed=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; failed=1; }

# 1. Every required variable exists in .env.example
for v in POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DATABASE_URL JWT_SECRET \
         JWT_ALGORITHM ACCESS_TOKEN_EXPIRE_MINUTES FIELD_ENCRYPTION_KEY BACKUP_KEY; do
  grep -q "^$v=" .env.example && pass "$v is in .env.example" || fail "$v missing from .env.example"
done

# 2. Secrets are placeholders only
for v in POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DATABASE_URL JWT_SECRET \
         FIELD_ENCRYPTION_KEY BACKUP_KEY; do
  grep -q "^$v=.*CHANGE_ME" .env.example && pass "$v is a placeholder" || fail "$v is not a placeholder"
done

# 3. Fixed settings from the ticket
grep -q "^JWT_ALGORITHM=HS256$" .env.example && pass "JWT_ALGORITHM=HS256" || fail "JWT_ALGORITHM"
grep -q "^ACCESS_TOKEN_EXPIRE_MINUTES=30$" .env.example && pass "token expiry 30" || fail "token expiry"

# 4. The database host is the local Compose service "db" (not a shared server)
grep -q "^DATABASE_URL=.*@db:5432/" .env.example && pass "DATABASE_URL host is db" || fail "DATABASE_URL host"

# 5. Compose has no hard-coded password and does not publish the DB port
grep -qE "^ *[A-Z_]*PASSWORD: *[^\$ ]" docker-compose.yml && fail "hard-coded password in compose" || pass "no hard-coded password in compose"
grep -q "5432:" docker-compose.yml && fail "db port is published" || pass "db port is not published"

# 6. Compose has the required db pieces
grep -q "pg_isready" docker-compose.yml && pass "healthcheck uses pg_isready" || fail "pg_isready"
grep -q "service_healthy" docker-compose.yml && pass "backend waits for healthy db" || fail "service_healthy"
grep -q "name: aidflow_pgdata" docker-compose.yml && pass "volume aidflow_pgdata" || fail "volume name"

# 7. .env is git-ignored
grep -qx ".env" .gitignore && pass ".env is git-ignored" || fail ".env not in .gitignore"

exit $failed
