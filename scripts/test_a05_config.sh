#!/usr/bin/env bash
# Static checks for ticket A-05 (nginx + HTTPS). Run: bash scripts/test_a05_config.sh
# Reads the config files only; it does not need Docker or a running stack.
cd "$(dirname "$0")/.." || exit 1
failed=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; failed=1; }
has()  { grep -qE -- "$2" "$1"; }

CONF=nginx/aidflow.conf
SEC=nginx/snippets/security_headers.conf
PRX=nginx/snippets/proxy_common.conf
ALL="$CONF $SEC $PRX"

# 1. compose: nginx service, 80/443, backend not published
has docker-compose.yml '^  nginx:'            && pass "nginx service exists" || fail "nginx service missing"
has docker-compose.yml '"443:443"'            && pass "443 published"        || fail "443 not published"
has docker-compose.yml '"80:80"'              && pass "80 published"         || fail "80 not published"
if awk '/^  backend:/{b=1;next} /^  [a-z]+:/{b=0} b&&/^    ports:/{f=1} END{exit !f}' docker-compose.yml; then
  fail "backend still publishes a host port"; else pass "backend publishes no host port"; fi
grep -q "8000:8000" docker-compose.yml && fail "8000:8000 still in compose" || pass "no 8000:8000 mapping"

# 2. cert and key: read-only, paths from env, created only if present
for v in TLS_CERT_PATH TLS_KEY_PATH; do
  has docker-compose.yml "\\\$\\{$v:-" && pass "$v used in compose" || fail "$v not used in compose"
  has .env.example "^$v=" && pass "$v in .env.example" || fail "$v missing from .env.example"
done
n=$(grep -c 'read_only: true' docker-compose.yml); [ "$n" -ge 2 ] && pass "cert and key mounts are read_only" || fail "cert/key not both read_only"
has docker-compose.yml 'create_host_path: false' && pass "missing cert fails loudly" || fail "create_host_path: false missing"
has docker-compose.yml './secrets:' && fail "whole secrets/ folder mounted" || pass "secrets/ folder is not mounted as a whole"

# 3. TLS
has $CONF 'ssl_protocols +TLSv1\.2 TLSv1\.3;' && pass "TLS 1.2 and 1.3 only" || fail "ssl_protocols"
has $CONF 'listen 443 ssl' && pass "listens on 443 ssl" || fail "443 listener"
has $CONF 'return 301 https://' && pass "80 redirects to https" || fail "redirect"
if grep -E '^ *ssl_ciphers' $CONF | grep -qiE 'CBC|3DES|RC4|NULL|EXPORT|MD5|aRSA|:AES[0-9]|!?kRSA|DES'; then
  fail "weak cipher in ssl_ciphers"; else pass "ssl_ciphers has only ECDHE + AEAD suites"; fi
grep -E '^ *ssl_ciphers' $CONF | grep -qvE 'ECDHE' && fail "non-ECDHE suite" || pass "all suites are ECDHE"

# 4. Security headers (set 'always')
has $SEC 'Strict-Transport-Security.*always'   && pass "HSTS"                    || fail "HSTS"
has $SEC 'X-Content-Type-Options "nosniff".*always' && pass "X-Content-Type-Options" || fail "X-Content-Type-Options"
has $SEC 'X-Frame-Options.*always'             && pass "X-Frame-Options"         || fail "X-Frame-Options"
has $SEC 'Referrer-Policy.*always'             && pass "Referrer-Policy"         || fail "Referrer-Policy"
n=$(grep -c 'add_header Content-Security-Policy' $CONF); [ "$n" -ge 3 ] && pass "CSP on every location" || fail "CSP missing on a location"

# 5. Routing
has $CONF 'location /api/ ' && pass "/api/ location" || fail "/api/ location"
has $CONF 'http://backend:8000'  && pass "/api/ -> backend:8000" || fail "backend upstream"
has $CONF 'http://frontend:5173' && pass "/ -> frontend"         || fail "frontend upstream"

# 6. Anti-spoofing: EVERY location with proxy_pass includes proxy_common.conf,
#    and that file blanks both headers. (A location that sets its own
#    proxy_set_header loses inherited ones, so this must be per location.)
has $PRX 'proxy_set_header X-SSL-Client-Verify +"";' && pass "X-SSL-Client-Verify blanked" || fail "X-SSL-Client-Verify not blanked"
has $PRX 'proxy_set_header X-SSL-Client-S-DN +"";'   && pass "X-SSL-Client-S-DN blanked"   || fail "X-SSL-Client-S-DN not blanked"
bad=$(awk '/^ *location /{inloc=1; inc=0; pp=0} inloc&&/proxy_common\.conf/{inc=1} inloc&&/proxy_pass/{pp=1} inloc&&/^    }/{ if(pp&&!inc) print "x"; inloc=0 }' $CONF)
[ -z "$bad" ] && pass "every proxy_pass location includes proxy_common.conf" || fail "a proxy_pass location lacks proxy_common.conf"
grep -rn 'proxy_set_header X-SSL' $CONF | grep -v '""' | grep -q . && fail "X-SSL header set to a non-empty value" || pass "no X-SSL header set to a value (until I-03)"

# 7. Temporary cert script
[ -x scripts/dev_self_signed_cert.sh ] && pass "dev_self_signed_cert.sh is executable" || fail "cert script missing/not executable"
grep -q "TEMPORARY" scripts/dev_self_signed_cert.sh && pass "cert script says TEMPORARY" || fail "cert script not labelled TEMPORARY"
grep -qx "secrets/\*" .gitignore && pass "secrets/* is git-ignored" || fail "secrets/* not git-ignored"

exit $failed
