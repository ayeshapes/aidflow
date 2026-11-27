# Testing report: ticket A-04 security tests

Date of run: 2026-11-27. Scope: SEC-01, SEC-02, SEC-03, SEC-11 (plus the supporting A-04 tests listed at the end).

## Summary

| ID | Objective | Result |
|---|---|---|
| SEC-01 | Unauthenticated request to every protected route returns 401 | PASS |
| SEC-02 | Field-officer token against admin endpoints returns 403 | PASS |
| SEC-03 | users table holds only bcrypt hashes, no plaintext | PASS |
| SEC-11 | Six rapid bad logins return 429 | PASS |

Full backend suite at the time of the run:
```text

68 role/capability checks, 0 mismatches
223 passed in 33.82s
```

## Test environment

```text
Python 3.12.3
fastapi 0.165.0
starlette 1.10.0
SQLAlchemy 2.1.9
alembic 1.20.1
bcrypt 5.0.0
PyJWT 2.7.0
pytest 9.2.0
httpx 0.29.0
psql (PostgreSQL) 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
```
- Automated tests run with in-memory SQLite and the app imported directly (FastAPI `TestClient`, no network).
- SEC-03 supplementary evidence ran against PostgreSQL 16.15 with the Alembic migrations applied.
- Not yet run inside Docker Compose (the Dockerfile uses Python 3.11; this run used 3.12.3). Re-run with `./scripts/dev.sh test` before relying on it for the final report.
- Tester: automated run by the assistant; a team member should repeat it and initial it.

## How to reproduce

```bash
cd backend
pytest -v app/tests/test_security.py -k sec01          # SEC-01
pytest -v app/tests/test_sec_02_03_11.py -k sec02      # SEC-02
pytest -v app/tests/test_sec_02_03_11.py -k sec03      # SEC-03
pytest -v app/tests/test_sec_02_03_11.py -k sec11      # SEC-11
# log lines, as shown below:
pytest -v -o log_cli=true -o log_cli_level=INFO <same arguments>
```

## SEC-01: Unauthenticated access to every protected route

| Field | Content |
|---|---|
| **ID** | SEC-01 |
| **Objective** | Show that no protected endpoint can be used without credentials, now and for routes added later. |
| **Preconditions** | Application importable; no database content needed. The route list is read automatically from `app.routes` (nothing is hand-listed). Public routes are an explicit allow-list (`PUBLIC_ROUTES` in `test_security.py`): `GET /api/health`, `POST /api/auth/login`, and the Swagger/OpenAPI pages. |
| **Steps** | 1. Enumerate every `(method, path)` in `app.routes`. 2. Remove the allow-listed public routes. 3. Send each remaining request twice: with no `Authorization` header, and with `Authorization: Bearer not.a.real-token`. 4. Check status, body and `WWW-Authenticate` header. |
| **Expected result** | Every protected route returns `401` with `{"error": {"code": "UNAUTHORIZED", ...}}` and `WWW-Authenticate: Bearer`. Guard tests confirm the enumeration found the routes it should. |
| **Actual result** | 8 protected routes x 2 variants = 16 cases, all `401` with the expected body and header. 5 guard/meta tests also pass (OpenAPI cross-check, known routes present, no stale allow-list entries, an unprotected route in a throw-away app is caught, an unrecognised route type fails loudly). |
| **Pass / Fail** | **PASS** |
| **Screenshot** | Not applicable: these are API-level automated tests with no UI. The terminal output below is the evidence. |

**Terminal output (pytest)**
```text
$ pytest -v app/tests/test_security.py -k sec01
test_sec01_protected_route_returns_401_without_credentials[POST /api/auth/logout-no-credentials] PASSED [  4%]
test_sec01_protected_route_returns_401_without_credentials[POST /api/auth/logout-garbage-bearer-token] PASSED [  9%]
test_sec01_protected_route_returns_401_without_credentials[GET /api/auth/me-no-credentials] PASSED [ 14%]
test_sec01_protected_route_returns_401_without_credentials[GET /api/auth/me-garbage-bearer-token] PASSED [ 19%]
test_sec01_protected_route_returns_401_without_credentials[GET /api/users-no-credentials] PASSED [ 23%]
test_sec01_protected_route_returns_401_without_credentials[GET /api/users-garbage-bearer-token] PASSED [ 28%]
test_sec01_protected_route_returns_401_without_credentials[POST /api/users-no-credentials] PASSED [ 33%]
test_sec01_protected_route_returns_401_without_credentials[POST /api/users-garbage-bearer-token] PASSED [ 38%]
test_sec01_protected_route_returns_401_without_credentials[GET /api/users/{user_id}-no-credentials] PASSED [ 42%]
test_sec01_protected_route_returns_401_without_credentials[GET /api/users/{user_id}-garbage-bearer-token] PASSED [ 47%]
test_sec01_protected_route_returns_401_without_credentials[POST /api/users/{user_id}/activate-no-credentials] PASSED [ 52%]
test_sec01_protected_route_returns_401_without_credentials[POST /api/users/{user_id}/activate-garbage-bearer-token] PASSED [ 57%]
test_sec01_protected_route_returns_401_without_credentials[POST /api/users/{user_id}/deactivate-no-credentials] PASSED [ 61%]
test_sec01_protected_route_returns_401_without_credentials[POST /api/users/{user_id}/deactivate-garbage-bearer-token] PASSED [ 66%]
test_sec01_protected_route_returns_401_without_credentials[PATCH /api/users/{user_id}/role-no-credentials] PASSED [ 71%]
test_sec01_protected_route_returns_401_without_credentials[PATCH /api/users/{user_id}/role-garbage-bearer-token] PASSED [ 76%]
test_sec01_every_openapi_operation_was_enumerated PASSED [ 80%]
test_sec01_the_protected_set_is_not_empty_and_has_the_known_routes PASSED [ 85%]
test_sec01_public_allowlist_has_no_stale_entries PASSED [ 90%]
test_sec01_checker_catches_an_unprotected_route PASSED [ 95%]
test_sec01_enumerator_fails_loudly_on_a_route_it_cannot_test PASSED [100%]
============================== 21 passed in 1.03s ==============================
```

**Observed HTTP exchange** (captured separately by replaying the scenario against the real app)
```text
# SEC-01  GET /api/users, no Authorization header
HTTP 401
Www-Authenticate: Bearer
{"error": {"code": "UNAUTHORIZED", "message": "Not authenticated"}} 

# SEC-01  POST /api/users/1/deactivate, no Authorization header
HTTP 401
Www-Authenticate: Bearer
{"error": {"code": "UNAUTHORIZED", "message": "Not authenticated"}}
```

**Relevant log lines** (the only lines emitted are from the test client; see Observation 1)
```text
client: POST http://testserver/api/auth/logout "HTTP/1.1 401 Unauthorized"
client: POST http://testserver/api/auth/logout "HTTP/1.1 401 Unauthorized"
client: GET http://testserver/api/auth/me "HTTP/1.1 401 Unauthorized"
```

**Detection check** (a defect was injected on purpose to prove the test can fail; source was restored afterwards)
```text
Planted bug 1: a new `GET /api/auth/oops-new-endpoint` with no auth dependency -> 2 FAILED (both variants), 21 passed.
Planted bug 2: `dependencies=[Depends(can_manage_users)]` removed from the users router -> 4 FAILED (the GET routes that relied on it), 17 passed.
```


## SEC-02: Field-officer token against admin endpoints

| Field | Content |
|---|---|
| **ID** | SEC-02 |
| **Objective** | Show that a logged-in field officer cannot use endpoints that need a capability the field role lacks, and that the refused action does not happen. |
| **Preconditions** | User `officer1` with role `field` exists and logs in through `POST /api/auth/login` to obtain a real token. Target routes are discovered from the live app: every route whose dependency tree requires a capability the field role does not hold (today: the 6 `/api/users` operations, all `manage_users`). |
| **Steps** | 1. Log in as the field officer. 2. Call each discovered admin endpoint with that token. 3. Call the same `GET /api/users` as an admin (control). 4. Try three damaging calls as the field officer (create an admin user, promote self to admin, deactivate the admin) and then read the database. |
| **Expected result** | Every admin endpoint returns `403` with `{"error": {"code": "FORBIDDEN", ...}}`. Admin gets `200` on the same endpoint. The database is unchanged after the refused calls. |
| **Actual result** | 6 of 6 discovered endpoints returned `403` with the standard body. Admin control returned `200`. After the refused calls no `backdoor` user existed, the officer's role was still `field`, and the admin was still active. |
| **Pass / Fail** | **PASS** |
| **Screenshot** | Not applicable: these are API-level automated tests with no UI. The terminal output below is the evidence. |

**Terminal output (pytest)**
```text
$ pytest -v app/tests/test_sec_02_03_11.py -k sec02
test_sec02_discovery_found_the_admin_endpoints PASSED [ 11%]
test_sec02_field_officer_token_gets_403_on_admin_endpoints[GET /api/users] PASSED [ 22%]
test_sec02_field_officer_token_gets_403_on_admin_endpoints[POST /api/users] PASSED [ 33%]
test_sec02_field_officer_token_gets_403_on_admin_endpoints[GET /api/users/{user_id}] PASSED [ 44%]
test_sec02_field_officer_token_gets_403_on_admin_endpoints[POST /api/users/{user_id}/activate] PASSED [ 55%]
test_sec02_field_officer_token_gets_403_on_admin_endpoints[POST /api/users/{user_id}/deactivate] PASSED [ 66%]
test_sec02_field_officer_token_gets_403_on_admin_endpoints[PATCH /api/users/{user_id}/role] PASSED [ 77%]
test_sec02_the_same_endpoint_works_for_an_admin PASSED [ 88%]
test_sec02_forbidden_requests_change_nothing PASSED [100%]
======================= 9 passed, 6 deselected in 4.05s ========================
```

**Observed HTTP exchange** (captured separately by replaying the scenario against the real app)
```text
# SEC-02  GET /api/users, field-officer token
HTTP 403
{"error": {"code": "FORBIDDEN", "message": "You do not have permission to do this"}} 

# SEC-02  PATCH /api/users/1/role {role: admin}, field-officer token
HTTP 403
{"error": {"code": "FORBIDDEN", "message": "You do not have permission to do this"}}
```

**Relevant log lines** (first parametrised case: the login that creates the token, then the refused request; see Observation 1)
```text

```

**Detection check** (a defect was injected on purpose to prove the test can fail; source was restored afterwards)
```text
Defect: `manage_users` granted to `ADMIN, FIELD` in `core/permissions.py` -> `test_sec02_discovery_found_the_admin_endpoints`, `test_sec02_the_same_endpoint_works_for_an_admin` and `test_sec02_forbidden_requests_change_nothing` FAILED (3 failed). The per-route cases were skipped because nothing remained to discover, so the discovery guard is what reports it.

39:    "manage_users":                   frozenset({ADMIN, FIELD}),  # users, roles, activation
FAILED app/tests/test_sec_02_03_11.py::test_sec02_discovery_found_the_admin_endpoints
FAILED app/tests/test_sec_02_03_11.py::test_sec02_the_same_endpoint_works_for_an_admin
FAILED app/tests/test_sec_02_03_11.py::test_sec02_forbidden_requests_change_nothing
3 failed, 1 skipped, 6 deselected, 1 warning in 2.58s
```


## SEC-03: Password storage format

| Field | Content |
|---|---|
| **ID** | SEC-03 |
| **Objective** | Show that the users table stores only bcrypt hashes and no plaintext password anywhere. |
| **Preconditions** | Five users with known passwords (including symbols, spaces and non-ASCII): one made by direct insert (as `create_admin` does), the rest through `POST /api/users`. Real bcrypt cost 12 is used (the test does not use the cheap hashes of other test files). |
| **Steps** | 1. Query the table directly with raw SQL (`SELECT * FROM users`), bypassing the ORM. 2. Check every `password_hash` against `^\$2[aby]\$12\$[./A-Za-z0-9]{53}$` and length 60. 3. Check that no known plaintext appears in any column of any row. 4. Verify each hash with `bcrypt.checkpw` against its own user's password and no one else's. 5. Check two users with the same password get different hashes. 6. Check passwords and hashes do not appear in captured logs. |
| **Expected result** | All hashes are cost-12 bcrypt, no plaintext in the table, hashes verify only for their owner, hashes are salted, logs are clean. |
| **Actual result** | 5 of 5 rows matched the bcrypt pattern (60 characters). No plaintext found in any column. Each hash verified for its own password only. Same password -> different hashes. No password or `$2b$` string in the log output. |
| **Pass / Fail** | **PASS** |
| **Screenshot** | Not applicable: these are API-level automated tests with no UI. The terminal output below is the evidence. |

**Terminal output (pytest)**
```text
$ pytest -v app/tests/test_sec_02_03_11.py -k sec03
test_sec03_every_stored_hash_is_bcrypt_and_none_contains_the_plaintext PASSED [ 33%]
test_sec03_same_password_gets_different_hashes PASSED [ 66%]
test_sec03_plaintext_and_hashes_do_not_reach_the_logs PASSED [100%]
====================== 3 passed, 12 deselected in 10.81s =======================
```

**Observed HTTP exchange** (captured separately by replaying the scenario against the real app)
```text
(not applicable: no HTTP response is the subject of this test)
```

**Relevant log lines** (user creation events; they record the role only, never a password or hash)
```text
aidflow.audit:INFO:audit action=login_success actor_id=1 target=admin1 outcome=success details={}
client: POST http://testserver/api/auth/login "HTTP/1.1 200 OK"
aidflow.audit:INFO:audit action=user_create actor_id=1 target=carol outcome=success details={'role': 'field'}
client: POST http://testserver/api/users "HTTP/1.1 201 Created"
aidflow.audit:INFO:audit action=user_create actor_id=1 target=dave outcome=success details={'role': 'field'}
client: POST http://testserver/api/users "HTTP/1.1 201 Created"
aidflow.audit:INFO:audit action=user_create actor_id=1 target=erin outcome=success details={'role': 'field'}
client: POST http://testserver/api/users "HTTP/1.1 201 Created"
```

**Detection check** (a defect was injected on purpose to prove the test can fail; source was restored afterwards)
```text
Defect: `create_user` stores `data.password` instead of its hash -> 2 FAILED:

19:        password_hash=data.password,
E           AssertionError: carol: not a cost-12 bcrypt hash: Tr0ub4dor&3-...
E           assert None
E       AssertionError: assert (2 == 2 and 'shared-password-123' != 'shared-password-123')
FAILED app/tests/test_sec_02_03_11.py::test_sec03_every_stored_hash_is_bcrypt_and_none_contains_the_plaintext
FAILED app/tests/test_sec_02_03_11.py::test_sec03_same_password_gets_different_hashes
2 failed, 1 passed, 12 deselected, 1 warning in 2.51s
```

**Supplementary evidence on PostgreSQL 16** (the project's real database engine; the automated test itself uses in-memory SQLite). Migrations were applied, users were created through the API, and the table was queried directly with `psql`:
```text
$ alembic upgrade head          (no output on success; the table below exists, so it ran)
POST /api/users carol -> 201
POST /api/users dave -> 201
POST /api/users erin -> 201

$ psql -d aidflow -c "SELECT id, username, role, length(password_hash) AS len, password_hash FROM users ORDER BY id"
 id | username | role  | len |                        password_hash                         
----+----------+-------+-----+--------------------------------------------------------------
  1 | admin1   | admin |  60 | $2b$12$IFZj3hhDLcej5VBg6x9HQejtbiw9oNOKIB7ajr8ZoGMwaFMe1bqF6
  2 | carol    | field |  60 | $2b$12$rMba3n9E6izG9TuwN0A3lO1/Y8aZfbwsubkUnZVC1jSigxVphct8K
  3 | dave     | field |  60 | $2b$12$EDbCSmdx9Qaq9pPkAIUx/OBv.TadHWGd9qiAlWQUUk9okF.5GSTCG
  4 | erin     | field |  60 | $2b$12$qifb0LrMY/wyOehTwvBxj.kMuBTwVfbSnvhy8xS/HpzKZizPE6ELm
(4 rows)


$ psql -d aidflow -c "rows whose hash is NOT cost-12 bcrypt (want 0)"
 not_bcrypt12 
--------------
            0
(1 row)


$ psql -d aidflow -c "rows where ANY column contains a known plaintext (want 0)"
 plaintext_hits 
----------------
              0
(1 row)

$ psql -d aidflow -c "control: same row-as-text LIKE technique, for a username that IS in the table"
 control_hits_for_username_carol 
---------------------------------
                               1
(1 row)
```
The control shows the row-as-text `LIKE` search does find text that is in the table, so the `0` above is a real negative rather than a broken query.


## SEC-11: Brute-force login is rate limited

| Field | Content |
|---|---|
| **ID** | SEC-11 |
| **Objective** | Show that six rapid bad logins from one client for one username are refused with 429, in the standard error shape with a `Retry-After` header. |
| **Preconditions** | Fresh limiter state (reset before each test). Case A: existing user `alice`. Case B: username `ghost` that does not exist. Same client IP in both. Limit: 5 attempts per minute per IP + username. |
| **Steps** | 1. Send 6 `POST /api/auth/login` requests in a row with a wrong password. 2. Record each status. 3. Inspect the 6th response. 4. Send the CORRECT password immediately afterwards. |
| **Expected result** | Attempts 1-5 return `401`; attempt 6 returns `429`, `RATE_LIMITED`, with a `Retry-After` of 1-60 seconds and no token. The same happens for an unknown user. The correct password is also refused while the limit holds. |
| **Actual result** | Statuses were `[401, 401, 401, 401, 401, 429]` for both the existing and the unknown user. The 6th response carried `Retry-After: 59` and the standard body. The correct password was refused with `429` too. |
| **Pass / Fail** | **PASS** |
| **Screenshot** | Not applicable: these are API-level automated tests with no UI. The terminal output below is the evidence. |

**Terminal output (pytest)**
```text
$ pytest -v app/tests/test_sec_02_03_11.py -k sec11
test_sec11_six_rapid_bad_logins_return_429[existing-user] PASSED [ 33%]
test_sec11_six_rapid_bad_logins_return_429[unknown-user] PASSED [ 66%]
test_sec11_the_block_holds_even_for_the_right_password PASSED [100%]
======================= 3 passed, 12 deselected in 5.32s =======================
```

**Observed HTTP exchange** (captured separately by replaying the scenario against the real app)
```text
# SEC-11  bad login #1 -> HTTP 401
# SEC-11  bad login #2 -> HTTP 401
# SEC-11  bad login #3 -> HTTP 401
# SEC-11  bad login #4 -> HTTP 401
# SEC-11  bad login #5 -> HTTP 401

# SEC-11  bad login #6
HTTP 429
Retry-After: 59
{"error": {"code": "RATE_LIMITED", "message": "Too many login attempts. Try again later."}}
```

**Relevant log lines** (existing-user case: five `login_failure` events, one `account_locked` event on the 5th failure, and no audit event for the rate-limited 6th request; see Observation 2)
```text
aidflow.audit:INFO:audit action=login_failure actor_id=None target=alice outcome=failure details={'reason': 'bad_password'}
client: POST http://testserver/api/auth/login "HTTP/1.1 401 Unauthorized"
aidflow.audit:INFO:audit action=login_failure actor_id=None target=alice outcome=failure details={'reason': 'bad_password'}
client: POST http://testserver/api/auth/login "HTTP/1.1 401 Unauthorized"
aidflow.audit:INFO:audit action=login_failure actor_id=None target=alice outcome=failure details={'reason': 'bad_password'}
client: POST http://testserver/api/auth/login "HTTP/1.1 401 Unauthorized"
aidflow.audit:INFO:audit action=login_failure actor_id=None target=alice outcome=failure details={'reason': 'bad_password'}
client: POST http://testserver/api/auth/login "HTTP/1.1 401 Unauthorized"
aidflow.audit:INFO:audit action=login_failure actor_id=None target=alice outcome=failure details={'reason': 'bad_password'}
aidflow.audit:INFO:audit action=account_locked actor_id=None target=alice outcome=failure details={'failed_attempts': 5, 'locked_minutes': 15, 'locked_until': '2026-11-27T05:17:34.374283+00:00'}
client: POST http://testserver/api/auth/login "HTTP/1.1 401 Unauthorized"
client: POST http://testserver/api/auth/login "HTTP/1.1 429 Too Many Requests"
```

**Detection check** (a defect was injected on purpose to prove the test can fail; source was restored afterwards)
```text
Defect: `LOGIN_MAX_ATTEMPTS = 6` -> 2 FAILED:

93:LOGIN_MAX_ATTEMPTS = 6
E       assert [401, 401, 401, 401, 401, 401] == [401, 401, 401, 401, 401, 429]
E       assert [401, 401, 401, 401, 401, 401] == [401, 401, 401, 401, 401, 429]
FAILED app/tests/test_sec_02_03_11.py::test_sec11_six_rapid_bad_logins_return_429[existing-user]
FAILED app/tests/test_sec_02_03_11.py::test_sec11_six_rapid_bad_logins_return_429[unknown-user]
2 failed, 1 passed, 12 deselected, 1 warning in 6.36s
```


## Observations and limitations

1. **Denied requests are not audited.** A `401` or `403` on a protected route produces no application log line or audit record; the only lines in the SEC-01 and SEC-02 logs come from the test client. If the Access Control Policy requires access-denied events in the audit log, that is not implemented yet.
2. **Rate-limited requests are not audited, by design.** Auditing every refused attempt would let an attacker flood the audit log. The lockout (`account_locked`) and each failed login are recorded.
3. **SEC-11 and account lockout overlap.** For an existing user, the 5th bad password locks the account, and the 6th request is then stopped by the rate limiter first (`429`). For an unknown user only the rate limiter acts. Both give the same `429` shape.
4. **The rate limiter keeps its counters in process memory.** With more than one uvicorn worker an attacker gets that many times the limit. Move the counters to Redis or the database first. Lockout is stored in the database and is unaffected.
5. **SEC-03 checks storage, not password strength.** It confirms cost-12 bcrypt format and absence of plaintext, not password policy.
6. **No screenshots.** None of these tests has a user interface.

## Supporting A-04 tests (not part of the IDs above)

`app/tests/test_login_protection.py` (23 tests): sliding-window behaviour, per-IP and per-username keys, `Retry-After`, lockout after 5 consecutive failures, 15-minute expiry, reset on success, lockout audit event, identical responses for locked and unknown accounts.
Migration `0002` was checked on SQLite and PostgreSQL (upgrade, downgrade, existing-row backfill, no model/migration drift), and 12 simultaneous wrong guesses on PostgreSQL were counted exactly (no lost updates, one lockout event).
