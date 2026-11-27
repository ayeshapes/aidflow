"""SEC-02, SEC-03, SEC-11 (ticket A-04).

SEC-02  a field-officer token against admin endpoints -> 403
SEC-03  the users table holds bcrypt hashes and no plaintext password
SEC-11  six rapid bad logins -> 429
(SEC-01 lives in test_security.py.)
"""
import logging
import re

import bcrypt
import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from app.core.permissions import FIELD, roles_with
from app.main import app
from app.models import User

# Shared fixtures and helpers from the A-01 tests (real bcrypt cost 12 here:
# SEC-03 is about what production stores, so these tests do not use cheap hashes).
from app.tests.test_auth import (  # noqa: F401  (fixtures are used by name)
    ADMIN_PW, USER_PW, admin, admin_token, auth, client, db_session, hashes,
    login, make_user, token_for,
)

FORBIDDEN = {"error": {"code": "FORBIDDEN", "message": "You do not have permission to do this"}}


# ---------------------------------------------------------------------------
# SEC-02
# ---------------------------------------------------------------------------
def _flatten(routes):
    """Yield every concrete route, whichever way this FastAPI version nests them."""
    for route in routes:
        if hasattr(route, "effective_route_contexts"):
            yield from _flatten(route.effective_route_contexts())
        else:
            yield route


def _capabilities(dependant) -> set[str]:
    """Capabilities a route demands: require_capability() tags its checker."""
    found = set()
    for dep in dependant.dependencies:
        cap = getattr(dep.call, "capability", None)
        if cap:
            found.add(cap)
        found |= _capabilities(dep)
    return found


def _field_forbidden_routes() -> set[tuple[str, str]]:
    """Every (METHOD, path) that requires a capability the field role does NOT
    hold. Read from the live app, so a new admin route is covered automatically."""
    out = set()
    for route in _flatten(app.routes):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        caps = _capabilities(dependant)
        if any(FIELD not in roles_with(c) for c in caps):
            out |= {(m, route.path) for m in route.methods}
    return out


FIELD_FORBIDDEN = _field_forbidden_routes()
ADMIN_ENDPOINTS_TODAY = {
    ("GET", "/api/users"), ("POST", "/api/users"), ("GET", "/api/users/{user_id}"),
    ("PATCH", "/api/users/{user_id}/role"),
    ("POST", "/api/users/{user_id}/activate"), ("POST", "/api/users/{user_id}/deactivate"),
}


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


@pytest.fixture
def field_token(client, make_user):
    make_user("officer1", role="field")
    return token_for(client, "officer1", USER_PW)


def test_sec02_discovery_found_the_admin_endpoints():
    """Guard: the test must not pass by finding nothing to attack."""
    assert ADMIN_ENDPOINTS_TODAY <= FIELD_FORBIDDEN, sorted(ADMIN_ENDPOINTS_TODAY - FIELD_FORBIDDEN)


@pytest.mark.parametrize(
    "method,path",
    [pytest.param(m, p, id=f"{m} {p}") for m, p in sorted(FIELD_FORBIDDEN, key=lambda x: (x[1], x[0]))],
)
def test_sec02_field_officer_token_gets_403_on_admin_endpoints(client, field_token, method, path):
    response = client.request(method, _concrete(path), headers=auth(field_token))
    assert response.status_code == 403, f"{method} {path} -> {response.status_code}: {response.text}"
    assert response.json() == FORBIDDEN


def test_sec02_the_same_endpoint_works_for_an_admin(client, admin_token, field_token):
    """Control: the 403 is about the role, not about a broken endpoint."""
    assert client.get("/api/users", headers=auth(admin_token)).status_code == 200
    assert client.get("/api/users", headers=auth(field_token)).status_code == 403


def test_sec02_forbidden_requests_change_nothing(client, db_session, admin, field_token):
    """A 403 must also mean the action did not happen."""
    me = client.get("/api/auth/me", headers=auth(field_token)).json()
    h = auth(field_token)
    assert client.post("/api/users", headers=h, json={
        "username": "backdoor", "password": "long-enough-password", "role": "admin"}).status_code == 403
    assert client.patch(f"/api/users/{me['id']}/role", headers=h, json={"role": "admin"}).status_code == 403
    assert client.post(f"/api/users/{admin.id}/deactivate", headers=h).status_code == 403

    with sessionmaker(bind=db_session.get_bind())() as s:
        assert s.scalar(select(User).where(User.username == "backdoor")) is None
        assert s.get(User, me["id"]).role == "field"
        assert s.get(User, admin.id).is_active is True


# ---------------------------------------------------------------------------
# SEC-03
# ---------------------------------------------------------------------------
# '$2b$' + cost '12' + '$' + 22-char salt + 31-char hash = 60 characters.
BCRYPT_COST_12 = re.compile(r"^\$2[aby]\$12\$[./A-Za-z0-9]{53}$")

KNOWN_PASSWORDS = {
    "carol": "Tr0ub4dor&3-horse-staple",
    "dave": "correct-horse-battery-staple",
    "erin": "pa$$w0rd with spaces ünï",
}


@pytest.fixture
def populated(client, db_session, make_user, admin, admin_token):
    """Users made every way the app can make them, each with a known password."""
    plaintext = {"admin1": ADMIN_PW}
    make_user("alice")  # direct insert (as create_admin does)
    plaintext["alice"] = USER_PW
    for name, pw in KNOWN_PASSWORDS.items():  # through the public API
        r = client.post("/api/users", headers=auth(admin_token),
                        json={"username": name, "password": pw, "role": "field"})
        assert r.status_code == 201, r.text
        plaintext[name] = pw
    return plaintext


def test_sec03_every_stored_hash_is_bcrypt_and_none_contains_the_plaintext(db_session, populated):
    # Raw SQL, bypassing the ORM: this is what is physically in the table.
    rows = db_session.execute(text("SELECT * FROM users ORDER BY id")).mappings().all()
    assert len(rows) == len(populated) >= 5, "the table must actually contain the users"

    for row in rows:
        h = row["password_hash"]
        assert BCRYPT_COST_12.match(h), f"{row['username']}: not a cost-12 bcrypt hash: {h[:12]}..."
        assert len(h) == 60

    # No plaintext anywhere in ANY column of ANY row, not just in password_hash.
    everything = " | ".join(str(v) for row in rows for v in row.values())
    for user, pw in populated.items():
        assert pw not in everything, f"plaintext password of {user} found in the users table"

    # The hashes are real: each verifies against its own user's password, and only that one.
    by_user = {row["username"]: row["password_hash"] for row in rows}
    for user, pw in populated.items():
        assert bcrypt.checkpw(pw.encode(), by_user[user].encode()), user
        for other, other_pw in populated.items():
            if other != user:
                assert not bcrypt.checkpw(other_pw.encode(), by_user[user].encode())


def test_sec03_same_password_gets_different_hashes(client, db_session, admin_token):
    """Salting: two users with one password must not share a hash."""
    for name in ("frank", "grace"):
        client.post("/api/users", headers=auth(admin_token),
                    json={"username": name, "password": "shared-password-123", "role": "field"})
    h = dict(db_session.execute(
        text("SELECT username, password_hash FROM users WHERE username IN ('frank','grace')")).all())
    assert len(h) == 2 and h["frank"] != h["grace"]


def test_sec03_plaintext_and_hashes_do_not_reach_the_logs(client, admin_token, caplog):
    with caplog.at_level(logging.DEBUG):
        client.post("/api/users", headers=auth(admin_token),
                    json={"username": "heidi", "password": "log-me-if-you-dare-1", "role": "field"})
        login(client, "heidi", "log-me-if-you-dare-1")
        login(client, "heidi", "wrong-password-xx")
    assert "log-me-if-you-dare-1" not in caplog.text and "wrong-password-xx" not in caplog.text
    assert "$2b$" not in caplog.text
    assert "action=user_create" in caplog.text  # the events were logged, just without secrets


# ---------------------------------------------------------------------------
# SEC-11
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("username", ["alice", "ghost"], ids=["existing-user", "unknown-user"])
def test_sec11_six_rapid_bad_logins_return_429(client, make_user, username):
    make_user("alice")
    responses = [login(client, username, "wrong-password-xx") for _ in range(6)]

    assert [r.status_code for r in responses] == [401, 401, 401, 401, 401, 429]
    sixth = responses[-1]
    assert sixth.json() == {"error": {"code": "RATE_LIMITED",
                                      "message": "Too many login attempts. Try again later."}}
    assert 1 <= int(sixth.headers["retry-after"]) <= 60
    assert "access_token" not in sixth.text


def test_sec11_the_block_holds_even_for_the_right_password(client, make_user):
    make_user("alice")
    for _ in range(6):
        login(client, "alice", "wrong-password-xx")
    assert login(client, "alice", USER_PW).status_code == 429
