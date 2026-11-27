"""A-01: login, logout, tokens, user management."""
import logging
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import security
from app.core.config import settings
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import TokenDenylist, User

ADMIN_PW = "admin-password-123"
USER_PW = "worker-password-456"


@pytest.fixture(scope="session")
def hashes():
    # bcrypt at cost 12 is slow on purpose, so hash each test password once.
    return {ADMIN_PW: hash_password(ADMIN_PW), USER_PW: hash_password(USER_PW)}


@pytest.fixture
def db_session():
    # StaticPool: every thread shares one in-memory SQLite database.
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    with factory() as session:
        yield session
    engine.dispose()


@pytest.fixture
def client(db_session):
    def override():
        # Separate session per request, like the real get_db.
        with sessionmaker(bind=db_session.get_bind(), autoflush=False)() as s:
            yield s

    app.dependency_overrides[get_db] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def make_user(db_session, hashes):
    def _make(username, role="field", active=True, password=USER_PW):
        user = User(username=username, password_hash=hashes[password], role=role, is_active=active)
        db_session.add(user)
        db_session.commit()
        return user

    return _make


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def token_for(client, username, password):
    response = login(client, username, password)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture
def admin(make_user):
    return make_user("admin1", role="admin", password=ADMIN_PW)


@pytest.fixture
def admin_token(client, admin):
    return token_for(client, "admin1", ADMIN_PW)


def forge(claims, secret=None, algorithm="HS256"):
    secret = secret or settings.jwt_secret
    return jwt.encode(claims, secret, algorithm=algorithm)


def good_claims(user_id, **override):
    claims = {
        "sub": str(user_id), "role": "admin", "jti": "forged-jti",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    claims.update(override)
    return claims


# ---------- password hashing ----------

def test_hash_is_bcrypt_cost_12_and_salted():
    h1, h2 = hash_password("some-long-password"), hash_password("some-long-password")
    assert h1.startswith("$2b$12$")
    assert h1 != h2  # random salt
    assert bcrypt.checkpw(b"some-long-password", h1.encode())


def test_verify_password_handles_overlong_and_garbage():
    h = hash_password("some-long-password")
    assert security.verify_password("some-long-password", h)
    assert not security.verify_password("x" * 100, h)
    assert not security.verify_password("some-long-password", "not-a-hash")


def test_db_stores_bcrypt_hash_not_plaintext(client, db_session, admin_token):
    pw = "brand-new-password-1"
    r = client.post(
        "/api/users", headers=auth(admin_token),
        json={"username": "newbie", "password": pw, "role": "field"},
    )
    assert r.status_code == 201
    stored = db_session.scalar(select(User).where(User.username == "newbie")).password_hash
    assert stored.startswith("$2b$12$")
    assert pw not in stored
    assert bcrypt.checkpw(pw.encode(), stored.encode())


# ---------- login ----------

def test_login_returns_jwt_with_required_claims(client, make_user):
    user = make_user("alice")
    body = login(client, "alice", USER_PW).json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == settings.access_token_expire_minutes * 60
    claims = jwt.decode(body["access_token"], settings.jwt_secret, algorithms=["HS256"])
    assert claims["sub"] == str(user.id) and claims["role"] == "field"
    assert claims["jti"]
    ttl = claims["exp"] - datetime.now(timezone.utc).timestamp()
    assert 0 < ttl <= settings.access_token_expire_minutes * 60


def test_login_username_is_case_insensitive(client, make_user):
    make_user("alice")
    assert login(client, "  ALICE ", USER_PW).status_code == 200


def test_wrong_username_and_wrong_password_look_identical(client, make_user):
    make_user("alice")
    bad_pw = login(client, "alice", "wrong-password-xx")
    bad_user = login(client, "nobody", "wrong-password-xx")
    assert bad_pw.status_code == bad_user.status_code == 401
    assert bad_pw.json() == bad_user.json()
    assert bad_pw.json()["error"]["message"] == "Invalid username or password"


def test_unknown_user_still_runs_a_bcrypt_check(client, monkeypatch):
    calls = []
    real = bcrypt.checkpw
    monkeypatch.setattr(
        security.bcrypt, "checkpw", lambda *a, **k: (calls.append(1), real(*a, **k))[1]
    )
    assert login(client, "ghost", "whatever-password").status_code == 401
    assert calls, "dummy hash must be checked so timing matches a real user"


def test_inactive_user_cannot_log_in_even_with_correct_password(client, make_user):
    make_user("sleepy", active=False)
    response = login(client, "sleepy", USER_PW)
    assert response.status_code == 401
    assert response.json() == login(client, "nobody", USER_PW).json()  # generic, same body


def test_login_never_logs_the_password(client, make_user, caplog):
    make_user("alice")
    secret = "super-secret-typed-password"
    with caplog.at_level(logging.DEBUG):
        login(client, "alice", secret)
        login(client, "alice", USER_PW)
    assert secret not in caplog.text and USER_PW not in caplog.text


def test_login_validation_errors_are_422_and_do_not_echo_password(client):
    secret = "p" * 300
    r = client.post("/api/auth/login", json={"username": "a", "password": secret})
    assert r.status_code == 422 and secret not in r.text
    assert client.post("/api/auth/login", json={"username": "a"}).status_code == 422


# ---------- tokens ----------

def test_me_returns_current_user_without_hash(client, admin, admin_token):
    r = client.get("/api/auth/me", headers=auth(admin_token))
    assert r.status_code == 200
    assert r.json()["username"] == "admin1"
    assert set(r.json()) == {"id", "username", "role", "is_active", "created_at"}


def test_missing_or_garbage_token_is_401(client):
    assert client.get("/api/auth/me").status_code == 401
    r = client.get("/api/auth/me", headers=auth("not.a.jwt"))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert r.json()["error"]["code"] == "UNAUTHORIZED"


def test_expired_token_is_rejected(client, admin):
    past = datetime.now(timezone.utc) - timedelta(seconds=5)
    token = forge(good_claims(admin.id, exp=past))
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401


def test_tampered_token_is_rejected(client, make_user, admin):
    token = token_for(client, "admin1", ADMIN_PW)
    header, payload, signature = token.split(".")
    # 1) flip a signature character
    flipped = signature[:-2] + ("A" if signature[-2] != "A" else "B") + signature[-1]
    assert client.get("/api/auth/me", headers=auth(f"{header}.{payload}.{flipped}")).status_code == 401
    # 2) a lowly user edits their payload to say role=admin, keeping the old signature
    make_user("worker")
    worker_token = token_for(client, "worker", USER_PW)
    h, p, s = worker_token.split(".")
    import base64, json
    claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    claims["role"] = "admin"
    forged_p = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    r = client.get("/api/auth/me", headers=auth(f"{h}.{forged_p}.{s}"))
    assert r.status_code == 401


def test_token_signed_with_wrong_secret_or_alg_none_is_rejected(client, admin):
    wrong = forge(good_claims(admin.id), secret="another-secret-another-secret-123456")
    assert client.get("/api/auth/me", headers=auth(wrong)).status_code == 401
    none_token = jwt.encode(good_claims(admin.id), key=None, algorithm="none")
    assert client.get("/api/auth/me", headers=auth(none_token)).status_code == 401


def test_token_missing_jti_is_rejected(client, admin):
    claims = good_claims(admin.id)
    del claims["jti"]
    assert client.get("/api/auth/me", headers=auth(forge(claims))).status_code == 401


def test_role_comes_from_database_not_token(client, admin, make_user):
    make_user("worker")
    # Valid signature, but claims role=admin for a field user.
    token = forge(good_claims(make_user("worker2").id, role="admin"))
    assert client.get("/api/users", headers=auth(token)).status_code == 403


# ---------- logout ----------

def test_logout_denylists_token(client, db_session, admin, admin_token):
    r = client.post("/api/auth/logout", headers=auth(admin_token))
    assert r.status_code == 200
    assert db_session.scalars(select(TokenDenylist)).all()
    assert client.get("/api/auth/me", headers=auth(admin_token)).status_code == 401
    assert client.post("/api/auth/logout", headers=auth(admin_token)).status_code == 401
    # a fresh login still works
    assert client.get("/api/auth/me", headers=auth(token_for(client, "admin1", ADMIN_PW))).status_code == 200


def test_logout_removes_expired_denylist_rows(client, db_session, admin, admin_token):
    db_session.add(TokenDenylist(jti="old", expires_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    db_session.commit()
    client.post("/api/auth/logout", headers=auth(admin_token))
    assert db_session.get(TokenDenylist, "old") is None


def test_deactivated_user_token_stops_working_immediately(client, admin_token, make_user):
    victim = make_user("victim")
    victim_token = token_for(client, "victim", USER_PW)
    assert client.get("/api/auth/me", headers=auth(victim_token)).status_code == 200
    assert client.post(f"/api/users/{victim.id}/deactivate", headers=auth(admin_token)).status_code == 200
    assert client.get("/api/auth/me", headers=auth(victim_token)).status_code == 401


# ---------- user management ----------

def test_non_admin_gets_403_and_anonymous_gets_401(client, make_user):
    make_user("worker")
    token = token_for(client, "worker", USER_PW)
    for method, path in [("get", "/api/users"), ("get", "/api/users/1"), ("post", "/api/users"),
                         ("patch", "/api/users/1/role"), ("post", "/api/users/1/activate"),
                         ("post", "/api/users/1/deactivate")]:
        assert getattr(client, method)(path, headers=auth(token)).status_code == 403, path
        assert getattr(client, method)(path).status_code == 401, path


def test_create_user_and_new_user_can_log_in(client, admin_token):
    r = client.post("/api/users", headers=auth(admin_token),
                    json={"username": "Bob.Smith", "password": "correct-horse-battery", "role": "warehouse"})
    assert r.status_code == 201
    assert r.json()["username"] == "bob.smith" and r.json()["is_active"] is True
    assert login(client, "bob.smith", "correct-horse-battery").status_code == 200


@pytest.mark.parametrize("payload", [
    {"username": "bob", "password": "short", "role": "field"},                # too short
    {"username": "bob", "password": "x" * 73, "role": "field"},               # over bcrypt limit
    {"username": "bob", "password": " " * 12, "role": "field"},               # only spaces
    {"username": "bob", "password": "long-enough-password", "role": "root"},  # bad role
    {"username": "b!", "password": "long-enough-password", "role": "field"},  # bad username
    {"username": "bob", "password": "long-enough-password", "role": "field", "is_admin": True},  # extra field
    {"username": "bob", "role": "field"},                                     # missing password
])
def test_create_user_invalid_input_is_422(client, admin_token, payload):
    r = client.post("/api/users", headers=auth(admin_token), json=payload)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
    if payload.get("password") and payload["password"].strip():
        assert payload["password"] not in r.text


def test_password_of_exactly_12_chars_is_accepted(client, admin_token):
    r = client.post("/api/users", headers=auth(admin_token),
                    json={"username": "twelve", "password": "123456789012", "role": "field"})
    assert r.status_code == 201


def test_duplicate_username_is_409(client, admin_token, make_user):
    make_user("taken")
    r = client.post("/api/users", headers=auth(admin_token),
                    json={"username": "TAKEN", "password": "long-enough-password", "role": "field"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "USERNAME_TAKEN"


def test_list_is_paginated(client, admin_token, make_user):
    for i in range(24):
        make_user(f"user{i:02d}")
    page1 = client.get("/api/users?page=1&page_size=10", headers=auth(admin_token)).json()
    page3 = client.get("/api/users?page=3&page_size=10", headers=auth(admin_token)).json()
    assert page1["total"] == 25 and len(page1["items"]) == 10 and page1["page"] == 1
    assert len(page3["items"]) == 5
    assert client.get("/api/users?page_size=1000", headers=auth(admin_token)).status_code == 422


def test_get_user_and_404(client, admin_token, admin):
    assert client.get(f"/api/users/{admin.id}", headers=auth(admin_token)).json()["username"] == "admin1"
    assert client.get("/api/users/9999", headers=auth(admin_token)).status_code == 404
    assert client.get("/api/users/abc", headers=auth(admin_token)).status_code == 422


def test_change_role(client, admin_token, make_user):
    u = make_user("worker")
    r = client.patch(f"/api/users/{u.id}/role", headers=auth(admin_token), json={"role": "auditor"})
    assert r.status_code == 200 and r.json()["role"] == "auditor"
    assert client.patch(f"/api/users/{u.id}/role", headers=auth(admin_token), json={"role": "god"}).status_code == 422


def test_deactivate_then_activate(client, admin_token, make_user):
    u = make_user("worker")
    assert client.post(f"/api/users/{u.id}/deactivate", headers=auth(admin_token)).json()["is_active"] is False
    assert login(client, "worker", USER_PW).status_code == 401
    assert client.post(f"/api/users/{u.id}/activate", headers=auth(admin_token)).json()["is_active"] is True
    assert login(client, "worker", USER_PW).status_code == 200


def test_admin_cannot_lock_themselves_out(client, admin, admin_token):
    assert client.post(f"/api/users/{admin.id}/deactivate", headers=auth(admin_token)).status_code == 409
    assert client.patch(f"/api/users/{admin.id}/role", headers=auth(admin_token), json={"role": "field"}).status_code == 409


def test_no_hard_delete(client, admin_token, make_user):
    u = make_user("worker")
    assert client.delete(f"/api/users/{u.id}", headers=auth(admin_token)).status_code == 405


def test_password_hash_never_appears_in_any_response(client, db_session, admin_token, make_user):
    u = make_user("worker")
    hashes_in_db = [x.password_hash for x in db_session.scalars(select(User))]
    responses = [
        client.get("/api/users", headers=auth(admin_token)),
        client.get(f"/api/users/{u.id}", headers=auth(admin_token)),
        client.post("/api/users", headers=auth(admin_token),
                    json={"username": "fresh", "password": "long-enough-password", "role": "field"}),
        client.patch(f"/api/users/{u.id}/role", headers=auth(admin_token), json={"role": "auditor"}),
        client.post(f"/api/users/{u.id}/deactivate", headers=auth(admin_token)),
        client.post(f"/api/users/{u.id}/activate", headers=auth(admin_token)),
        client.get("/api/auth/me", headers=auth(admin_token)),
    ]
    for r in responses:
        assert r.status_code in (200, 201), r.text
        assert "password" not in r.text.lower()
        assert "$2b$" not in r.text
        assert not any(h in r.text for h in hashes_in_db)


def test_audit_record_called_for_each_event(client, admin_token, make_user, monkeypatch):
    from app.services import audit
    events = []
    monkeypatch.setattr(audit, "record", lambda db, action, **kw: events.append((action, kw)))
    u = make_user("worker")
    login(client, "worker", "wrong-password-xx")
    token = token_for(client, "worker", USER_PW)
    client.post("/api/auth/logout", headers=auth(token))
    client.post("/api/users", headers=auth(admin_token),
                json={"username": "fresh", "password": "long-enough-password", "role": "field"})
    client.patch(f"/api/users/{u.id}/role", headers=auth(admin_token), json={"role": "auditor"})
    client.post(f"/api/users/{u.id}/deactivate", headers=auth(admin_token))
    client.post(f"/api/users/{u.id}/activate", headers=auth(admin_token))
    names = [e[0] for e in events]
    assert names == ["login_failure", "login_success", "logout", "user_create",
                     "role_change", "user_deactivate", "user_activate"]
    # No submitted password and no hash may reach the audit log.
    assert "wrong-password-xx" not in str(events)
    assert USER_PW not in str(events) and "long-enough-password" not in str(events)
    assert "$2b$" not in str(events)
