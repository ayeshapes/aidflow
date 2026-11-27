"""A-04: login rate limiting, failed-login tracking and account lockout."""
from datetime import datetime, timedelta, timezone

import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.core import security
from app.core.rate_limit import SlidingWindowLimiter, login_limiter
from app.main import app
from app.models import User
from app.services import audit

# Reuse the fixtures and helpers of the A-01 tests instead of copying them.
from app.tests.test_auth import (  # noqa: F401  (fixtures are used by name)
    ADMIN_PW, USER_PW, client, db_session, login, make_user,
)

WRONG = "wrong-password-xx"


def _cheap_hash(plain: str) -> str:
    # bcrypt cost 4 instead of 12. These tests make dozens of logins and do not
    # test hash strength (test_auth.py does), so this keeps them to seconds.
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=4)).decode()


@pytest.fixture(scope="session")
def hashes():  # overrides test_auth's fixture of the same name, for this module only
    return {ADMIN_PW: _cheap_hash(ADMIN_PW), USER_PW: _cheap_hash(USER_PW)}


@pytest.fixture(autouse=True)
def _cheap_dummy_hash(monkeypatch):
    # The "unknown user / locked account" path checks against a dummy hash.
    monkeypatch.setattr(security, "_DUMMY_HASH", _cheap_hash("dummy-password"))


def user_row(db_session, username) -> User:
    # A fresh session each time: the app commits from its own sessions.
    with sessionmaker(bind=db_session.get_bind())() as s:
        return s.scalar(select(User).where(User.username == username))


def _as_utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


@pytest.fixture
def no_rate_limit(monkeypatch):
    """Lockout tests make many attempts in a row; take the 429 out of the way."""
    monkeypatch.setattr("app.api.auth.login_limiter", SlidingWindowLimiter(10**9, 60))


# ---------------------------------------------------------------------------
# The limiter itself (fake clock: no sleeping)
# ---------------------------------------------------------------------------

class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_limiter_allows_max_hits_then_blocks_with_seconds_to_wait():
    clock = FakeClock()
    lim = SlidingWindowLimiter(5, 60, clock=clock)
    assert [lim.hit("k") for _ in range(5)] == [0, 0, 0, 0, 0]
    assert lim.hit("k") == 60
    clock.now += 45.2
    assert lim.hit("k") == 15  # whole seconds, rounded UP, so a retry is never too early


def test_limiter_window_slides_instead_of_resetting_on_the_minute():
    clock = FakeClock()
    lim = SlidingWindowLimiter(2, 60, clock=clock)
    assert lim.hit("k") == 0          # t=0
    clock.now += 30
    assert lim.hit("k") == 0          # t=30
    assert lim.hit("k") > 0           # full
    clock.now += 31                   # t=61: the t=0 hit has expired, the t=30 one has not
    assert lim.hit("k") == 0
    assert lim.hit("k") > 0


def test_limiter_refused_hits_are_not_recorded():
    clock = FakeClock()
    lim = SlidingWindowLimiter(1, 60, clock=clock)
    assert lim.hit("k") == 0
    for _ in range(100):  # hammering a blocked key...
        clock.now += 0.1
        assert lim.hit("k") > 0
    clock.now = 1000.0 + 60.5  # ...does not push the release time out
    assert lim.hit("k") == 0


def test_limiter_keys_are_independent():
    lim = SlidingWindowLimiter(1, 60, clock=FakeClock())
    assert lim.hit(("1.1.1.1", "alice")) == 0
    assert lim.hit(("1.1.1.1", "bob")) == 0
    assert lim.hit(("2.2.2.2", "alice")) == 0
    assert lim.hit(("1.1.1.1", "alice")) > 0


def test_limiter_forgets_idle_keys_so_memory_cannot_grow_forever():
    clock = FakeClock()
    lim = SlidingWindowLimiter(5, 60, clock=clock)
    for i in range(1000):
        lim.hit(("1.1.1.1", f"user{i}"))
    assert len(lim._hits) == 1000
    clock.now += 61
    lim.hit("trigger")  # the sweep runs inside hit()
    assert len(lim._hits) == 1


# ---------------------------------------------------------------------------
# Rate limiting through the real endpoint
# ---------------------------------------------------------------------------

def test_sixth_attempt_in_a_minute_is_429_in_the_standard_shape(client):
    # Unknown username: isolates the rate limit from the account lockout.
    for _ in range(5):
        assert login(client, "ghost", WRONG).status_code == 401
    r = login(client, "ghost", WRONG)
    assert r.status_code == 429
    assert r.json() == {"error": {"code": "RATE_LIMITED",
                                  "message": "Too many login attempts. Try again later."}}
    assert 1 <= int(r.headers["retry-after"]) <= 60


def test_rate_limit_counts_by_username_not_just_ip(client, make_user):
    make_user("alice")
    for _ in range(6):
        login(client, "ghost", WRONG)
    assert login(client, "ghost", WRONG).status_code == 429
    assert login(client, "alice", USER_PW).status_code == 200  # other username, same IP


def test_rate_limit_counts_by_ip_not_just_username(client):
    for _ in range(6):
        login(client, "ghost", WRONG)
    assert login(client, "ghost", WRONG).status_code == 429
    other_ip = TestClient(app, client=("10.9.8.7", 50000))
    assert login(other_ip, "ghost", WRONG).status_code == 401  # same username, other IP


def test_rate_limit_ignores_case_and_spaces_in_the_username(client):
    for name in ["ghost", "GHOST", " ghost ", "Ghost", "gHoSt"]:
        assert login(client, name, WRONG).status_code == 401
    assert login(client, "  GHOST", WRONG).status_code == 429


def test_rate_limited_request_never_reaches_bcrypt(client, monkeypatch):
    for _ in range(5):
        login(client, "ghost", WRONG)
    checks = []
    real = bcrypt.checkpw
    monkeypatch.setattr(security.bcrypt, "checkpw", lambda *a, **k: (checks.append(1), real(*a, **k))[1])
    assert login(client, "ghost", WRONG).status_code == 429
    assert checks == [], "a refused attempt must cost no password hashing"


def test_429_does_not_reveal_whether_the_account_exists(client, make_user):
    make_user("alice")
    bodies = []
    for name in ("alice", "ghost"):
        for _ in range(5):
            login(client, name, WRONG)
        r = login(client, name, WRONG)
        bodies.append((r.status_code, r.json(), "retry-after" in r.headers))
    assert bodies[0] == bodies[1] and bodies[0][0] == 429


def test_validation_errors_do_not_use_up_attempts(client):
    for _ in range(10):
        assert client.post("/api/auth/login", json={"username": "ghost"}).status_code == 422
    assert login(client, "ghost", WRONG).status_code == 401


# ---------------------------------------------------------------------------
# Failed-login tracking and lockout
# ---------------------------------------------------------------------------

def test_failures_are_counted_and_fifth_one_locks_for_15_minutes(client, db_session, make_user, no_rate_limit):
    make_user("alice")
    for n in range(1, 5):
        assert login(client, "alice", WRONG).status_code == 401
        row = user_row(db_session, "alice")
        assert row.failed_login_count == n and row.locked_until is None

    before = datetime.now(timezone.utc)
    assert login(client, "alice", WRONG).status_code == 401  # the 5th
    row = user_row(db_session, "alice")
    assert row.failed_login_count == 5
    remaining = _as_utc(row.locked_until) - before
    assert timedelta(minutes=14, seconds=55) < remaining < timedelta(minutes=15, seconds=5)


def test_locked_account_refuses_even_the_correct_password(client, make_user, no_rate_limit):
    make_user("alice")
    for _ in range(5):
        login(client, "alice", WRONG)
    r = login(client, "alice", USER_PW)
    assert r.status_code == 401
    assert "access_token" not in r.text


def test_locked_account_looks_exactly_like_an_unknown_user(client, make_user, no_rate_limit):
    """Otherwise 5 bad guesses would be an account-existence test."""
    make_user("alice")
    for _ in range(5):
        login(client, "alice", WRONG)
    locked = login(client, "alice", USER_PW)
    unknown = login(client, "ghost", USER_PW)
    assert (locked.status_code, locked.json()) == (unknown.status_code, unknown.json())
    assert dict(locked.headers).keys() == dict(unknown.headers).keys()


def test_locked_attempt_still_runs_one_bcrypt_check(client, make_user, no_rate_limit, monkeypatch):
    make_user("alice")
    for _ in range(5):
        login(client, "alice", WRONG)
    calls = []
    real = bcrypt.checkpw
    monkeypatch.setattr(security.bcrypt, "checkpw", lambda *a, **k: (calls.append(1), real(*a, **k))[1])
    login(client, "alice", USER_PW)
    assert len(calls) == 1, "same cost as any other login, so timing does not reveal the lock"


def test_attempts_while_locked_do_not_extend_the_lock(client, db_session, make_user, no_rate_limit):
    make_user("alice")
    for _ in range(5):
        login(client, "alice", WRONG)
    first = user_row(db_session, "alice")
    for _ in range(3):
        login(client, "alice", WRONG)
    again = user_row(db_session, "alice")
    assert (again.failed_login_count, again.locked_until) == (first.failed_login_count, first.locked_until)


def test_success_resets_the_counter_so_failures_must_be_consecutive(client, db_session, make_user, no_rate_limit):
    make_user("alice")
    for _ in range(4):
        login(client, "alice", WRONG)
    assert login(client, "alice", USER_PW).status_code == 200
    row = user_row(db_session, "alice")
    assert row.failed_login_count == 0 and row.locked_until is None
    for _ in range(4):  # 4 more failures: still not locked
        login(client, "alice", WRONG)
    assert login(client, "alice", USER_PW).status_code == 200


def test_lock_expires_and_the_user_gets_a_clean_slate(client, db_session, make_user, no_rate_limit):
    make_user("alice")
    for _ in range(5):
        login(client, "alice", WRONG)
    with sessionmaker(bind=db_session.get_bind())() as s:  # pretend 15 minutes passed
        s.get(User, user_row(db_session, "alice").id).locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        s.commit()

    # A typo right after expiry counts as failure 1, not as a 6th that re-locks.
    assert login(client, "alice", WRONG).status_code == 401
    row = user_row(db_session, "alice")
    assert row.failed_login_count == 1 and row.locked_until is None
    assert login(client, "alice", USER_PW).status_code == 200
    assert user_row(db_session, "alice").failed_login_count == 0


def test_correct_password_after_expiry_logs_in_and_clears_the_lock(client, db_session, make_user, no_rate_limit):
    make_user("alice")
    for _ in range(5):
        login(client, "alice", WRONG)
    with sessionmaker(bind=db_session.get_bind())() as s:
        s.get(User, user_row(db_session, "alice").id).locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        s.commit()
    assert login(client, "alice", USER_PW).status_code == 200
    row = user_row(db_session, "alice")
    assert row.failed_login_count == 0 and row.locked_until is None


def test_one_users_failures_do_not_touch_another_user(client, db_session, make_user, no_rate_limit):
    make_user("alice")
    make_user("bob")
    for _ in range(5):
        login(client, "alice", WRONG)
    assert login(client, "bob", USER_PW).status_code == 200
    assert user_row(db_session, "bob").failed_login_count == 0


def test_lockout_is_audited_once_at_the_fifth_failure(client, make_user, no_rate_limit, monkeypatch):
    events = []
    monkeypatch.setattr(audit, "record", lambda db, action, **kw: events.append((action, kw)))
    make_user("alice")
    for _ in range(4):
        login(client, "alice", WRONG)
    assert [e[0] for e in events] == ["login_failure"] * 4  # nothing about locking yet

    login(client, "alice", WRONG)
    login(client, "alice", USER_PW)  # refused while locked: a failure, but no second lockout record
    assert [e[0] for e in events] == ["login_failure"] * 5 + ["account_locked", "login_failure"]

    action, kw = events[5]
    assert kw["target"] == "alice" and kw["outcome"] == "failure"
    assert kw["details"]["failed_attempts"] == 5 and kw["details"]["locked_minutes"] == 15
    assert events[6][1]["details"] == {"reason": "account_locked"}
    assert WRONG not in str(events) and USER_PW not in str(events) and "$2b$" not in str(events)


def test_inactive_user_with_right_password_is_not_counted_as_a_failure(client, db_session, make_user, no_rate_limit):
    make_user("sleepy", active=False)
    for _ in range(6):
        assert login(client, "sleepy", USER_PW).status_code == 401
    assert user_row(db_session, "sleepy").failed_login_count == 0
