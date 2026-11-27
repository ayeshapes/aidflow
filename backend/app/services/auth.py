"""Login logic, including failed-login tracking and account lockout."""
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

from sqlalchemy import case, select, update
from sqlalchemy.orm import Session

from app.core.security import burn_dummy_verification, verify_password
from app.models import User

# Lock the account after this many CONSECUTIVE failures, for this long.
MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION = timedelta(minutes=15)


def normalize_username(raw: str) -> str:
    return raw.strip().lower()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    # PostgreSQL returns timezone-aware values; SQLite (used by the tests)
    # drops the zone. We always store UTC, so a naive value means UTC.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class AuthResult(NamedTuple):
    user: User | None
    # Why it failed. For the audit log ONLY: the HTTP response is identical
    # for every reason, so callers must never send it to the client.
    reason: str | None = None
    # Set only when THIS failed attempt was the one that locked the account.
    newly_locked_until: datetime | None = None


def authenticate(db: Session, username: str, password: str) -> AuthResult:
    """Check credentials. Every failure costs one bcrypt check and looks the
    same from outside (unknown user, wrong password, disabled, locked)."""
    user = db.scalar(select(User).where(User.username == normalize_username(username)))

    if user is None:
        # Spend the same time as a real check (see core/security.py).
        burn_dummy_verification(password)
        return AuthResult(None, "unknown_user")

    now = _utcnow()
    locked_until = _as_utc(user.locked_until)
    if locked_until is not None:
        if locked_until > now:
            # Locked: refuse even a correct password. Attempts made while
            # locked are not counted and do not extend the lock; otherwise
            # anyone could keep an account locked forever by retrying.
            # The bcrypt check still runs so a locked account does not
            # answer faster than an unlocked one.
            burn_dummy_verification(password)
            return AuthResult(None, "account_locked")
        # The lock has run out: start from a clean slate, so the user gets
        # 5 fresh tries instead of being re-locked by a single typo.
        _clear_failures(db, user.id)
        locked_until = None

    # The password is checked BEFORE is_active. Otherwise a disabled account
    # would answer faster than an enabled one and reveal that it exists.
    if not verify_password(password, user.password_hash):
        return AuthResult(None, "bad_password", _register_failure(db, user.id, now))
    if not user.is_active:
        return AuthResult(None, "inactive_user")

    if user.failed_login_count or locked_until is not None:
        _clear_failures(db, user.id)
    return AuthResult(user)


def _register_failure(db: Session, user_id: int, now: datetime) -> datetime | None:
    """Count one failed login; lock the account if that makes MAX_FAILED_LOGINS.

    ONE atomic UPDATE ... RETURNING: the database adds 1 to whatever the
    current value is. Reading the count into Python and writing back count+1
    would let two simultaneous guesses both write the same number, handing an
    attacker extra attempts.

    Returns the lock expiry if this attempt triggered the lockout, else None.
    Only the request that sees the count reach exactly MAX_FAILED_LOGINS
    reports it, so the lockout is audited once.
    """
    until = now + LOCKOUT_DURATION
    result = db.execute(
        update(User)
        .where(User.id == user_id)
        .values(
            failed_login_count=User.failed_login_count + 1,
            locked_until=case(
                (User.failed_login_count + 1 >= MAX_FAILED_LOGINS, until),
                else_=User.locked_until,
            ),
        )
        .returning(User.failed_login_count)
        .execution_options(synchronize_session=False)
    )
    new_count = result.scalar_one()
    # Commit now: the request is about to fail with a 401, and the failure
    # must be stored anyway.
    db.commit()
    return until if new_count == MAX_FAILED_LOGINS else None


def _clear_failures(db: Session, user_id: int) -> None:
    db.execute(
        update(User)
        .where(User.id == user_id)
        .values(failed_login_count=0, locked_until=None)
        .execution_options(synchronize_session=False)
    )
    db.commit()
