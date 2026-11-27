from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.core.permissions import bearer_scheme, get_current_user
from app.core.rate_limit import login_limiter
from app.core.security import create_access_token, decode_access_token
from app.db.session import get_db
from app.models import TokenDenylist, User
from app.schemas.auth import LoginRequest, MessageOut, TokenOut
from app.schemas.user import UserOut
from app.services import audit
from app.services.auth import LOCKOUT_DURATION, MAX_FAILED_LOGINS, authenticate, normalize_username

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    username = normalize_username(body.username)

    # Rate limit FIRST, before any database or bcrypt work, so a flood of
    # guesses is cheap to refuse. The key is (client IP, normalised username):
    # "Alice" and " alice " share one bucket. It applies to unknown usernames
    # too, so a 429 says nothing about whether an account exists.
    ip = request.client.host if request.client else "unknown"
    retry_after = login_limiter.hit((ip, username))
    if retry_after:
        raise AppError(
            429, "RATE_LIMITED", "Too many login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    result = authenticate(db, body.username, body.password)
    if result.user is None:
        # The audit log gets the real reason; the client gets a message that is
        # the same for wrong username, wrong password, disabled and locked
        # accounts. The password itself is never passed to audit or any logger.
        audit.record(
            db, "login_failure",
            target=username[:100],
            outcome="failure",
            details={"reason": result.reason},
        )
        if result.newly_locked_until is not None:
            audit.record(
                db, "account_locked",
                target=username[:100],
                outcome="failure",
                details={
                    "failed_attempts": MAX_FAILED_LOGINS,
                    "locked_minutes": int(LOCKOUT_DURATION.total_seconds() // 60),
                    "locked_until": result.newly_locked_until.isoformat(),
                },
            )
        raise AppError(401, "UNAUTHORIZED", "Invalid username or password")

    user = result.user
    token, expires_in = create_access_token(user.id, user.role)
    audit.record(db, "login_success", actor_id=user.id, target=user.username)
    return TokenOut(access_token=token, expires_in=expires_in)


@router.post("/logout", response_model=MessageOut)
def logout(
    user: User = Depends(get_current_user),  # proves the token is valid first
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    # Safe to decode again: get_current_user just accepted this exact token.
    claims = decode_access_token(credentials.credentials)
    expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)

    # Housekeeping: rows for tokens that have expired by themselves are useless.
    db.execute(delete(TokenDenylist).where(TokenDenylist.expires_at < datetime.now(timezone.utc)))
    db.add(TokenDenylist(jti=claims["jti"], expires_at=expires_at))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # two logouts raced; the token is already denied, which is the goal

    audit.record(db, "logout", actor_id=user.id, target=user.username)
    return MessageOut(message="Logged out")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
