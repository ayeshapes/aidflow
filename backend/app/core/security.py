"""Password hashing and JWT helpers.

Nothing in this file logs anything. Passwords and tokens are secrets, so the
safest logging rule is "never pass them to a logger at all".
"""
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.core.config import settings

# Cost 12 means 2^12 rounds of work per hash (~0.2-0.3 s). That is slow enough
# to make mass password guessing expensive for an attacker who steals the
# database, but still unnoticeable for a person logging in.
BCRYPT_COST = 12

# bcrypt only reads the first 72 BYTES of a password. We refuse longer ones
# (see the password policy) instead of silently ignoring the tail.
BCRYPT_MAX_BYTES = 72


def hash_password(plain: str) -> str:
    """Return a salted bcrypt hash. gensalt() makes a fresh random salt each
    time, so two users with the same password get different hashes."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_COST)).decode("ascii")


def verify_password(plain: str, password_hash: str) -> bool:
    """Check a password against a stored hash. Never raises on bad input."""
    data = plain.encode("utf-8")
    if len(data) > BCRYPT_MAX_BYTES:
        # Cannot possibly match a hash we created (we never hash such passwords).
        # Newer bcrypt versions raise on this, so answer "no" ourselves.
        return False
    try:
        # checkpw compares in constant time, so response time does not reveal
        # how many leading characters were right.
        return bcrypt.checkpw(data, password_hash.encode("ascii"))
    except ValueError:
        # Malformed hash in the database: treat as "no match", not a crash.
        return False


# A real bcrypt hash of a random throw-away password, made once at startup.
# When someone logs in with a username that does not exist, we still run a
# full bcrypt check against this. Otherwise "unknown user" would answer in
# ~1 ms while "wrong password" takes ~250 ms, and an attacker could use that
# timing gap to discover which usernames exist.
_DUMMY_HASH = hash_password(uuid.uuid4().hex)


def burn_dummy_verification(plain: str) -> None:
    """Spend the same time a real password check would. The result is ignored."""
    verify_password(plain, _DUMMY_HASH)


def create_access_token(user_id: int, role: str) -> tuple[str, int]:
    """Make a signed JWT. Returns (token, lifetime_in_seconds).

    Claims:
      sub  who the token is for (the user id)
      role informational only: the server re-reads the role from the database
           on every request, so a role change or deactivation works immediately
      exp  expiry; PyJWT enforces it when we decode
      jti  unique id for this token, so logout can revoke just this one token
    """
    lifetime = timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": str(user_id),  # JWT spec says sub is a string
        "role": role,
        "exp": datetime.now(timezone.utc) + lifetime,
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, int(lifetime.total_seconds())


def decode_access_token(token: str) -> dict:
    """Verify signature and expiry and return the claims.

    Raises jwt.PyJWTError for ANY problem (bad signature, expired, malformed,
    missing claim). Callers turn that into one generic 401.
    """
    return jwt.decode(
        token,
        settings.jwt_secret,
        # We choose the allowed algorithm; we never trust the one named inside
        # the token. This blocks the classic "alg: none" and algorithm-swap tricks.
        algorithms=[settings.jwt_algorithm],
        # A token without these claims is refused, even if correctly signed.
        options={"require": ["exp", "sub", "jti"]},
    )
