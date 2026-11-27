import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.security import BCRYPT_MAX_BYTES
from app.models.user import Role

MIN_PASSWORD_LENGTH = 12
USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,49}$")


def validate_password_policy(value: str) -> str:
    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    # bcrypt silently ignores everything after 72 bytes. Better to say no than
    # to let someone believe their 100-character password is fully used.
    if len(value.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError(f"Password must be at most {BCRYPT_MAX_BYTES} bytes")
    if not value.strip():
        raise ValueError("Password must not be only spaces")
    return value


class UserCreate(BaseModel):
    username: str
    password: str = Field(repr=False)
    role: Role

    model_config = ConfigDict(extra="forbid")

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        # Lower-case so "Alice" and "alice" cannot be two different accounts.
        v = v.strip().lower()
        if not USERNAME_PATTERN.match(v):
            raise ValueError(
                "Username must be 3-50 characters: letters, digits, '.', '_' or '-'"
            )
        return v

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        return validate_password_policy(v)


class RoleUpdate(BaseModel):
    role: Role

    model_config = ConfigDict(extra="forbid")


class UserOut(BaseModel):
    """The ONLY shape in which a user leaves the API. It has no password_hash
    field, so the hash cannot leak, even by accident."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Role
    is_active: bool
    created_at: datetime
