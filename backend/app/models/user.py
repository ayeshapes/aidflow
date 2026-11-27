"""User account table."""
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Role(str, Enum):
    """The four roles from the project brief. Anything else is rejected."""

    admin = "admin"
    warehouse = "warehouse"
    field = "field"
    auditor = "auditor"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    # Belt and braces: even if some future code path skips the Pydantic check,
    # the database itself refuses a role that is not on the list.
    __table_args__ = (
        CheckConstraint(
            "role IN ('admin', 'warehouse', 'field', 'auditor')", name="ck_users_role"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Stored lower-case, so "Alice" and "alice" can never be two accounts.
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    # Only the bcrypt hash is ever stored. There is no column for a plaintext password.
    password_hash: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(20))
    # Accounts are switched off, never deleted, so audit records keep pointing
    # at a real user row.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Brute-force defence (ticket A-04). Both are changed ONLY by
    # services/auth.py, with single atomic UPDATE statements.
    # Consecutive failed logins; set back to 0 by a successful login.
    failed_login_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default=text("0")
    )
    # While this is in the future, login is refused whatever the password.
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
