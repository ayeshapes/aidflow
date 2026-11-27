"""Logged-out tokens. A JWT cannot be "taken back" once issued, so on logout we
remember its jti (unique id) here and get_current_user refuses it afterwards."""
from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TokenDenylist(Base):
    __tablename__ = "token_denylist"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Once a token is past its own expiry it is invalid anyway, so rows older
    # than this can be deleted. That keeps the table from growing forever.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
