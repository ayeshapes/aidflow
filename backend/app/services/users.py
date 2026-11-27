"""User management logic (called by the admin-only routes)."""
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.core.security import hash_password
from app.models import User
from app.schemas.user import UserCreate


def create_user(db: Session, data: UserCreate) -> User:
    if db.scalar(select(User.id).where(User.username == data.username)):
        raise AppError(409, "USERNAME_TAKEN", "That username is already taken")
    user = User(
        username=data.username,
        # The plaintext password lives only in this function call. What gets
        # stored is the hash.
        password_hash=hash_password(data.password),
        role=data.role.value,
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # Two requests created the same username at the same moment.
        db.rollback()
        raise AppError(409, "USERNAME_TAKEN", "That username is already taken")
    db.refresh(user)
    return user


def get_user_or_404(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise AppError(404, "USER_NOT_FOUND", "User not found")
    return user
