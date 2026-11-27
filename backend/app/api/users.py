from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.core.permissions import require_capability
from app.db.session import get_db
from app.models import User
from app.schemas.pagination import Page
from app.schemas.user import RoleUpdate, UserCreate, UserOut
from app.services import audit
from app.services.pagination import PageParams, paginate
from app.services.users import create_user, get_user_or_404

can_manage_users = require_capability("manage_users")

# Every route below requires an authenticated, active user holding the
# "manage_users" capability (see core/permissions.py). Setting it once on
# the router means a new route added here cannot forget the check.
router = APIRouter(prefix="/users", tags=["users"], dependencies=[Depends(can_manage_users)])


@router.post("", response_model=UserOut, status_code=201)
def create(body: UserCreate, db: Session = Depends(get_db), admin: User = Depends(can_manage_users)):
    user = create_user(db, body)
    audit.record(
        db, "user_create", actor_id=admin.id, target=user.username,
        details={"role": user.role},  # the password is deliberately not included
    )
    return user


@router.get("", response_model=Page[UserOut])
def list_users(params: PageParams = Depends(), db: Session = Depends(get_db)):
    # order_by is required for stable pages (see services/pagination.py).
    return paginate(db, select(User).order_by(User.id), params.page, params.page_size)


@router.get("/{user_id}", response_model=UserOut)
def get_one(user_id: int, db: Session = Depends(get_db)):
    return get_user_or_404(db, user_id)


@router.patch("/{user_id}/role", response_model=UserOut)
def change_role(
    user_id: int, body: RoleUpdate,
    db: Session = Depends(get_db), admin: User = Depends(can_manage_users),
):
    user = get_user_or_404(db, user_id)
    # An admin cannot demote themselves. Combined with the same rule on
    # deactivation, this guarantees the system can never be left with no admin.
    if user.id == admin.id and body.role.value != user.role:
        raise AppError(409, "SELF_CHANGE_FORBIDDEN", "You cannot change your own role")
    old_role = user.role
    user.role = body.role.value
    db.commit()
    db.refresh(user)
    audit.record(
        db, "role_change", actor_id=admin.id, target=user.username,
        details={"from": old_role, "to": user.role},
    )
    return user


def _set_active(db: Session, admin: User, user_id: int, active: bool) -> User:
    user = get_user_or_404(db, user_id)
    if user.id == admin.id and not active:
        raise AppError(409, "SELF_CHANGE_FORBIDDEN", "You cannot deactivate your own account")
    user.is_active = active
    db.commit()
    db.refresh(user)
    audit.record(
        db, "user_activate" if active else "user_deactivate",
        actor_id=admin.id, target=user.username,
    )
    return user


@router.post("/{user_id}/activate", response_model=UserOut)
def activate(user_id: int, db: Session = Depends(get_db), admin: User = Depends(can_manage_users)):
    return _set_active(db, admin, user_id, True)


@router.post("/{user_id}/deactivate", response_model=UserOut)
def deactivate(user_id: int, db: Session = Depends(get_db), admin: User = Depends(can_manage_users)):
    # No DELETE route exists on purpose: accounts are only ever switched off.
    return _set_active(db, admin, user_id, False)
