from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User, UserRole


class UserNotFoundError(Exception):
    pass


class AdminSelfLockoutError(Exception):
    pass


def get_all_users(db: Session) -> Sequence[User]:
    return db.scalars(select(User).order_by(User.id.asc())).all()


def get_user(db: Session, *, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise UserNotFoundError
    return user


def update_user(
    db: Session,
    *,
    user_id: int,
    acting_admin_id: int,
    role: UserRole | None = None,
    is_active: bool | None = None,
) -> User:
    user = get_user(db, user_id=user_id)
    if user.id == acting_admin_id and (
        role == UserRole.USER or is_active is False
    ):
        raise AdminSelfLockoutError

    if role is not None:
        user.role = role
    if is_active is not None:
        user.is_active = is_active

    db.commit()
    db.refresh(user)
    return user
