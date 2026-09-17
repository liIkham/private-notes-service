from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.user import User, UserRole
from app.normalization import normalize_username
from app.security import DUMMY_PASSWORD_HASH, hash_password, verify_password


UNIQUE_VIOLATION_SQLSTATE = "23505"
USERNAME_UNIQUE_CONSTRAINT = "uq_users_username"


class UsernameAlreadyExistsError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class InactiveUserError(Exception):
    pass


def is_username_unique_violation(exc: IntegrityError) -> bool:
    original_error = exc.orig
    sqlstate = getattr(original_error, "sqlstate", None)
    diagnostic = getattr(original_error, "diag", None)
    constraint_name = getattr(diagnostic, "constraint_name", None)
    return (
        sqlstate == UNIQUE_VIOLATION_SQLSTATE
        and constraint_name == USERNAME_UNIQUE_CONSTRAINT
    )


def register_user(db: Session, username: str, password: str) -> User:
    normalized_username = normalize_username(username)

    existing_user_id = db.scalar(
        select(User.id).where(User.username == normalized_username)
    )
    if existing_user_id is not None:
        raise UsernameAlreadyExistsError

    user = User(
        username=normalized_username,
        password_hash=hash_password(password),
        role=UserRole.USER,
        is_active=True,
    )
    db.add(user)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if is_username_unique_violation(exc):
            raise UsernameAlreadyExistsError from exc
        raise

    db.refresh(user)
    return user


def authenticate_user(db: Session, username: str, password: str) -> User:
    normalized_username = normalize_username(username)
    user = db.scalar(select(User).where(User.username == normalized_username))

    password_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    password_is_valid = verify_password(password, password_hash)
    if user is None or not password_is_valid:
        raise InvalidCredentialsError
    if not user.is_active:
        raise InactiveUserError
    return user
