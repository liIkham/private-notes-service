import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.user import User, UserRole
from app.scripts.create_admin import create_admin
from app.security import hash_password, verify_password
from app.services.auth import UsernameAlreadyExistsError


def test_create_admin_uses_normalized_username_and_secure_password_hash(
    client_and_session: tuple[object, sessionmaker[Session]],
) -> None:
    _, session_factory = client_and_session
    plaintext_password = "correct horse battery staple"

    with session_factory() as db:
        admin = create_admin(db, "  FIRST_Admin  ", plaintext_password)

        assert admin.username == "first_admin"
        assert admin.role == UserRole.ADMIN
        assert admin.is_active is True
        assert admin.password_hash != plaintext_password
        assert plaintext_password not in admin.password_hash
        assert verify_password(plaintext_password, admin.password_hash)


def test_create_admin_does_not_overwrite_an_existing_user(
    client_and_session: tuple[object, sessionmaker[Session]],
) -> None:
    _, session_factory = client_and_session
    original_hash = hash_password("original password")

    with session_factory() as db:
        existing_user = User(
            username="existing_user",
            password_hash=original_hash,
            role=UserRole.USER,
            is_active=True,
        )
        db.add(existing_user)
        db.commit()

        with pytest.raises(UsernameAlreadyExistsError):
            create_admin(db, "  EXISTING_USER ", "replacement password")

        stored_user = db.scalar(
            select(User).where(User.username == "existing_user")
        )
        user_count = db.scalar(select(func.count()).select_from(User))

        assert stored_user is not None
        assert stored_user.role == UserRole.USER
        assert stored_user.password_hash == original_hash
        assert user_count == 1


@pytest.mark.parametrize(
    "username",
    ["ab", "a" * 65, "invalid name", "user!", "uſer"],
)
def test_create_admin_rejects_invalid_username(
    client_and_session: tuple[object, sessionmaker[Session]],
    username: str,
) -> None:
    _, session_factory = client_and_session

    with session_factory() as db:
        with pytest.raises(ValidationError):
            create_admin(db, username, "valid password")

        assert db.scalar(select(func.count()).select_from(User)) == 0


@pytest.mark.parametrize("password", ["short", "x" * 129])
def test_create_admin_rejects_invalid_password(
    client_and_session: tuple[object, sessionmaker[Session]],
    password: str,
) -> None:
    _, session_factory = client_and_session

    with session_factory() as db:
        with pytest.raises(ValidationError):
            create_admin(db, "valid_admin", password)

        assert db.scalar(select(func.count()).select_from(User)) == 0
