from datetime import datetime, timezone

from sqlalchemy import Enum, UniqueConstraint

from app.models.user import User, UserRole
from app.schemas.user import UserRead


def test_user_table_metadata() -> None:
    table = User.__table__

    assert list(table.columns.keys()) == [
        "id",
        "username",
        "password_hash",
        "role",
        "is_active",
        "created_at",
    ]
    assert table.columns["username"].type.length == 64
    assert table.columns["password_hash"].type.length == 255
    assert table.columns["created_at"].type.timezone is True
    assert any(
        isinstance(constraint, UniqueConstraint)
        and [column.name for column in constraint.columns] == ["username"]
        for constraint in table.constraints
    )

    role_type = table.columns["role"].type
    assert isinstance(role_type, Enum)
    assert role_type.name == "user_role"
    assert role_type.enums == ["user", "admin"]


def test_user_read_does_not_expose_password_hash() -> None:
    user = User(
        id=1,
        username="alice",
        password_hash="not-a-plaintext-password",
        role=UserRole.USER,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )

    payload = UserRead.model_validate(user).model_dump()

    assert payload["username"] == "alice"
    assert payload["role"] == UserRole.USER
    assert "password_hash" not in payload
