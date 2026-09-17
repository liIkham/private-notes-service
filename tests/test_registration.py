from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.models.user import User, UserRole
from app.security import hash_password, verify_password
from app.services.auth import UsernameAlreadyExistsError, register_user
from tests.helpers import get_csrf_headers


class FakePostgresDiagnostic:
    def __init__(self, constraint_name: str | None) -> None:
        self.constraint_name = constraint_name


class FakePostgresError(Exception):
    def __init__(self, sqlstate: str, constraint_name: str | None) -> None:
        super().__init__("simulated database error")
        self.sqlstate = sqlstate
        self.diag = FakePostgresDiagnostic(constraint_name)


def make_integrity_error(sqlstate: str, constraint_name: str | None) -> IntegrityError:
    return IntegrityError(
        "INSERT",
        {},
        FakePostgresError(sqlstate, constraint_name),
    )


def test_register_user_successfully(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    plaintext_password = "correct horse battery staple"
    csrf_headers = get_csrf_headers(client)

    response = client.post(
        "/api/auth/register",
        json={"username": "  IlHaM  ", "password": plaintext_password},
        headers=csrf_headers,
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["username"] == "ilham"
    assert payload["role"] == "user"
    assert payload["is_active"] is True
    assert "password" not in payload
    assert "password_hash" not in payload

    with session_factory() as db:
        user = db.scalar(select(User).where(User.username == "ilham"))

    assert user is not None
    assert user.role == UserRole.USER
    assert user.password_hash != plaintext_password
    assert plaintext_password not in user.password_hash
    assert verify_password(plaintext_password, user.password_hash)


def test_duplicate_normalized_username_returns_conflict(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    password = "a sufficiently long password"
    csrf_headers = get_csrf_headers(client)

    first_response = client.post(
        "/api/auth/register",
        json={"username": "Ilham", "password": password},
        headers=csrf_headers,
    )
    duplicate_response = client.post(
        "/api/auth/register",
        json={"username": "  ILHAM  ", "password": password},
        headers=csrf_headers,
    )

    assert first_response.status_code == 201
    assert duplicate_response.status_code == 409
    assert duplicate_response.json() == {"detail": "Username is already registered"}

    with session_factory() as db:
        user_count = db.scalar(select(func.count()).select_from(User))
    assert user_count == 1


@pytest.mark.parametrize(
    "username",
    ["ab", "a" * 65, "invalid name", "user!", "пользователь"],
)
def test_invalid_username_is_rejected(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    username: str,
) -> None:
    client, _ = client_and_session
    csrf_headers = get_csrf_headers(client)

    response = client.post(
        "/api/auth/register",
        json={"username": username, "password": "valid password"},
        headers=csrf_headers,
    )

    assert response.status_code == 422


def test_unicode_rejected_before_casefold_can_produce_ascii(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    csrf_headers = get_csrf_headers(client)

    response = client.post(
        "/api/auth/register",
        json={"username": "uſer", "password": "valid password"},
        headers=csrf_headers,
    )

    assert response.status_code == 422
    with session_factory() as db:
        user_count = db.scalar(select(func.count()).select_from(User))
    assert user_count == 0


@pytest.mark.parametrize("password", ["short", "x" * 129])
def test_invalid_password_is_rejected(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    password: str,
) -> None:
    client, _ = client_and_session
    csrf_headers = get_csrf_headers(client)

    response = client.post(
        "/api/auth/register",
        json={"username": "valid_user", "password": password},
        headers=csrf_headers,
    )

    assert response.status_code == 422
    assert all("input" not in error for error in response.json()["detail"])


def test_registration_rejects_role_escalation(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    csrf_headers = get_csrf_headers(client)

    response = client.post(
        "/api/auth/register",
        json={
            "username": "attacker",
            "password": "valid password",
            "role": "admin",
        },
        headers=csrf_headers,
    )

    assert response.status_code == 422
    with session_factory() as db:
        user_count = db.scalar(select(func.count()).select_from(User))
    assert user_count == 0


def test_hash_password_and_verify_password() -> None:
    plaintext_password = "another secure password"

    password_hash = hash_password(plaintext_password)

    assert password_hash != plaintext_password
    assert verify_password(plaintext_password, password_hash)
    assert not verify_password("wrong password", password_hash)


def test_integrity_error_is_rolled_back_and_mapped_to_duplicate(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, session_factory = client_and_session

    with session_factory() as db:
        rollback = Mock(wraps=db.rollback)
        monkeypatch.setattr(db, "rollback", rollback)
        monkeypatch.setattr(
            db,
            "commit",
            Mock(side_effect=make_integrity_error("23505", "uq_users_username")),
        )

        with pytest.raises(UsernameAlreadyExistsError):
            register_user(db, "race_user", "valid password")

        rollback.assert_called_once_with()


@pytest.mark.parametrize(
    "integrity_error",
    [
        make_integrity_error("23505", "uq_users_other_field"),
        make_integrity_error("23502", None),
    ],
)
def test_other_integrity_error_is_rolled_back_and_reraised(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
    integrity_error: IntegrityError,
) -> None:
    _, session_factory = client_and_session

    with session_factory() as db:
        rollback = Mock(wraps=db.rollback)
        monkeypatch.setattr(db, "rollback", rollback)
        monkeypatch.setattr(db, "commit", Mock(side_effect=integrity_error))

        with pytest.raises(IntegrityError) as raised:
            register_user(db, "other_error", "valid password")

        assert raised.value is integrity_error
        rollback.assert_called_once_with()
