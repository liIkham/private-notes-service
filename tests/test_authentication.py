from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.models.user import User, UserRole
from app.security import create_access_token, hash_password
from tests.helpers import get_csrf_headers


TEST_PASSWORD = "correct horse battery staple"


def create_user(
    session_factory: sessionmaker[Session],
    *,
    username: str = "ilham",
    is_active: bool = True,
) -> User:
    with session_factory() as db:
        user = User(
            username=username,
            password_hash=hash_password(TEST_PASSWORD),
            role=UserRole.USER,
            is_active=is_active,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def encode_test_token(payload: dict[str, object], secret: str | None = None) -> str:
    return jwt.encode(
        payload,
        secret or settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def test_login_sets_secure_cookie_and_cookie_authenticates_me(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    user = create_user(session_factory)
    csrf_headers = get_csrf_headers(client)

    response = client.post(
        "/api/auth/login",
        json={"username": "  ILHAM  ", "password": TEST_PASSWORD},
        headers=csrf_headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == user.id
    assert response.json()["username"] == "ilham"
    assert "password" not in response.json()
    assert "password_hash" not in response.json()

    set_cookie = response.headers["set-cookie"]
    cookie_attributes = {
        part.strip().lower() for part in set_cookie.split(";")[1:]
    }
    assert set_cookie.startswith(f"{settings.access_token_cookie_name}=")
    assert "httponly" in cookie_attributes
    assert "samesite=lax" in cookie_attributes
    assert "path=/" in cookie_attributes
    assert "secure" not in cookie_attributes

    token = response.cookies[settings.access_token_cookie_name]
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["sub"] == str(user.id)
    assert {"sub", "iat", "exp"} == set(payload)
    assert "password" not in payload
    assert "password_hash" not in payload

    me_response = client.get("/api/auth/me")
    assert me_response.status_code == 200
    assert me_response.json() == response.json()


def test_wrong_username_and_password_have_same_response(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    create_user(session_factory)
    csrf_headers = get_csrf_headers(client)

    wrong_username = client.post(
        "/api/auth/login",
        json={"username": "unknown", "password": TEST_PASSWORD},
        headers=csrf_headers,
    )
    wrong_password = client.post(
        "/api/auth/login",
        json={"username": "ilham", "password": "wrong password"},
        headers=csrf_headers,
    )

    assert wrong_username.status_code == 401
    assert wrong_password.status_code == 401
    assert wrong_username.json() == wrong_password.json() == {
        "detail": "Invalid username or password"
    }
    assert wrong_username.headers["www-authenticate"] == "Bearer"
    assert settings.access_token_cookie_name not in wrong_username.cookies
    assert settings.access_token_cookie_name not in wrong_password.cookies


def test_inactive_user_cannot_login_or_use_existing_token(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    user = create_user(session_factory, is_active=False)
    csrf_headers = get_csrf_headers(client)

    login_response = client.post(
        "/api/auth/login",
        json={"username": user.username, "password": TEST_PASSWORD},
        headers=csrf_headers,
    )
    assert login_response.status_code == 403
    assert settings.access_token_cookie_name not in login_response.cookies

    client.cookies.set(
        settings.access_token_cookie_name,
        create_access_token(user.id),
    )
    me_response = client.get("/api/auth/me")
    assert me_response.status_code == 403
    assert me_response.json() == {"detail": "Inactive user"}


def test_me_without_cookie_returns_unauthorized(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session

    response = client.get("/api/auth/me")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("token", ["not-a-jwt", "a.b.c"])
def test_me_rejects_malformed_token(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    token: str,
) -> None:
    client, _ = client_and_session
    client.cookies.set(settings.access_token_cookie_name, token)

    assert client.get("/api/auth/me").status_code == 401


def test_me_rejects_invalid_signature(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session
    token = encode_test_token(
        {
            "sub": "1",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        secret="different-test-secret-at-least-32-characters",
    )
    client.cookies.set(settings.access_token_cookie_name, token)

    assert client.get("/api/auth/me").status_code == 401


def test_me_rejects_expired_token(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session
    client.cookies.set(
        settings.access_token_cookie_name,
        create_access_token(1, expires_delta=timedelta(seconds=-1)),
    )

    assert client.get("/api/auth/me").status_code == 401


def test_me_rejects_token_without_expiration(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session
    client.cookies.set(
        settings.access_token_cookie_name,
        encode_test_token({"sub": "1"}),
    )

    assert client.get("/api/auth/me").status_code == 401


@pytest.mark.parametrize("subject", [None, "not-an-integer", "0", "01"])
def test_me_rejects_missing_or_invalid_subject(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    subject: str | None,
) -> None:
    client, _ = client_and_session
    payload: dict[str, object] = {
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    }
    if subject is not None:
        payload["sub"] = subject
    client.cookies.set(
        settings.access_token_cookie_name,
        encode_test_token(payload),
    )

    assert client.get("/api/auth/me").status_code == 401


def test_me_rejects_token_for_deleted_user(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session
    client.cookies.set(
        settings.access_token_cookie_name,
        create_access_token(999_999),
    )

    assert client.get("/api/auth/me").status_code == 401


def test_logout_deletes_cookie_and_me_becomes_unauthorized(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    create_user(session_factory)
    csrf_headers = get_csrf_headers(client)
    login_response = client.post(
        "/api/auth/login",
        json={"username": "ilham", "password": TEST_PASSWORD},
        headers=csrf_headers,
    )
    assert login_response.status_code == 200

    logout_response = client.post("/api/auth/logout", headers=csrf_headers)

    assert logout_response.status_code == 204
    assert logout_response.content == b""
    deletion_cookie = logout_response.headers["set-cookie"].lower()
    assert f"{settings.access_token_cookie_name}=\"\"" in deletion_cookie
    assert "max-age=0" in deletion_cookie
    assert settings.access_token_cookie_name not in client.cookies
    assert settings.csrf_cookie_name not in client.cookies
    assert client.get("/api/auth/me").status_code == 401
