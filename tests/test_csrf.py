from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.models.user import User, UserRole
from app.security import hash_password
from tests.helpers import get_csrf_headers


TEST_PASSWORD = "correct horse battery staple"
LOGIN_PAYLOAD = {"username": "ilham", "password": TEST_PASSWORD}


def create_user(session_factory: sessionmaker[Session]) -> User:
    with session_factory() as db:
        user = User(
            username="ilham",
            password_hash=hash_password(TEST_PASSWORD),
            role=UserRole.USER,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def assert_invalid_csrf(response: Response) -> None:
    assert response.status_code == 403
    assert response.json() == {"detail": "Invalid CSRF token"}


def test_csrf_endpoint_sets_js_readable_cookie_and_rotates_token(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session

    first = client.get("/api/auth/csrf")

    assert first.status_code == 200
    first_token = first.json()["csrf_token"]
    assert first_token
    assert first.cookies[settings.csrf_cookie_name] == first_token
    cookie = first.headers["set-cookie"]
    cookie_attributes = {part.strip().lower() for part in cookie.split(";")[1:]}
    assert cookie.startswith(f"{settings.csrf_cookie_name}=")
    assert "httponly" not in cookie_attributes
    assert "samesite=lax" in cookie_attributes
    assert "path=/" in cookie_attributes
    assert "secure" not in cookie_attributes

    second = client.get("/api/auth/csrf")
    second_token = second.json()["csrf_token"]
    assert second_token != first_token
    assert client.cookies[settings.csrf_cookie_name] == second_token


def test_login_without_csrf_cookie_or_header_is_forbidden(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session

    assert_invalid_csrf(client.post("/api/auth/login", json=LOGIN_PAYLOAD))


def test_csrf_header_without_cookie_is_forbidden(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session

    response = client.post(
        "/api/auth/login",
        json=LOGIN_PAYLOAD,
        headers={settings.csrf_header_name: "header-only"},
    )

    assert_invalid_csrf(response)


def test_csrf_cookie_without_header_is_forbidden(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session
    client.get("/api/auth/csrf")

    assert_invalid_csrf(client.post("/api/auth/login", json=LOGIN_PAYLOAD))


def test_mismatched_csrf_cookie_and_header_are_forbidden(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session
    get_csrf_headers(client)

    response = client.post(
        "/api/auth/login",
        json=LOGIN_PAYLOAD,
        headers={settings.csrf_header_name: "different-token"},
    )

    assert_invalid_csrf(response)


def test_malformed_and_oversized_csrf_values_are_forbidden(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session

    for value in ["short", "x" * 1_000, "invalid+token/value"]:
        client.cookies.set(settings.csrf_cookie_name, value)
        response = client.post(
            "/api/auth/logout",
            headers={settings.csrf_header_name: value},
        )
        assert_invalid_csrf(response)


def test_valid_csrf_allows_login_note_creation_and_unprotected_gets(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    create_user(session_factory)
    csrf_headers = get_csrf_headers(client)

    login = client.post(
        "/api/auth/login",
        json=LOGIN_PAYLOAD,
        headers=csrf_headers,
    )
    create_note = client.post(
        "/api/notes",
        json={"title": "CSRF protected", "content": "Content"},
        headers=csrf_headers,
    )

    assert login.status_code == 200
    assert create_note.status_code == 201
    assert client.get("/health").status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/api/notes").status_code == 200


def test_authenticated_note_creation_without_csrf_is_forbidden(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    create_user(session_factory)
    csrf_headers = get_csrf_headers(client)
    assert client.post(
        "/api/auth/login",
        json=LOGIN_PAYLOAD,
        headers=csrf_headers,
    ).status_code == 200
    del client.cookies[settings.csrf_cookie_name]

    response = client.post(
        "/api/notes",
        json={"title": "Rejected", "content": "No CSRF"},
    )

    assert_invalid_csrf(response)
