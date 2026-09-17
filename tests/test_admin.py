from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.models.note import Note
from app.models.user import User, UserRole
from app.security import hash_password
from tests.helpers import get_csrf_headers


TEST_PASSWORD = "correct horse battery staple"


def create_user(
    session_factory: sessionmaker[Session],
    *,
    username: str,
    role: UserRole = UserRole.USER,
    is_active: bool = True,
) -> User:
    with session_factory() as db:
        user = User(
            username=username,
            password_hash=hash_password(TEST_PASSWORD),
            role=role,
            is_active=is_active,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def create_note(
    session_factory: sessionmaker[Session],
    *,
    owner_id: int,
    title: str,
    created_at: datetime,
) -> Note:
    with session_factory() as db:
        note = Note(
            owner_id=owner_id,
            title=title,
            content=f"Content for {title}",
            created_at=created_at,
            updated_at=created_at,
        )
        db.add(note)
        db.commit()
        db.refresh(note)
        return note


def login_and_get_token(client: TestClient, username: str) -> str:
    client.cookies.clear()
    csrf_headers = get_csrf_headers(client)
    client.headers.update(csrf_headers)
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": TEST_PASSWORD},
        headers=csrf_headers,
    )
    assert response.status_code == 200
    return response.cookies[settings.access_token_cookie_name]


def use_token(client: TestClient, token: str) -> None:
    csrf_token = client.cookies.get(settings.csrf_cookie_name)
    client.cookies.clear()
    if csrf_token is not None:
        client.cookies.set(settings.csrf_cookie_name, csrf_token)
    client.cookies.set(settings.access_token_cookie_name, token)


ADMIN_REQUESTS = [
    ("get", "/api/admin/users", None),
    ("get", "/api/admin/users/1", None),
    ("patch", "/api/admin/users/1", {"is_active": True}),
    ("get", "/api/admin/notes", None),
    ("get", "/api/admin/notes/1", None),
]


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_REQUESTS)
def test_anonymous_user_cannot_access_admin_api(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    method: str,
    path: str,
    body: dict[str, bool] | None,
) -> None:
    client, _ = client_and_session
    csrf_headers = get_csrf_headers(client)

    response = client.request(method, path, json=body, headers=csrf_headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_REQUESTS)
def test_regular_user_cannot_access_admin_api(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    method: str,
    path: str,
    body: dict[str, bool] | None,
) -> None:
    client, session_factory = client_and_session
    user = create_user(session_factory, username="regular_user")
    login_and_get_token(client, user.username)

    response = client.request(method, path, json=body)

    assert response.status_code == 403
    assert response.json() == {"detail": "Admin access required"}


def test_admin_lists_and_reads_users_without_secrets(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    admin = create_user(
        session_factory,
        username="admin_user",
        role=UserRole.ADMIN,
    )
    regular = create_user(session_factory, username="regular_user")
    login_and_get_token(client, admin.username)

    list_response = client.get("/api/admin/users")
    read_response = client.get(f"/api/admin/users/{regular.id}")
    missing_response = client.get("/api/admin/users/999999")

    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == [admin.id, regular.id]
    assert all("password" not in item for item in list_response.json())
    assert all("password_hash" not in item for item in list_response.json())
    assert read_response.status_code == 200
    assert read_response.json()["username"] == regular.username
    assert "password_hash" not in read_response.json()
    assert missing_response.status_code == 404
    assert missing_response.json() == {"detail": "User not found"}


def test_admin_can_update_user_role_and_active_state(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    admin = create_user(
        session_factory,
        username="admin_user",
        role=UserRole.ADMIN,
    )
    target = create_user(session_factory, username="target_user")
    login_and_get_token(client, admin.username)

    assert client.patch(
        f"/api/admin/users/{target.id}", json={"is_active": False}
    ).json()["is_active"] is False
    assert client.patch(
        f"/api/admin/users/{target.id}", json={"is_active": True}
    ).json()["is_active"] is True
    assert client.patch(
        f"/api/admin/users/{target.id}", json={"role": "admin"}
    ).json()["role"] == "admin"
    assert client.patch(
        f"/api/admin/users/{target.id}", json={"role": "user"}
    ).json()["role"] == "user"

    with session_factory() as db:
        updated = db.get(User, target.id)
        assert updated is not None
        assert updated.role == UserRole.USER
        assert updated.is_active is True


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"role": None},
        {"is_active": None},
        {"role": "owner"},
        {"username": "hacked"},
        {"password": "new password"},
        {"password_hash": "not-allowed"},
        {"created_at": "2026-01-01T00:00:00Z"},
    ],
)
def test_admin_user_update_rejects_invalid_or_forbidden_fields(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    payload: dict[str, object],
) -> None:
    client, session_factory = client_and_session
    admin = create_user(
        session_factory,
        username="admin_user",
        role=UserRole.ADMIN,
    )
    target = create_user(session_factory, username="target_user")
    login_and_get_token(client, admin.username)

    response = client.patch(f"/api/admin/users/{target.id}", json=payload)

    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [{"role": "user"}, {"is_active": False}],
)
def test_admin_cannot_demote_or_deactivate_self(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    payload: dict[str, object],
) -> None:
    client, session_factory = client_and_session
    admin = create_user(
        session_factory,
        username="admin_user",
        role=UserRole.ADMIN,
    )
    login_and_get_token(client, admin.username)

    response = client.patch(f"/api/admin/users/{admin.id}", json=payload)

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Admin cannot deactivate or demote own account"
    }
    with session_factory() as db:
        unchanged = db.get(User, admin.id)
        assert unchanged is not None
        assert unchanged.role == UserRole.ADMIN
        assert unchanged.is_active is True
    assert client.get("/api/admin/users").status_code == 200


def test_role_changes_apply_to_an_already_issued_token(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    admin = create_user(
        session_factory,
        username="admin_user",
        role=UserRole.ADMIN,
    )
    user = create_user(session_factory, username="regular_user")
    admin_token = login_and_get_token(client, admin.username)
    user_token = login_and_get_token(client, user.username)

    use_token(client, user_token)
    assert client.get("/api/admin/users").status_code == 403

    use_token(client, admin_token)
    promoted = client.patch(
        f"/api/admin/users/{user.id}", json={"role": "admin"}
    )
    assert promoted.status_code == 200

    use_token(client, user_token)
    assert client.get("/api/admin/users").status_code == 200

    use_token(client, admin_token)
    demoted = client.patch(
        f"/api/admin/users/{user.id}", json={"role": "user"}
    )
    assert demoted.status_code == 200

    use_token(client, user_token)
    assert client.get("/api/admin/users").status_code == 403


def test_deactivation_and_reactivation_apply_to_existing_token(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    admin = create_user(
        session_factory,
        username="admin_user",
        role=UserRole.ADMIN,
    )
    user = create_user(
        session_factory,
        username="second_admin",
        role=UserRole.ADMIN,
    )
    admin_token = login_and_get_token(client, admin.username)
    user_token = login_and_get_token(client, user.username)

    use_token(client, user_token)
    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/api/admin/users").status_code == 200

    use_token(client, admin_token)
    assert client.patch(
        f"/api/admin/users/{user.id}", json={"is_active": False}
    ).status_code == 200

    use_token(client, user_token)
    assert client.get("/api/auth/me").status_code == 403
    assert client.get("/api/notes").status_code == 403
    assert client.get("/api/admin/users").status_code == 403

    use_token(client, admin_token)
    assert client.patch(
        f"/api/admin/users/{user.id}", json={"is_active": True}
    ).status_code == 200

    use_token(client, user_token)
    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/api/admin/users").status_code == 200


def test_admin_notes_api_is_read_only_and_separate_from_personal_api(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    admin = create_user(
        session_factory,
        username="admin_user",
        role=UserRole.ADMIN,
    )
    alice = create_user(session_factory, username="alice")
    bob = create_user(session_factory, username="bob")
    admin_note = create_note(
        session_factory,
        owner_id=admin.id,
        title="Admin note",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    alice_note = create_note(
        session_factory,
        owner_id=alice.id,
        title="Alice note",
        created_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    bob_note = create_note(
        session_factory,
        owner_id=bob.id,
        title="Bob note",
        created_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    login_and_get_token(client, admin.username)

    all_notes = client.get("/api/admin/notes")
    foreign_admin_read = client.get(f"/api/admin/notes/{alice_note.id}")
    foreign_personal_read = client.get(f"/api/notes/{alice_note.id}")
    personal_list = client.get("/api/notes")

    assert all_notes.status_code == 200
    assert [item["id"] for item in all_notes.json()] == [
        bob_note.id,
        alice_note.id,
        admin_note.id,
    ]
    assert all("owner_id" in item for item in all_notes.json())
    assert foreign_admin_read.status_code == 200
    assert foreign_admin_read.json()["owner_id"] == alice.id
    assert foreign_personal_read.status_code == 404
    assert personal_list.status_code == 200
    assert [item["id"] for item in personal_list.json()] == [admin_note.id]
    assert "owner_id" not in personal_list.json()[0]

    assert client.get("/api/admin/notes/999999").status_code == 404
    assert client.patch(
        f"/api/admin/notes/{alice_note.id}", json={"title": "Changed"}
    ).status_code == 405
    assert client.delete(f"/api/admin/notes/{alice_note.id}").status_code == 405
