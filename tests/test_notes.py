from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

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
) -> User:
    with session_factory() as db:
        user = User(
            username=username,
            password_hash=hash_password(TEST_PASSWORD),
            role=role,
            is_active=True,
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
    content: str = "content",
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> Note:
    values: dict[str, object] = {
        "owner_id": owner_id,
        "title": title,
        "content": content,
    }
    if created_at is not None:
        values["created_at"] = created_at
    if updated_at is not None:
        values["updated_at"] = updated_at

    with session_factory() as db:
        note = Note(**values)
        db.add(note)
        db.commit()
        db.refresh(note)
        return note


def login(client: TestClient, username: str) -> dict[str, str]:
    csrf_headers = get_csrf_headers(client)
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": TEST_PASSWORD},
        headers=csrf_headers,
    )
    assert response.status_code == 200
    return csrf_headers


@pytest.mark.parametrize(
    ("method", "path", "json_body"),
    [
        ("post", "/api/notes", {"title": "Title", "content": "Content"}),
        ("get", "/api/notes", None),
        ("get", "/api/notes/1", None),
        ("patch", "/api/notes/1", {"title": "Changed"}),
        ("delete", "/api/notes/1", None),
    ],
)
def test_notes_endpoints_require_authentication(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    method: str,
    path: str,
    json_body: dict[str, str] | None,
) -> None:
    client, _ = client_and_session
    csrf_headers = get_csrf_headers(client)

    response = client.request(method, path, json=json_body, headers=csrf_headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_create_note_sets_backend_owner_and_returns_safe_schema(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    user = create_user(session_factory, username="alice")
    other = create_user(session_factory, username="bob")
    csrf_headers = login(client, user.username)

    response = client.post(
        "/api/notes",
        json={"title": "  Shopping  ", "content": "Buy milk\n  and bread"},
        headers=csrf_headers,
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["title"] == "Shopping"
    assert payload["content"] == "Buy milk\n  and bread"
    assert payload["created_at"]
    assert payload["updated_at"]
    assert "owner_id" not in payload

    with session_factory() as db:
        note = db.get(Note, payload["id"])
        assert note is not None
        assert note.owner_id == user.id

    rejected = client.post(
        "/api/notes",
        json={"title": "Attack", "content": "No", "owner_id": other.id},
        headers=csrf_headers,
    )
    assert rejected.status_code == 422
    with session_factory() as db:
        count = db.scalar(select(func.count()).select_from(Note))
    assert count == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"title": "   ", "content": "Content"},
        {"title": "x" * 201, "content": "Content"},
        {"title": "Title", "content": "x" * 100_001},
    ],
)
def test_create_note_rejects_invalid_title_or_oversized_content(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    payload: dict[str, str],
) -> None:
    client, session_factory = client_and_session
    user = create_user(session_factory, username="alice")
    csrf_headers = login(client, user.username)

    response = client.post("/api/notes", json=payload, headers=csrf_headers)

    assert response.status_code == 422
    with session_factory() as db:
        assert db.scalar(select(func.count()).select_from(Note)) == 0


def test_list_returns_only_current_users_notes_in_stable_order(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    alice = create_user(session_factory, username="alice")
    bob = create_user(session_factory, username="bob")
    create_note(
        session_factory,
        owner_id=alice.id,
        title="Alice older",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    create_note(
        session_factory,
        owner_id=bob.id,
        title="Bob private",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    create_note(
        session_factory,
        owner_id=alice.id,
        title="Alice newer",
        created_at=datetime(2025, 2, 1, tzinfo=timezone.utc),
    )
    login(client, alice.username)

    response = client.get("/api/notes")

    assert response.status_code == 200
    assert [note["title"] for note in response.json()] == [
        "Alice newer",
        "Alice older",
    ]


def test_read_own_note_and_hide_foreign_note_existence(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    alice = create_user(session_factory, username="alice")
    bob = create_user(session_factory, username="bob")
    own = create_note(session_factory, owner_id=alice.id, title="Own")
    foreign = create_note(session_factory, owner_id=bob.id, title="Foreign")
    login(client, alice.username)

    own_response = client.get(f"/api/notes/{own.id}")
    foreign_response = client.get(f"/api/notes/{foreign.id}")
    missing_response = client.get("/api/notes/999999")

    assert own_response.status_code == 200
    assert own_response.json()["id"] == own.id
    assert foreign_response.status_code == missing_response.status_code == 404
    assert foreign_response.json() == missing_response.json() == {
        "detail": "Note not found"
    }


def test_patch_updates_only_allowed_fields_and_timestamp(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    alice = create_user(session_factory, username="alice")
    old_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    note = create_note(
        session_factory,
        owner_id=alice.id,
        title="Before",
        content="Old content",
        created_at=old_time,
        updated_at=old_time,
    )
    csrf_headers = login(client, alice.username)

    title_response = client.patch(
        f"/api/notes/{note.id}",
        json={"title": "  After  "},
        headers=csrf_headers,
    )
    content_response = client.patch(
        f"/api/notes/{note.id}",
        json={"content": "New\n content"},
        headers=csrf_headers,
    )
    both_response = client.patch(
        f"/api/notes/{note.id}",
        json={"title": "Final", "content": "Final content"},
        headers=csrf_headers,
    )

    assert title_response.status_code == 200
    assert title_response.json()["title"] == "After"
    assert title_response.json()["content"] == "Old content"
    assert content_response.status_code == 200
    assert content_response.json()["content"] == "New\n content"
    assert both_response.status_code == 200
    assert both_response.json()["title"] == "Final"
    assert both_response.json()["content"] == "Final content"
    updated_at = datetime.fromisoformat(both_response.json()["updated_at"])
    assert updated_at.replace(tzinfo=timezone.utc) > old_time

    for forbidden_payload in (
        {},
        {"owner_id": 999},
        {"id": 999},
        {"created_at": "2020-01-01T00:00:00Z"},
        {"updated_at": "2020-01-01T00:00:00Z"},
    ):
        assert (
            client.patch(
                f"/api/notes/{note.id}",
                json=forbidden_payload,
                headers=csrf_headers,
            ).status_code
            == 422
        )


def test_foreign_note_is_unchanged_after_idor_attempts(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    alice = create_user(session_factory, username="alice")
    bob = create_user(session_factory, username="bob")
    foreign = create_note(
        session_factory,
        owner_id=bob.id,
        title="Bob title",
        content="Bob content",
    )
    csrf_headers = login(client, alice.username)

    responses = [
        client.get(f"/api/notes/{foreign.id}"),
        client.patch(
            f"/api/notes/{foreign.id}",
            json={"title": "Stolen", "content": "Changed"},
            headers=csrf_headers,
        ),
        client.delete(f"/api/notes/{foreign.id}", headers=csrf_headers),
    ]

    assert all(response.status_code == 404 for response in responses)
    assert all(response.json() == {"detail": "Note not found"} for response in responses)
    with session_factory() as db:
        unchanged = db.get(Note, foreign.id)
        assert unchanged is not None
        assert unchanged.owner_id == bob.id
        assert unchanged.title == "Bob title"
        assert unchanged.content == "Bob content"


def test_delete_own_note_and_missing_note_have_expected_semantics(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    alice = create_user(session_factory, username="alice")
    note = create_note(session_factory, owner_id=alice.id, title="Delete me")
    csrf_headers = login(client, alice.username)

    response = client.delete(f"/api/notes/{note.id}", headers=csrf_headers)

    assert response.status_code == 204
    assert response.content == b""
    assert client.get(f"/api/notes/{note.id}").status_code == 404
    assert (
        client.delete("/api/notes/999999", headers=csrf_headers).status_code == 404
    )
    with session_factory() as db:
        assert db.get(Note, note.id) is None


def test_admin_has_no_bypass_in_personal_notes_routes(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, session_factory = client_and_session
    admin = create_user(
        session_factory,
        username="admin_user",
        role=UserRole.ADMIN,
    )
    other = create_user(session_factory, username="ordinary_user")
    own = create_note(session_factory, owner_id=admin.id, title="Admin own")
    foreign = create_note(session_factory, owner_id=other.id, title="User private")
    login(client, admin.username)

    response = client.get("/api/notes")

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [own.id]
    assert client.get(f"/api/notes/{foreign.id}").status_code == 404


def test_sqlite_test_database_enforces_note_owner_foreign_key(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    _, session_factory = client_and_session

    with session_factory() as db:
        db.add(Note(owner_id=999999, title="Orphan", content="Not allowed"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
