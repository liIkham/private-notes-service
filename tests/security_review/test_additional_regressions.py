"""Additional security regression tests found during the independent review."""

import jwt
import pytest
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.models.note import Note
from app.models.user import User, UserRole
from app.security import create_access_token, hash_password


def test_actual_deleted_user_cannot_use_previously_issued_token(client_and_session):
    client, factory = client_and_session
    with factory() as db:
        user = User(username="deleted_review", password_hash=hash_password("review password"))
        db.add(user)
        db.commit()
        token = create_access_token(user.id)
        db.delete(user)
        db.commit()
    client.cookies.set(settings.access_token_cookie_name, token)
    assert client.get("/api/auth/me").status_code == 401


def test_signed_admin_claim_does_not_override_database_role(client_and_session):
    client, factory = client_and_session
    with factory() as db:
        user = User(username="claim_review", password_hash=hash_password("review password"),
                    role=UserRole.USER)
        db.add(user)
        db.commit()
        token = jwt.encode({"sub": str(user.id), "exp": 4102444800, "role": "admin"},
                           settings.jwt_secret_key.get_secret_value(), algorithm="HS256")
    client.cookies.set(settings.access_token_cookie_name, token)
    assert client.get("/api/auth/me").json()["role"] == "user"
    assert client.get("/api/admin/users").status_code == 403


def test_failed_write_does_not_expose_private_note_in_exception(client_and_session):
    _, factory = client_and_session
    sentinel = "PRIVATE_REVIEW_CONTENT_MUST_NOT_BE_LOGGED"
    with factory() as db:
        db.add(Note(owner_id=999999, title="review", content=sentinel))
        with pytest.raises(IntegrityError) as raised:
            db.commit()
        db.rollback()
    assert sentinel not in str(raised.value)
