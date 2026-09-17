"""Security regression tests retained from the independent review."""

from unittest.mock import Mock
from html.parser import HTMLParser

import jwt
import pytest
from pydantic import ValidationError

from app.config import Settings, settings
from app.database import engine
from app.models.user import User, UserRole
from app.security import hash_password
from app.services import auth
from tests.helpers import get_csrf_headers


@pytest.fixture
def review_account(client_and_session):
    client, factory = client_and_session
    with factory() as db:
        user = User(username="review_admin", password_hash=hash_password("review password"),
                    role=UserRole.ADMIN, is_active=True)
        db.add(user)
        db.commit()
        user_id = user.id
    headers = get_csrf_headers(client)
    assert client.post("/api/auth/login", headers=headers, json={
        "username": "review_admin", "password": "review password",
    }).status_code == 200
    return client, factory, user_id, headers


UNSAFE = [
    ("POST", "/api/auth/register", {"username": "new_review", "password": "review password"}, 201),
    ("POST", "/api/auth/login", {"username": "review_admin", "password": "review password"}, 200),
    ("POST", "/api/auth/logout", None, 204),
    ("POST", "/api/notes", {"title": "review", "content": "text"}, 201),
    ("PATCH", "/api/notes/{note}", {"title": "changed"}, 200),
    ("DELETE", "/api/notes/{note}", None, 204),
    ("PATCH", "/api/admin/users/{user}", {"is_active": True}, 200),
]


@pytest.mark.parametrize("method,path,body,success", UNSAFE)
@pytest.mark.parametrize("mode", ["neither", "cookie_only", "header_only", "mismatch", "rotated", "valid"])
def test_csrf_matrix(review_account, method, path, body, success, mode):
    client, _, user_id, headers = review_account
    note_id = client.post("/api/notes", headers=headers,
                          json={"title": "review", "content": "text"}).json()["id"]
    if mode in {"neither", "header_only"}:
        del client.cookies[settings.csrf_cookie_name]
    if mode in {"neither", "cookie_only"}:
        headers = {}
    if mode == "mismatch":
        headers = {settings.csrf_header_name: "wrong"}
    if mode == "rotated":
        get_csrf_headers(client)
    response = client.request(method, path.format(note=note_id, user=user_id),
                              json=body, headers=headers)
    assert response.status_code == (success if mode == "valid" else 403)
    if mode != "valid":
        assert response.json() == {"detail": "Invalid CSRF token"}


@pytest.mark.parametrize("username,expected", [
    ("ab", 422), ("abc", 201), ("a" * 64, 201), ("a" * 65, 422),
    ("uſer", 422), ("straße", 422), ("Kelvin", 422), ("юзер", 422),
    ("<script>alert(1)</script>", 422),
])
def test_registration_username_boundaries(client_and_session, username, expected):
    client, _ = client_and_session
    response = client.post("/api/auth/register", headers=get_csrf_headers(client),
                           json={"username": username, "password": "valid password"})
    assert response.status_code == expected


@pytest.mark.parametrize("length,expected", [(7, 422), (8, 201), (128, 201), (129, 422)])
def test_registration_password_boundaries(client_and_session, length, expected):
    client, _ = client_and_session
    password = "p" * length
    response = client.post("/api/auth/register", headers=get_csrf_headers(client),
                           json={"username": "review_user", "password": password})
    assert response.status_code == expected
    assert password not in response.text
    assert "password_hash" not in response.text


@pytest.mark.parametrize("field,value,expected", [
    ("title", "", 422), ("title", "   ", 422), ("title", "x", 201),
    ("title", "x" * 200, 201), ("title", "x" * 201, 422),
    ("content", "", 201), ("content", "x" * 100000, 201),
    ("content", "x" * 100001, 422), ("title", "nul\x00title", 422),
    ("content", "nul\x00content", 422),
])
def test_note_boundaries(review_account, field, value, expected):
    client, _, _, headers = review_account
    data = {"title": "title", "content": "text", field: value}
    assert client.post("/api/notes", headers=headers, json=data).status_code == expected


@pytest.mark.parametrize(
    "subject",
    ["-1", "0", "abc", "1.0", str(2 ** 63), 1, None],
)
def test_bad_subject_is_unauthorized(client_and_session, subject):
    client, _ = client_and_session
    token = jwt.encode({"sub": subject, "exp": 4102444800},
                       settings.jwt_secret_key.get_secret_value(), algorithm="HS256")
    client.cookies.set(settings.access_token_cookie_name, token)
    assert client.get("/api/auth/me").status_code == 401


def test_changed_sub_cannot_impersonate_other_user(review_account):
    client, _, _, _ = review_account
    original = client.cookies.get(settings.access_token_cookie_name)
    payload = jwt.decode(original, options={"verify_signature": False})
    payload["sub"] = "99999"
    forged = jwt.encode(payload, "attacker-key-with-at-least-32-characters", algorithm="HS256")
    # Preserve the original signature but replace the payload segment.
    tampered = ".".join([original.split(".")[0], forged.split(".")[1], original.split(".")[2]])
    client.cookies.clear()
    client.cookies.set(settings.access_token_cookie_name, tampered)
    assert client.get("/api/auth/me").status_code == 401


@pytest.mark.parametrize("secure", [False, True])
def test_cookie_security_flags(review_account, monkeypatch, secure):
    client, _, _, _ = review_account
    monkeypatch.setattr(settings, "cookie_secure", secure)
    csrf = client.get("/api/auth/csrf")
    csrf_cookie = csrf.headers["set-cookie"].lower()
    assert ("secure" in csrf_cookie) is secure
    assert "httponly" not in csrf_cookie
    # Explicit Cookie header models HTTPS delivery when TestClient uses HTTP.
    token = csrf.json()["csrf_token"]
    response = client.post("/api/auth/login", headers={
        "Cookie": f"csrf_token={token}", "X-CSRF-Token": token,
    }, json={"username": "review_admin", "password": "review password"})
    cookie = response.headers["set-cookie"].lower()
    assert response.status_code == 200
    assert ("secure" in cookie) is secure
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie


def test_example_secret_must_be_rejected():
    with pytest.raises(ValidationError):
        Settings(_env_file=None,
                 jwt_secret_key="replace-with-a-random-secret-at-least-32-characters")


def test_random_secret_is_accepted():
    configured = Settings(
        _env_file=None,
        jwt_secret_key="R4ndom-test-secret-with-more-than-32-characters-917",
    )
    assert configured.jwt_secret_key.get_secret_value().startswith("R4ndom-")


def test_production_requires_secure_cookies():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", cookie_secure=False,
                 jwt_secret_key="audit-only-key-with-at-least-32-characters")


def test_development_allows_insecure_cookies():
    configured = Settings(
        _env_file=None,
        app_env="development",
        cookie_secure=False,
        jwt_secret_key="audit-only-key-with-at-least-32-characters",
    )
    assert configured.cookie_secure is False


def test_settings_validation_does_not_expose_jwt_secret():
    secret = "private-production-secret-with-at-least-32-characters"
    with pytest.raises(ValidationError) as raised:
        Settings(
            _env_file=None,
            app_env="production",
            cookie_secure=False,
            jwt_secret_key=secret,
        )
    assert secret not in str(raised.value)


def test_missing_user_performs_password_verification(client_and_session, monkeypatch):
    _, factory = client_and_session
    verify = Mock(return_value=False)
    monkeypatch.setattr(auth, "verify_password", verify)
    with factory() as db:
        with pytest.raises(auth.InvalidCredentialsError):
            auth.authenticate_user(db, "absent_user", "wrong password")
    verify.assert_called_once()


def test_database_engine_hides_sensitive_parameters():
    assert engine.hide_parameters is True


def test_non_ascii_csrf_is_controlled_forbidden(client_and_session):
    client, _ = client_and_session
    # Raw HTTP header bytes are decoded by ASGI; compare_digest(str, str) rejects non-ASCII.
    response = client.post("/api/auth/logout", headers=[
        (b"cookie", b"csrf_token=\xff"), (b"x-csrf-token", b"\xff"),
    ])
    assert response.status_code == 403
    assert response.json() == {"detail": "Invalid CSRF token"}


@pytest.mark.parametrize(
    "path",
    [
        "/api/notes/{resource_id}",
        "/api/admin/users/{resource_id}",
        "/api/admin/notes/{resource_id}",
    ],
)
def test_oversized_resource_id_is_controlled(review_account, path):
    client, _, _, _ = review_account
    response = client.get(path.format(resource_id=2 ** 63))
    assert response.status_code == 422


@pytest.mark.parametrize("path", ["/login", "/register"])
def test_password_form_has_no_native_get_fallback(client_and_session, path):
    class FormParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.methods = []

        def handle_starttag(self, tag, attrs):
            if tag == "form":
                self.methods.append(dict(attrs).get("method", "get").lower())

    client, _ = client_and_session
    parser = FormParser()
    parser.feed(client.get(path).text)
    assert parser.methods and all(method == "post" for method in parser.methods)
