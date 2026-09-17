from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker


def test_root_redirects_to_notes(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, _ = client_and_session

    response = client.get("/", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"] == "/notes"


@pytest.mark.parametrize(
    ("path", "expected_text", "script_name"),
    [
        ("/login", "Вход", "login.js"),
        ("/register", "Регистрация", "register.js"),
        ("/notes", "Мои заметки", "notes.js"),
        ("/admin", "Админ-панель", "admin.js"),
    ],
)
def test_page_routes_return_html(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    path: str,
    expected_text: str,
    script_name: str,
) -> None:
    client, _ = client_and_session

    response = client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert expected_text in response.text
    assert f"/static/js/{script_name}" in response.text
    assert "/static/css/styles.css" in response.text


@pytest.mark.parametrize(
    ("path", "content_type"),
    [
        ("/static/css/styles.css", "text/css"),
        ("/static/js/api.js", "text/javascript"),
        ("/static/js/login.js", "text/javascript"),
        ("/static/js/register.js", "text/javascript"),
        ("/static/js/notes.js", "text/javascript"),
        ("/static/js/admin.js", "text/javascript"),
    ],
)
def test_frontend_static_files_are_available(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    path: str,
    content_type: str,
) -> None:
    client, _ = client_and_session

    response = client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(content_type)
    assert response.content


def test_frontend_javascript_does_not_handle_jwt_or_use_unsafe_html() -> None:
    javascript_directory = Path(__file__).parents[1] / "app" / "static" / "js"
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(javascript_directory.glob("*.js"))
    )

    assert "innerHTML" not in source
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "access_token" not in source
    assert "Authorization" not in source


@pytest.mark.parametrize(
    "path",
    ["/login", "/register", "/notes", "/admin", "/api/auth/me"],
)
def test_security_headers_are_applied(
    client_and_session: tuple[TestClient, sessionmaker[Session]],
    path: str,
) -> None:
    client, _ = client_and_session

    response = client.get(path)

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in response.headers


def test_logout_script_retries_stale_csrf_without_false_redirect() -> None:
    source = (
        Path(__file__).parents[1] / "app" / "static" / "js" / "api.js"
    ).read_text(encoding="utf-8")

    assert "await getCsrfToken(true)" in source
    assert "Сессия остаётся активной" in source
    assert source.count('window.location.replace("/login")') == 1
