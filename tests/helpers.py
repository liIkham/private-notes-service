from fastapi.testclient import TestClient

from app.config import settings


def get_csrf_headers(client: TestClient) -> dict[str, str]:
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    token = response.json()["csrf_token"]
    assert client.cookies.get(settings.csrf_cookie_name) == token
    return {settings.csrf_header_name: token}
