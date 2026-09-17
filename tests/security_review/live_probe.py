"""Opt-in destructive probes, restricted to the disposable review PostgreSQL host."""

import base64
import json
import os
import statistics
import time

import httpx
import jwt
import psycopg


BASE = "http://notes-security-audit-20260917-api-1:8000"
DB_HOST = "notes-security-audit-20260917-db-1"
PASSWORD = "temporary audit password"
SECRET = "audit-only-secret-20260917-with-at-least-32-characters"


def csrf(client):
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def login(username, password=PASSWORD):
    client = httpx.Client(base_url=BASE, timeout=20)
    response = client.post("/api/auth/login", headers=csrf(client),
                           json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    assert "password" not in response.text and "token" not in response.text
    return client, response.json()


def main():
    assert os.environ.get("SECURITY_AUDIT_CONFIRM") == "isolated"
    result = {}
    with psycopg.connect(host=DB_HOST, dbname="notes", user="notes",
                         password=os.environ.get(
                             "AUDIT_DB_PASSWORD",
                             "audit_only_database_20260917",
                         )) as db:
        # This database exists only inside the named audit Compose project.
        for name in ["audit_alice", "audit_bob"]:
            with httpx.Client(base_url=BASE) as client:
                response = client.post("/api/auth/register", headers=csrf(client),
                                       json={"username": name, "password": PASSWORD})
                assert response.status_code == 201, response.text
        alice, a = login("audit_alice")
        bob, b = login("audit_bob")
        admin, root = login(
            os.environ.get("AUDIT_ADMIN_USERNAME", "audit_bootstrap"),
            os.environ["AUDIT_ADMIN_PASSWORD"],
        )
        clients = [alice, bob, admin]
        try:
            sql_payload = "'); DROP TABLE users; -- <script>window.auditXss=1</script>"
            notes = []
            for client in clients:
                response = client.post("/api/notes", headers=csrf(client),
                                       json={"title": "audit note", "content": sql_payload})
                assert response.status_code == 201
                notes.append(response.json())
            foreign = notes[1]["id"]
            for method in ["GET", "PATCH", "DELETE"]:
                kwargs = {"json": {"content": "attacker replacement"}} if method == "PATCH" else {}
                foreign_response = alice.request(method, f"/api/notes/{foreign}",
                                                 headers=csrf(alice), **kwargs)
                missing_response = alice.request(method, "/api/notes/999999",
                                                 headers=csrf(alice), **kwargs)
                assert foreign_response.status_code == missing_response.status_code == 404
                assert foreign_response.json() == missing_response.json()
            assert bob.get(f"/api/notes/{foreign}").json()["content"] == sql_payload
            for field, value in [("owner_id", b["id"]), ("id", 999),
                                 ("created_at", "2000-01-01T00:00:00Z"),
                                 ("updated_at", "2000-01-01T00:00:00Z")]:
                assert alice.post("/api/notes", headers=csrf(alice), json={
                    "title": "x", "content": "x", field: value}).status_code == 422
                assert alice.patch(f"/api/notes/{notes[0]['id']}", headers=csrf(alice),
                                   json={field: value}).status_code == 422
            result["idor_and_mass_assignment"] = "passed; foreign note unchanged"
            assert admin.get("/api/notes").json() == [notes[2]]
            assert admin.get(f"/api/notes/{foreign}").status_code == 404
            assert admin.get(f"/api/admin/notes/{foreign}").status_code == 200
            for method in ["PATCH", "DELETE"]:
                assert admin.request(method, f"/api/admin/notes/{foreign}",
                                     headers=csrf(admin), json={"content": "x"}).status_code == 405
            assert admin.post("/api/admin/notes", headers=csrf(admin), json={}).status_code == 405
            for client, expected in [(alice, 403), (httpx.Client(base_url=BASE), 401)]:
                for path in ["/api/admin/users", f"/api/admin/users/{a['id']}",
                             "/api/admin/notes", f"/api/admin/notes/{foreign}"]:
                    assert client.get(path).status_code == expected
                assert client.patch(f"/api/admin/users/{a['id']}", headers=csrf(client),
                                    json={"is_active": True}).status_code == expected
            for data in [{"role": "user"}, {"is_active": False}]:
                assert admin.patch(f"/api/admin/users/{root['id']}", headers=csrf(admin),
                                   json=data).status_code == 409
            old_jwt = alice.cookies.get("access_token")
            for role, expected in [("admin", 200), ("user", 403)]:
                assert admin.patch(f"/api/admin/users/{a['id']}", headers=csrf(admin),
                                   json={"role": role}).status_code == 200
                assert alice.get("/api/admin/users").status_code == expected
                assert alice.cookies.get("access_token") == old_jwt
            for active, expected in [(False, 403), (True, 200)]:
                assert admin.patch(f"/api/admin/users/{a['id']}", headers=csrf(admin),
                                   json={"is_active": active}).status_code == 200
                for path in ["/api/auth/me", "/api/notes"]:
                    assert alice.get(path).status_code == expected
                if not active:
                    assert alice.get("/api/admin/users").status_code == 403
            result["admin_and_existing_jwt"] = "passed; promotion, demotion, inactive, reactivation"

            token_cases = {
                "malformed": "abc.def.xyz",
                "wrong_signature": jwt.encode({"sub": str(a['id']), "exp": 4102444800},
                                              "wrong-signing-secret-with-32-characters", algorithm="HS256"),
            }
            for name, claims in {
                "expired": {"sub": str(a['id']), "exp": 1},
                "missing_exp": {"sub": str(a['id'])}, "missing_sub": {"exp": 4102444800},
                "zero": {"sub": "0", "exp": 4102444800},
                "negative": {"sub": "-1", "exp": 4102444800},
                "nonnumeric": {"sub": "abc", "exp": 4102444800},
                "missing_user": {"sub": "999999", "exp": 4102444800},
            }.items():
                token_cases[name] = jwt.encode(claims, SECRET, algorithm="HS256")
            parts = old_jwt.split(".")
            payload = jwt.decode(old_jwt, options={"verify_signature": False})
            payload["sub"] = str(b["id"])
            changed = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            token_cases["tampered_sub_to_bob"] = f"{parts[0]}.{changed}.{parts[2]}"
            with httpx.Client(base_url=BASE) as stranger:
                for name, token in token_cases.items():
                    response = stranger.get("/api/auth/me", headers={"Cookie": f"access_token={token}"})
                    assert response.status_code == 401, name
            result["jwt_attacks"] = {name: 401 for name in token_cases}

            samples = {"missing_username": [], "wrong_password": []}
            for _ in range(12):
                for label, name in [("missing_username", "audit_absent"), ("wrong_password", "audit_alice")]:
                    start = time.perf_counter()
                    response = alice.post("/api/auth/login", headers=csrf(alice),
                                          json={"username": name, "password": "wrong password"})
                    samples[label].append((time.perf_counter() - start) * 1000)
                    assert response.status_code == 401
                    assert response.json() == {"detail": "Invalid username or password"}
            result["login_median_ms_12_samples"] = {key: round(statistics.median(vals), 2)
                                                   for key, vals in samples.items()}
            result["sql_text_roundtrip"] = bob.get(f"/api/notes/{foreign}").json()["content"] == sql_payload
            ids = ["0", "-1", "abc", str(2 ** 63), "9" * 100]
            result["id_boundaries"] = {value: alice.get(f"/api/notes/{value}").status_code for value in ids}
            assert all(status == 422 for status in result["id_boundaries"].values())

            # Real psycopg failures: all rejected writes use SAVEPOINT rollback.
            statements = {
                "fk": ("INSERT INTO notes(owner_id,title,content) VALUES (%s,%s,%s)", (999999, "x", "x")),
                "unique": ("INSERT INTO users(username,password_hash) VALUES (%s,%s)", ("audit_alice", "test-hash")),
                "enum": ("UPDATE users SET role=%s WHERE id=%s", ("root", a["id"])),
                "not_null": ("INSERT INTO notes(owner_id,title,content) VALUES (%s,%s,%s)", (a["id"], "x", None)),
            }
            constraints = {}
            for name, (sql, params) in statements.items():
                try:
                    with db.transaction():
                        db.execute(sql, params)
                except psycopg.Error as error:
                    constraints[name] = {"sqlstate": error.sqlstate, "constraint": error.diag.constraint_name}
            assert set(constraints) == set(statements)
            result["postgres_constraints"] = constraints
            result["owner_index"] = db.execute("SELECT indexname FROM pg_indexes WHERE tablename='notes'").fetchall()
            sensitive = "PRIVATE_AUDIT_NOTE_SENTINEL_20260917"
            response = alice.post("/api/notes", headers=csrf(alice),
                                  json={"title": "nul probe", "content": sensitive + "\x00"})
            result["nul_text"] = {"status": response.status_code,
                                  "response_contains_private_text": sensitive in response.text,
                                  "body": response.text[:80]}
            assert response.status_code == 422
            assert sensitive not in response.text
            note_id = notes[0]["id"]
            assert alice.patch(f"/api/notes/{note_id}", headers=csrf(alice),
                               json={"content": "changed"}).status_code == 200
            assert alice.delete(f"/api/notes/{note_id}", headers=csrf(alice)).status_code == 204
            result["clean_crud"] = "passed"
            header_names = ["content-security-policy", "x-content-type-options", "referrer-policy",
                            "x-frame-options", "strict-transport-security", "cache-control"]
            result["response_headers"] = {path: {name: alice.get(path).headers.get(name) for name in header_names}
                                          for path in ["/login", "/notes", "/api/auth/me", "/api/notes"]}
            for headers in result["response_headers"].values():
                assert headers["content-security-policy"]
                assert headers["x-content-type-options"] == "nosniff"
                assert headers["referrer-policy"] == "no-referrer"
                assert headers["x-frame-options"] == "DENY"
                assert headers["cache-control"] == "no-store"
                assert headers["strict-transport-security"] is None
            stale = csrf(alice)
            csrf(alice)
            assert alice.post("/api/auth/logout", headers=stale).status_code == 403
            assert alice.get("/api/auth/me").status_code == 200
            assert alice.post("/api/auth/logout", headers=csrf(alice)).status_code == 204
            assert alice.get("/api/auth/me").status_code == 401
            result["stale_logout_preserves_session_valid_logout_removes"] = True
        finally:
            for client in clients:
                client.close()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
