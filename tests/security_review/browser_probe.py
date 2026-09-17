"""Real Chromium probes; only run against the disposable review stack."""

import json
import os
import uuid
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import expect, sync_playwright


BASE = "http://notes-security-audit-20260917-api-1:8000"
PASSWORD = "browser audit password"
PAYLOAD = '<img src=x onerror="window.auditXss=1">'
CONTENT = '<script>window.auditXss=2</script>\nSQL: \'); DROP TABLE notes; --'


def login(page, username, password):
    page.goto(BASE + "/login")
    page.wait_for_load_state("networkidle")
    page.locator("#username").fill(username)
    page.locator("#password").fill(password)
    page.locator("#login-submit").click()
    page.wait_for_url("**/notes")
    expect(page.locator("#current-username")).to_have_text(username)
    expect(page.locator("#notes-loading")).to_be_hidden()


def main():
    assert os.environ.get("SECURITY_AUDIT_CONFIRM") == "isolated"
    result = {}
    username = "audit_browser_" + uuid.uuid4().hex[:8]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context()
        page = context.new_page()
        page.goto(BASE + "/register")
        page.wait_for_load_state("networkidle")
        page.locator("#username").fill(username)
        page.locator("#password").fill(PASSWORD)
        page.locator("#password-repeat").fill(PASSWORD)
        page.locator("#register-submit").click()
        page.wait_for_url("**/login?registered=1")
        login(page, username, PASSWORD)
        page.locator("#new-note-button").click()
        page.locator("#note-title").fill("browser CRUD")
        page.locator("#note-content").fill("browser content")
        page.locator("#note-submit").click()
        expect(page.locator(".note-card h3")).to_have_text("browser CRUD")
        page.locator(".note-card .button--secondary").click()
        page.locator("#note-title").fill("edited CRUD")
        page.locator("#note-submit").click()
        expect(page.locator(".note-card h3")).to_have_text("edited CRUD")
        page.on("dialog", lambda dialog: dialog.accept())
        page.locator(".note-card .button--danger").click()
        expect(page.locator(".note-card")).to_have_count(0)
        result["browser_registration_login_crud"] = "passed"

        page.locator("#new-note-button").click()
        page.locator("#note-title").fill(PAYLOAD)
        page.locator("#note-content").fill(CONTENT)
        page.locator("#note-submit").click()
        expect(page.locator(".note-card h3")).to_have_text(PAYLOAD)
        expect(page.locator(".note-card__content")).to_have_text(CONTENT)
        assert page.locator(".note-card img, .note-card script").count() == 0
        assert page.evaluate("window.auditXss === undefined")
        assert "access_token" not in page.evaluate("document.cookie")
        assert page.evaluate("localStorage.length + sessionStorage.length") == 0
        result["xss_personal_dom_and_jwt_invisibility"] = "passed"

        tab_b = context.new_page()
        tab_b.goto(BASE + "/notes")
        expect(tab_b.locator("#notes-loading")).to_be_hidden()
        with page.expect_response("**/api/auth/logout") as logout:
            page.locator("#logout-button").click()
        page.wait_for_url("**/login")
        assert logout.value.status == 403
        assert context.request.get(BASE + "/api/auth/me").status == 401
        result["stale_csrf_logout"] = {
            "first_api_status": 403,
            "retry_succeeded": True,
            "session_still_active": False,
        }

        login(page, username, PASSWORD)
        page.route("**/api/auth/logout", lambda route: route.abort())
        page.locator("#logout-button").click()
        expect(page).to_have_url(BASE + "/notes")
        expect(page.locator("#notes-message")).to_contain_text("Сессия остаётся активной")
        assert context.request.get(BASE + "/api/auth/me").status == 200
        result["network_failure_logout"] = {
            "redirect_login": False,
            "session_still_active": True,
            "error_visible": True,
        }
        page.unroute("**/api/auth/logout")
        page.locator("#logout-button").click()
        page.wait_for_url("**/login")
        assert context.request.get(BASE + "/api/auth/me").status == 401
        result["successful_browser_logout"] = "passed"

        admin_context = browser.new_context()
        admin_page = admin_context.new_page()
        login(
            admin_page,
            os.environ.get("AUDIT_ADMIN_USERNAME", "audit_bootstrap"),
            os.environ["AUDIT_ADMIN_PASSWORD"],
        )
        admin_page.locator("#admin-link").click()
        expect(admin_page.locator("#admin-notes-loading")).to_be_hidden()
        expect(admin_page.locator("#users-loading")).to_be_hidden()
        assert PAYLOAD in admin_page.locator("#admin-notes-body").text_content()
        assert admin_page.locator("#admin-notes-body img, #admin-notes-body script").count() == 0
        assert admin_page.evaluate("window.auditXss === undefined")
        assert admin_page.locator("#admin-notes-body button").count() == 0
        result["admin_dom_xss_and_read_only_notes"] = "passed"
        target = admin_page.locator("#users-body tr").filter(has_text=username)
        target.locator("select").select_option("admin")
        target.locator("button").click()
        expect(target.locator("select")).to_have_value("admin")
        admin_page.wait_for_load_state("networkidle")
        assert [u for u in admin_context.request.get(BASE + "/api/admin/users").json()
                if u["username"] == username][0]["role"] == "admin"
        result["admin_user_management_browser"] = "passed"

        # Same-site, different-origin framing: cookies are still sent under Lax.
        frame_page = admin_context.new_page()
        attacker_origin = BASE.replace(":8000", ":8001")
        frame_page.route(attacker_origin + "/**", lambda route: route.fulfill(
            status=200, content_type="text/html", body=f'<iframe src="{BASE}/admin"></iframe>'))
        frame_page.goto(attacker_origin + "/frame-probe")
        frame_page.wait_for_load_state("networkidle")
        result["cross_origin_frame_urls"] = [frame.url for frame in frame_page.frames]
        result["cross_origin_frame_users_table_visible"] = frame_page.frame_locator("iframe").locator("#users-table").is_visible()

        for route, button in [("login", "login-submit"), ("register", "register-submit")]:
            no_js = browser.new_context(java_script_enabled=False)
            form_page = no_js.new_page()
            form_page.goto(BASE + "/" + route)
            form_page.locator("#username").fill("audit_nojs_user")
            form_page.locator("#password").fill("FORM_QUERY_AUDIT_SENTINEL")
            if route == "register":
                form_page.locator("#password-repeat").fill("FORM_QUERY_AUDIT_SENTINEL")
            form_page.locator("#" + button).click()
            form_page.wait_for_url("**/api/auth/**")
            query = parse_qs(urlparse(form_page.url).query)
            assert "password" not in query
            assert "FORM_QUERY_AUDIT_SENTINEL" not in form_page.url
            result[route + "_without_js_password_in_url"] = False
            no_js.close()
        browser.close()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
