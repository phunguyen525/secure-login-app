import os
import re
import runpy
import sqlite3
import time
from datetime import timedelta

os.environ["SECRET_KEY"] = "pytest-only-secret-key-0123456789"
os.environ["FORCE_INSECURE_COOKIES"] = "0"
os.environ["FLASK_DEBUG"] = "0"

import bcrypt
import flask
import pytest

import app as app_module
import db

flask_app = app_module.app
limiter = app_module.limiter

BASE_URL = "https://localhost"
SAME_ORIGIN = {"Referer": BASE_URL + "/"}

ADMIN_PASSWORD = "AdminTestPassword!2026"
CUSTOMER_PASSWORD = "AliceTestPassword!2026"
NEW_CUSTOMER_PASSWORD = "AliceNewPassword!2026"
WRONG_PASSWORD = "WrongPassword!2026xyz"
ADMIN_HASH = db.hash_password(ADMIN_PASSWORD)
CUSTOMER_HASH = db.hash_password(CUSTOMER_PASSWORD)
ORIGINAL_DATABASE = db.DATABASE

LEGACY_USERS_TABLE = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

PROTECTED_PAGES = ["/feedback", "/change-password", "/create-user", "/feedback-list"]
ADMIN_PAGES = ["/create-user", "/feedback-list"]


class Browser:
    def __init__(self):
        self.client = flask_app.test_client()

    def get(self, path, **kwargs):
        return self.client.get(path, base_url=BASE_URL, **kwargs)

    def csrf_token(self, path):
        page = self.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def post(self, path, data=None, token_from=None, with_token=True, headers=None, **kwargs):
        form = dict(data or {})
        if with_token:
            form["csrf_token"] = self.csrf_token(token_from or path)
        request_headers = dict(SAME_ORIGIN)
        request_headers.update(headers or {})
        return self.client.post(path, data=form, headers=request_headers, base_url=BASE_URL, **kwargs)

    def login(self, username, password, **kwargs):
        return self.post("/login", {"username": username, "password": password}, **kwargs)

    def signup(self, username, password, confirm_password=None, extra=None, **kwargs):
        form = {
            "username": username,
            "password": password,
            "confirm_password": password if confirm_password is None else confirm_password,
        }
        form.update(extra or {})
        return self.post("/signup", form, **kwargs)

    def logout(self):
        return self.post("/logout", token_from="/", follow_redirects=True)


def text(response):
    return response.get_data(as_text=True)


def query(sql, params=()):
    conn = db.get_connection()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows


def execute(sql, params=()):
    conn = db.get_connection()
    conn.execute(sql, params)
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def fresh_database(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "INSTANCE_DIR", str(tmp_path))
    monkeypatch.setattr(db, "DATABASE", str(tmp_path / "test.db"))
    db.init_database()
    execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("admin", ADMIN_HASH, "admin"),
    )
    execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("alice", CUSTOMER_HASH, "customer"),
    )
    flask_app.config["TESTING"] = True
    limiter.reset()
    yield


@pytest.fixture
def browser():
    return Browser()


@pytest.fixture
def admin():
    session = Browser()
    session.login("admin", ADMIN_PASSWORD)
    return session


@pytest.fixture
def customer():
    session = Browser()
    session.login("alice", CUSTOMER_PASSWORD)
    return session


class TestSecurityConfiguration:
    def test_running_app_py_does_not_enable_debug_cwe_489(self, monkeypatch):
        calls = []
        monkeypatch.setattr(flask.Flask, "run", lambda self, *args, **kwargs: calls.append(kwargs))
        monkeypatch.setenv("FLASK_DEBUG", "0")
        runpy.run_path(app_module.__file__, run_name="__main__")
        assert flask_app.debug is False
        assert calls and calls[0].get("debug") is False

    def test_session_expires_after_15_minutes_cwe_613(self):
        assert flask_app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=15)

    def test_session_cookie_is_secure_httponly_samesite_cwe_614_cwe_1004(self, browser):
        cookie = browser.login("alice", CUSTOMER_PASSWORD).headers.get("Set-Cookie", "")
        assert "Secure" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=Lax" in cookie

    def test_security_headers_are_sent_cwe_1021_cwe_693(self, browser):
        headers = browser.get("/").headers
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Referrer-Policy"] == "same-origin"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

    def test_content_security_policy_blocks_inline_code_cwe_79(self, browser):
        csp = browser.get("/").headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp

    def test_authenticated_pages_are_not_cached_cwe_525(self, customer):
        assert customer.get("/feedback").headers["Cache-Control"] == "no-store"

    def test_stylesheet_is_served_and_never_rate_limited(self, browser):
        statuses = {browser.get("/static/style.css").status_code for _ in range(60)}
        assert statuses == {200}


class TestAuthentication:
    def test_valid_credentials_log_in(self, browser):
        response = browser.login("alice", CUSTOMER_PASSWORD, follow_redirects=True)
        assert "Login successful." in text(response)
        assert browser.get("/feedback").status_code == 200

    def test_wrong_password_gets_generic_error_cwe_203(self, browser):
        response = browser.login("alice", WRONG_PASSWORD)
        assert "Invalid username or password." in text(response)

    def test_unknown_user_gets_the_same_generic_error_cwe_204(self, browser):
        response = browser.login("nobody_here", WRONG_PASSWORD)
        assert "Invalid username or password." in text(response)

    @pytest.mark.parametrize("payload", ["' OR '1'='1' --", "admin'--", "\" OR 1=1 --", "admin' /*"])
    def test_sql_injection_in_login_is_rejected_cwe_89(self, browser, payload):
        response = browser.login(payload, "anything-at-all")
        assert "Invalid username or password." in text(response)
        assert "Please log in first." in text(browser.get("/feedback", follow_redirects=True))

    @pytest.mark.parametrize("password", ["A" * 100, "ệ" * 30])
    def test_overlong_password_is_rejected_without_crashing_cwe_20(self, browser, password):
        response = browser.login("alice", password)
        assert response.status_code == 200
        assert "Invalid username or password." in text(response)

    def test_login_timing_does_not_reveal_valid_usernames_cwe_208(self):
        def average_login_seconds(username):
            samples = []
            for _ in range(3):
                limiter.reset()
                session = Browser()
                token = session.csrf_token("/login")
                start = time.perf_counter()
                session.client.post(
                    "/login",
                    data={"username": username, "password": WRONG_PASSWORD, "csrf_token": token},
                    headers=SAME_ORIGIN,
                    base_url=BASE_URL,
                )
                samples.append(time.perf_counter() - start)
            return sum(samples) / len(samples)

        existing_user = average_login_seconds("alice")
        missing_user = average_login_seconds("no_such_user")
        assert missing_user > existing_user * 0.5

    def test_logout_ends_the_session(self, customer):
        response = customer.logout()
        assert "You have been logged out." in text(response)
        assert "Please log in first." in text(customer.get("/feedback", follow_redirects=True))

    def test_logout_cannot_be_triggered_by_get_request_cwe_352(self, customer):
        assert customer.get("/logout").status_code == 405
        assert customer.get("/feedback").status_code == 200


class TestPasswordPolicy:
    def test_short_password_is_rejected_cwe_521(self, browser):
        response = browser.signup("newuser", "Short!2026")
        assert "at least 15 characters" in text(response)
        assert query("SELECT id FROM users WHERE username = 'newuser'") == []

    def test_password_equal_to_username_is_rejected_cwe_521(self, browser):
        response = browser.signup("longusername12345", "longusername12345")
        assert "must not be the same as the username" in text(response)

    def test_password_confirmation_must_match(self, browser):
        response = browser.signup("newuser", "NewUserPassword!2026", "DifferentPassword!2026")
        assert "do not match" in text(response)

    def test_password_over_72_bytes_is_rejected_without_crashing_cwe_20(self, browser):
        response = browser.signup("newuser", "ệ" * 64)
        assert response.status_code == 200
        assert "at most 72 bytes" in text(response)

    def test_passwords_are_stored_as_bcrypt_hashes_cwe_256_cwe_916(self, browser):
        browser.signup("newuser", "NewUserPassword!2026")
        stored = query("SELECT password_hash FROM users WHERE username = 'newuser'")[0]["password_hash"]
        assert stored != "NewUserPassword!2026"
        assert stored.startswith("$2b$")
        assert bcrypt.checkpw(b"NewUserPassword!2026", stored.encode("utf-8"))

    def test_default_admin_gets_random_strong_password_cwe_798(self, capsys, monkeypatch):
        execute("DELETE FROM users WHERE username = 'admin'")
        monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
        db.create_default_admin()
        printed = re.search(r"password: (\S+)", capsys.readouterr().out).group(1)
        stored = query("SELECT password_hash FROM users WHERE username = 'admin'")[0]["password_hash"]
        assert db.validate_password_policy(printed, "admin") == (True, "")
        assert db.check_password(printed, stored)
        assert not db.check_password("Admin123!", stored)

    def test_weak_admin_password_from_environment_is_refused_cwe_521(self, monkeypatch):
        execute("DELETE FROM users WHERE username = 'admin'")
        monkeypatch.setenv("ADMIN_PASSWORD", "Admin123!")
        with pytest.raises(SystemExit):
            db.create_default_admin()
        assert query("SELECT id FROM users WHERE username = 'admin'") == []


class TestAccountManagement:
    def test_signup_always_creates_least_privileged_customer_cwe_269(self, browser):
        browser.signup("newuser", "NewUserPassword!2026", extra={"role": "admin"})
        roles = [row["role"] for row in query("SELECT role FROM users WHERE username = 'newuser'")]
        assert roles == ["customer"]

    def test_case_variant_of_existing_username_is_rejected_cwe_178(self, browser):
        response = browser.signup("ADMIN", "SpoofedAdminPassword!2026")
        assert "Username already exists." in text(response)
        assert query("SELECT id FROM users WHERE username = 'ADMIN' COLLATE BINARY") == []

    def test_case_variant_rejected_on_database_created_with_old_schema_cwe_178(self, browser, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DATABASE", str(tmp_path / "legacy.db"))
        execute(LEGACY_USERS_TABLE)
        execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", ADMIN_HASH, "admin"),
        )
        response = browser.signup("ADMIN", "SpoofedAdminPassword!2026")
        assert "Username already exists." in text(response)
        assert query("SELECT id FROM users WHERE username = 'ADMIN'") == []

    def test_schema_rejects_case_variant_usernames_cwe_178(self):
        with pytest.raises(sqlite3.IntegrityError):
            execute("INSERT INTO users (username, password_hash, role) VALUES ('ADMIN', 'x', 'customer')")

    @pytest.mark.parametrize("username", ["<script>x</script>", "bad user", "robert'); --", "ab", "x" * 51])
    def test_username_allowlist_is_enforced_cwe_20(self, browser, username):
        response = browser.signup(username, "ValidPassword!2026xy")
        assert "Username must be 3-50 characters" in text(response)
        assert query("SELECT id FROM users WHERE username = ?", (username,)) == []

    def test_duplicate_insert_race_is_handled_cwe_367(self, browser, monkeypatch):
        monkeypatch.setattr(app_module, "username_exists", lambda conn, username: False)
        response = browser.signup("alice", "AnotherPassword!2026")
        assert response.status_code == 200
        assert "Username already exists." in text(response)

    def test_admin_can_create_user(self, admin):
        response = admin.post(
            "/create-user",
            {"username": "bob", "password": "BobPassword!2026xy", "role": "customer"},
            follow_redirects=True,
        )
        assert "User created successfully." in text(response)
        assert query("SELECT role FROM users WHERE username = 'bob'")[0]["role"] == "customer"

    def test_create_user_rejects_unknown_role_cwe_20(self, admin):
        response = admin.post(
            "/create-user",
            {"username": "bob", "password": "BobPassword!2026xy", "role": "superadmin"},
        )
        assert "Invalid role selected." in text(response)
        assert query("SELECT id FROM users WHERE username = 'bob'") == []

    def test_change_password_requires_current_password_cwe_620(self, customer):
        response = customer.post(
            "/change-password",
            {
                "current_password": WRONG_PASSWORD,
                "new_password": NEW_CUSTOMER_PASSWORD,
                "confirm_password": NEW_CUSTOMER_PASSWORD,
            },
        )
        assert "Current password is incorrect." in text(response)

    def test_change_password_rejects_reusing_current_password(self, customer):
        response = customer.post(
            "/change-password",
            {
                "current_password": CUSTOMER_PASSWORD,
                "new_password": CUSTOMER_PASSWORD,
                "confirm_password": CUSTOMER_PASSWORD,
            },
        )
        assert "must be different from the current password" in text(response)

    def test_change_password_logs_out_and_replaces_old_password(self, customer):
        response = customer.post(
            "/change-password",
            {
                "current_password": CUSTOMER_PASSWORD,
                "new_password": NEW_CUSTOMER_PASSWORD,
                "confirm_password": NEW_CUSTOMER_PASSWORD,
            },
            follow_redirects=True,
        )
        assert "Password changed successfully." in text(response)
        assert "Please log in first." in text(customer.get("/feedback", follow_redirects=True))
        assert "Invalid username or password." in text(customer.login("alice", CUSTOMER_PASSWORD))
        assert "Login successful." in text(customer.login("alice", NEW_CUSTOMER_PASSWORD, follow_redirects=True))


class TestAccessControl:
    @pytest.mark.parametrize("path", PROTECTED_PAGES)
    def test_anonymous_user_is_sent_to_login_cwe_306(self, browser, path):
        response = browser.get(path, follow_redirects=True)
        assert "Please log in first." in text(response)

    @pytest.mark.parametrize("path", ADMIN_PAGES)
    def test_customer_cannot_open_admin_pages_cwe_285(self, customer, path):
        response = customer.get(path, follow_redirects=True)
        assert "Access denied." in text(response)

    def test_customer_cannot_create_users_with_direct_post_cwe_285(self, customer):
        customer.post(
            "/create-user",
            {"username": "sneaky", "password": "SneakyPassword!2026", "role": "admin"},
            token_from="/feedback",
        )
        assert query("SELECT id FROM users WHERE username = 'sneaky'") == []

    def test_demoted_admin_loses_access_immediately_cwe_285(self, admin):
        assert admin.get("/create-user").status_code == 200
        execute("UPDATE users SET role = 'customer' WHERE username = 'admin'")
        assert "Access denied." in text(admin.get("/create-user", follow_redirects=True))

    def test_session_of_deleted_user_is_rejected_cwe_613(self, customer):
        execute("DELETE FROM users WHERE username = 'alice'")
        assert "Please log in first." in text(customer.get("/feedback", follow_redirects=True))


class TestInjectionAndXss:
    def test_stored_xss_in_feedback_is_escaped_cwe_79(self, customer, admin):
        payload = "<script>alert(document.cookie)</script>"
        customer.post("/feedback", {"subject": "XSS probe", "message": payload})
        page = text(admin.get("/feedback-list"))
        assert payload not in page
        assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in page

    def test_sql_injection_in_feedback_is_stored_as_plain_text_cwe_89(self, customer):
        payload = "x'); DROP TABLE users; --"
        customer.post("/feedback", {"subject": "SQLi probe", "message": payload})
        assert query("SELECT message FROM feedback")[0]["message"] == payload
        assert len(query("SELECT id FROM users")) == 2

    @pytest.mark.parametrize(
        "subject, message, error",
        [
            ("", "valid message", "Subject and message are required."),
            ("ab", "valid message", "Subject must be between 3 and 100 characters."),
            ("x" * 101, "valid message", "Subject must be between 3 and 100 characters."),
            ("Valid subject", "tiny", "Message must be between 5 and 1000 characters."),
            ("Valid subject", "x" * 1001, "Message must be between 5 and 1000 characters."),
        ],
    )
    def test_feedback_input_is_validated_cwe_20(self, customer, subject, message, error):
        response = customer.post("/feedback", {"subject": subject, "message": message})
        assert error in text(response)
        assert query("SELECT id FROM feedback") == []


class TestCsrf:
    def test_post_without_token_is_rejected_cwe_352(self, customer):
        response = customer.post(
            "/feedback",
            {"subject": "No token", "message": "no csrf token here"},
            with_token=False,
            follow_redirects=True,
        )
        assert "CSRF validation failed" in text(response)
        assert query("SELECT id FROM feedback") == []

    def test_post_with_forged_token_is_rejected_cwe_352(self, customer):
        response = customer.post(
            "/feedback",
            {"subject": "Forged", "message": "forged csrf token", "csrf_token": "forged-token"},
            with_token=False,
            follow_redirects=True,
        )
        assert "CSRF validation failed" in text(response)
        assert query("SELECT id FROM feedback") == []

    def test_cross_site_post_is_rejected_cwe_352(self, customer):
        customer.post(
            "/feedback",
            {"subject": "Cross site", "message": "sent from another origin"},
            headers={"Referer": "https://evil.example/attack"},
        )
        assert query("SELECT id FROM feedback") == []

    def test_csrf_error_never_redirects_off_site_cwe_601(self, customer):
        response = customer.post(
            "/feedback",
            {"subject": "Phish", "message": "open redirect probe"},
            with_token=False,
            headers={"Referer": "https://evil.example/phish"},
        )
        assert "evil.example" not in response.headers["Location"]

    def test_csrf_error_returns_to_same_site_page(self, customer):
        response = customer.post(
            "/feedback",
            {"subject": "Retry", "message": "expired token retry"},
            with_token=False,
            headers={"Referer": BASE_URL + "/feedback"},
        )
        assert response.headers["Location"] == BASE_URL + "/feedback"


class TestRateLimiting:
    def test_login_is_rate_limited_cwe_307(self, browser):
        responses = [browser.login("alice", WRONG_PASSWORD) for _ in range(6)]
        assert [r.status_code for r in responses[:5]] == [200] * 5
        assert responses[5].status_code == 429
        assert "Too many requests" in text(responses[5])

    def test_signup_is_rate_limited_cwe_770(self, browser):
        statuses = [browser.signup(f"user{i}x", "short").status_code for i in range(6)]
        assert statuses[:5] == [200] * 5
        assert statuses[5] == 429


class TestRobustness:
    def test_database_path_does_not_depend_on_working_directory(self):
        assert os.path.isabs(ORIGINAL_DATABASE)
        assert ORIGINAL_DATABASE.endswith(os.path.join("instance", "app.db"))

    def test_foreign_keys_are_enforced(self):
        with pytest.raises(sqlite3.IntegrityError):
            execute("INSERT INTO feedback (user_id, subject, message) VALUES (999, 'x', 'y')")


class TestUserInterface:
    def test_errors_and_successes_use_matching_alert_styles(self, browser):
        error_page = text(browser.login("alice", WRONG_PASSWORD))
        assert 'class="alert alert-error">Invalid username or password.' in error_page
        success_page = text(browser.login("alice", CUSTOMER_PASSWORD, follow_redirects=True))
        assert 'class="alert alert-success">Login successful.' in success_page

    def test_logged_in_home_page_hides_login_and_signup_links(self, customer):
        page = text(customer.get("/"))
        assert 'href="/signup"' not in page
        assert 'href="/login"' not in page
