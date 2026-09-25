from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse
import os
import re
import sqlite3

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError

from db import (
    get_connection,
    check_password,
    hash_password,
    validate_password_policy,
    DUMMY_PASSWORD_HASH,
)

load_dotenv()

app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY is not set.")

app.config["SECRET_KEY"] = secret_key

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FORCE_INSECURE_COOKIES") != "1"

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{3,50}")
USERNAME_RULE_MESSAGE = (
    "Username must be 3-50 characters and contain only letters, "
    "numbers, dots, underscores or hyphens."
)

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def is_valid_username(username):
    return USERNAME_PATTERN.fullmatch(username) is not None


def username_exists(conn, username):
    row = conn.execute(
        "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
        (username,)
    ).fetchone()
    return row is not None


def is_safe_redirect_target(target):
    if not target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(target)
    return redirect_url.scheme in ("http", "https") and redirect_url.netloc == host_url.netloc


@app.before_request
def refresh_session_timeout():
    if "user_id" in session:
        session.permanent = True
        session.modified = True


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash(f"CSRF validation failed: {e.description}")
    target = request.referrer if is_safe_redirect_target(request.referrer) else url_for("login")
    return redirect(target)


@app.errorhandler(429)
def ratelimit_handler(e):
    return (
        render_template(
            "base.html",
            error_message="Too many requests. Please try again later."
        ),
        429,
    )


def get_current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    conn = get_connection()
    user = conn.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()

    return user


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user = get_current_user()
        if user is None:
            session.clear()
            flash("Please log in first.")
            return redirect(url_for("login"))
        session["role"] = user["role"]
        return view(*args, **kwargs)
    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user = get_current_user()
        if user is None:
            session.clear()
            flash("Please log in first.")
            return redirect(url_for("login"))

        session["role"] = user["role"]

        if user["role"] != "admin":
            flash("Access denied.")
            return redirect(url_for("home"))

        return view(*args, **kwargs)
    return wrapped_view


@app.route("/")
def home():
    user = get_current_user()
    return render_template("home.html", user=user)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
@limiter.limit("20 per hour", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == "" or password == "":
            flash("Username and password are required.")
            return render_template("login.html")

        conn = get_connection()
        user = conn.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        password_hash = user["password_hash"] if user is not None else DUMMY_PASSWORD_HASH
        password_ok = check_password(password, password_hash)

        if user is not None and password_ok:
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            flash("Login successful.", "success")
            return redirect(url_for("home"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
@limiter.limit("20 per hour", methods=["POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if username == "" or password == "" or confirm_password == "":
            flash("All fields are required.")
            return render_template("signup.html")

        if not is_valid_username(username):
            flash(USERNAME_RULE_MESSAGE)
            return render_template("signup.html")

        if password != confirm_password:
            flash("Password and confirm password do not match.")
            return render_template("signup.html")

        is_valid, error_message = validate_password_policy(password, username)
        if not is_valid:
            flash(error_message)
            return render_template("signup.html")

        conn = get_connection()

        if username_exists(conn, username):
            conn.close()
            flash("Username already exists.")
            return render_template("signup.html")

        hashed_password = hash_password(password)

        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, hashed_password, "customer")
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Username already exists.")
            return render_template("signup.html")

        conn.close()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def change_password():
    user = get_current_user()

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if current_password == "" or new_password == "" or confirm_password == "":
            flash("All fields are required.")
            return render_template("change_password.html", user=user)

        if new_password != confirm_password:
            flash("New password and confirm password do not match.")
            return render_template("change_password.html", user=user)

        is_valid, error_message = validate_password_policy(new_password, user["username"])
        if not is_valid:
            flash(error_message)
            return render_template("change_password.html", user=user)

        conn = get_connection()
        db_user = conn.execute(
            "SELECT id, password_hash FROM users WHERE id = ?",
            (user["id"],)
        ).fetchone()

        if not check_password(current_password, db_user["password_hash"]):
            conn.close()
            flash("Current password is incorrect.")
            return render_template("change_password.html", user=user)

        if check_password(new_password, db_user["password_hash"]):
            conn.close()
            flash("New password must be different from the current password.")
            return render_template("change_password.html", user=user)

        new_hashed_password = hash_password(new_password)

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hashed_password, user["id"])
        )
        conn.commit()
        conn.close()

        session.clear()
        flash("Password changed successfully. Please log in again.", "success")
        return redirect(url_for("login"))

    return render_template("change_password.html", user=user)


@app.route("/create-user", methods=["GET", "POST"])
@admin_required
@limiter.limit("10 per hour", methods=["POST"])
def create_user():
    user = get_current_user()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()

        if username == "" or password == "" or role == "":
            flash("All fields are required.")
            return render_template("create_user.html", user=user)

        if not is_valid_username(username):
            flash(USERNAME_RULE_MESSAGE)
            return render_template("create_user.html", user=user)

        is_valid, error_message = validate_password_policy(password, username)
        if not is_valid:
            flash(error_message)
            return render_template("create_user.html", user=user)

        if role not in ["admin", "customer"]:
            flash("Invalid role selected.")
            return render_template("create_user.html", user=user)

        conn = get_connection()

        if username_exists(conn, username):
            conn.close()
            flash("Username already exists.")
            return render_template("create_user.html", user=user)

        hashed_password = hash_password(password)

        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Username already exists.")
            return render_template("create_user.html", user=user)

        conn.close()

        flash("User created successfully.", "success")
        return redirect(url_for("create_user"))

    return render_template("create_user.html", user=user)


@app.route("/feedback", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
@limiter.limit("30 per hour", methods=["POST"])
def feedback():
    user = get_current_user()

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if subject == "" or message == "":
            flash("Subject and message are required.")
            return render_template("feedback_form.html", user=user)

        if len(subject) < 3 or len(subject) > 100:
            flash("Subject must be between 3 and 100 characters.")
            return render_template("feedback_form.html", user=user)

        if len(message) < 5 or len(message) > 1000:
            flash("Message must be between 5 and 1000 characters.")
            return render_template("feedback_form.html", user=user)

        conn = get_connection()
        conn.execute(
            "INSERT INTO feedback (user_id, subject, message) VALUES (?, ?, ?)",
            (user["id"], subject, message)
        )
        conn.commit()
        conn.close()

        flash("Feedback submitted successfully.", "success")
        return redirect(url_for("feedback"))

    return render_template("feedback_form.html", user=user)


@app.route("/feedback-list")
@admin_required
@limiter.limit("30 per hour")
def feedback_list():
    user = get_current_user()

    conn = get_connection()
    feedback_items = conn.execute(
        """
        SELECT feedback.id, feedback.subject, feedback.message, feedback.created_at, users.username
        FROM feedback
        JOIN users ON feedback.user_id = users.id
        ORDER BY feedback.created_at DESC
        """
    ).fetchall()
    conn.close()

    return render_template("feedback_list.html", user=user, feedback_items=feedback_items)


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
