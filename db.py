import os
import secrets
import string
import sqlite3
import bcrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DATABASE = os.path.join(INSTANCE_DIR, "app.db")
SCHEMA = os.path.join(BASE_DIR, "schema.sql")

MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 64
MAX_PASSWORD_BYTES = 72


def validate_password_policy(password, username=""):
    if password == "":
        return False, "Password is required."

    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."

    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must be at most {MAX_PASSWORD_LENGTH} characters long."

    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False, f"Password must be at most {MAX_PASSWORD_BYTES} bytes long."

    if username and password.casefold() == username.casefold():
        return False, "Password must not be the same as the username."

    return True, ""


def get_connection():
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_database():
    conn = get_connection()

    with open(SCHEMA, "r") as f:
        conn.executescript(f.read())

    conn.commit()
    conn.close()


def hash_password(password):
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError("Password exceeds bcrypt's 72-byte limit.")
    hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_bytes.decode("utf-8")


def check_password(password, hashed_password):
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        return False
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


def generate_strong_password(length=20):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_default_admin():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    existing_user = cursor.fetchone()

    if existing_user is None:
        admin_password = os.environ.get("ADMIN_PASSWORD")

        if admin_password:
            is_valid, error_message = validate_password_policy(admin_password, "admin")
            if not is_valid:
                conn.close()
                raise SystemExit(f"ADMIN_PASSWORD rejected: {error_message}")
        else:
            admin_password = generate_strong_password()

        admin_hash = hash_password(admin_password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_hash, "admin")
        )
        conn.commit()
        print("Default admin created.")
        print("username: admin")
        print(f"password: {admin_password}")
        print("Save this password now -- it is not stored anywhere else. "
              "Log in and change it immediately via /change-password.")
    else:
        print("Admin already exists.")

    conn.close()
