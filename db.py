import os
import sqlite3
import bcrypt

DATABASE = "instance/app.db"


def get_connection():
    os.makedirs("instance", exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_connection()

    with open("schema.sql", "r") as f:
        conn.executescript(f.read())

    conn.commit()
    conn.close()


def hash_password(password):
    password_bytes = password.encode("utf-8")
    hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_bytes.decode("utf-8")


def check_password(password, hashed_password):
    password_bytes = password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_default_admin():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    existing_user = cursor.fetchone()

    if existing_user is None:
        admin_hash = hash_password("Admin123!")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_hash, "admin")
        )
        conn.commit()
        print("Default admin created.")
        print("username: admin")
        print("password: Admin123!")
    else:
        print("Admin already exists.")

    conn.close()