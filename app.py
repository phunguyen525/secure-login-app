from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from db import get_connection, check_password, hash_password

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-later-for-final-submission"


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
        if session.get("user_id") is None:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


@app.route("/")
def home():
    user = get_current_user()
    return render_template("home.html", user=user)


@app.route("/login", methods=["GET", "POST"])
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

        if user is not None and check_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            flash("Login successful.")
            return redirect(url_for("home"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = get_current_user()

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if current_password == "" or new_password == "" or confirm_password == "":
            flash("All fields are required.")
            return render_template("change_password.html", user=user)

        if len(new_password) < 8:
            flash("New password must be at least 8 characters long.")
            return render_template("change_password.html", user=user)

        if new_password != confirm_password:
            flash("New password and confirm password do not match.")
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

        new_hashed_password = hash_password(new_password)

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hashed_password, user["id"])
        )
        conn.commit()
        conn.close()

        session.clear()
        flash("Password changed successfully. Please log in again.")
        return redirect(url_for("login"))

    return render_template("change_password.html", user=user)


if __name__ == "__main__":
    app.run(debug=True)