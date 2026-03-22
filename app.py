from flask import Flask, render_template, request, redirect, url_for, session, flash
from db import get_connection, check_password

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


if __name__ == "__main__":
    app.run(debug=True)