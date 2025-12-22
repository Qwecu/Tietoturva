from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # replace for production

DB_NAME = "database.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            secret TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])

#SQL Injection begins!
        conn = get_db()
        vulnerablecode =  f"SELECT * FROM users WHERE username='{username}' AND password={password}"
        user = conn.execute(
            vulnerablecode
        ).fetchone()
        conn.close()

#SQL injection ends! Corrected code follows:

        # conn = get_db()
        # user = conn.execute(
        #     "SELECT * FROM users WHERE username=? AND password=?",
        #     (username, password)
        # ).fetchone()
        # conn.close()

        if user:
            session["user_id"] = user["id"]
            return redirect(url_for("profile"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        finally:
            conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    if request.method == "POST":
        new_secret = request.form["secret"]
        conn.execute(
            "UPDATE users SET secret=? WHERE id=?",
            (new_secret, session["user_id"])
        )
        conn.commit()

    user = conn.execute(
        "SELECT username, secret FROM users WHERE id=?",
        (session["user_id"],)
    ).fetchone()

    conn.close()
    return render_template("profile.html", user=user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, use_reloader=False)