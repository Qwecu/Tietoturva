# import debugpy
# debugpy.listen(5678)
# print("Waiting for debugger attach...")
#debugpy.wait_for_client()  # optional; remove for normal runs

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
    print("Initdb!")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")

    cur.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        salt BLOB NOT NULL,
        password_hash BLOB NOT NULL,
        secret TEXT DEFAULT ''
    )
""")

    conn.commit()
    conn.close()

#SAFE HASHING BEGINS
# import os
# ITERATIONS = 200_000

# def hash_password(username, password_plaintext):
    

#     salt = salt_by_username(username)
#     password_hash = hashlib.pbkdf2_hmac(
#     'sha256',
#     password_plaintext.encode('utf-8'),
#     salt,
#     ITERATIONS
#     )
#     return password_hash.hex()

# def hash_password_generate_salted(password_plaintext) -> tuple[bytes, bytes]:
#     salt = os.urandom(16)

#     password_hash = hashlib.pbkdf2_hmac(
#         'sha256',
#         password_plaintext.encode('utf-8'),
#         salt,
#         ITERATIONS
#     )

#     return password_hash.hex(), salt


#SAFE HASHING ENDS

#UNSAFE HASHING BEGINS

def hash_password_generate_salted(password_plaintext) -> tuple[bytes, bytes]:
    return hashlib.sha256(password_plaintext.encode()).hexdigest(), b''

def hash_password(username, password_plaintext):
    return hashlib.sha256(password_plaintext.encode()).hexdigest()

#UNSAFE HASHING ENDS

def salt_by_username(username: str) -> bytes:
    print("Salt req fir user" + username)
    conn = get_db()
    try:
        result = conn.execute(
            "SELECT salt FROM users WHERE username=?",
            (username,)
        ).fetchone()
        print("Salt of today is " + result["salt"].hex())
        return result["salt"]
    finally:
        conn.close()


@app.route("/", methods=["GET", "POST"])
def login():
    print("login!")
    if request.method == "POST":
        username = request.form["username"]
        print("username " + username)
        hashed_password = hash_password(username, request.form["password"])

#SQL Injection begins!
        conn = get_db()
        vulnerablecode =  f"SELECT * FROM users WHERE username='{username}' AND password_hash='{hashed_password}'"
        print(vulnerablecode)
        user = conn.execute(
            vulnerablecode
        ).fetchone()
        conn.close()

#SQL injection ends! Corrected code follows:

        # conn = get_db()
        # user = conn.execute(
        #     "SELECT * FROM users WHERE username=? AND password_hash=?",
        #     (username, hashed_password)
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
        password_plaintext = request.form["password"]
        password_hashed, salt = hash_password_generate_salted(request.form["password"])

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hashed, salt)
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