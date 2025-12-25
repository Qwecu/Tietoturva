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
    cur.execute("DROP TABLE IF EXISTS login_audit")

    cur.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        salt BLOB NOT NULL,
        password_hash BLOB NOT NULL,
        secret TEXT DEFAULT '',
        role TEXT DEFAULT 'commoner'
    )
""")

    cur.execute("""
    CREATE TABLE login_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER,
        username TEXT NOT NULL,

        success INTEGER NOT NULL,     -- 1 = success, 0 = failure
        ip_address TEXT,
        user_agent TEXT,

        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (user_id) REFERENCES users(id)
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

# def hash_password_generate_salted(password_plaintext) -> tuple[str, bytes]:
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

def hash_password_generate_salted(password_plaintext) -> tuple[str, bytes]:
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



        #Flaw 5 corrected by following code:
        # user_id = user["id"] if user else None
        # success = 1 if user else 0

        # print(f"Logged values {user_id}, {username}, {success}, {request.remote_addr}, {request.headers.get("User-Agent")}")

        # conn = get_db()
        # conn.execute(
        #     """
        #     INSERT INTO login_audit (user_id, username, success, ip_address, user_agent)
        #     VALUES (?, ?, ?, ?, ?)
        #     """,
        #     (
        #         user_id,
        #         username,
        #         success,
        #         request.remote_addr,
        #         request.headers.get("User-Agent")
        #     )
        # )

        # conn.close()

        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            
            return redirect(url_for("profile"))

    
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password_plaintext = request.form["password"]
        # Fix for flaw 4
        # if test_password_strength(password_plaintext) == False:
        #     return "Bad bad password"
        is_admin = "is_admin" in request.form
        role = 'admin' if is_admin else 'commoner'
        password_hashed, salt = hash_password_generate_salted(password_plaintext)

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                (username, password_hashed, salt, role)
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




@app.route("/admin")
def admin():
    print("admin requested!")
    print (session.get("role"))
    #This fixes flaw 3
    # if "user_id" not in session or not session.get("role") == 'admin':
    #     return render_template("forbidden.html")
    return render_template("admin.html")


import re

def test_password_strength(password_plaintext: str) -> bool:

    if len(password_plaintext) < 12:
        return False

    if not re.search(r"[a-z]", password_plaintext):
        return False

    if not re.search(r"[A-Z]", password_plaintext):
        return False

    if not re.search(r"[0-9]", password_plaintext):
        return False

    special_chars = re.findall(
        r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]",
        password_plaintext
    )

    if len(special_chars) < 3:
        return False

    return True

if __name__ == "__main__":
    init_db()
    app.run(debug=True, use_reloader=False)