from __future__ import annotations

import logging
import os
import re
import sqlite3
import time
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MIN_PASSWORD_LENGTH = 8
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("secure-login-demo")
LOCAL_DEV_FALLBACK_SECRET = "local-dev-learning-only-change-me"


def create_app(test_config: dict | None = None) -> Flask:
    secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY") or LOCAL_DEV_FALLBACK_SECRET
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secret_key,
        DATABASE=str(Path(app.root_path) / "app.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        TESTING=False,
    )

    if test_config:
        app.config.update(test_config)
    elif secret_key == LOCAL_DEV_FALLBACK_SECRET:
        LOGGER.warning("Using local-dev fallback SECRET_KEY. Set FLASK_SECRET_KEY for local learning.")

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error: Exception | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db() -> None:
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INTEGER NOT NULL,
                locked_until INTEGER NOT NULL
            )
            """
        )
        db.commit()

    @app.before_request
    def ensure_db() -> None:
        init_db()

    def get_attempt(username: str) -> sqlite3.Row | None:
        return get_db().execute(
            "SELECT username, fail_count, locked_until FROM login_attempts WHERE username = ?",
            (username,),
        ).fetchone()

    def reset_attempt(username: str) -> None:
        db = get_db()
        db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
        db.commit()

    def register_failed_attempt(username: str) -> None:
        now = int(time.time())
        attempt = get_attempt(username)
        db = get_db()
        if attempt is None:
            db.execute(
                "INSERT INTO login_attempts (username, fail_count, locked_until) VALUES (?, ?, ?)",
                (username, 1, 0),
            )
        else:
            fail_count = int(attempt["fail_count"]) + 1
            locked_until = now + LOCKOUT_SECONDS if fail_count >= MAX_ATTEMPTS else 0
            db.execute(
                "UPDATE login_attempts SET fail_count = ?, locked_until = ? WHERE username = ?",
                (fail_count, locked_until, username),
            )
        db.commit()

    def is_locked(username: str) -> bool:
        attempt = get_attempt(username)
        if attempt is None:
            return False
        return int(attempt["locked_until"]) > int(time.time())

    def validate_credentials(username: str, password: str) -> str | None:
        if not USERNAME_RE.fullmatch(username):
            return "Username must be 3-32 chars (letters, digits, underscore)."
        if len(password) < MIN_PASSWORD_LENGTH:
            return "Password must be at least 8 characters."
        return None

    @app.route("/")
    def index() -> str:
        return render_template("index.html", username=session.get("username"))

    @app.route("/register", methods=["GET", "POST"])
    def register() -> str:
        message = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            validation_error = validate_credentials(username, password)
            if validation_error:
                message = validation_error
            else:
                try:
                    get_db().execute(
                        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password), int(time.time())),
                    )
                    get_db().commit()
                    LOGGER.info("audit_event=register_success username=%s ip=%s", username, request.remote_addr)
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    message = "Username already exists."
        return render_template("register.html", message=message)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str:
        message = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if is_locked(username):
                LOGGER.warning("audit_event=login_locked username=%s ip=%s", username, request.remote_addr)
                message = "Account temporarily locked. Try again later."
                return render_template("login.html", message=message)

            user = get_db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["username"] = user["username"]
                reset_attempt(username)
                LOGGER.info("audit_event=login_success username=%s ip=%s", username, request.remote_addr)
                return redirect(url_for("index"))

            register_failed_attempt(username)
            LOGGER.warning("audit_event=login_failed username=%s ip=%s", username, request.remote_addr)
            message = "Invalid username or password."
        return render_template("login.html", message=message)

    @app.route("/logout")
    def logout() -> str:
        username = session.get("username")
        session.clear()
        if username:
            LOGGER.info("audit_event=logout username=%s ip=%s", username, request.remote_addr)
        return redirect(url_for("index"))

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="127.0.0.1", port=5000, debug=False)
