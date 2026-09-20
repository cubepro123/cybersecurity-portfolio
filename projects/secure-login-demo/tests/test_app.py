from __future__ import annotations

from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))
from app import create_app


def make_client(tmp_path: Path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db"), "SECRET_KEY": "test"})
    return app.test_client()


def test_register_and_login_success(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    register = client.post("/register", data={"username": "student_1", "password": "StrongPass1"}, follow_redirects=True)
    assert register.status_code == 200

    login = client.post("/login", data={"username": "student_1", "password": "StrongPass1"}, follow_redirects=True)
    assert login.status_code == 200
    assert b"Welcome" in login.data


def test_login_lockout(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    client.post("/register", data={"username": "locked_user", "password": "StrongPass1"}, follow_redirects=True)

    for _ in range(5):
        response = client.post("/login", data={"username": "locked_user", "password": "WrongPass"}, follow_redirects=True)
        assert b"Invalid username or password." in response.data

    locked_response = client.post("/login", data={"username": "locked_user", "password": "StrongPass1"}, follow_redirects=True)
    assert b"Account temporarily locked" in locked_response.data


def test_rejects_invalid_username(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.post("/register", data={"username": "!!", "password": "StrongPass1"}, follow_redirects=True)
    assert b"Username must be" in response.data


def test_uses_flask_secret_key_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("FLASK_SECRET_KEY", "from-env")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    app = create_app()
    assert app.config["SECRET_KEY"] == "from-env"


def test_uses_local_learning_fallback_secret_when_env_missing(monkeypatch) -> None:
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    app = create_app()
    assert app.config["SECRET_KEY"] == "local-dev-learning-only-change-me"
