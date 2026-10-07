from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

from src.grc_dashboard.store import create_user

APP_FILE = Path(__file__).resolve().parents[1] / "app.py"


def test_first_admin_setup_login_and_viewer_permissions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database_url = f"sqlite:///{(tmp_path / 'app.sqlite3').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    bootstrap_token = "b" * 64
    monkeypatch.setenv("BOOTSTRAP_ADMIN_TOKEN", bootstrap_token)

    app = AppTest.from_file(str(APP_FILE), default_timeout=30).run()
    assert not app.exception
    assert app.title[0].value == "Create the first administrator"

    for text_input, value in zip(
        app.text_input,
        (
            "Example Organization",
            "root",
            "Root Administrator",
            "root-password-for-test",
            "root-password-for-test",
            bootstrap_token,
        ),
    ):
        text_input.set_value(value)
    app.button[0].click().run()
    assert not app.exception
    assert app.title[0].value == "Sign in"

    create_user(
        "reader",
        "Read Only User",
        "reader-password-for-test",
        "viewer",
        "root",
        database_url,
    )
    app = AppTest.from_file(str(APP_FILE), default_timeout=30).run()
    assert app.title[0].value == "Sign in"
    app.text_input[0].set_value("root")
    app.text_input[1].set_value("root-password-for-test")
    app.button[0].click().run()
    assert not app.exception
    assert any(radio.label == "Navigate" for radio in app.radio)
    app.radio[0].set_value("Controls & risk").run()
    assert any(radio.label == "Control action" for radio in app.radio)

    app = AppTest.from_file(str(APP_FILE), default_timeout=30).run()
    assert app.title[0].value == "Sign in"
    app.text_input[0].set_value("reader")
    app.text_input[1].set_value("reader-password-for-test")
    app.button[0].click().run()
    assert not app.exception
    assert app.title[0].value == "Set your personal password"
    app.text_input[0].set_value("reader-password-for-test")
    app.text_input[1].set_value("reader-updated-password")
    app.text_input[2].set_value("reader-updated-password")
    app.button[0].click().run()
    assert not app.exception

    app = AppTest.from_file(str(APP_FILE), default_timeout=30).run()
    app.text_input[0].set_value("reader")
    app.text_input[1].set_value("reader-updated-password")
    app.button[0].click().run()
    assert not app.exception
    assert app.session_state["active_page"] == "Overview"
    assert any(radio.label == "Navigate" for radio in app.radio)
    app.radio[0].set_value("Controls & risk").run()
    assert any("viewer role allows read-only" in item.value.lower() for item in app.info)
    assert not any(radio.label == "Control action" for radio in app.radio)
