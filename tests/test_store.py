from __future__ import annotations

from pathlib import Path

import pytest

from src.grc_dashboard.data import CONTROL_DATA
from src.grc_dashboard.risk_engine import summarize_risk_register
from src.grc_dashboard.security import (
    can_edit_controls,
    can_manage_users,
    hash_password,
    verify_password,
)
from src.grc_dashboard.store import (
    authenticate_user,
    change_password,
    controls,
    create_initial_admin,
    create_user,
    delete_control,
    get_control,
    get_engine,
    initialize_database,
    list_audit_events,
    list_controls,
    list_users,
    reset_user_password,
    save_control,
    update_user,
    validate_control,
)


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    path = tmp_path / "grc-test.sqlite3"
    url = f"sqlite:///{path.as_posix()}"
    initialize_database(url)
    return url


def test_seed_is_idempotent_and_control_crud_is_audited(database_url: str) -> None:
    initialize_database(database_url)
    assert len(list_controls(database_url)) == len(CONTROL_DATA)

    record = dict(CONTROL_DATA[0], id="TEST-001")
    save_control(record, "admin", creating=True, database_url=database_url)
    record["status_score"] = 55
    save_control(record, "editor", creating=False, database_url=database_url)
    assert get_control("TEST-001", database_url)["status_score"] == 55

    delete_control("TEST-001", "admin", database_url)
    assert get_control("TEST-001", database_url) is None
    actions = [event["action"] for event in list_audit_events(database_url=database_url)[:3]]
    assert actions == ["deleted", "updated", "created"]


def test_empty_register_is_not_reseeded_after_explicit_deletion(database_url: str) -> None:
    with get_engine(database_url).begin() as connection:
        connection.execute(controls.delete())
    initialize_database(database_url)
    assert list_controls(database_url) == []


def test_control_validation_rejects_invalid_score_and_date() -> None:
    record = dict(CONTROL_DATA[0], id="INVALID")
    record["status_score"] = 101
    with pytest.raises(ValueError, match="0 to 100"):
        validate_control(record)

    record["status_score"] = 50
    record["due_date"] = "not-a-date"
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        validate_control(record)

    record["due_date"] = "20261007"
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        validate_control(record)
    record["due_date"] = "2026-10-07"
    record["status_score"] = 50.5
    with pytest.raises(ValueError, match="whole number"):
        validate_control(record)


def test_initial_admin_authentication_and_password_change(database_url: str) -> None:
    create_initial_admin("Root.Admin", "Root Administrator", "a-strong-password-123", database_url)
    first_session = authenticate_user("ROOT.ADMIN", "a-strong-password-123", database_url)
    assert first_session is not None
    assert first_session["role"] == "administrator"
    assert authenticate_user("root.admin", "incorrect-password", database_url) is None

    change_password(
        first_session["id"],
        "a-strong-password-123",
        "an-even-stronger-password-456",
        database_url,
    )
    assert authenticate_user("root.admin", "a-strong-password-123", database_url) is None
    next_session = authenticate_user(
        "root.admin",
        "an-even-stronger-password-456",
        database_url,
    )
    assert next_session is not None
    assert next_session["auth_version"] == first_session["auth_version"] + 1


def test_user_roles_follow_least_privilege_and_admin_guard(database_url: str) -> None:
    create_initial_admin("admin", "Administrator", "administrator-password", database_url)
    create_user(
        "analyst",
        "Risk Analyst",
        "risk-analyst-password",
        "viewer",
        "admin",
        database_url,
    )
    analyst = authenticate_user("analyst", "risk-analyst-password", database_url)
    assert analyst is not None
    assert not can_edit_controls(analyst["role"])
    assert not can_manage_users(analyst["role"])

    admin = next(user for user in list_users(database_url) if user["username"] == "admin")
    with pytest.raises(ValueError, match="At least one active administrator"):
        update_user(admin["id"], "viewer", False, "admin", database_url)

    update_user(analyst["id"], "editor", True, "admin", database_url)
    upgraded_session = authenticate_user("analyst", "risk-analyst-password", database_url)
    assert upgraded_session is not None
    assert upgraded_session["role"] == "editor"
    assert upgraded_session["auth_version"] == analyst["auth_version"] + 1


def test_admin_password_reset_requires_change_on_next_sign_in(database_url: str) -> None:
    create_initial_admin("admin", "Administrator", "administrator-password", database_url)
    create_user(
        "analyst",
        "Risk Analyst",
        "temporary-password-123",
        "viewer",
        "admin",
        database_url,
    )
    old_session = authenticate_user("analyst", "temporary-password-123", database_url)
    assert old_session is not None
    assert old_session["must_change_password"]

    reset_user_password(
        old_session["id"],
        "reset-temporary-password",
        "admin",
        database_url,
    )
    assert authenticate_user("analyst", "temporary-password-123", database_url) is None
    reset_session = authenticate_user("analyst", "reset-temporary-password", database_url)
    assert reset_session is not None
    assert reset_session["must_change_password"]
    assert reset_session["auth_version"] == old_session["auth_version"] + 1

    change_password(
        reset_session["id"],
        "reset-temporary-password",
        "permanent-password-456",
        database_url,
    )
    final_session = authenticate_user("analyst", "permanent-password-456", database_url)
    assert final_session is not None
    assert not final_session["must_change_password"]


def test_password_hash_is_salted_and_verified() -> None:
    first_hash = hash_password("correct-horse-battery-staple")
    second_hash = hash_password("correct-horse-battery-staple")
    assert first_hash != second_hash
    assert verify_password("correct-horse-battery-staple", first_hash)
    assert not verify_password("wrong-password", first_hash)
    assert not verify_password("anything", "malformed")


def test_risk_summary_supports_one_shot_iterables() -> None:
    result = summarize_risk_register(
        iter(
            [
                {"risk_level": "Low"},
                {"risk_level": "Moderate"},
                {"risk_level": "High"},
                {"risk_level": "Critical"},
            ]
        )
    )
    assert result == {"total": 4, "low": 1, "moderate": 1, "high": 1, "critical": 1}
