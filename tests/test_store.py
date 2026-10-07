from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from src.grc_dashboard.data import CONTROL_DATA
from src.grc_dashboard.risk_engine import summarize_risk_register
from src.grc_dashboard.security import (
    can_edit_controls,
    can_manage_users,
    hash_password,
    verify_password,
)
from src.grc_dashboard.store import (
    PROJECT_ROOT,
    add_workspace_member,
    authenticate_user,
    change_password,
    controls,
    create_group,
    create_initial_admin,
    create_organization,
    create_user,
    delete_control,
    get_control,
    get_engine,
    get_workspace_context,
    initialize_database,
    list_audit_events,
    list_control_history,
    list_controls,
    list_group_members,
    list_groups,
    list_threat_triage,
    list_user_organizations,
    list_users,
    reset_user_password,
    save_control,
    set_group_members,
    update_threat_triage,
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
    create_initial_admin("admin", "Administrator", "administrator-password", database_url)
    assert len(list_controls(database_url, actor="admin")) == len(CONTROL_DATA)

    record = dict(CONTROL_DATA[0], id="TEST-001")
    save_control(record, "admin", creating=True, database_url=database_url)
    record["status_score"] = 55
    save_control(record, "admin", creating=False, database_url=database_url)
    assert get_control("TEST-001", database_url, actor="admin")["status_score"] == 55

    delete_control("TEST-001", "admin", database_url)
    assert get_control("TEST-001", database_url, actor="admin") is None
    actions = [
        event["action"]
        for event in list_audit_events(
            database_url=database_url,
            actor="admin",
        )[:3]
    ]
    assert actions == ["deleted", "updated", "created"]


def test_empty_register_is_not_reseeded_after_explicit_deletion(database_url: str) -> None:
    create_initial_admin("admin", "Administrator", "administrator-password", database_url)
    with get_engine(database_url).begin() as connection:
        connection.execute(controls.delete())
    initialize_database(database_url)
    assert list_controls(database_url, actor="admin") == []


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

    admin = next(
        user for user in list_users(database_url, actor="admin") if user["username"] == "admin"
    )
    with pytest.raises(ValueError, match="At least one active administrator"):
        update_user(admin["id"], "viewer", False, "admin", database_url)

    update_user(analyst["id"], "editor", True, "admin", database_url)
    upgraded_session = authenticate_user("analyst", "risk-analyst-password", database_url)
    assert upgraded_session is not None
    assert get_workspace_context(upgraded_session["id"], 1, database_url)["role"] == "editor"
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


def test_workspace_isolation_and_duplicate_control_ids(database_url: str) -> None:
    create_initial_admin("admin", "Administrator", "administrator-password", database_url)
    second_workspace = create_organization("Acme Security", "admin", 1, database_url)
    first_record = dict(CONTROL_DATA[0], id="SHARED-001")
    second_record = dict(CONTROL_DATA[1], id="SHARED-001")
    save_control(first_record, "admin", creating=True, database_url=database_url)
    save_control(
        second_record,
        "admin",
        creating=True,
        organization_id=second_workspace,
        database_url=database_url,
    )
    first_value = get_control("SHARED-001", database_url, actor="admin", organization_id=1)
    second_value = get_control(
        "SHARED-001",
        database_url,
        actor="admin",
        organization_id=second_workspace,
    )
    assert first_value["control"] != second_value["control"]
    assert second_workspace in {
        workspace["id"] for workspace in list_user_organizations(1, "admin", database_url)
    }

    create_user(
        "acme-reader",
        "Acme Reader",
        "acme-reader-password",
        "viewer",
        "admin",
        database_url,
        organization_id=second_workspace,
    )
    assert (
        len(
            list_controls(
                database_url,
                actor="acme-reader",
                organization_id=second_workspace,
            )
        )
        == len(CONTROL_DATA) + 1
    )
    with pytest.raises(ValueError, match="permission"):
        list_controls(database_url, actor="acme-reader", organization_id=1)
    with pytest.raises(ValueError, match="permission"):
        get_control("SHARED-001", database_url, actor="acme-reader", organization_id=1)
    with pytest.raises(ValueError, match="permission"):
        delete_control(
            "SHARED-001",
            "acme-reader",
            database_url,
            organization_id=second_workspace,
        )
    assert all(
        entry["organization_id"] == second_workspace
        for entry in list_audit_events(
            database_url=database_url,
            actor="admin",
            organization_id=second_workspace,
        )
    )
    with pytest.raises(ValueError, match="permission"):
        list_audit_events(
            database_url=database_url,
            actor="acme-reader",
            organization_id=second_workspace,
        )


def test_group_grants_editor_within_workspace_without_admin_privilege(database_url: str) -> None:
    create_initial_admin("admin", "Administrator", "administrator-password", database_url)
    workspace_id = create_organization("Group Lab", "admin", 1, database_url)
    create_user(
        "analyst",
        "Analyst",
        "analyst-password-123",
        "viewer",
        "admin",
        database_url,
        organization_id=workspace_id,
    )
    analyst = authenticate_user("analyst", "analyst-password-123", database_url)
    assert analyst is not None
    add_workspace_member("analyst", "viewer", 1, "admin", database_url)
    assert get_workspace_context(analyst["id"], 1, database_url)["role"] == "viewer"
    with pytest.raises(ValueError, match="administrator is direct only"):
        create_group("Platform admins", "administrator", workspace_id, "admin", database_url)
    group_id = create_group("Platform team", "editor", workspace_id, "admin", database_url)
    set_group_members(group_id, [analyst["id"]], workspace_id, "admin", database_url)
    assert list_group_members(group_id, workspace_id, "admin", database_url) == [analyst["id"]]
    assert get_workspace_context(analyst["id"], workspace_id, database_url)["role"] == "editor"
    assert (
        next(
            group
            for group in list_groups(workspace_id, "admin", database_url)
            if group["id"] == group_id
        )["member_count"]
        == 1
    )
    save_control(
        dict(CONTROL_DATA[0], id="GROUP-EDIT"),
        "analyst",
        creating=True,
        organization_id=workspace_id,
        database_url=database_url,
    )
    with pytest.raises(ValueError, match="permission"):
        create_group("Not allowed", "viewer", workspace_id, "analyst", database_url)


def test_threat_triage_is_workspace_scoped_and_validated(database_url: str) -> None:
    create_initial_admin("admin", "Administrator", "administrator-password", database_url)
    other_workspace = create_organization("Second Workspace", "admin", 1, database_url)
    update_threat_triage(
        "CVE-2025-12345",
        "Reviewing",
        "Check the affected asset inventory.",
        1,
        "admin",
        database_url,
    )
    assert list_threat_triage(1, "admin", database_url)[0]["status"] == "Reviewing"
    assert list_threat_triage(other_workspace, "admin", database_url) == []
    with pytest.raises(ValueError, match="valid CVE"):
        update_threat_triage("not-a-cve", "Reviewing", "", 1, "admin", database_url)
    with pytest.raises(ValueError, match="valid triage status"):
        update_threat_triage("CVE-2025-12345", "Unknown", "", 1, "admin", database_url)


def test_upgrade_backfills_existing_users_controls_and_audit(tmp_path: Path) -> None:
    database_url = f"sqlite:///{(tmp_path / 'legacy.sqlite3').as_posix()}"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(config, "0001_initial")
    now = "2026-10-01 12:00:00"
    with get_engine(database_url).begin() as connection:
        connection.execute(
            sa.text(
                "INSERT INTO users (username, display_name, password_hash, role, is_active, "
                "must_change_password, auth_version, created_at) VALUES "
                "('legacy-admin', 'Legacy Admin', 'unused', 'administrator', 1, 0, 0, :now)"
            ),
            {"now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO controls (id, control, domain, framework, owner, status, "
                "status_score, evidence, risk_level, due_date, note, created_at, updated_at) "
                "VALUES ('LEGACY-01', 'Legacy security control', 'Protect', 'NIST CSF 2.0', "
                "'Security', 'Partially implemented', 40, 'ticket-1', 'High', '2026-12-01', "
                "'Legacy remediation', :now, :now)"
            ),
            {"now": now},
        )
        connection.execute(
            sa.text(
                "INSERT INTO audit_log (actor_username, action, entity_type, entity_id, details, "
                "created_at) VALUES ('legacy-admin', 'created', 'user', 'legacy-admin', "
                "'Before tenant migration', :now)"
            ),
            {"now": now},
        )
        connection.execute(
            sa.text("INSERT INTO app_settings (key, value) VALUES ('sample_data_seeded', 'true')")
        )

    initialize_database(database_url)
    migrated = list_controls(database_url, actor="legacy-admin")
    assert len(migrated) == 1
    assert migrated[0]["id"] == "LEGACY-01"
    assert migrated[0]["likelihood"] == 4
    assert migrated[0]["impact"] == 4
    assert list_user_organizations(1, "legacy-admin", database_url)[0]["name"] == (
        "Northstar Workspace"
    )
    assert (
        list_audit_events(database_url=database_url, actor="legacy-admin")[0]["organization_id"]
        == 1
    )
    assert (
        list_control_history(1, "legacy-admin", database_url=database_url)[0]["actor_username"]
        == "migration"
    )


def test_upgrade_recovers_when_organization_table_was_partially_created(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{(tmp_path / 'partial-upgrade.sqlite3').as_posix()}"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(config, "0001_initial")
    with get_engine(database_url).begin() as connection:
        connection.execute(
            sa.text(
                "CREATE TABLE organizations ("
                "id INTEGER NOT NULL PRIMARY KEY, "
                "name VARCHAR(120) NOT NULL UNIQUE, "
                "slug VARCHAR(64) NOT NULL UNIQUE, "
                "created_at DATETIME NOT NULL)"
            )
        )

    initialize_database(database_url)

    with get_engine(database_url).connect() as connection:
        assert (
            connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one()
            == "0002_workspaces"
        )
        assert connection.execute(sa.text("SELECT COUNT(*) FROM organizations")).scalar_one() == 1
    create_initial_admin("admin", "Administrator", "administrator-password", database_url)
    assert len(list_controls(database_url, actor="admin")) == len(CONTROL_DATA)
