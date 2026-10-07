from __future__ import annotations

import os
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from alembic import command
from alembic.config import Config
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    event,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from src.grc_dashboard.data import CONTROL_DATA
from src.grc_dashboard.security import ROLES, hash_password, validate_username

metadata = MetaData()
PROJECT_ROOT = Path(__file__).resolve().parents[2]

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(64), nullable=False, unique=True),
    Column("display_name", String(120), nullable=False),
    Column("password_hash", String(200), nullable=False),
    Column("role", String(20), nullable=False),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("must_change_password", Boolean, nullable=False, default=False),
    Column("auth_version", Integer, nullable=False, default=0),
    Column("created_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("role IN ('administrator', 'editor', 'viewer')", name="valid_user_role"),
)

controls = Table(
    "controls",
    metadata,
    Column("id", String(32), primary_key=True),
    Column("control", String(240), nullable=False),
    Column("domain", String(100), nullable=False),
    Column("framework", String(120), nullable=False),
    Column("owner", String(120), nullable=False),
    Column("status", String(40), nullable=False),
    Column("status_score", Integer, nullable=False),
    Column("evidence", Text, nullable=False, default=""),
    Column("risk_level", String(20), nullable=False),
    Column("due_date", String(10), nullable=False),
    Column("note", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("status_score >= 0 AND status_score <= 100", name="valid_control_score"),
    CheckConstraint(
        "risk_level IN ('Low', 'Moderate', 'High', 'Critical')", name="valid_risk_level"
    ),
    CheckConstraint(
        "status IN ('Not started', 'Partially implemented', 'Implemented', 'Not applicable')",
        name="valid_control_status",
    ),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("actor_username", String(64), nullable=False),
    Column("action", String(40), nullable=False),
    Column("entity_type", String(40), nullable=False),
    Column("entity_id", String(64), nullable=False),
    Column("details", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

app_settings = Table(
    "app_settings",
    metadata,
    Column("key", String(80), primary_key=True),
    Column("value", String(200), nullable=False),
)

CONTROL_STATUSES = (
    "Not started",
    "Partially implemented",
    "Implemented",
    "Not applicable",
)
RISK_LEVELS = ("Low", "Moderate", "High", "Critical")
CONTROL_FIELDS = (
    "id",
    "control",
    "domain",
    "framework",
    "owner",
    "status",
    "status_score",
    "evidence",
    "risk_level",
    "due_date",
    "note",
)


def _resolve_database_url(database_url: str | None) -> str:
    url = database_url or os.environ.get("DATABASE_URL", "sqlite:///./data/grc_dashboard.db")
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url.removeprefix("postgres://")
    elif url.startswith("postgresql://") and "+psycopg" not in url:
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    if not (url.startswith("sqlite:///") or url.startswith("postgresql+psycopg://")):
        raise ValueError("DATABASE_URL must use SQLite or PostgreSQL with the psycopg driver.")
    if url.startswith("sqlite:///") and ":memory:" not in url:
        database_path = url.removeprefix("sqlite:///")
        if database_path.startswith("./"):
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    return url


def get_engine(database_url: str | None = None) -> Engine:
    return _create_engine(_resolve_database_url(database_url))


@lru_cache(maxsize=8)
def _create_engine(url: str) -> Engine:
    kwargs: dict[str, Any] = {"pool_pre_ping": True}
    if url.startswith("sqlite:///"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite:///"):

        @event.listens_for(engine, "connect")
        def _configure_sqlite_connection(connection: Any, _record: Any) -> None:
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

    return engine


def _now() -> datetime:
    return datetime.now(timezone.utc)


def initialize_database(database_url: str | None = None) -> None:
    _initialize_database(_resolve_database_url(database_url))


@lru_cache(maxsize=8)
def _initialize_database(database_url: str) -> None:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(config, "head")
    engine = get_engine(database_url)
    with engine.begin() as connection:
        seeded = connection.execute(
            select(app_settings.c.value).where(app_settings.c.key == "sample_data_seeded")
        ).first()
        if seeded is None:
            existing = connection.execute(select(func.count()).select_from(controls)).scalar_one()
            if existing == 0:
                now = _now()
                connection.execute(
                    insert(controls),
                    [
                        {
                            **{field: record[field] for field in CONTROL_FIELDS},
                            "created_at": now,
                            "updated_at": now,
                        }
                        for record in CONTROL_DATA
                    ],
                )
            connection.execute(insert(app_settings).values(key="sample_data_seeded", value="true"))


def list_controls(database_url: str | None = None) -> list[dict[str, Any]]:
    with get_engine(database_url).connect() as connection:
        result = connection.execute(select(controls).order_by(controls.c.id))
        return [dict(row) for row in result.mappings()]


def get_control(control_id: str, database_url: str | None = None) -> dict[str, Any] | None:
    with get_engine(database_url).connect() as connection:
        row = (
            connection.execute(select(controls).where(controls.c.id == control_id))
            .mappings()
            .first()
        )
        return dict(row) if row else None


def validate_control(record: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {field: record.get(field, "") for field in CONTROL_FIELDS}
    normalized["id"] = str(normalized["id"] or "").strip().upper()
    if not normalized["id"] or len(normalized["id"]) > 32:
        raise ValueError("Control ID is required and must be 32 characters or fewer.")
    for field, maximum in (
        ("control", 240),
        ("domain", 100),
        ("framework", 120),
        ("owner", 120),
    ):
        normalized[field] = str(normalized[field] or "").strip()
        if not normalized[field]:
            raise ValueError(f"{field.replace('_', ' ').title()} is required.")
        if len(normalized[field]) > maximum:
            raise ValueError(
                f"{field.replace('_', ' ').title()} must be {maximum} characters or fewer."
            )
    if normalized["status"] not in CONTROL_STATUSES:
        raise ValueError("Select a valid implementation status.")
    if normalized["risk_level"] not in RISK_LEVELS:
        raise ValueError("Select a valid risk rating.")
    raw_score = normalized["status_score"]
    if isinstance(raw_score, bool):
        raise ValueError("Control score must be a whole number from 0 to 100.")
    if isinstance(raw_score, float) and not raw_score.is_integer():
        raise ValueError("Control score must be a whole number from 0 to 100.")
    try:
        score = int(raw_score)
    except (OverflowError, TypeError, ValueError) as error:
        raise ValueError("Control score must be a whole number from 0 to 100.") from error
    if not 0 <= score <= 100:
        raise ValueError("Control score must be a whole number from 0 to 100.")
    normalized["status_score"] = score
    normalized["due_date"] = str(normalized["due_date"] or "").strip()
    try:
        parsed_due_date = date.fromisoformat(normalized["due_date"])
    except ValueError as error:
        raise ValueError("Due date must be a valid date in YYYY-MM-DD format.") from error
    if parsed_due_date.isoformat() != normalized["due_date"]:
        raise ValueError("Due date must be a valid date in YYYY-MM-DD format.")
    for field in ("evidence", "note"):
        normalized[field] = str(normalized[field] or "").strip()
        if len(normalized[field]) > 4000:
            raise ValueError(f"{field.title()} must be 4000 characters or fewer.")
    return normalized


def _write_audit(
    connection: Any,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str,
    details: str,
) -> None:
    connection.execute(
        insert(audit_log).values(
            actor_username=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details[:1000],
            created_at=_now(),
        )
    )


def save_control(
    record: Mapping[str, Any],
    actor: str,
    *,
    creating: bool,
    database_url: str | None = None,
) -> None:
    normalized = validate_control(record)
    engine = get_engine(database_url)
    with engine.begin() as connection:
        existing = connection.execute(
            select(controls.c.id).where(controls.c.id == normalized["id"])
        ).first()
        if creating and existing:
            raise ValueError(f"Control ID {normalized['id']} already exists.")
        if not creating and not existing:
            raise ValueError(f"Control {normalized['id']} no longer exists.")
        now = _now()
        if creating:
            connection.execute(
                insert(controls).values(
                    **normalized,
                    created_at=now,
                    updated_at=now,
                )
            )
            action = "created"
        else:
            connection.execute(
                update(controls)
                .where(controls.c.id == normalized["id"])
                .values(
                    **{key: value for key, value in normalized.items() if key != "id"},
                    updated_at=now,
                )
            )
            action = "updated"
        _write_audit(connection, actor, action, "control", normalized["id"], normalized["control"])


def delete_control(
    control_id: str,
    actor: str,
    database_url: str | None = None,
) -> None:
    engine = get_engine(database_url)
    with engine.begin() as connection:
        row = connection.execute(
            select(controls.c.control).where(controls.c.id == control_id)
        ).first()
        if row is None:
            raise ValueError(f"Control {control_id} no longer exists.")
        connection.execute(controls.delete().where(controls.c.id == control_id))
        _write_audit(connection, actor, "deleted", "control", control_id, row[0])


def list_users(database_url: str | None = None) -> list[dict[str, Any]]:
    with get_engine(database_url).connect() as connection:
        result = connection.execute(
            select(
                users.c.id,
                users.c.username,
                users.c.display_name,
                users.c.role,
                users.c.is_active,
                users.c.must_change_password,
                users.c.created_at,
            ).order_by(users.c.username)
        )
        return [dict(row) for row in result.mappings()]


def user_count(database_url: str | None = None) -> int:
    with get_engine(database_url).connect() as connection:
        return int(connection.execute(select(func.count()).select_from(users)).scalar_one())


def create_initial_admin(
    username: str,
    display_name: str,
    password: str,
    database_url: str | None = None,
) -> None:
    username = validate_username(username)
    display_name = display_name.strip()
    if not display_name or len(display_name) > 120:
        raise ValueError("Display name is required and must be 120 characters or fewer.")
    password_hash = hash_password(password)
    engine = get_engine(database_url)
    try:
        with engine.begin() as connection:
            if connection.execute(select(func.count()).select_from(users)).scalar_one():
                raise ValueError("Initial administrator setup has already been completed.")
            connection.execute(
                insert(users).values(
                    username=username,
                    display_name=display_name,
                    password_hash=password_hash,
                    role="administrator",
                    is_active=True,
                    must_change_password=False,
                    created_at=_now(),
                )
            )
            _write_audit(connection, username, "created", "user", username, "Initial administrator")
    except IntegrityError as error:
        raise ValueError("That username is already in use.") from error


def create_user(
    username: str,
    display_name: str,
    password: str,
    role: str,
    actor: str,
    database_url: str | None = None,
) -> None:
    username = validate_username(username)
    display_name = display_name.strip()
    if not display_name or len(display_name) > 120:
        raise ValueError("Display name is required and must be 120 characters or fewer.")
    if role not in ROLES:
        raise ValueError("Select a valid user role.")
    password_hash = hash_password(password)
    engine = get_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                insert(users).values(
                    username=username,
                    display_name=display_name,
                    password_hash=password_hash,
                    role=role,
                    is_active=True,
                    must_change_password=True,
                    created_at=_now(),
                )
            )
            _write_audit(connection, actor, "created", "user", username, f"Role: {role}")
    except IntegrityError as error:
        raise ValueError("That username is already in use.") from error


def authenticate_user(
    username: str, password: str, database_url: str | None = None
) -> dict[str, Any] | None:
    from src.grc_dashboard.security import verify_password

    normalized = username.strip().lower()
    dummy_hash = _dummy_password_hash()
    with get_engine(database_url).connect() as connection:
        row = (
            connection.execute(select(users).where(users.c.username == normalized))
            .mappings()
            .first()
        )
    stored_hash = row["password_hash"] if row else dummy_hash
    password_matches = verify_password(password, stored_hash)
    if row is None or not row["is_active"] or not password_matches:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
        "must_change_password": row["must_change_password"],
        "auth_version": row["auth_version"],
    }


@lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    return hash_password("northstar-dummy-password-not-used")


def update_user(
    user_id: int,
    role: str,
    is_active: bool,
    actor: str,
    database_url: str | None = None,
) -> None:
    if role not in ROLES:
        raise ValueError("Select a valid user role.")
    engine = get_engine(database_url)
    with engine.begin() as connection:
        target = connection.execute(
            select(users.c.username, users.c.role, users.c.is_active).where(users.c.id == user_id)
        ).first()
        if target is None:
            raise ValueError("This user no longer exists.")
        if target.role == "administrator" and (role != "administrator" or not is_active):
            active_admin_ids = (
                connection.execute(
                    select(users.c.id)
                    .where(users.c.role == "administrator", users.c.is_active.is_(True))
                    .order_by(users.c.id)
                    .with_for_update()
                )
                .scalars()
                .all()
            )
            active_admins = len(active_admin_ids)
            current_is_active_admin = target.role == "administrator" and target.is_active
            desired_is_active_admin = role == "administrator" and is_active
            if current_is_active_admin and not desired_is_active_admin:
                active_admins -= 1
            if active_admins < 1:
                raise ValueError("At least one active administrator account must remain.")
        connection.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(role=role, is_active=is_active, auth_version=users.c.auth_version + 1)
        )
        _write_audit(
            connection,
            actor,
            "updated",
            "user",
            target.username,
            f"Role: {role}; active: {is_active}",
        )


def change_password(
    user_id: int,
    current_password: str,
    new_password: str,
    database_url: str | None = None,
) -> None:
    from src.grc_dashboard.security import verify_password

    engine = get_engine(database_url)
    new_hash = hash_password(new_password)
    with engine.begin() as connection:
        row = connection.execute(
            select(users.c.username, users.c.password_hash).where(users.c.id == user_id)
        ).first()
        if row is None or not verify_password(current_password, row.password_hash):
            raise ValueError("Current password is incorrect.")
        connection.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(
                password_hash=new_hash,
                must_change_password=False,
                auth_version=users.c.auth_version + 1,
            )
        )
        _write_audit(connection, row.username, "changed_password", "user", row.username, "")


def reset_user_password(
    user_id: int,
    temporary_password: str,
    actor: str,
    database_url: str | None = None,
) -> None:
    password_hash = hash_password(temporary_password)
    engine = get_engine(database_url)
    with engine.begin() as connection:
        row = connection.execute(select(users.c.username).where(users.c.id == user_id)).first()
        if row is None:
            raise ValueError("This user no longer exists.")
        connection.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(
                password_hash=password_hash,
                must_change_password=True,
                auth_version=users.c.auth_version + 1,
            )
        )
        _write_audit(
            connection,
            actor,
            "reset_password",
            "user",
            row.username,
            "Password change required at next sign-in",
        )


def list_audit_events(limit: int = 200, database_url: str | None = None) -> list[dict[str, Any]]:
    bounded_limit = max(1, min(int(limit), 1000))
    with get_engine(database_url).connect() as connection:
        result = connection.execute(
            select(audit_log).order_by(audit_log.c.id.desc()).limit(bounded_limit)
        )
        return [dict(row) for row in result.mappings()]
