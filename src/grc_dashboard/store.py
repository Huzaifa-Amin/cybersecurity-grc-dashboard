from __future__ import annotations

import os
import re
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
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    UniqueConstraint,
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

organizations = Table(
    "organizations",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(120), nullable=False, unique=True),
    Column("slug", String(64), nullable=False, unique=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

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
    Column("organization_id", Integer, nullable=False),
    Column("id", String(32), nullable=False),
    Column("control", String(240), nullable=False),
    Column("domain", String(100), nullable=False),
    Column("framework", String(120), nullable=False),
    Column("owner", String(120), nullable=False),
    Column("status", String(40), nullable=False),
    Column("status_score", Integer, nullable=False),
    Column("likelihood", Integer, nullable=False),
    Column("impact", Integer, nullable=False),
    Column("evidence", Text, nullable=False, default=""),
    Column("risk_level", String(20), nullable=False),
    Column("due_date", String(10), nullable=False),
    Column("note", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("organization_id", "id"),
    ForeignKeyConstraint(
        ["organization_id"],
        ["organizations.id"],
        name="fk_controls_organization",
    ),
    CheckConstraint("status_score >= 0 AND status_score <= 100", name="valid_control_score"),
    CheckConstraint("likelihood >= 1 AND likelihood <= 5", name="valid_likelihood"),
    CheckConstraint("impact >= 1 AND impact <= 5", name="valid_impact"),
    CheckConstraint(
        "risk_level IN ('Low', 'Moderate', 'High', 'Critical')", name="valid_risk_level"
    ),
    CheckConstraint(
        "status IN ('Not started', 'Partially implemented', 'Implemented', 'Not applicable')",
        name="valid_control_status",
    ),
)

organization_memberships = Table(
    "organization_memberships",
    metadata,
    Column("organization_id", Integer, ForeignKey("organizations.id"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("role", String(20), nullable=False),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    CheckConstraint(
        "role IN ('administrator', 'editor', 'viewer')",
        name="valid_membership_role",
    ),
)

groups = Table(
    "groups",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("organization_id", Integer, ForeignKey("organizations.id"), nullable=False),
    Column("name", String(100), nullable=False),
    Column("role", String(20), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("organization_id", "name", name="uq_group_organization_name"),
    UniqueConstraint("id", "organization_id", name="uq_group_id_organization"),
    CheckConstraint("role IN ('editor', 'viewer')", name="valid_group_role"),
)

group_memberships = Table(
    "group_memberships",
    metadata,
    Column("organization_id", Integer, primary_key=True),
    Column("group_id", Integer, primary_key=True),
    Column("user_id", Integer, primary_key=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["organization_id", "user_id"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        name="fk_group_memberships_org_user",
    ),
    ForeignKeyConstraint(
        ["group_id", "organization_id"],
        ["groups.id", "groups.organization_id"],
        name="fk_group_memberships_group_org",
    ),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("organization_id", Integer, ForeignKey("organizations.id"), nullable=False),
    Column("actor_username", String(64), nullable=False),
    Column("action", String(40), nullable=False),
    Column("entity_type", String(40), nullable=False),
    Column("entity_id", String(64), nullable=False),
    Column("details", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

control_history = Table(
    "control_history",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("organization_id", Integer, nullable=False),
    Column("control_id", String(32), nullable=False),
    Column("actor_username", String(64), nullable=False),
    Column("status", String(40), nullable=False),
    Column("status_score", Integer, nullable=False),
    Column("risk_level", String(20), nullable=False),
    Column("recorded_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["organization_id", "control_id"],
        ["controls.organization_id", "controls.id"],
        name="fk_control_history_control",
        ondelete="CASCADE",
    ),
)

threat_triage = Table(
    "threat_triage",
    metadata,
    Column("organization_id", Integer, ForeignKey("organizations.id"), primary_key=True),
    Column("cve_id", String(24), primary_key=True),
    Column("status", String(24), nullable=False),
    Column("notes", String(1000), nullable=False, default=""),
    Column("updated_by", String(64), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint(
        "status IN ('New', 'Reviewing', 'Mitigating', 'Mitigated', 'Not applicable')",
        name="valid_threat_triage_status",
    ),
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
    "likelihood",
    "impact",
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


_ROLE_WEIGHT = {"viewer": 0, "editor": 1, "administrator": 2}


def _workspace_role(connection: Any, organization_id: int, user_id: int) -> str | None:
    membership = connection.execute(
        select(organization_memberships.c.role)
        .select_from(
            organization_memberships.join(users, users.c.id == organization_memberships.c.user_id)
        )
        .where(
            organization_memberships.c.organization_id == organization_id,
            organization_memberships.c.user_id == user_id,
            organization_memberships.c.is_active.is_(True),
            users.c.is_active.is_(True),
        )
    ).scalar_one_or_none()
    if membership is None:
        return None
    group_roles = connection.execute(
        select(groups.c.role)
        .select_from(
            group_memberships.join(
                groups,
                (groups.c.id == group_memberships.c.group_id)
                & (groups.c.organization_id == group_memberships.c.organization_id),
            )
        )
        .where(
            group_memberships.c.organization_id == organization_id,
            group_memberships.c.user_id == user_id,
        )
    ).scalars()
    roles = [membership, *group_roles]
    return max(roles, key=_ROLE_WEIGHT.__getitem__)


def _require_workspace_role(
    connection: Any,
    organization_id: int,
    actor: str,
    minimum_role: str = "viewer",
) -> int:
    row = connection.execute(
        select(users.c.id).where(users.c.username == actor, users.c.is_active.is_(True))
    ).first()
    if row is None:
        raise ValueError("This account is not an active workspace member.")
    role = _workspace_role(connection, organization_id, int(row.id))
    if role is None or _ROLE_WEIGHT[role] < _ROLE_WEIGHT[minimum_role]:
        raise ValueError("You do not have permission to access this workspace action.")
    return int(row.id)


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
        organization = connection.execute(
            select(organizations.c.id).order_by(organizations.c.id).limit(1)
        ).first()
        if organization is None:
            result = connection.execute(
                insert(organizations).values(
                    name="Northstar Workspace",
                    slug="northstar-workspace",
                    created_at=_now(),
                )
            )
            organization_id = int(result.inserted_primary_key[0])
        else:
            organization_id = int(organization.id)
        seed_key = f"sample_data_seeded_org_{organization_id}"
        seeded = connection.execute(
            select(app_settings.c.value).where(app_settings.c.key == seed_key)
        ).first()
        if seeded is None:
            existing = connection.execute(
                select(func.count())
                .select_from(controls)
                .where(controls.c.organization_id == organization_id)
            ).scalar_one()
            if existing == 0:
                now = _now()
                connection.execute(
                    insert(controls),
                    [
                        {
                            "organization_id": organization_id,
                            **{field: record[field] for field in CONTROL_FIELDS},
                            "created_at": now,
                            "updated_at": now,
                        }
                        for record in CONTROL_DATA
                    ],
                )
                connection.execute(
                    insert(control_history),
                    [
                        {
                            "organization_id": organization_id,
                            "control_id": record["id"],
                            "actor_username": "system",
                            "status": record["status"],
                            "status_score": record["status_score"],
                            "risk_level": record["risk_level"],
                            "recorded_at": now,
                        }
                        for record in CONTROL_DATA
                    ],
                )
            connection.execute(insert(app_settings).values(key=seed_key, value="true"))


def list_controls(
    database_url: str | None = None,
    *,
    organization_id: int = 1,
    actor: str | None = None,
) -> list[dict[str, Any]]:
    with get_engine(database_url).connect() as connection:
        if actor is None:
            raise ValueError("An authenticated workspace member is required.")
        _require_workspace_role(connection, organization_id, actor)
        result = connection.execute(
            select(controls)
            .where(controls.c.organization_id == organization_id)
            .order_by(controls.c.id)
        )
        return [dict(row) for row in result.mappings()]


def get_control(
    control_id: str,
    database_url: str | None = None,
    *,
    organization_id: int = 1,
    actor: str | None = None,
) -> dict[str, Any] | None:
    with get_engine(database_url).connect() as connection:
        if actor is None:
            raise ValueError("An authenticated workspace member is required.")
        _require_workspace_role(connection, organization_id, actor)
        row = (
            connection.execute(
                select(controls).where(
                    controls.c.organization_id == organization_id,
                    controls.c.id == control_id,
                )
            )
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
    for field in ("likelihood", "impact"):
        raw_value = normalized[field]
        if isinstance(raw_value, bool) or (
            isinstance(raw_value, float) and not raw_value.is_integer()
        ):
            raise ValueError(f"{field.title()} must be a whole number from 1 to 5.")
        try:
            value = int(raw_value)
        except (OverflowError, TypeError, ValueError) as error:
            raise ValueError(f"{field.title()} must be a whole number from 1 to 5.") from error
        if not 1 <= value <= 5:
            raise ValueError(f"{field.title()} must be a whole number from 1 to 5.")
        normalized[field] = value
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
    organization_id: int,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str,
    details: str,
) -> None:
    connection.execute(
        insert(audit_log).values(
            organization_id=organization_id,
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
    organization_id: int = 1,
    database_url: str | None = None,
) -> None:
    normalized = validate_control(record)
    engine = get_engine(database_url)
    with engine.begin() as connection:
        _require_workspace_role(connection, organization_id, actor, "editor")
        existing = connection.execute(
            select(controls.c.id).where(
                controls.c.organization_id == organization_id,
                controls.c.id == normalized["id"],
            )
        ).first()
        if creating and existing:
            raise ValueError(f"Control ID {normalized['id']} already exists.")
        if not creating and not existing:
            raise ValueError(f"Control {normalized['id']} no longer exists.")
        now = _now()
        if creating:
            connection.execute(
                insert(controls).values(
                    organization_id=organization_id,
                    **normalized,
                    created_at=now,
                    updated_at=now,
                )
            )
            action = "created"
        else:
            connection.execute(
                update(controls)
                .where(
                    controls.c.organization_id == organization_id,
                    controls.c.id == normalized["id"],
                )
                .values(
                    **{key: value for key, value in normalized.items() if key != "id"},
                    updated_at=now,
                )
            )
            action = "updated"
        connection.execute(
            insert(control_history).values(
                organization_id=organization_id,
                control_id=normalized["id"],
                actor_username=actor,
                status=normalized["status"],
                status_score=normalized["status_score"],
                risk_level=normalized["risk_level"],
                recorded_at=now,
            )
        )
        _write_audit(
            connection,
            organization_id,
            actor,
            action,
            "control",
            normalized["id"],
            normalized["control"],
        )


def delete_control(
    control_id: str,
    actor: str,
    database_url: str | None = None,
    *,
    organization_id: int = 1,
) -> None:
    engine = get_engine(database_url)
    with engine.begin() as connection:
        _require_workspace_role(connection, organization_id, actor, "administrator")
        row = connection.execute(
            select(controls.c.control).where(
                controls.c.organization_id == organization_id,
                controls.c.id == control_id,
            )
        ).first()
        if row is None:
            raise ValueError(f"Control {control_id} no longer exists.")
        connection.execute(
            controls.delete().where(
                controls.c.organization_id == organization_id,
                controls.c.id == control_id,
            )
        )
        _write_audit(
            connection,
            organization_id,
            actor,
            "deleted",
            "control",
            control_id,
            row[0],
        )


def list_users(
    database_url: str | None = None,
    *,
    organization_id: int = 1,
    actor: str | None = None,
) -> list[dict[str, Any]]:
    if actor is None:
        raise ValueError("An authenticated workspace administrator is required.")
    return list_workspace_members(organization_id, actor, database_url)


def list_workspace_members(
    organization_id: int,
    actor: str,
    database_url: str | None = None,
) -> list[dict[str, Any]]:
    with get_engine(database_url).connect() as connection:
        _require_workspace_role(connection, organization_id, actor, "administrator")
        result = connection.execute(
            select(
                users.c.id,
                users.c.username,
                users.c.display_name,
                organization_memberships.c.role,
                organization_memberships.c.is_active,
                users.c.must_change_password,
                users.c.created_at,
            )
            .select_from(users.join(organization_memberships))
            .where(organization_memberships.c.organization_id == organization_id)
            .order_by(users.c.username)
        )
        members = [dict(row) for row in result.mappings()]
        for member in members:
            member["direct_role"] = member.pop("role")
            member["effective_role"] = _workspace_role(
                connection, organization_id, int(member["id"])
            )
            member["groups"] = ", ".join(
                connection.execute(
                    select(groups.c.name)
                    .select_from(
                        groups.join(
                            group_memberships,
                            (groups.c.id == group_memberships.c.group_id)
                            & (groups.c.organization_id == group_memberships.c.organization_id),
                        )
                    )
                    .where(
                        group_memberships.c.organization_id == organization_id,
                        group_memberships.c.user_id == member["id"],
                    )
                    .order_by(groups.c.name)
                ).scalars()
            )
        return members


def user_count(database_url: str | None = None) -> int:
    with get_engine(database_url).connect() as connection:
        return int(connection.execute(select(func.count()).select_from(users)).scalar_one())


def create_initial_admin(
    username: str,
    display_name: str,
    password: str,
    database_url: str | None = None,
    *,
    organization_name: str = "Northstar Workspace",
) -> None:
    username = validate_username(username)
    display_name = display_name.strip()
    if not display_name or len(display_name) > 120:
        raise ValueError("Display name is required and must be 120 characters or fewer.")
    organization_name = organization_name.strip()
    if not organization_name or len(organization_name) > 120:
        raise ValueError("Workspace name is required and must be 120 characters or fewer.")
    password_hash = hash_password(password)
    engine = get_engine(database_url)
    try:
        with engine.begin() as connection:
            if connection.execute(select(func.count()).select_from(users)).scalar_one():
                raise ValueError("Initial administrator setup has already been completed.")
            organization = connection.execute(
                select(organizations.c.id).order_by(organizations.c.id).limit(1)
            ).first()
            if organization is None:
                result = connection.execute(
                    insert(organizations).values(
                        name=organization_name,
                        slug=_organization_slug(organization_name),
                        created_at=_now(),
                    )
                )
                organization_id = int(result.inserted_primary_key[0])
            else:
                organization_id = int(organization.id)
                connection.execute(
                    update(organizations)
                    .where(organizations.c.id == organization_id)
                    .values(name=organization_name, slug=_organization_slug(organization_name))
                )
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
            user_id = int(
                connection.execute(
                    select(users.c.id).where(users.c.username == username)
                ).scalar_one()
            )
            connection.execute(
                insert(organization_memberships).values(
                    organization_id=organization_id,
                    user_id=user_id,
                    role="administrator",
                    is_active=True,
                    created_at=_now(),
                )
            )
            _write_audit(
                connection,
                organization_id,
                username,
                "created",
                "user",
                username,
                "Initial workspace administrator",
            )
    except IntegrityError as error:
        raise ValueError("That username is already in use.") from error


def create_user(
    username: str,
    display_name: str,
    password: str,
    role: str,
    actor: str,
    database_url: str | None = None,
    *,
    organization_id: int = 1,
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
            _require_workspace_role(connection, organization_id, actor, "administrator")
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
            user_id = int(
                connection.execute(
                    select(users.c.id).where(users.c.username == username)
                ).scalar_one()
            )
            connection.execute(
                insert(organization_memberships).values(
                    organization_id=organization_id,
                    user_id=user_id,
                    role=role,
                    is_active=True,
                    created_at=_now(),
                )
            )
            _write_audit(
                connection,
                organization_id,
                actor,
                "created",
                "user",
                username,
                f"Workspace role: {role}",
            )
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


def _organization_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")
    if not slug:
        raise ValueError("Workspace name must contain letters or numbers.")
    return slug[:64].rstrip("-")


def list_user_organizations(
    user_id: int,
    actor: str,
    database_url: str | None = None,
) -> list[dict[str, Any]]:
    with get_engine(database_url).connect() as connection:
        account = connection.execute(
            select(users.c.id).where(
                users.c.id == user_id,
                users.c.username == actor,
                users.c.is_active.is_(True),
            )
        ).first()
        if account is None:
            raise ValueError("This account is not active.")
        rows = connection.execute(
            select(
                organizations.c.id,
                organizations.c.name,
                organization_memberships.c.role,
            )
            .select_from(organizations.join(organization_memberships))
            .where(
                organization_memberships.c.user_id == user_id,
                organization_memberships.c.is_active.is_(True),
            )
            .order_by(organizations.c.name)
        ).mappings()
        workspaces = []
        for row in rows:
            workspace = dict(row)
            workspace["role"] = _workspace_role(connection, int(row["id"]), user_id)
            workspaces.append(workspace)
        return workspaces


def get_workspace_context(
    user_id: int,
    organization_id: int,
    database_url: str | None = None,
) -> dict[str, Any]:
    with get_engine(database_url).connect() as connection:
        row = (
            connection.execute(
                select(
                    organizations.c.id,
                    organizations.c.name,
                )
                .select_from(organizations.join(organization_memberships))
                .where(
                    organizations.c.id == organization_id,
                    organization_memberships.c.user_id == user_id,
                    organization_memberships.c.is_active.is_(True),
                )
            )
            .mappings()
            .first()
        )
        role = _workspace_role(connection, organization_id, user_id)
        if row is None or role is None:
            raise ValueError("You are not an active member of the selected workspace.")
        return {**dict(row), "role": role}


def create_organization(
    name: str,
    actor: str,
    current_organization_id: int,
    database_url: str | None = None,
) -> int:
    name = name.strip()
    if not name or len(name) > 120:
        raise ValueError("Workspace name is required and must be 120 characters or fewer.")
    slug = _organization_slug(name)
    engine = get_engine(database_url)
    try:
        with engine.begin() as connection:
            creator_id = _require_workspace_role(
                connection, current_organization_id, actor, "administrator"
            )
            result = connection.execute(
                insert(organizations).values(name=name, slug=slug, created_at=_now())
            )
            organization_id = int(result.inserted_primary_key[0])
            now = _now()
            connection.execute(
                insert(organization_memberships).values(
                    organization_id=organization_id,
                    user_id=creator_id,
                    role="administrator",
                    is_active=True,
                    created_at=now,
                )
            )
            connection.execute(
                insert(controls),
                [
                    {
                        "organization_id": organization_id,
                        **{field: record[field] for field in CONTROL_FIELDS},
                        "created_at": now,
                        "updated_at": now,
                    }
                    for record in CONTROL_DATA
                ],
            )
            connection.execute(
                insert(app_settings).values(
                    key=f"sample_data_seeded_org_{organization_id}", value="true"
                )
            )
            _write_audit(
                connection,
                organization_id,
                actor,
                "created",
                "organization",
                str(organization_id),
                name,
            )
            connection.execute(
                insert(control_history),
                [
                    {
                        "organization_id": organization_id,
                        "control_id": record["id"],
                        "actor_username": actor,
                        "status": record["status"],
                        "status_score": record["status_score"],
                        "risk_level": record["risk_level"],
                        "recorded_at": now,
                    }
                    for record in CONTROL_DATA
                ],
            )
            return organization_id
    except IntegrityError as error:
        raise ValueError("A workspace with that name already exists.") from error


def add_workspace_member(
    username: str,
    role: str,
    organization_id: int,
    actor: str,
    database_url: str | None = None,
) -> None:
    username = validate_username(username)
    if role not in ROLES:
        raise ValueError("Select a valid workspace role.")
    with get_engine(database_url).begin() as connection:
        _require_workspace_role(connection, organization_id, actor, "administrator")
        account = connection.execute(
            select(users.c.id).where(users.c.username == username, users.c.is_active.is_(True))
        ).first()
        if account is None:
            raise ValueError("No active account has that username.")
        try:
            connection.execute(
                insert(organization_memberships).values(
                    organization_id=organization_id,
                    user_id=int(account.id),
                    role=role,
                    is_active=True,
                    created_at=_now(),
                )
            )
        except IntegrityError as error:
            raise ValueError("That account is already a member of this workspace.") from error
        _write_audit(
            connection,
            organization_id,
            actor,
            "added",
            "user",
            username,
            f"Workspace role: {role}",
        )


def create_group(
    name: str,
    role: str,
    organization_id: int,
    actor: str,
    database_url: str | None = None,
) -> int:
    name = name.strip()
    if not name or len(name) > 100:
        raise ValueError("Group name is required and must be 100 characters or fewer.")
    if role not in ("viewer", "editor"):
        raise ValueError("Groups may grant viewer or editor access; administrator is direct only.")
    try:
        with get_engine(database_url).begin() as connection:
            _require_workspace_role(connection, organization_id, actor, "administrator")
            result = connection.execute(
                insert(groups).values(
                    organization_id=organization_id,
                    name=name,
                    role=role,
                    created_at=_now(),
                )
            )
            group_id = int(result.inserted_primary_key[0])
            _write_audit(
                connection, organization_id, actor, "created", "group", str(group_id), name
            )
            return group_id
    except IntegrityError as error:
        raise ValueError("A group with that name already exists in this workspace.") from error


def list_groups(
    organization_id: int,
    actor: str,
    database_url: str | None = None,
) -> list[dict[str, Any]]:
    with get_engine(database_url).connect() as connection:
        _require_workspace_role(connection, organization_id, actor)
        rows = connection.execute(
            select(
                groups.c.id,
                groups.c.name,
                groups.c.role,
                func.count(group_memberships.c.user_id).label("member_count"),
            )
            .select_from(
                groups.outerjoin(
                    group_memberships,
                    (group_memberships.c.group_id == groups.c.id)
                    & (group_memberships.c.organization_id == groups.c.organization_id),
                )
            )
            .where(groups.c.organization_id == organization_id)
            .group_by(groups.c.id)
            .order_by(groups.c.name)
        ).mappings()
        return [dict(row) for row in rows]


def list_group_members(
    group_id: int,
    organization_id: int,
    actor: str,
    database_url: str | None = None,
) -> list[int]:
    with get_engine(database_url).connect() as connection:
        _require_workspace_role(connection, organization_id, actor, "administrator")
        group_exists = connection.execute(
            select(groups.c.id).where(
                groups.c.id == group_id, groups.c.organization_id == organization_id
            )
        ).first()
        if group_exists is None:
            raise ValueError("This group does not belong to the selected workspace.")
        return list(
            connection.execute(
                select(group_memberships.c.user_id).where(
                    group_memberships.c.group_id == group_id,
                    group_memberships.c.organization_id == organization_id,
                )
            ).scalars()
        )


def set_group_members(
    group_id: int,
    user_ids: list[int],
    organization_id: int,
    actor: str,
    database_url: str | None = None,
) -> None:
    unique_user_ids = sorted(set(user_ids))
    with get_engine(database_url).begin() as connection:
        _require_workspace_role(connection, organization_id, actor, "administrator")
        group = connection.execute(
            select(groups.c.name).where(
                groups.c.id == group_id, groups.c.organization_id == organization_id
            )
        ).first()
        if group is None:
            raise ValueError("This group does not belong to the selected workspace.")
        if unique_user_ids:
            active_members = set(
                connection.execute(
                    select(organization_memberships.c.user_id).where(
                        organization_memberships.c.organization_id == organization_id,
                        organization_memberships.c.user_id.in_(unique_user_ids),
                        organization_memberships.c.is_active.is_(True),
                    )
                ).scalars()
            )
            if active_members != set(unique_user_ids):
                raise ValueError("Every group member must be an active workspace member.")
        connection.execute(
            group_memberships.delete().where(
                group_memberships.c.organization_id == organization_id,
                group_memberships.c.group_id == group_id,
            )
        )
        if unique_user_ids:
            connection.execute(
                insert(group_memberships),
                [
                    {
                        "organization_id": organization_id,
                        "group_id": group_id,
                        "user_id": user_id,
                        "created_at": _now(),
                    }
                    for user_id in unique_user_ids
                ],
            )
        _write_audit(
            connection,
            organization_id,
            actor,
            "updated",
            "group",
            str(group_id),
            f"Members: {len(unique_user_ids)}",
        )


def list_control_history(
    organization_id: int,
    actor: str,
    limit: int = 1000,
    database_url: str | None = None,
) -> list[dict[str, Any]]:
    bounded_limit = max(1, min(int(limit), 5000))
    with get_engine(database_url).connect() as connection:
        _require_workspace_role(connection, organization_id, actor)
        rows = connection.execute(
            select(control_history)
            .where(control_history.c.organization_id == organization_id)
            .order_by(control_history.c.recorded_at)
            .limit(bounded_limit)
        )
        return [dict(row) for row in rows.mappings()]


def list_threat_triage(
    organization_id: int,
    actor: str,
    database_url: str | None = None,
) -> list[dict[str, Any]]:
    with get_engine(database_url).connect() as connection:
        _require_workspace_role(connection, organization_id, actor)
        rows = connection.execute(
            select(threat_triage)
            .where(threat_triage.c.organization_id == organization_id)
            .order_by(threat_triage.c.updated_at.desc())
        )
        return [dict(row) for row in rows.mappings()]


def update_threat_triage(
    cve_id: str,
    status: str,
    notes: str,
    organization_id: int,
    actor: str,
    database_url: str | None = None,
) -> None:
    normalized_cve = cve_id.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized_cve):
        raise ValueError("Enter a valid CVE identifier.")
    if status not in ("New", "Reviewing", "Mitigating", "Mitigated", "Not applicable"):
        raise ValueError("Select a valid triage status.")
    notes = notes.strip()
    if len(notes) > 1000:
        raise ValueError("Triage notes must be 1000 characters or fewer.")
    with get_engine(database_url).begin() as connection:
        _require_workspace_role(connection, organization_id, actor, "editor")
        values = {
            "status": status,
            "notes": notes,
            "updated_by": actor,
            "updated_at": _now(),
        }
        existing = connection.execute(
            select(threat_triage.c.cve_id).where(
                threat_triage.c.organization_id == organization_id,
                threat_triage.c.cve_id == normalized_cve,
            )
        ).first()
        if existing:
            connection.execute(
                update(threat_triage)
                .where(
                    threat_triage.c.organization_id == organization_id,
                    threat_triage.c.cve_id == normalized_cve,
                )
                .values(**values)
            )
            action = "updated"
        else:
            connection.execute(
                insert(threat_triage).values(
                    organization_id=organization_id,
                    cve_id=normalized_cve,
                    **values,
                )
            )
            action = "created"
        _write_audit(
            connection,
            organization_id,
            actor,
            action,
            "threat_triage",
            normalized_cve,
            f"Status: {status}",
        )


@lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    return hash_password("northstar-dummy-password-not-used")


def update_user(
    user_id: int,
    role: str,
    is_active: bool,
    actor: str,
    database_url: str | None = None,
    *,
    organization_id: int = 1,
) -> None:
    if role not in ROLES:
        raise ValueError("Select a valid user role.")
    engine = get_engine(database_url)
    with engine.begin() as connection:
        _require_workspace_role(connection, organization_id, actor, "administrator")
        target = connection.execute(
            select(
                users.c.username,
                organization_memberships.c.role,
                organization_memberships.c.is_active,
            )
            .select_from(users.join(organization_memberships))
            .where(
                users.c.id == user_id,
                organization_memberships.c.organization_id == organization_id,
            )
        ).first()
        if target is None:
            raise ValueError("This account is not a member of the selected workspace.")
        if target.role == "administrator" and (role != "administrator" or not is_active):
            active_admin_ids = (
                connection.execute(
                    select(organization_memberships.c.user_id)
                    .where(
                        organization_memberships.c.organization_id == organization_id,
                        organization_memberships.c.role == "administrator",
                        organization_memberships.c.is_active.is_(True),
                    )
                    .order_by(organization_memberships.c.user_id)
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
            update(organization_memberships)
            .where(
                organization_memberships.c.organization_id == organization_id,
                organization_memberships.c.user_id == user_id,
            )
            .values(role=role, is_active=is_active)
        )
        connection.execute(
            update(users).where(users.c.id == user_id).values(auth_version=users.c.auth_version + 1)
        )
        _write_audit(
            connection,
            organization_id,
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
    *,
    organization_id: int = 1,
) -> None:
    from src.grc_dashboard.security import verify_password

    engine = get_engine(database_url)
    new_hash = hash_password(new_password)
    with engine.begin() as connection:
        if _workspace_role(connection, organization_id, user_id) is None:
            raise ValueError("This account is not an active workspace member.")
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
        _write_audit(
            connection,
            organization_id,
            row.username,
            "changed_password",
            "user",
            row.username,
            "",
        )


def reset_user_password(
    user_id: int,
    temporary_password: str,
    actor: str,
    database_url: str | None = None,
    *,
    organization_id: int = 1,
) -> None:
    password_hash = hash_password(temporary_password)
    engine = get_engine(database_url)
    with engine.begin() as connection:
        _require_workspace_role(connection, organization_id, actor, "administrator")
        row = connection.execute(
            select(users.c.username)
            .select_from(users.join(organization_memberships))
            .where(
                users.c.id == user_id,
                organization_memberships.c.organization_id == organization_id,
            )
        ).first()
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
            organization_id,
            actor,
            "reset_password",
            "user",
            row.username,
            "Password change required at next sign-in",
        )


def list_audit_events(
    limit: int = 200,
    database_url: str | None = None,
    *,
    organization_id: int = 1,
    actor: str | None = None,
) -> list[dict[str, Any]]:
    bounded_limit = max(1, min(int(limit), 1000))
    with get_engine(database_url).connect() as connection:
        if actor is None:
            raise ValueError("An authenticated workspace administrator is required.")
        _require_workspace_role(connection, organization_id, actor, "administrator")
        result = connection.execute(
            select(audit_log)
            .where(audit_log.c.organization_id == organization_id)
            .order_by(audit_log.c.id.desc())
            .limit(bounded_limit)
        )
        return [dict(row) for row in result.mappings()]
