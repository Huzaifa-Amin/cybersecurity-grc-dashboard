"""Create initial Northstar database schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("auth_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('administrator', 'editor', 'viewer')",
            name="valid_user_role",
        ),
    )
    op.create_table(
        "controls",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("control", sa.String(length=240), nullable=False),
        sa.Column("domain", sa.String(length=100), nullable=False),
        sa.Column("framework", sa.String(length=120), nullable=False),
        sa.Column("owner", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("status_score", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("due_date", sa.String(length=10), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status_score >= 0 AND status_score <= 100",
            name="valid_control_score",
        ),
        sa.CheckConstraint(
            "risk_level IN ('Low', 'Moderate', 'High', 'Critical')",
            name="valid_risk_level",
        ),
        sa.CheckConstraint(
            "status IN ('Not started', 'Partially implemented', 'Implemented', "
            "'Not applicable')",
            name="valid_control_status",
        ),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_username", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("entity_type", sa.String(length=40), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(length=80), primary_key=True),
        sa.Column("value", sa.String(length=200), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
    op.drop_table("audit_log")
    op.drop_table("controls")
    op.drop_table("users")
