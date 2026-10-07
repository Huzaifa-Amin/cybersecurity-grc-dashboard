"""Add organization-isolated workspaces, groups, and control history.

Revision ID: 0002_workspaces
Revises: 0001_initial
Create Date: 2026-10-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_workspaces"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "organizations" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "organizations",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(length=120), nullable=False, unique=True),
            sa.Column("slug", sa.String(length=64), nullable=False, unique=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    if bind.execute(sa.text("SELECT COUNT(*) FROM organizations")).scalar_one() == 0:
        op.execute(
            sa.text(
                "INSERT INTO organizations (id, name, slug, created_at) "
                "VALUES (1, 'Northstar Workspace', 'northstar-workspace', CURRENT_TIMESTAMP)"
            )
        )
    op.create_table(
        "organization_memberships",
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id"),
            primary_key=True,
        ),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('administrator', 'editor', 'viewer')",
            name="valid_membership_role",
        ),
    )
    op.execute(
        sa.text(
            "INSERT INTO organization_memberships "
            "(organization_id, user_id, role, is_active, created_at) "
            "SELECT 1, id, role, is_active, created_at FROM users"
        )
    )

    op.create_table(
        "controls_new",
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("control", sa.String(length=240), nullable=False),
        sa.Column("domain", sa.String(length=100), nullable=False),
        sa.Column("framework", sa.String(length=120), nullable=False),
        sa.Column("owner", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("status_score", sa.Integer(), nullable=False),
        sa.Column("likelihood", sa.Integer(), nullable=False),
        sa.Column("impact", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("due_date", sa.String(length=10), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("organization_id", "id"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_controls_organization",
        ),
        sa.CheckConstraint(
            "status_score >= 0 AND status_score <= 100",
            name="valid_control_score",
        ),
        sa.CheckConstraint("likelihood >= 1 AND likelihood <= 5", name="valid_likelihood"),
        sa.CheckConstraint("impact >= 1 AND impact <= 5", name="valid_impact"),
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
    op.execute(
        sa.text(
            "INSERT INTO controls_new "
            "(organization_id, id, control, domain, framework, owner, status, status_score, "
            "likelihood, impact, "
            "evidence, risk_level, due_date, note, created_at, updated_at) "
            "SELECT 1, id, control, domain, framework, owner, status, status_score, "
            "CASE risk_level WHEN 'Low' THEN 2 WHEN 'Moderate' THEN 3 "
            "WHEN 'High' THEN 4 ELSE 5 END, "
            "CASE risk_level WHEN 'Low' THEN 2 WHEN 'Moderate' THEN 3 "
            "WHEN 'High' THEN 4 ELSE 5 END, evidence, "
            "risk_level, due_date, note, created_at, updated_at FROM controls"
        )
    )
    op.drop_table("controls")
    op.rename_table("controls_new", "controls")

    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.add_column(
            sa.Column(
                "organization_id",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("1"),
            )
        )
        batch_op.create_foreign_key(
            "fk_audit_log_organization",
            "organizations",
            ["organization_id"],
            ["id"],
        )
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.alter_column("organization_id", server_default=None)

    op.create_table(
        "groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "name", name="uq_group_organization_name"),
        sa.UniqueConstraint("id", "organization_id", name="uq_group_id_organization"),
        sa.CheckConstraint("role IN ('editor', 'viewer')", name="valid_group_role"),
    )
    op.create_table(
        "group_memberships",
        sa.Column("organization_id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            name="fk_group_memberships_org_user",
        ),
        sa.ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["groups.id", "groups.organization_id"],
            name="fk_group_memberships_group_org",
        ),
    )
    op.create_table(
        "control_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("control_id", sa.String(length=32), nullable=False),
        sa.Column("actor_username", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("status_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "control_id"],
            ["controls.organization_id", "controls.id"],
            name="fk_control_history_control",
            ondelete="CASCADE",
        ),
    )
    op.create_table(
        "threat_triage",
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=24), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("notes", sa.String(length=1000), nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("organization_id", "cve_id"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], name="fk_threat_triage_organization"
        ),
        sa.CheckConstraint(
            "status IN ('New', 'Reviewing', 'Mitigating', 'Mitigated', 'Not applicable')",
            name="valid_threat_triage_status",
        ),
    )
    op.execute(
        sa.text(
            "INSERT INTO control_history "
            "(organization_id, control_id, actor_username, status, status_score, risk_level, "
            "recorded_at) SELECT 1, id, 'migration', status, status_score, risk_level, updated_at "
            "FROM controls"
        )
    )
    existing_seed = (
        op.get_bind()
        .execute(sa.text("SELECT value FROM app_settings WHERE key = 'sample_data_seeded'"))
        .first()
    )
    if existing_seed is not None:
        op.execute(
            sa.text(
                "INSERT INTO app_settings (key, value) "
                "VALUES ('sample_data_seeded_org_1', 'true')"
            )
        )


def downgrade() -> None:
    op.drop_table("threat_triage")
    op.drop_table("control_history")
    op.drop_table("group_memberships")
    op.drop_table("groups")
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.drop_constraint("fk_audit_log_organization", type_="foreignkey")
        batch_op.drop_column("organization_id")
    op.create_table(
        "controls_old",
        sa.Column("id", sa.String(length=32), nullable=False, primary_key=True),
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
    )
    op.execute(
        sa.text(
            "INSERT INTO controls_old "
            "(id, control, domain, framework, owner, status, status_score, evidence, risk_level, "
            "due_date, note, created_at, updated_at) "
            "SELECT id, control, domain, framework, owner, status, status_score, evidence, "
            "risk_level, due_date, note, created_at, updated_at "
            "FROM controls WHERE organization_id=1"
        )
    )
    op.drop_table("controls")
    op.rename_table("controls_old", "controls")
    op.drop_table("organization_memberships")
    op.drop_table("organizations")
    op.execute(sa.text("DELETE FROM app_settings WHERE key = 'sample_data_seeded_org_1'"))
