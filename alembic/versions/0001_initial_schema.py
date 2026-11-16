"""initial schema for findings storage

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

JsonType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("summary", JsonType, nullable=False),
    )
    op.create_index("ix_scan_runs_status", "scan_runs", ["status"])
    op.create_index("ix_scan_runs_target", "scan_runs", ["target"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_run_id", sa.Uuid(), sa.ForeignKey("scan_runs.id"), nullable=True),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("evidence", JsonType, nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("references", JsonType, nullable=False),
        sa.Column("confidence", sa.Numeric(5, 4), nullable=False),
        sa.Column("metadata", JsonType, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("finding_id"),
    )
    op.create_index("ix_findings_finding_id", "findings", ["finding_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_target", "findings", ["target"])
    op.create_index("ix_findings_created_at", "findings", ["created_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("decision", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("metadata", JsonType, nullable=False),
    )
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"])

    op.create_table(
        "remediation_proposals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("proposed_change", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_remediation_proposals_finding_id", "remediation_proposals", ["finding_id"])
    op.create_index("ix_remediation_proposals_status", "remediation_proposals", ["status"])

    op.create_table(
        "approval_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column(
            "proposal_id",
            sa.Uuid(),
            sa.ForeignKey("remediation_proposals.id"),
            nullable=True,
        ),
        sa.Column("owner", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_token_hash", sa.String(64), nullable=True),
        sa.Column("metadata", JsonType, nullable=False),
    )
    op.create_index("ix_approval_records_finding_id", "approval_records", ["finding_id"])
    op.create_index("ix_approval_records_status", "approval_records", ["status"])


def downgrade() -> None:
    op.drop_table("approval_records")
    op.drop_table("remediation_proposals")
    op.drop_table("audit_events")
    op.drop_table("findings")
    op.drop_table("scan_runs")
