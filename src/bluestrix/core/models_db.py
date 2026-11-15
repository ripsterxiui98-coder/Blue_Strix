"""SQLAlchemy ORM models for scan runs, findings, audit, and remediation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from bluestrix.core.database import Base

# JSONB on Postgres; plain JSON elsewhere (e.g. SQLite tests)
JsonType = JSON().with_variant(JSONB(), "postgresql")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    target: Mapped[str] = mapped_column(Text, index=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)

    findings: Mapped[list["FindingRecord"]] = relationship(back_populates="scan_run")


class FindingRecord(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_target", "target"),
        Index("ix_findings_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_runs.id"), nullable=True, index=True
    )
    finding_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(32), default="INFO")
    status: Mapped[str] = mapped_column(String(32), default="open")
    category: Mapped[str] = mapped_column(String(64), default="general")
    target: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    confidence: Mapped[float] = mapped_column(Numeric(5, 4), default=0.5)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JsonType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scan_run: Mapped[Optional[ScanRun]] = relationship(back_populates="findings")


class AuditEventRecord(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_timestamp", "timestamp"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text, default="")
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JsonType, default=dict)


class RemediationProposal(Base):
    __tablename__ = "remediation_proposals"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="INFO")
    target: Mapped[str] = mapped_column(Text)
    proposed_change: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="proposed", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    approvals: Mapped[list["ApprovalRecord"]] = relationship(back_populates="proposal")


class ApprovalRecord(Base):
    __tablename__ = "approval_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    proposal_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("remediation_proposals.id"), nullable=True
    )
    owner: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_token_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JsonType, default=dict)

    proposal: Mapped[Optional[RemediationProposal]] = relationship(back_populates="approvals")
