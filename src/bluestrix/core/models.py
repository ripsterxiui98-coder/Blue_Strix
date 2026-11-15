from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_TESTED = "NOT_TESTED"
    BLOCKED = "BLOCKED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ActionType(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DEPLOY = "DEPLOY"
    TRANSFER = "TRANSFER"
    SIGN = "SIGN"
    EXECUTE = "EXECUTE"
    REMEDIATE = "REMEDIATE"


class Evidence(BaseModel):
    source: str
    kind: str = "observation"
    value: Any = None
    location: Optional[str] = None
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"BSX-{uuid4().hex[:12]}")
    title: str
    description: str
    severity: Severity = Severity.INFO
    status: CheckStatus = CheckStatus.NOT_TESTED
    category: str = "general"
    target: str
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityDecision(BaseModel):
    allowed: bool
    reason: str
    action: ActionType
    target: str
    policy_id: Optional[str] = None
    requires_human_approval: bool = False


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "system"
    action: str
    target: str
    decision: str
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)
