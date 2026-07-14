from datetime import datetime
from typing import Optional
from uuid import UUID as PythonUUID
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from iam_guardian.database import Base


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[PythonUUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )
    check_name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_arn: Mapped[str] = mapped_column(String(500), nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    llm_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScanORM(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    account_id: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="completed", nullable=False)
    total_findings: Mapped[int] = mapped_column(default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PolicyRewriteORM(Base):
    __tablename__ = "policy_rewrites"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    finding_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    original_policy: Mapped[dict] = mapped_column(JSON, nullable=False)
    rewritten_policy: Mapped[dict] = mapped_column(JSON, nullable=False)
    diff_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    simulation_result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    rewrite_status: Mapped[str] = mapped_column(
        String(50),
        default="verified",
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class EscalationPathORM(Base):
    __tablename__ = "escalation_paths"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    account_id: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    principal_arn: Mapped[str] = mapped_column(String(500), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(10), nullable=False)
    principal_name: Mapped[str] = mapped_column(String(255), nullable=False)
    matched_combo: Mapped[list] = mapped_column(JSON, nullable=False)
    effective_permissions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attack_story: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    narrative: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ChatSessionORM(Base):
    __tablename__ = "chat_sessions"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    session_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(10), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RequestLogORM(Base):
    __tablename__ = "request_logs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    request_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    username: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    llm_tokens_used: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
