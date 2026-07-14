from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from iam_guardian.auth import get_current_user
from iam_guardian.database import get_db
from iam_guardian.db_models import (
    ChatSessionORM,
    EscalationPathORM,
    FindingORM,
    PolicyRewriteORM,
    RequestLogORM,
    ScanORM,
)
from iam_guardian.models import MetricsResponse

metrics_router = APIRouter(prefix="/metrics", tags=["metrics"])


@metrics_router.get("", response_model=MetricsResponse)
async def get_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Return a dashboard-ready metrics summary aggregated from the database.
    """
    scan_count_result = await db.execute(select(func.count(ScanORM.id)))
    total_scans = scan_count_result.scalar() or 0

    latest_scan_result = await db.execute(
        select(ScanORM).order_by(ScanORM.created_at.desc()).limit(1)
    )
    latest_scan = latest_scan_result.scalar_one_or_none()
    latest_scan_at = latest_scan.created_at.isoformat() if latest_scan else None

    severity_counts_result = await db.execute(
        select(FindingORM.severity, func.count(FindingORM.id).label("cnt")).group_by(
            FindingORM.severity
        )
    )
    all_severity_counts = {row[0]: row[1] for row in severity_counts_result.all()}

    open_severity_result = await db.execute(
        select(FindingORM.severity, func.count(FindingORM.id).label("cnt"))
        .where(FindingORM.status == "open")
        .group_by(FindingORM.severity)
    )
    open_by_severity = {row[0]: row[1] for row in open_severity_result.all()}

    total_findings_result = await db.execute(select(func.count(FindingORM.id)))
    total_findings = total_findings_result.scalar() or 0

    open_findings_result = await db.execute(
        select(func.count(FindingORM.id)).where(FindingORM.status == "open")
    )
    open_findings = open_findings_result.scalar() or 0

    resolved_findings_result = await db.execute(
        select(func.count(FindingORM.id)).where(FindingORM.status == "resolved")
    )
    resolved_findings = resolved_findings_result.scalar() or 0

    esc_count_result = await db.execute(select(func.count(EscalationPathORM.id)))
    total_escalation_paths = esc_count_result.scalar() or 0

    critical_esc_result = await db.execute(
        select(func.count(EscalationPathORM.id)).where(
            EscalationPathORM.severity == "critical"
        )
    )
    critical_escalation_paths = critical_esc_result.scalar() or 0

    avg_latency_result = await db.execute(select(func.avg(RequestLogORM.latency_ms)))
    avg_latency_raw = avg_latency_result.scalar()
    avg_latency_ms = round(float(avg_latency_raw), 1) if avg_latency_raw else 0.0

    try:
        p95_result = await db.execute(
            text(
                "SELECT PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) "
                "FROM request_logs"
            )
        )
        p95_raw = p95_result.scalar()
        p95_latency_ms = round(float(p95_raw), 1) if p95_raw else 0.0
    except Exception:
        p95_latency_ms = 0.0

    total_requests_result = await db.execute(select(func.count(RequestLogORM.id)))
    total_requests = total_requests_result.scalar() or 0

    error_count_result = await db.execute(
        select(func.count(RequestLogORM.id)).where(RequestLogORM.status_code >= 400)
    )
    error_count = error_count_result.scalar() or 0

    since_24h = datetime.utcnow() - timedelta(hours=24)
    requests_24h_result = await db.execute(
        select(func.count(RequestLogORM.id)).where(RequestLogORM.created_at >= since_24h)
    )
    requests_last_24h = requests_24h_result.scalar() or 0

    total_chat_turns_result = await db.execute(
        select(func.count(ChatSessionORM.id)).where(ChatSessionORM.role == "user")
    )
    total_chat_turns = total_chat_turns_result.scalar() or 0

    unique_sessions_result = await db.execute(
        select(func.count(func.distinct(ChatSessionORM.session_id)))
    )
    unique_chat_sessions = unique_sessions_result.scalar() or 0

    rewrite_count_result = await db.execute(select(func.count(PolicyRewriteORM.id)))
    total_rewrites = rewrite_count_result.scalar() or 0

    verified_result = await db.execute(
        select(func.count(PolicyRewriteORM.id)).where(
            PolicyRewriteORM.rewrite_status == "verified"
        )
    )
    verified_rewrites = verified_result.scalar() or 0

    needs_review_result = await db.execute(
        select(func.count(PolicyRewriteORM.id)).where(
            PolicyRewriteORM.rewrite_status == "needs_review"
        )
    )
    needs_review_rewrites = needs_review_result.scalar() or 0

    top_endpoints_result = await db.execute(
        select(
            RequestLogORM.endpoint,
            func.count(RequestLogORM.id).label("count"),
            func.avg(RequestLogORM.latency_ms).label("avg_latency"),
        )
        .group_by(RequestLogORM.endpoint)
        .order_by(func.count(RequestLogORM.id).desc())
        .limit(10)
    )
    top_endpoints = [
        {
            "endpoint": row[0],
            "count": row[1],
            "avg_latency": round(float(row[2]), 1) if row[2] else 0.0,
        }
        for row in top_endpoints_result.all()
    ]

    return MetricsResponse(
        generated_at=datetime.utcnow().isoformat(),
        total_scans=total_scans,
        latest_scan_at=latest_scan_at,
        total_findings=total_findings,
        open_findings=open_findings,
        resolved_findings=resolved_findings,
        open_findings_by_severity=open_by_severity,
        all_findings_by_severity=all_severity_counts,
        total_escalation_paths=total_escalation_paths,
        critical_escalation_paths=critical_escalation_paths,
        total_requests=total_requests,
        requests_last_24h=requests_last_24h,
        avg_latency_ms=avg_latency_ms,
        p95_latency_ms=p95_latency_ms,
        error_count=error_count,
        error_rate=round(error_count / total_requests, 4) if total_requests else 0.0,
        top_endpoints=top_endpoints,
        total_chat_turns=total_chat_turns,
        unique_chat_sessions=unique_chat_sessions,
        total_rewrites=total_rewrites,
        verified_rewrites=verified_rewrites,
        needs_review_rewrites=needs_review_rewrites,
    )
