import asyncio
from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam_guardian.auditors.cross_account import check_cross_account_trust
from iam_guardian.auditors.escalation import (
    check_escalation_paths,
    enumerate_escalation_paths,
)
from iam_guardian.auditors.narrator import generate_narratives_batch
from iam_guardian.auditors.wildcard_actions import check_wildcard_actions
from iam_guardian.auth import get_current_user
from iam_guardian.cloudtrail.analyzer import score_events
from iam_guardian.cloudtrail.anomaly_narrator import generate_narratives_for_anomalies
from iam_guardian.cloudtrail.anomaly_scorer import ANOMALY_THRESHOLD, score_all_events
from iam_guardian.cloudtrail.cloudtrail import fetch_iam_events
from iam_guardian.compliance.report_builder import build_compliance_report
from iam_guardian.database import get_db
from iam_guardian.db_models import (
    EscalationPathORM,
    FindingORM,
    PolicyRewriteORM,
    ScanORM,
)
from iam_guardian.explainer import explain_finding
from iam_guardian.models import (
    AuditRequest,
    AuditResponse,
    AnomalousEventRecord,
    CloudTrailAnomalyReport,
    CloudTrailEventRecord,
    CloudTrailReportResponse,
    ComplianceReport,
    DeltaFinding,
    EscalationPathRecord,
    EscalationScanResponse,
    Finding,
    FindingRecord,
    PrincipalActivityRecord,
    PolicyRewriteRecord,
    RewriteResponse,
    ScanDelta,
    ScanRecord,
    SimulationResult,
    StatusUpdate,
)
from iam_guardian.rewriter import rewrite_policy
from iam_guardian.simulator import simulate_rewrite

router = APIRouter()

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "iam-guardian"}


@router.post("/audit/run", response_model=AuditResponse)
async def run_audit(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> AuditResponse:
    scan_id = str(uuid4())
    mock_policies = [
        {
            "resource_arn": f"arn:aws:iam::{request.account_id}:role/AdminRole",
            "policy_doc": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ],
            },
            "type": "permission",
        },
        {
            "resource_arn": (
                f"arn:aws:iam::{request.account_id}:role/CrossAccountRole"
            ),
            "policy_doc": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "type": "trust",
        },
        {
            "resource_arn": f"arn:aws:iam::{request.account_id}:role/DevRole",
            "policy_doc": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:PassRole",
                            "lambda:CreateFunction",
                            "lambda:InvokeFunction",
                            "iam:AttachRolePolicy",
                            "s3:GetObject",
                        ],
                        "Resource": "*",
                    }
                ],
            },
            "type": "permission",
        },
    ]

    findings: List[Finding] = []
    for policy in mock_policies:
        if policy["type"] == "permission":
            findings += check_wildcard_actions(
                policy["policy_doc"],
                policy["resource_arn"],
            )
            findings += check_escalation_paths(
                policy["policy_doc"],
                policy["resource_arn"],
            )
        elif policy["type"] == "trust":
            findings += check_cross_account_trust(
                policy["policy_doc"],
                policy["resource_arn"],
                request.account_id,
            )

    loop = asyncio.get_event_loop()
    for finding in findings:
        raw_data = finding.model_dump(mode="json")
        llm_explanation = await loop.run_in_executor(
            None,
            explain_finding,
            raw_data,
        )
        db.add(
            FindingORM(
                scan_id=scan_id,
                check_name=finding.title,
                severity=finding.severity.value,
                resource_arn=finding.resource,
                raw_data=raw_data,
                llm_explanation=llm_explanation,
            )
        )

    severity_counts = {severity: 0 for severity in SEVERITY_RANK}
    for finding in findings:
        severity_counts[finding.severity.value] += 1

    db.add(
        ScanORM(
            id=scan_id,
            account_id=request.account_id,
            status="completed",
            total_findings=len(findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
        )
    )

    await db.commit()

    return AuditResponse(
        audit_id=scan_id,
        account_id=request.account_id,
        status="completed",
        findings=findings,
        total_findings=len(findings),
        run_at=datetime.utcnow().isoformat(),
    )


@router.get("/audit/findings", response_model=List[FindingRecord])
async def list_findings(
    severity: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> List[FindingRecord]:
    query = select(FindingORM)
    if severity:
        query = query.where(FindingORM.severity == severity)
    if scan_id:
        query = query.where(FindingORM.scan_id == scan_id)
    query = query.order_by(FindingORM.created_at.desc()).limit(limit)

    result = await db.execute(query)
    records = result.scalars().all()

    return [
        FindingRecord(
            id=str(record.id),
            scan_id=record.scan_id,
            check_name=record.check_name,
            severity=record.severity,
            resource_arn=record.resource_arn,
            raw_data=record.raw_data,
            llm_explanation=record.llm_explanation,
            status=record.status,
            created_at=record.created_at.isoformat(),
        )
        for record in records
    ]


@router.patch("/audit/findings/{finding_id}/status", response_model=FindingRecord)
async def update_finding_status(
    finding_id: str,
    payload: StatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> FindingRecord:
    try:
        finding_uuid = UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    result = await db.execute(
        select(FindingORM).where(FindingORM.id == finding_uuid)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    finding.status = payload.status
    await db.commit()
    await db.refresh(finding)

    return FindingRecord(
        id=str(finding.id),
        scan_id=finding.scan_id,
        check_name=finding.check_name,
        severity=finding.severity,
        resource_arn=finding.resource_arn,
        raw_data=finding.raw_data,
        llm_explanation=finding.llm_explanation,
        status=finding.status,
        created_at=finding.created_at.isoformat(),
    )


@router.get("/audit/scans", response_model=List[ScanRecord])
async def list_scans(
    account_id: Optional[str] = None,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> List[ScanRecord]:
    query = select(ScanORM)
    if account_id:
        query = query.where(ScanORM.account_id == account_id)
    query = query.order_by(ScanORM.created_at.desc()).limit(limit)

    result = await db.execute(query)
    scans = result.scalars().all()

    return [
        ScanRecord(
            id=scan.id,
            account_id=scan.account_id,
            status=scan.status,
            total_findings=scan.total_findings,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            created_at=scan.created_at.isoformat(),
        )
        for scan in scans
    ]


def _delta_finding(record: FindingORM) -> DeltaFinding:
    return DeltaFinding(
        id=str(record.id),
        scan_id=record.scan_id,
        check_name=record.check_name,
        severity=record.severity,
        resource_arn=record.resource_arn,
        status=record.status,
        created_at=record.created_at.isoformat(),
    )


@router.get("/audit/delta", response_model=ScanDelta)
async def get_scan_delta(
    scan_a: str,
    scan_b: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> ScanDelta:
    scans_result = await db.execute(
        select(ScanORM).where(ScanORM.id.in_([scan_a, scan_b]))
    )
    existing_scan_ids = {scan.id for scan in scans_result.scalars().all()}
    for scan_id in (scan_a, scan_b):
        if scan_id not in existing_scan_ids:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    findings_result = await db.execute(
        select(FindingORM).where(FindingORM.scan_id.in_([scan_a, scan_b]))
    )
    all_findings = findings_result.scalars().all()

    findings_a = {
        (finding.check_name, finding.resource_arn): finding
        for finding in all_findings
        if finding.scan_id == scan_a
    }
    findings_b = {
        (finding.check_name, finding.resource_arn): finding
        for finding in all_findings
        if finding.scan_id == scan_b
    }

    keys_a = set(findings_a)
    keys_b = set(findings_b)
    persisted_keys = keys_a & keys_b

    regressed_findings = []
    for key in sorted(persisted_keys):
        severity_a = SEVERITY_RANK.get(findings_a[key].severity, -1)
        severity_b = SEVERITY_RANK.get(findings_b[key].severity, -1)
        if severity_b > severity_a:
            regressed_findings.append(_delta_finding(findings_b[key]))

    new_findings = [
        _delta_finding(findings_b[key])
        for key in sorted(keys_b - keys_a)
    ]
    resolved_findings = [
        _delta_finding(findings_a[key])
        for key in sorted(keys_a - keys_b)
    ]
    persisted_findings = [
        _delta_finding(findings_b[key])
        for key in sorted(persisted_keys)
    ]
    summary = (
        f"{len(new_findings)} new, "
        f"{len(resolved_findings)} resolved, "
        f"{len(regressed_findings)} regression(s)"
    )

    return ScanDelta(
        scan_a=scan_a,
        scan_b=scan_b,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        persisted_findings=persisted_findings,
        regressed_findings=regressed_findings,
        summary=summary,
    )


@router.post("/audit/rewrite/{finding_id}", response_model=RewriteResponse)
async def rewrite_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> RewriteResponse:
    try:
        finding_uuid = UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    result = await db.execute(
        select(FindingORM).where(FindingORM.id == finding_uuid)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    policy_doc = finding.raw_data or {}
    if "Statement" not in policy_doc:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }

    loop = asyncio.get_event_loop()
    rewritten_policy, diff_summary = await loop.run_in_executor(
        None,
        rewrite_policy,
        policy_doc,
    )

    account_id = "123456789012"
    if finding.resource_arn:
        parts = finding.resource_arn.split(":")
        if len(parts) >= 5 and parts[4]:
            account_id = parts[4]

    sim_result = await loop.run_in_executor(
        None,
        simulate_rewrite,
        policy_doc,
        rewritten_policy,
        account_id,
    )

    rewrite_status = sim_result.get("status", "simulation_unavailable")

    rewrite_row = PolicyRewriteORM(
        finding_id=finding_id,
        original_policy=policy_doc,
        rewritten_policy=rewritten_policy,
        diff_summary=diff_summary,
        simulation_result=sim_result,
        rewrite_status=rewrite_status,
    )
    db.add(rewrite_row)
    await db.commit()

    return RewriteResponse(
        finding_id=finding_id,
        check_name=finding.check_name,
        original_policy=policy_doc,
        rewritten_policy=rewritten_policy,
        diff_summary=diff_summary,
        simulation_result=SimulationResult(**sim_result),
        rewrite_status=rewrite_status,
    )


@router.get("/audit/rewrites", response_model=List[PolicyRewriteRecord])
async def get_rewrites(
    finding_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> List[PolicyRewriteRecord]:
    stmt = (
        select(PolicyRewriteORM)
        .order_by(PolicyRewriteORM.created_at.desc())
        .limit(limit)
    )
    if finding_id:
        stmt = stmt.where(PolicyRewriteORM.finding_id == finding_id)
    if status:
        stmt = stmt.where(PolicyRewriteORM.rewrite_status == status)

    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [
        PolicyRewriteRecord(
            id=row.id,
            finding_id=row.finding_id,
            original_policy=row.original_policy,
            rewritten_policy=row.rewritten_policy,
            diff_summary=row.diff_summary,
            simulation_result=row.simulation_result,
            rewrite_status=row.rewrite_status,
            created_at=row.created_at.isoformat(),
        )
        for row in rows
    ]


@router.get("/audit/escalation-paths", response_model=EscalationScanResponse)
async def get_escalation_paths(
    account_id: str = "123456789012",
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> EscalationScanResponse:
    loop = asyncio.get_event_loop()

    raw_paths = await loop.run_in_executor(
        None,
        enumerate_escalation_paths,
        account_id,
    )

    if not raw_paths:
        return EscalationScanResponse(
            account_id=account_id,
            scan_id=str(uuid4()),
            total_paths=0,
            critical_count=0,
            high_count=0,
            paths=[],
            scanned_at=datetime.utcnow().isoformat(),
        )

    enriched_paths = await loop.run_in_executor(
        None,
        generate_narratives_batch,
        raw_paths,
    )

    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
    }
    enriched_paths.sort(key=lambda path: severity_rank.get(path["severity"], 99))

    scan_id = str(uuid4())
    orm_rows = []
    for path in enriched_paths:
        row = EscalationPathORM(
            account_id=account_id,
            principal_arn=path["principal_arn"],
            principal_type=path["principal_type"],
            principal_name=path["principal_name"],
            matched_combo=path["matched_combo"],
            effective_permissions=path["effective_permissions"],
            severity=path["severity"],
            title=path["title"],
            description=path["description"],
            attack_story=path["attack_story"],
            narrative=path["narrative"],
            tags=path["tags"],
        )
        db.add(row)
        orm_rows.append(row)
    await db.commit()
    for row in orm_rows:
        await db.refresh(row)

    path_records = [
        EscalationPathRecord(
            id=row.id,
            account_id=account_id,
            principal_arn=path["principal_arn"],
            principal_type=path["principal_type"],
            principal_name=path["principal_name"],
            matched_combo=path["matched_combo"],
            effective_permissions=path["effective_permissions"],
            severity=path["severity"],
            title=path["title"],
            description=path["description"],
            attack_story=path["attack_story"],
            narrative=path["narrative"],
            tags=path["tags"],
            created_at=row.created_at.isoformat(),
        )
        for row, path in zip(orm_rows, enriched_paths)
    ]

    return EscalationScanResponse(
        account_id=account_id,
        scan_id=scan_id,
        total_paths=len(path_records),
        critical_count=sum(1 for path in path_records if path.severity == "critical"),
        high_count=sum(1 for path in path_records if path.severity == "high"),
        paths=path_records,
        scanned_at=datetime.utcnow().isoformat(),
    )


@router.get("/audit/compliance-report", response_model=ComplianceReport)
async def get_compliance_report(
    account_id: str = "123456789012",
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> ComplianceReport:
    stmt = (
        select(FindingORM)
        .order_by(FindingORM.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    rows = result.scalars().all()

    findings_dicts = [
        {
            "check_name": row.check_name,
            "severity": row.severity,
            "resource_arn": row.resource_arn,
            "status": row.status,
        }
        for row in rows
    ]

    loop = asyncio.get_event_loop()
    report = await loop.run_in_executor(
        None,
        build_compliance_report,
        findings_dicts,
        account_id,
    )

    return report


@router.get("/audit/cloudtrail", response_model=CloudTrailReportResponse)
async def get_cloudtrail_report(
    account_id: str = "123456789012",
    days: int = 90,
    region: str = "us-east-1",
    current_user: dict = Depends(get_current_user),
) -> CloudTrailReportResponse:
    loop = asyncio.get_event_loop()

    events = await loop.run_in_executor(
        None,
        fetch_iam_events,
        account_id,
        days,
        region,
    )
    report = await loop.run_in_executor(
        None,
        score_events,
        events,
        account_id,
        days,
    )

    def event_to_record(event: dict) -> CloudTrailEventRecord:
        return CloudTrailEventRecord(
            event_id=event["event_id"],
            event_name=event["event_name"],
            event_time=event["event_time"],
            region=event["region"],
            source_ip=event["source_ip"],
            user_agent=event["user_agent"],
            error_code=event.get("error_code"),
            error_message=event.get("error_message"),
            identity_type=event["identity_type"],
            principal_id=event["principal_id"],
            account_id=event["account_id"],
            actor_arn=event["actor_arn"],
            session_name=event["session_name"],
            weight=event["weight"],
        )

    def principal_to_record(principal) -> PrincipalActivityRecord:
        return PrincipalActivityRecord(
            principal_id=principal.principal_id,
            identity_type=principal.identity_type,
            account_id=principal.account_id,
            actor_arn=principal.actor_arn,
            event_count=principal.event_count,
            high_weight_count=principal.high_weight_count,
            total_score=principal.total_score,
            anomaly_flags=principal.anomaly_flags,
            flagged_events=[
                event_to_record(event) for event in principal.flagged_events
            ],
        )

    return CloudTrailReportResponse(
        account_id=report.account_id,
        period_days=report.period_days,
        total_events=report.total_events,
        watched_event_counts=report.watched_event_counts,
        principals=[principal_to_record(principal) for principal in report.principals],
        root_activity=[event_to_record(event) for event in report.root_activity],
        high_score_principals=[
            principal_to_record(principal)
            for principal in report.high_score_principals
        ],
        error_events=[event_to_record(event) for event in report.error_events],
        report_generated_at=report.report_generated_at,
    )


@router.get("/audit/cloudtrail-anomalies", response_model=CloudTrailAnomalyReport)
async def get_cloudtrail_anomalies(
    account_id: str = "123456789012",
    days: int = 90,
    region: str = "us-east-1",
    min_score: int = ANOMALY_THRESHOLD,
    current_user: dict = Depends(get_current_user),
) -> CloudTrailAnomalyReport:
    loop = asyncio.get_event_loop()

    events = await loop.run_in_executor(
        None,
        fetch_iam_events,
        account_id,
        days,
        region,
    )
    scored_events = await loop.run_in_executor(None, score_all_events, events)
    anomalous = [
        event for event in scored_events if event["anomaly_score"] >= min_score
    ]

    if anomalous:
        enriched = await loop.run_in_executor(
            None,
            generate_narratives_for_anomalies,
            anomalous,
        )
    else:
        enriched = []

    breakdown = {
        "after_hours": sum(
            1
            for event in scored_events
            if any(
                "business hours" in reason
                for reason in event.get("anomaly_reasons", [])
            )
        ),
        "new_ip": sum(
            1
            for event in scored_events
            if any(
                "New source IP" in reason
                for reason in event.get("anomaly_reasons", [])
            )
        ),
        "root_activity": sum(
            1
            for event in scored_events
            if any(
                "root account" in reason
                for reason in event.get("anomaly_reasons", [])
            )
        ),
        "new_event_type": sum(
            1
            for event in scored_events
            if any(
                "First time" in reason
                for reason in event.get("anomaly_reasons", [])
            )
        ),
    }

    anomaly_records = [
        AnomalousEventRecord(
            event_id=event["event_id"],
            event_name=event["event_name"],
            event_time=event["event_time"],
            region=event["region"],
            source_ip=event["source_ip"],
            user_agent=event.get("user_agent", ""),
            error_code=event.get("error_code"),
            identity_type=event["identity_type"],
            principal_id=event["principal_id"],
            account_id=event["account_id"],
            actor_arn=event["actor_arn"],
            session_name=event["session_name"],
            weight=event["weight"],
            anomaly_score=event["anomaly_score"],
            anomaly_reasons=event["anomaly_reasons"],
            is_anomaly=event["is_anomaly"],
            narrative=event.get("narrative"),
        )
        for event in enriched
    ]

    return CloudTrailAnomalyReport(
        account_id=account_id,
        period_days=days,
        total_events_analyzed=len(scored_events),
        total_anomalies=len(anomaly_records),
        anomaly_threshold=min_score,
        anomalies=anomaly_records,
        score_breakdown=breakdown,
        report_generated_at=datetime.utcnow().isoformat(),
    )
