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
from iam_guardian.database import get_db
from iam_guardian.db_models import EscalationPathORM, FindingORM, PolicyRewriteORM
from iam_guardian.explainer import explain_finding
from iam_guardian.models import (
    AuditRequest,
    AuditResponse,
    EscalationPathRecord,
    EscalationScanResponse,
    Finding,
    FindingRecord,
    PolicyRewriteRecord,
    RewriteResponse,
    SimulationResult,
)
from iam_guardian.rewriter import rewrite_policy
from iam_guardian.simulator import simulate_rewrite

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "iam-guardian"}


@router.post("/audit/run", response_model=AuditResponse)
async def run_audit(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> AuditResponse:
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
                check_name=finding.title,
                severity=finding.severity.value,
                resource_arn=finding.resource,
                raw_data=raw_data,
                llm_explanation=llm_explanation,
            )
        )

    await db.commit()

    return AuditResponse(
        audit_id=str(uuid4()),
        account_id=request.account_id,
        status="completed",
        findings=findings,
        total_findings=len(findings),
        run_at=datetime.utcnow().isoformat(),
    )


@router.get("/audit/findings", response_model=List[FindingRecord])
async def list_findings(
    severity: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> List[FindingRecord]:
    query = select(FindingORM).order_by(FindingORM.created_at.desc()).limit(limit)

    if severity:
        query = (
            select(FindingORM)
            .where(FindingORM.severity == severity)
            .order_by(FindingORM.created_at.desc())
            .limit(limit)
        )

    result = await db.execute(query)
    records = result.scalars().all()

    return [
        FindingRecord(
            id=str(record.id),
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
