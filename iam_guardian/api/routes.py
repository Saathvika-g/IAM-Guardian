import asyncio
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam_guardian.auditors.cross_account import check_cross_account_trust
from iam_guardian.auditors.wildcard_actions import check_wildcard_actions
from iam_guardian.auth import get_current_user
from iam_guardian.database import get_db
from iam_guardian.db_models import FindingORM
from iam_guardian.explainer import explain_finding
from iam_guardian.models import (
    AuditRequest,
    AuditResponse,
    FindingRecord,
)

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
    ]

    findings = []
    for policy in mock_policies:
        if policy["type"] == "permission":
            findings += check_wildcard_actions(
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
