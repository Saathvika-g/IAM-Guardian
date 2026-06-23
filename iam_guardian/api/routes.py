from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam_guardian.database import get_db
from iam_guardian.db_models import FindingORM
from iam_guardian.models import (
    AuditRequest,
    AuditResponse,
    Finding,
    FindingRecord,
    Severity,
)

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "iam-guardian"}


@router.post("/audit/run", response_model=AuditResponse)
async def run_audit(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
) -> AuditResponse:
    findings = [
        Finding(
            id="IAM-001",
            title="Overly permissive IAM role allows wildcard actions",
            severity=Severity.critical,
            resource=f"arn:aws:iam::{request.account_id}:role/AdminWildcardRole",
            description=(
                "An IAM role has a policy statement that allows '*' actions, "
                "which grants unrestricted permissions."
            ),
            recommendation=(
                "Replace wildcard actions with least-privilege permissions "
                "required by the workload."
            ),
            tags=["iam", "least-privilege", "wildcard-actions"],
        ),
        Finding(
            id="IAM-002",
            title="MFA not enabled on root account",
            severity=Severity.high,
            resource=f"arn:aws:iam::{request.account_id}:root",
            description=(
                "The AWS account root user does not have multi-factor "
                "authentication enabled."
            ),
            recommendation=(
                "Enable MFA for the root account and avoid using root "
                "credentials for day-to-day operations."
            ),
            tags=["iam", "root-account", "mfa"],
        ),
        Finding(
            id="IAM-003",
            title="Unused IAM access key older than 90 days",
            severity=Severity.medium,
            resource=f"arn:aws:iam::{request.account_id}:user/legacy-service-account",
            description=(
                "An IAM access key has not been used in more than 90 days, "
                "increasing credential exposure risk."
            ),
            recommendation=(
                "Deactivate and delete unused access keys after confirming "
                "they are no longer required."
            ),
            tags=["iam", "access-key", "credential-hygiene"],
        ),
    ]

    for finding in findings:
        raw_data = finding.model_dump(mode="json")
        db.add(
            FindingORM(
                check_name=finding.title,
                severity=finding.severity.value,
                resource_arn=finding.resource,
                raw_data=raw_data,
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
