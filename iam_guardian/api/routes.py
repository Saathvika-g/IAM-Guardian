from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter

from iam_guardian.models import AuditRequest, AuditResponse, Finding, Severity

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "iam-guardian"}


@router.post("/audit/run", response_model=AuditResponse)
def run_audit(request: AuditRequest) -> AuditResponse:
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

    return AuditResponse(
        audit_id=str(uuid4()),
        account_id=request.account_id,
        status="completed",
        findings=findings,
        total_findings=len(findings),
        run_at=datetime.utcnow().isoformat(),
    )
