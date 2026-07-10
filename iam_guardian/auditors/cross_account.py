from typing import List
from uuid import uuid4

from iam_guardian.models import Finding, Severity


def _principal_strings(principal: object) -> List[str]:
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, list):
        values: List[str] = []
        for item in principal:
            values.extend(_principal_strings(item))
        return values
    if isinstance(principal, dict):
        aws_principal = principal.get("AWS")
        if aws_principal is None:
            return []
        return _principal_strings(aws_principal)
    return []


def _account_id_from_arn(principal: str) -> str:
    parts = principal.split(":")
    if len(parts) > 4:
        return parts[4]
    return ""


def check_cross_account_trust(
    trust_policy: dict,
    resource_arn: str,
    account_id: str,
) -> List[Finding]:
    findings: List[Finding] = []
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue

        for principal in _principal_strings(statement.get("Principal", {})):
            if principal == "*":
                findings.append(
                    Finding(
                        id=(
                            "CROSS_ACCOUNT_TRUST_WILDCARD_"
                            f"{uuid4().hex[:8].upper()}"
                        ),
                        title="Trust policy allows any AWS principal",
                        severity=Severity.critical,
                        resource=resource_arn,
                        description=(
                            "The role trust policy contains Principal: * -- any "
                            "AWS account or user can assume this role."
                        ),
                        recommendation=(
                            "Replace Principal: * with the specific AWS account "
                            "IDs or ARNs that require this role."
                        ),
                        tags=["cross-account", "trust-policy", "iam-role"],
                    )
                )
                continue

            if not principal.startswith("arn:aws:iam::"):
                continue

            external_account_id = _account_id_from_arn(principal)
            if external_account_id and external_account_id != account_id:
                findings.append(
                    Finding(
                        id=f"CROSS_ACCOUNT_TRUST_{uuid4().hex[:8].upper()}",
                        title=(
                            "Role trust policy allows external account: "
                            f"{external_account_id}"
                        ),
                        severity=Severity.high,
                        resource=resource_arn,
                        description=(
                            "The role trust policy grants sts:AssumeRole to "
                            f"account {external_account_id}, which is outside "
                            f"your account ({account_id})."
                        ),
                        recommendation=(
                            "Verify this cross-account trust is intentional. If "
                            "so, add an ExternalId condition. If not, remove the "
                            "external principal immediately."
                        ),
                        tags=["cross-account", "trust-policy", "iam-role"],
                    )
                )

    return findings
