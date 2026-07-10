from typing import List
from uuid import uuid4

from iam_guardian.models import Finding, Severity


def _has_wildcard(value: object) -> bool:
    if isinstance(value, str):
        return value == "*"
    if isinstance(value, list):
        return "*" in value
    return False


def check_wildcard_actions(policy_doc: dict, resource_arn: str) -> List[Finding]:
    findings: List[Finding] = []
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue

        if _has_wildcard(statement.get("Action")):
            findings.append(
                Finding(
                    id=f"WILDCARD_ACTION_{uuid4().hex[:8].upper()}",
                    title="Overly permissive IAM policy: wildcard Action",
                    severity=Severity.critical,
                    resource=resource_arn,
                    description=(
                        "This policy statement grants Action: * -- unrestricted "
                        "access to every AWS API call."
                    ),
                    recommendation=(
                        "Replace Action: * with the specific actions this principal "
                        "requires. Use IAM Access Analyzer to generate "
                        "least-privilege policies."
                    ),
                    tags=["wildcard", "iam-policy", "CIS-1.16"],
                )
            )

        if _has_wildcard(statement.get("Resource")):
            findings.append(
                Finding(
                    id=f"WILDCARD_RESOURCE_{uuid4().hex[:8].upper()}",
                    title="Overly permissive IAM policy: wildcard Resource",
                    severity=Severity.high,
                    resource=resource_arn,
                    description=(
                        "This policy statement applies to Resource: * -- every "
                        "resource in the account is in scope."
                    ),
                    recommendation=(
                        "Scope the Resource field to the specific ARNs this "
                        "principal needs to access."
                    ),
                    tags=["wildcard", "iam-policy", "CIS-1.16"],
                )
            )

    return findings
