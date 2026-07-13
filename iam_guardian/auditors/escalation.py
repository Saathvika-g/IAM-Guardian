from typing import List
from uuid import uuid4

from iam_guardian.models import Finding, Severity

ESCALATION_COMBOS = {
    frozenset(["iam:passrole", "lambda:createfunction"]): {
        "title": "Privilege escalation: iam:PassRole + lambda:CreateFunction",
        "severity": Severity.critical,
        "description": (
            "A principal with iam:PassRole and lambda:CreateFunction can create a new Lambda "
            "function, attach an admin IAM role to it, and invoke it to execute arbitrary "
            "actions under that role — effectively gaining full admin access."
        ),
        "attack_story": (
            "Attacker creates a Lambda function that calls sts:AssumeRole or runs "
            "aws iam attach-role-policy, passes an existing admin role to it via "
            "iam:PassRole, then invokes the function to escalate to admin."
        ),
        "tags": ["privilege-escalation", "lambda", "iam", "MITRE-T1098"],
    },
    frozenset(["iam:passrole", "ec2:runinstances"]): {
        "title": "Privilege escalation: iam:PassRole + ec2:RunInstances",
        "severity": Severity.critical,
        "description": (
            "A principal with iam:PassRole and ec2:RunInstances can launch an EC2 instance "
            "with an admin instance profile attached. Any code running on that instance "
            "inherits the admin role via the instance metadata service."
        ),
        "attack_story": (
            "Attacker launches an EC2 instance with an admin instance profile, SSHes in "
            "or uses EC2 user-data to run commands, and retrieves admin credentials from "
            "the instance metadata endpoint at 169.254.169.254."
        ),
        "tags": ["privilege-escalation", "ec2", "iam", "MITRE-T1098"],
    },
    frozenset(["iam:createaccesskey"]): {
        "title": "Privilege escalation: iam:CreateAccessKey on other users",
        "severity": Severity.critical,
        "description": (
            "A principal with iam:CreateAccessKey can generate new access keys for any "
            "other IAM user — including admin users — without that user's knowledge, "
            "granting silent persistent access under the target user's identity."
        ),
        "attack_story": (
            "Attacker calls iam:CreateAccessKey for an existing admin user, obtains "
            "long-term credentials for that user, and operates as them indefinitely "
            "while the original user remains unaware."
        ),
        "tags": ["privilege-escalation", "iam", "persistence", "MITRE-T1098"],
    },
    frozenset(["iam:createloginprofile"]): {
        "title": "Privilege escalation: iam:CreateLoginProfile on other users",
        "severity": Severity.high,
        "description": (
            "A principal with iam:CreateLoginProfile can set a console password for any "
            "IAM user that does not yet have one, including admin users, enabling console "
            "login as that user."
        ),
        "attack_story": (
            "Attacker calls iam:CreateLoginProfile for an admin IAM user that has no "
            "console password, sets a known password, and logs into the AWS console "
            "with full admin privileges."
        ),
        "tags": ["privilege-escalation", "iam", "console-access", "MITRE-T1078"],
    },
    frozenset(["iam:updateloginprofile"]): {
        "title": "Privilege escalation: iam:UpdateLoginProfile on other users",
        "severity": Severity.high,
        "description": (
            "A principal with iam:UpdateLoginProfile can change the console password of "
            "any existing IAM user, locking out the legitimate user and taking over "
            "their session."
        ),
        "attack_story": (
            "Attacker resets the console password of an admin IAM user via "
            "iam:UpdateLoginProfile, logs into the AWS console as that user, "
            "and gains persistent admin access while the original user is locked out."
        ),
        "tags": ["privilege-escalation", "iam", "account-takeover", "MITRE-T1078"],
    },
    frozenset(["iam:attachuserpolicy"]): {
        "title": "Privilege escalation: iam:AttachUserPolicy",
        "severity": Severity.critical,
        "description": (
            "A principal with iam:AttachUserPolicy can attach the AWS-managed "
            "AdministratorAccess policy directly to their own IAM user, "
            "granting themselves full admin permissions immediately."
        ),
        "attack_story": (
            "Attacker calls iam:AttachUserPolicy to attach arn:aws:iam::aws:policy/"
            "AdministratorAccess to their own user ARN, then operates with full "
            "admin access on the next API call."
        ),
        "tags": ["privilege-escalation", "iam", "MITRE-T1098"],
    },
    frozenset(["iam:attachrolepolicy"]): {
        "title": "Privilege escalation: iam:AttachRolePolicy",
        "severity": Severity.critical,
        "description": (
            "A principal with iam:AttachRolePolicy can attach AdministratorAccess "
            "to any IAM role — including roles they can already assume — escalating "
            "to full admin without any approval."
        ),
        "attack_story": (
            "Attacker identifies a role they can assume, calls iam:AttachRolePolicy "
            "to grant it AdministratorAccess, assumes the role via sts:AssumeRole, "
            "and now has unrestricted access to the entire account."
        ),
        "tags": ["privilege-escalation", "iam", "MITRE-T1098"],
    },
    frozenset(["iam:passrole", "glue:createjob"]): {
        "title": "Privilege escalation: iam:PassRole + glue:CreateJob",
        "severity": Severity.high,
        "description": (
            "A principal with iam:PassRole and glue:CreateJob can create an AWS Glue "
            "ETL job with an admin role attached. When the job runs, it executes arbitrary "
            "Python or Scala under the admin role's permissions."
        ),
        "attack_story": (
            "Attacker creates a Glue job with a script that exfiltrates S3 data or "
            "creates a backdoor IAM user, passes an admin role to the job via "
            "iam:PassRole, then triggers the job to execute with admin privileges."
        ),
        "tags": ["privilege-escalation", "glue", "iam", "MITRE-T1098"],
    },
    frozenset(["iam:passrole", "cloudformation:createstack"]): {
        "title": "Privilege escalation: iam:PassRole + cloudformation:CreateStack",
        "severity": Severity.high,
        "description": (
            "A principal with iam:PassRole and cloudformation:CreateStack can deploy "
            "a CloudFormation stack using an admin service role. All resources created "
            "by that stack are provisioned with admin-level permissions."
        ),
        "attack_story": (
            "Attacker deploys a CloudFormation stack that creates a new admin IAM user "
            "with known credentials, passing an admin role to CloudFormation via "
            "iam:PassRole so the stack executes with full account access."
        ),
        "tags": ["privilege-escalation", "cloudformation", "iam", "MITRE-T1098"],
    },
    frozenset(["sts:assumerole", "iam:putrolepolicy"]): {
        "title": "Privilege escalation: sts:AssumeRole + iam:PutRolePolicy",
        "severity": Severity.critical,
        "description": (
            "A principal with sts:AssumeRole and iam:PutRolePolicy can inject an inline "
            "policy granting admin access into any assumable role before assuming it, "
            "bootstrapping themselves to full admin in two API calls."
        ),
        "attack_story": (
            "Attacker calls iam:PutRolePolicy to inject an Allow * inline policy into "
            "a role they can assume, immediately calls sts:AssumeRole to get credentials "
            "for that role, and now operates with full admin access."
        ),
        "tags": ["privilege-escalation", "iam", "sts", "MITRE-T1098"],
    },
}


def _enumerate_permissions(policy_doc: dict) -> set[str]:
    permissions = set()
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", [])
        if isinstance(action, str):
            permissions.add(action.lower())
        elif isinstance(action, list):
            for action_name in action:
                permissions.add(action_name.lower())
    return permissions


def _matches_combo(permissions: set[str], combo: frozenset[str]) -> bool:
    for required_action in combo:
        matched = False
        if required_action in permissions:
            matched = True
        elif "*" in permissions:
            matched = True
        else:
            service = required_action.split(":")[0]
            if f"{service}:*" in permissions:
                matched = True
        if not matched:
            return False
    return True


def check_escalation_paths(policy_doc: dict, resource_arn: str) -> List[Finding]:
    findings = []
    permissions = _enumerate_permissions(policy_doc)

    if not permissions:
        return findings

    for combo, meta in ESCALATION_COMBOS.items():
        if _matches_combo(permissions, combo):
            findings.append(
                Finding(
                    id=f"ESC_{uuid4().hex[:8].upper()}",
                    title=meta["title"],
                    severity=meta["severity"],
                    resource=resource_arn,
                    description=meta["description"],
                    recommendation=(
                        "Remove or scope the following permissions to break this "
                        f"escalation path: {', '.join(sorted(combo))}. "
                        "Apply least-privilege: grant only the specific actions and "
                        "resources required. Consider AWS SCPs to deny these "
                        "combinations at the organization level."
                    ),
                    tags=meta["tags"],
                )
            )

    return findings
