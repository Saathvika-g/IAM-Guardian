from typing import List, Optional, TypedDict


class ControlMapping(TypedDict):
    check_name: str
    cis_control_id: Optional[str]
    cis_control_title: Optional[str]
    cis_section: Optional[str]
    nist_control_id: Optional[str]
    nist_control_title: Optional[str]
    nist_family: Optional[str]
    severity: str
    frameworks: List[str]


COMPLIANCE_MAP: dict[str, ControlMapping] = {
    "Overly permissive IAM policy: wildcard Action": {
        "check_name": "Overly permissive IAM policy: wildcard Action",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6",
        "nist_control_title": "Least Privilege",
        "nist_family": "AC - Access Control",
        "severity": "critical",
        "frameworks": ["CIS", "NIST"],
    },
    "Overly permissive IAM policy: wildcard Resource": {
        "check_name": "Overly permissive IAM policy: wildcard Resource",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6",
        "nist_control_title": "Least Privilege",
        "nist_family": "AC - Access Control",
        "severity": "high",
        "frameworks": ["CIS", "NIST"],
    },
    "Trust policy allows any AWS principal": {
        "check_name": "Trust policy allows any AWS principal",
        "cis_control_id": "CIS-1.21",
        "cis_control_title": (
            "Do not setup access keys during initial user setup for all IAM users "
            "that have a console password"
        ),
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-3",
        "nist_control_title": "Access Enforcement",
        "nist_family": "AC - Access Control",
        "severity": "critical",
        "frameworks": ["CIS", "NIST"],
    },
    "Privilege escalation: iam:PassRole + lambda:CreateFunction": {
        "check_name": "Privilege escalation: iam:PassRole + lambda:CreateFunction",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6(1)",
        "nist_control_title": "Least Privilege — Authorize Access to Security Functions",
        "nist_family": "AC - Access Control",
        "severity": "critical",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: iam:PassRole + ec2:RunInstances": {
        "check_name": "Privilege escalation: iam:PassRole + ec2:RunInstances",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6(1)",
        "nist_control_title": "Least Privilege — Authorize Access to Security Functions",
        "nist_family": "AC - Access Control",
        "severity": "critical",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: iam:CreateAccessKey on other users": {
        "check_name": "Privilege escalation: iam:CreateAccessKey on other users",
        "cis_control_id": "CIS-1.4",
        "cis_control_title": "Ensure no access keys exist for the root account",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-2",
        "nist_control_title": "Account Management",
        "nist_family": "AC - Access Control",
        "severity": "critical",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: iam:CreateLoginProfile on other users": {
        "check_name": "Privilege escalation: iam:CreateLoginProfile on other users",
        "cis_control_id": "CIS-1.2",
        "cis_control_title": (
            "Ensure multi-factor authentication (MFA) is enabled for all IAM users "
            "that have a console password"
        ),
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "IA-2",
        "nist_control_title": "Identification and Authentication",
        "nist_family": "IA - Identification and Authentication",
        "severity": "high",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: iam:UpdateLoginProfile on other users": {
        "check_name": "Privilege escalation: iam:UpdateLoginProfile on other users",
        "cis_control_id": "CIS-1.2",
        "cis_control_title": (
            "Ensure multi-factor authentication (MFA) is enabled for all IAM users "
            "that have a console password"
        ),
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "IA-2",
        "nist_control_title": "Identification and Authentication",
        "nist_family": "IA - Identification and Authentication",
        "severity": "high",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: iam:AttachUserPolicy": {
        "check_name": "Privilege escalation: iam:AttachUserPolicy",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6(7)",
        "nist_control_title": "Least Privilege — Review of User Privileges",
        "nist_family": "AC - Access Control",
        "severity": "critical",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: iam:AttachRolePolicy": {
        "check_name": "Privilege escalation: iam:AttachRolePolicy",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6(7)",
        "nist_control_title": "Least Privilege — Review of User Privileges",
        "nist_family": "AC - Access Control",
        "severity": "critical",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: iam:PassRole + glue:CreateJob": {
        "check_name": "Privilege escalation: iam:PassRole + glue:CreateJob",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6(1)",
        "nist_control_title": "Least Privilege — Authorize Access to Security Functions",
        "nist_family": "AC - Access Control",
        "severity": "high",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: iam:PassRole + cloudformation:CreateStack": {
        "check_name": "Privilege escalation: iam:PassRole + cloudformation:CreateStack",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6(1)",
        "nist_control_title": "Least Privilege — Authorize Access to Security Functions",
        "nist_family": "AC - Access Control",
        "severity": "high",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
    "Privilege escalation: sts:AssumeRole + iam:PutRolePolicy": {
        "check_name": "Privilege escalation: sts:AssumeRole + iam:PutRolePolicy",
        "cis_control_id": "CIS-1.16",
        "cis_control_title": "Ensure IAM policies are attached only to groups or roles",
        "cis_section": "1 - Identity and Access Management",
        "nist_control_id": "AC-6(1)",
        "nist_control_title": "Least Privilege — Authorize Access to Security Functions",
        "nist_family": "AC - Access Control",
        "severity": "critical",
        "frameworks": ["CIS", "NIST", "MITRE"],
    },
}

FRAMEWORK_INDEX: dict[str, list[str]] = {}
for check_name, mapping in COMPLIANCE_MAP.items():
    for framework in mapping["frameworks"]:
        FRAMEWORK_INDEX.setdefault(framework, []).append(check_name)

CIS_CONTROLS: dict[str, str] = {
    mapping["cis_control_id"]: mapping["cis_control_title"]
    for mapping in COMPLIANCE_MAP.values()
    if mapping["cis_control_id"]
}

NIST_CONTROLS: dict[str, str] = {
    mapping["nist_control_id"]: mapping["nist_control_title"]
    for mapping in COMPLIANCE_MAP.values()
    if mapping["nist_control_id"]
}


def get_mapping(check_name: str) -> Optional[ControlMapping]:
    """Return the control mapping for a check name, or None if unmapped."""
    return COMPLIANCE_MAP.get(check_name)


def get_frameworks_for_check(check_name: str) -> List[str]:
    """Return which frameworks a check name appears in."""
    mapping = get_mapping(check_name)
    return mapping["frameworks"] if mapping else []


def get_checks_for_framework(framework: str) -> List[str]:
    """Return all check names that map to a given framework."""
    return FRAMEWORK_INDEX.get(framework, [])
