from iam_guardian.auditors.cross_account import check_cross_account_trust
from iam_guardian.models import Severity

ACCOUNT_ID = "123456789012"
RESOURCE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/TestRole"


def test_external_account_string_arn():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = check_cross_account_trust(trust_policy, RESOURCE_ARN, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.high
    assert "999999999999" in findings[0].title


def test_external_account_list_arns():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::111111111111:root",
                        "arn:aws:iam::222222222222:role/Role",
                    ]
                },
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = check_cross_account_trust(trust_policy, RESOURCE_ARN, ACCOUNT_ID)

    assert len(findings) == 2
    assert all(finding.severity == Severity.high for finding in findings)


def test_same_account_no_finding():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = check_cross_account_trust(trust_policy, RESOURCE_ARN, ACCOUNT_ID)

    assert findings == []


def test_wildcard_principal_critical():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
        ],
    }

    findings = check_cross_account_trust(trust_policy, RESOURCE_ARN, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.critical
    assert "any AWS principal" in findings[0].title


def test_service_principal_ignored():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = check_cross_account_trust(trust_policy, RESOURCE_ARN, ACCOUNT_ID)

    assert findings == []


def test_mixed_principals():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::999999999999:root",
                    "Service": "ec2.amazonaws.com",
                },
                "Action": "sts:AssumeRole",
            }
        ],
    }

    findings = check_cross_account_trust(trust_policy, RESOURCE_ARN, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.high


def test_empty_trust_policy():
    trust_policy = {"Version": "2012-10-17", "Statement": []}

    findings = check_cross_account_trust(trust_policy, RESOURCE_ARN, ACCOUNT_ID)

    assert findings == []
