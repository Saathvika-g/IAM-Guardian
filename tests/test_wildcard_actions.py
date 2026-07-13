from iam_guardian.auditors.wildcard_actions import check_wildcard_actions
from iam_guardian.models import Severity

RESOURCE_ARN = "arn:aws:iam::123456789012:role/TestRole"


def test_wildcard_action_string():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}
        ],
    }

    findings = check_wildcard_actions(policy, RESOURCE_ARN)

    assert len(findings) == 1
    assert findings[0].severity == Severity.critical
    assert "wildcard Action" in findings[0].title


def test_wildcard_action_in_list():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "*"],
                "Resource": "arn:aws:s3:::bucket/*",
            }
        ],
    }

    findings = check_wildcard_actions(policy, RESOURCE_ARN)

    assert len(findings) == 1
    assert findings[0].severity == Severity.critical


def test_wildcard_resource_string():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }

    findings = check_wildcard_actions(policy, RESOURCE_ARN)

    assert len(findings) == 1
    assert findings[0].severity == Severity.high
    assert "wildcard Resource" in findings[0].title


def test_wildcard_resource_in_list():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": ["arn:aws:s3:::my-bucket", "*"],
            }
        ],
    }

    findings = check_wildcard_actions(policy, RESOURCE_ARN)

    assert len(findings) == 1
    assert findings[0].severity == Severity.high


def test_both_wildcards():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

    findings = check_wildcard_actions(policy, RESOURCE_ARN)

    assert len(findings) == 2
    assert {finding.severity for finding in findings} == {
        Severity.critical,
        Severity.high,
    }


def test_deny_statement_ignored():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }

    findings = check_wildcard_actions(policy, RESOURCE_ARN)

    assert findings == []


def test_no_wildcards():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::bucket/*"],
            }
        ],
    }

    findings = check_wildcard_actions(policy, RESOURCE_ARN)

    assert findings == []


def test_empty_policy():
    policy = {"Version": "2012-10-17", "Statement": []}

    findings = check_wildcard_actions(policy, RESOURCE_ARN)

    assert findings == []
