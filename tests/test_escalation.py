from iam_guardian.auditors.escalation import (
    ESCALATION_COMBOS,
    _enumerate_permissions,
    _matches_combo,
    check_escalation_paths,
)
from iam_guardian.models import Severity

RESOURCE_ARN = "arn:aws:iam::123456789012:role/DevRole"


def make_policy(*actions):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": "*"}],
    }


def test_enumerate_string_action():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
    }

    perms = _enumerate_permissions(policy)

    assert "iam:passrole" in perms


def test_enumerate_list_actions():
    perms = _enumerate_permissions(make_policy("iam:PassRole", "lambda:CreateFunction"))

    assert "iam:passrole" in perms
    assert "lambda:createfunction" in perms


def test_enumerate_skips_deny():
    policy = {"Statement": [{"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}]}

    assert _enumerate_permissions(policy) == set()


def test_enumerate_empty_policy():
    assert _enumerate_permissions({"Statement": []}) == set()


def test_matches_exact():
    perms = {"iam:passrole", "lambda:createfunction"}
    combo = frozenset(["iam:passrole", "lambda:createfunction"])

    assert _matches_combo(perms, combo) is True


def test_matches_bare_wildcard_covers_all():
    perms = {"*"}
    combo = frozenset(["iam:passrole", "lambda:createfunction"])

    assert _matches_combo(perms, combo) is True


def test_matches_service_wildcard():
    perms = {"iam:*", "lambda:createfunction"}
    combo = frozenset(["iam:passrole", "lambda:createfunction"])

    assert _matches_combo(perms, combo) is True


def test_no_match_missing_one_action():
    perms = {"iam:passrole"}
    combo = frozenset(["iam:passrole", "lambda:createfunction"])

    assert _matches_combo(perms, combo) is False


def test_no_match_empty_permissions():
    assert _matches_combo(set(), frozenset(["iam:passrole"])) is False


def test_detects_passrole_lambda():
    policy = make_policy("iam:PassRole", "lambda:CreateFunction")
    findings = check_escalation_paths(policy, RESOURCE_ARN)
    titles = [finding.title for finding in findings]

    assert any("lambda" in title.lower() for title in titles)
    assert all(finding.severity in (Severity.critical, Severity.high) for finding in findings)


def test_detects_passrole_ec2():
    policy = make_policy("iam:PassRole", "ec2:RunInstances")
    findings = check_escalation_paths(policy, RESOURCE_ARN)

    assert any("ec2" in finding.title.lower() for finding in findings)


def test_detects_attach_user_policy():
    policy = make_policy("iam:AttachUserPolicy")
    findings = check_escalation_paths(policy, RESOURCE_ARN)

    assert any("AttachUserPolicy" in finding.title for finding in findings)
    assert findings[0].severity == Severity.critical


def test_detects_multiple_combos():
    policy = make_policy("*")
    findings = check_escalation_paths(policy, RESOURCE_ARN)

    assert len(findings) == len(ESCALATION_COMBOS)


def test_no_findings_safe_policy():
    policy = make_policy("s3:GetObject", "s3:ListBucket")
    findings = check_escalation_paths(policy, RESOURCE_ARN)

    assert findings == []


def test_no_findings_deny_only():
    policy = {
        "Statement": [{"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}]
    }
    findings = check_escalation_paths(policy, RESOURCE_ARN)

    assert findings == []


def test_no_findings_empty_policy():
    findings = check_escalation_paths({"Statement": []}, RESOURCE_ARN)

    assert findings == []


def test_finding_has_required_fields():
    policy = make_policy("iam:PassRole", "lambda:CreateFunction")
    findings = check_escalation_paths(policy, RESOURCE_ARN)
    finding = findings[0]

    assert finding.id.startswith("ESC_")
    assert finding.resource == RESOURCE_ARN
    assert len(finding.tags) > 0
    assert "MITRE" in " ".join(finding.tags)
    assert "escalation" in finding.recommendation.lower()


def test_finding_recommendation_names_combo_actions():
    policy = make_policy("iam:PassRole", "lambda:CreateFunction")
    findings = check_escalation_paths(policy, RESOURCE_ARN)
    esc_finding = next(
        finding for finding in findings if "lambda" in finding.title.lower()
    )

    assert "iam:passrole" in esc_finding.recommendation.lower()
    assert "lambda:createfunction" in esc_finding.recommendation.lower()


def test_partial_combo_no_match():
    policy = make_policy("iam:PassRole")
    findings = check_escalation_paths(policy, RESOURCE_ARN)

    assert not any("lambda" in finding.title.lower() for finding in findings)


def test_case_insensitive_action_matching():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["IAM:PassRole", "LAMBDA:CreateFunction"],
                "Resource": "*",
            }
        ]
    }
    findings = check_escalation_paths(policy, RESOURCE_ARN)

    assert any("lambda" in finding.title.lower() for finding in findings)


def test_build_path_records_returns_matching_combos():
    from iam_guardian.auditors.escalation import _build_path_records

    permissions = {"iam:passrole", "lambda:createfunction"}
    records = _build_path_records(
        permissions,
        "arn:aws:iam::123456789012:role/DevRole",
        "role",
        "DevRole",
        "123456789012",
    )

    assert len(records) >= 1
    titles = [record["title"] for record in records]
    assert any("lambda" in title.lower() for title in titles)


def test_build_path_records_empty_on_no_match():
    from iam_guardian.auditors.escalation import _build_path_records

    records = _build_path_records(
        {"s3:getobject"},
        "arn:aws:iam::123456789012:role/ReadOnly",
        "role",
        "ReadOnly",
        "123456789012",
    )

    assert records == []


def test_enumerate_escalation_paths_no_credentials():
    from unittest.mock import patch

    from botocore.exceptions import NoCredentialsError

    with patch("boto3.client", side_effect=NoCredentialsError()):
        from iam_guardian.auditors.escalation import enumerate_escalation_paths

        result = enumerate_escalation_paths("123456789012")

    assert result == []


def test_enumerate_escalation_paths_with_mock_iam():
    """Full enumeration with mocked boto3 IAM client."""
    from unittest.mock import MagicMock, patch

    from iam_guardian.auditors.escalation import enumerate_escalation_paths

    mock_iam = MagicMock()

    mock_iam.get_paginator.side_effect = lambda op: {
        "list_users": _make_paginator(
            [{"UserName": "dev-user", "Arn": "arn:aws:iam::123456789012:user/dev-user"}]
        ),
        "list_roles": _make_paginator([]),
    }[op]

    mock_iam.list_user_policies.return_value = {"PolicyNames": ["DevPolicy"]}
    mock_iam.get_user_policy.return_value = {
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole", "lambda:CreateFunction"],
                    "Resource": "*",
                }
            ]
        }
    }
    mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}

    with patch("boto3.client", return_value=mock_iam):
        result = enumerate_escalation_paths("123456789012")

    assert len(result) >= 1
    assert result[0]["principal_name"] == "dev-user"
    assert any("lambda" in record["title"].lower() for record in result)


def _make_paginator(items):
    """Helper: returns a mock paginator that yields one page."""
    from unittest.mock import MagicMock

    mock_pager = MagicMock()
    mock_pager.paginate.return_value = [{"Users": items, "Roles": items}]
    return mock_pager
