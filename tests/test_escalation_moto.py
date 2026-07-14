import json

import boto3
from moto import mock_aws

from iam_guardian.auditors.escalation import enumerate_escalation_paths

ACCOUNT_ID = "123456789012"


def create_iam_client():
    return boto3.client("iam", region_name="us-east-1")


def make_policy_doc(*actions) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": list(actions),
                    "Resource": "*",
                }
            ],
        }
    )


def create_user_with_inline_policy(iam, username: str, *actions):
    iam.create_user(UserName=username)
    iam.put_user_policy(
        UserName=username,
        PolicyName=f"{username}-policy",
        PolicyDocument=make_policy_doc(*actions),
    )
    return username


def create_role_with_inline_policy(iam, rolename: str, *actions):
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=rolename, AssumeRolePolicyDocument=trust)
    iam.put_role_policy(
        RoleName=rolename,
        PolicyName=f"{rolename}-policy",
        PolicyDocument=make_policy_doc(*actions),
    )
    return rolename


def create_user_with_managed_policy(iam, username: str, *actions):
    iam.create_user(UserName=username)
    policy_resp = iam.create_policy(
        PolicyName=f"{username}-managed",
        PolicyDocument=make_policy_doc(*actions),
    )
    iam.attach_user_policy(
        UserName=username,
        PolicyArn=policy_resp["Policy"]["Arn"],
    )
    return username


@mock_aws
def test_detects_passrole_lambda_on_user():
    iam = create_iam_client()
    create_user_with_inline_policy(
        iam,
        "dev-user",
        "iam:PassRole",
        "lambda:CreateFunction",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)

    assert len(paths) >= 1
    assert any("lambda" in path["title"].lower() for path in paths)
    assert "dev-user" in {path["principal_name"] for path in paths}


@mock_aws
def test_detects_passrole_lambda_on_role():
    iam = create_iam_client()
    create_role_with_inline_policy(
        iam,
        "DevRole",
        "iam:PassRole",
        "lambda:CreateFunction",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)

    assert any(path["principal_name"] == "DevRole" for path in paths)
    assert any("lambda" in path["title"].lower() for path in paths)


@mock_aws
def test_detects_passrole_ec2_on_user():
    iam = create_iam_client()
    create_user_with_inline_policy(
        iam,
        "ec2-user",
        "iam:PassRole",
        "ec2:RunInstances",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)

    assert any("ec2" in path["title"].lower() for path in paths)


@mock_aws
def test_detects_escalation_via_managed_policy():
    iam = create_iam_client()
    create_user_with_managed_policy(
        iam,
        "managed-user",
        "iam:PassRole",
        "lambda:CreateFunction",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)

    assert any(path["principal_name"] == "managed-user" for path in paths)


@mock_aws
def test_wildcard_action_triggers_all_combos():
    iam = create_iam_client()
    create_user_with_inline_policy(iam, "admin-user", "*")

    paths = enumerate_escalation_paths(ACCOUNT_ID)
    admin_paths = [
        path for path in paths if path["principal_name"] == "admin-user"
    ]

    from iam_guardian.auditors.escalation import ESCALATION_COMBOS

    assert len(admin_paths) == len(ESCALATION_COMBOS)


@mock_aws
def test_safe_user_no_paths():
    iam = create_iam_client()
    create_user_with_inline_policy(
        iam,
        "readonly-user",
        "s3:GetObject",
        "s3:ListBucket",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)

    assert not any(path["principal_name"] == "readonly-user" for path in paths)


@mock_aws
def test_empty_account_no_paths():
    paths = enumerate_escalation_paths(ACCOUNT_ID)

    assert paths == []


@mock_aws
def test_multiple_users_detected_independently():
    iam = create_iam_client()
    create_user_with_inline_policy(
        iam,
        "user-a",
        "iam:PassRole",
        "lambda:CreateFunction",
    )
    create_user_with_inline_policy(iam, "user-b", "iam:AttachUserPolicy")
    create_user_with_inline_policy(iam, "user-c", "s3:GetObject")

    paths = enumerate_escalation_paths(ACCOUNT_ID)
    found_principals = {path["principal_name"] for path in paths}

    assert "user-a" in found_principals
    assert "user-b" in found_principals
    assert "user-c" not in found_principals


@mock_aws
def test_path_record_has_all_required_fields():
    iam = create_iam_client()
    create_user_with_inline_policy(
        iam,
        "field-test-user",
        "iam:PassRole",
        "lambda:CreateFunction",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)

    assert len(paths) >= 1
    required = [
        "principal_arn",
        "principal_type",
        "principal_name",
        "matched_combo",
        "combo_key",
        "effective_permissions",
        "severity",
        "title",
        "description",
        "attack_story",
        "tags",
        "narrative",
    ]
    for field in required:
        assert field in paths[0], f"Missing field: {field}"


@mock_aws
def test_path_record_narrative_is_empty_string():
    iam = create_iam_client()
    create_user_with_inline_policy(
        iam,
        "narrative-test",
        "iam:PassRole",
        "lambda:CreateFunction",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)

    assert all(path["narrative"] == "" for path in paths)


@mock_aws
def test_path_severity_matches_combo_definition():
    iam = create_iam_client()
    create_user_with_inline_policy(
        iam,
        "sev-user",
        "iam:PassRole",
        "lambda:CreateFunction",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)
    lambda_path = next(path for path in paths if "lambda" in path["title"].lower())

    assert lambda_path["severity"] == "critical"


@mock_aws
def test_aws_service_roles_are_skipped():
    iam = create_iam_client()
    create_role_with_inline_policy(
        iam,
        "RegularRole",
        "iam:PassRole",
        "lambda:CreateFunction",
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)
    service_role_paths = [
        path for path in paths if "/aws-service-role/" in path["principal_arn"]
    ]

    assert any(path["principal_name"] == "RegularRole" for path in paths)
    assert service_role_paths == []


@mock_aws
def test_permissions_merged_across_inline_and_managed():
    iam = create_iam_client()
    iam.create_user(UserName="split-perms-user")
    iam.put_user_policy(
        UserName="split-perms-user",
        PolicyName="inline-policy",
        PolicyDocument=make_policy_doc("iam:PassRole"),
    )
    policy_resp = iam.create_policy(
        PolicyName="managed-lambda",
        PolicyDocument=make_policy_doc("lambda:CreateFunction"),
    )
    iam.attach_user_policy(
        UserName="split-perms-user",
        PolicyArn=policy_resp["Policy"]["Arn"],
    )

    paths = enumerate_escalation_paths(ACCOUNT_ID)
    split_paths = [
        path for path in paths if path["principal_name"] == "split-perms-user"
    ]

    assert split_paths
    assert any("lambda" in path["title"].lower() for path in split_paths)
