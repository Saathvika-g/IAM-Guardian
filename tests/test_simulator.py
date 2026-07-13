from unittest.mock import MagicMock, patch

from iam_guardian.simulator.simulator import (
    _extract_actions,
    _extract_resources,
    simulate_rewrite,
)

ORIGINAL = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

REWRITTEN = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket/*",
        }
    ],
}

ACCOUNT = "123456789012"


def test_extract_actions_wildcard():
    actions = _extract_actions(ORIGINAL)

    assert "*" in actions


def test_extract_actions_list():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "*",
            }
        ]
    }

    actions = _extract_actions(policy)

    assert set(actions) == {"s3:GetObject", "s3:PutObject"}


def test_extract_actions_skips_deny():
    policy = {
        "Statement": [
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}
        ]
    }

    assert _extract_actions(policy) == []


def test_extract_resources_wildcard_string():
    assert _extract_resources(ORIGINAL) == ["*"]


def test_extract_resources_list_with_wildcard():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:Get*",
                "Resource": ["arn:aws:s3:::b", "*"],
            }
        ]
    }

    assert _extract_resources(policy) == ["*"]


def test_simulate_returns_verified_when_all_allowed():
    mock_iam = MagicMock()
    mock_iam.simulate_custom_policy.return_value = {
        "EvaluationResults": [
            {"EvalDecision": "allowed", "EvalActionName": "s3:GetObject"}
        ]
    }

    with patch("boto3.client", return_value=mock_iam):
        result = simulate_rewrite(
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                ]
            },
            REWRITTEN,
            ACCOUNT,
        )

    assert result["status"] == "verified"
    assert "s3:GetObject" in result["allowed_actions"]
    assert result["denied_actions"] == []


def test_simulate_returns_needs_review_when_action_denied():
    mock_iam = MagicMock()
    mock_iam.simulate_custom_policy.return_value = {
        "EvaluationResults": [
            {"EvalDecision": "implicitDeny", "EvalActionName": "s3:DeleteObject"}
        ]
    }

    with patch("boto3.client", return_value=mock_iam):
        result = simulate_rewrite(
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "*"}
                ]
            },
            REWRITTEN,
            ACCOUNT,
        )

    assert result["status"] == "needs_review"
    assert "s3:DeleteObject" in result["denied_actions"]


def test_simulate_returns_unavailable_on_no_credentials():
    from botocore.exceptions import NoCredentialsError

    with patch("boto3.client", side_effect=NoCredentialsError()):
        result = simulate_rewrite(
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                ]
            },
            REWRITTEN,
            ACCOUNT,
        )

    assert result["status"] == "simulation_unavailable"
    assert "credentials" in result["detail"].lower()


def test_simulate_returns_unavailable_on_empty_actions():
    result = simulate_rewrite(
        {"Statement": []},
        REWRITTEN,
        ACCOUNT,
    )

    assert result["status"] == "simulation_unavailable"


def test_simulate_never_raises_on_unexpected_error():
    with patch("boto3.client", side_effect=RuntimeError("totally unexpected")):
        result = simulate_rewrite(
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                ]
            },
            REWRITTEN,
            ACCOUNT,
        )

    assert result["status"] == "simulation_unavailable"
    assert "RuntimeError" in result["detail"]


def test_simulate_skips_wildcard_action_before_boto_call():
    with patch("boto3.client") as mock_client:
        result = simulate_rewrite(ORIGINAL, REWRITTEN, ACCOUNT)

    assert result["status"] == "simulation_unavailable"
    assert result["original_actions"] == ["*"]
    assert "Action: *" in result["detail"]
    mock_client.assert_not_called()
