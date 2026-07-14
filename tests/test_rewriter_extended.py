import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from iam_guardian.models import IAMPolicyModel
from iam_guardian.rewriter.rewriter import (
    _build_diff_prompt,
    _build_rewrite_prompt,
    _call_groq_json,
    _get_diff_summary,
    rewrite_policy,
)

GROQ_PATCH = "iam_guardian.rewriter.rewriter._call_groq_json"
DIFF_PATCH = "iam_guardian.rewriter.rewriter._get_diff_summary"
CLIENT_PATCH = "iam_guardian.rewriter.rewriter.client"

WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

VALID_LEAST_PRIVILEGE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

MULTI_STATEMENT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket/*",
        },
        {
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem"],
            "Resource": "arn:aws:dynamodb:::table/MyTable",
        },
        {
            "Effect": "Deny",
            "Action": ["s3:DeleteObject"],
            "Resource": "*",
        },
    ],
}


def test_iam_policy_model_action_as_string():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ],
    }

    model = IAMPolicyModel.model_validate(policy)

    assert model.Statement[0].Action == "s3:GetObject"


def test_iam_policy_model_action_as_list():
    model = IAMPolicyModel.model_validate(VALID_LEAST_PRIVILEGE)

    assert isinstance(model.Statement[0].Action, list)
    assert "s3:GetObject" in model.Statement[0].Action


def test_iam_policy_model_resource_as_string():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        ],
    }

    model = IAMPolicyModel.model_validate(policy)

    assert model.Statement[0].Resource == "arn:aws:s3:::b/*"


def test_iam_policy_model_resource_as_list():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:Get*",
                "Resource": ["arn:aws:s3:::b/*", "arn:aws:s3:::b"],
            }
        ],
    }

    model = IAMPolicyModel.model_validate(policy)

    assert isinstance(model.Statement[0].Resource, list)


def test_iam_policy_model_optional_sid():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }

    model = IAMPolicyModel.model_validate(policy)

    assert model.Statement[0].Sid == "AllowS3Read"


def test_iam_policy_model_sid_optional_defaults_none():
    model = IAMPolicyModel.model_validate(VALID_LEAST_PRIVILEGE)

    assert model.Statement[0].Sid is None


def test_iam_policy_model_optional_condition():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringEquals": {"s3:prefix": "home/"}},
            }
        ],
    }

    model = IAMPolicyModel.model_validate(policy)

    assert model.Statement[0].Condition is not None


def test_iam_policy_model_missing_statement_raises():
    with pytest.raises(ValidationError):
        IAMPolicyModel.model_validate({"Version": "2012-10-17"})


def test_iam_policy_model_empty_statement_list_valid():
    model = IAMPolicyModel.model_validate(
        {"Version": "2012-10-17", "Statement": []}
    )

    assert model.Statement == []


def test_iam_policy_model_missing_effect_raises():
    with pytest.raises(ValidationError):
        IAMPolicyModel.model_validate(
            {
                "Version": "2012-10-17",
                "Statement": [{"Action": "s3:GetObject", "Resource": "*"}],
            }
        )


def test_iam_policy_model_default_version():
    model = IAMPolicyModel.model_validate(
        {
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ]
        }
    )

    assert model.Version == "2012-10-17"


def test_iam_policy_model_multi_statement():
    model = IAMPolicyModel.model_validate(MULTI_STATEMENT_POLICY)
    effects = [statement.Effect for statement in model.Statement]

    assert len(model.Statement) == 3
    assert "Allow" in effects
    assert "Deny" in effects


def test_iam_policy_model_dump_excludes_none():
    model = IAMPolicyModel.model_validate(VALID_LEAST_PRIVILEGE)
    dumped = model.model_dump(exclude_none=True)
    first_statement = dumped["Statement"][0]

    assert "Sid" not in first_statement
    assert "Condition" not in first_statement
    assert "Principal" not in first_statement


def test_build_rewrite_prompt_contains_policy_json():
    prompt = _build_rewrite_prompt(WILDCARD_POLICY, strict=False)

    assert '"Action": "*"' in prompt or "Action" in prompt
    assert "least-privilege" in prompt.lower()


def test_build_rewrite_prompt_strict_contains_warning():
    prompt = _build_rewrite_prompt(WILDCARD_POLICY, strict=True)

    assert "IMPORTANT" in prompt or "previous response" in prompt.lower()


def test_build_rewrite_prompt_non_strict_no_warning():
    prompt = _build_rewrite_prompt(WILDCARD_POLICY, strict=False)

    assert "IMPORTANT" not in prompt


def test_build_diff_prompt_contains_both_policies():
    prompt = _build_diff_prompt(WILDCARD_POLICY, VALID_LEAST_PRIVILEGE)

    assert "Original" in prompt
    assert "Rewritten" in prompt


def test_call_groq_json_parses_response():
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value.choices[
        0
    ].message.content = json.dumps(VALID_LEAST_PRIVILEGE)

    with patch(CLIENT_PATCH, mock_client):
        result = _call_groq_json("some prompt")

    assert result["Version"] == "2012-10-17"
    assert "Statement" in result


def test_call_groq_json_uses_json_object_format():
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value.choices[
        0
    ].message.content = json.dumps(VALID_LEAST_PRIVILEGE)

    with patch(CLIENT_PATCH, mock_client):
        _call_groq_json("some prompt")

    call_kwargs = mock_client.chat.completions.create.call_args[1]
    assert call_kwargs.get("response_format") == {"type": "json_object"}


def test_get_diff_summary_returns_string():
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value.choices[
        0
    ].message.content = "Replaced wildcard with specific permissions."

    with patch(CLIENT_PATCH, mock_client):
        result = _get_diff_summary(WILDCARD_POLICY, VALID_LEAST_PRIVILEGE)

    assert isinstance(result, str)
    assert len(result) > 0


def test_get_diff_summary_does_not_use_json_format():
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value.choices[
        0
    ].message.content = "Summary."

    with patch(CLIENT_PATCH, mock_client):
        _get_diff_summary(WILDCARD_POLICY, VALID_LEAST_PRIVILEGE)

    call_kwargs = mock_client.chat.completions.create.call_args[1]
    assert "response_format" not in call_kwargs


def test_get_diff_summary_fallback_on_error():
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("network error")

    with patch(CLIENT_PATCH, mock_client):
        result = _get_diff_summary(WILDCARD_POLICY, VALID_LEAST_PRIVILEGE)

    assert "unavailable" in result.lower()


def test_rewrite_policy_success_path():
    with patch(GROQ_PATCH, return_value=VALID_LEAST_PRIVILEGE), patch(
        DIFF_PATCH,
        return_value="Removed wildcards.",
    ):
        rewritten, summary = rewrite_policy(WILDCARD_POLICY)

    assert "Statement" in rewritten
    assert summary == "Removed wildcards."


def test_rewrite_policy_returns_validated_model_dump():
    with patch(GROQ_PATCH, return_value=VALID_LEAST_PRIVILEGE), patch(
        DIFF_PATCH,
        return_value="Fixed.",
    ):
        rewritten, _ = rewrite_policy(WILDCARD_POLICY)

    model = IAMPolicyModel.model_validate(rewritten)
    assert len(model.Statement) >= 1


def test_rewrite_policy_retries_exactly_once_on_validation_error():
    call_count = {"n": 0}

    def side_effect(prompt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {"bad": "structure"}
        return VALID_LEAST_PRIVILEGE

    with patch(GROQ_PATCH, side_effect=side_effect), patch(
        DIFF_PATCH,
        return_value="Fixed on retry.",
    ):
        rewritten, _ = rewrite_policy(WILDCARD_POLICY)

    assert call_count["n"] == 2
    assert "Statement" in rewritten


def test_rewrite_policy_no_third_attempt():
    call_count = {"n": 0}

    def always_bad(prompt):
        call_count["n"] += 1
        return {"still": "bad"}

    with patch(GROQ_PATCH, side_effect=always_bad), patch(
        DIFF_PATCH,
        return_value="",
    ):
        rewritten, summary = rewrite_policy(WILDCARD_POLICY)

    assert call_count["n"] == 2
    assert rewritten == {}
    assert "Rewrite failed" in summary


def test_rewrite_policy_empty_dict_on_groq_exception():
    with patch(GROQ_PATCH, side_effect=Exception("API down")), patch(
        DIFF_PATCH,
        return_value="",
    ):
        rewritten, summary = rewrite_policy(WILDCARD_POLICY)

    assert rewritten == {}
    assert "Rewrite failed" in summary
    assert "Exception" in summary


def test_rewrite_policy_preserves_multi_statement():
    multi = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::b/*",
            },
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem"],
                "Resource": "arn:aws:dynamodb:::*",
            },
        ],
    }

    with patch(GROQ_PATCH, return_value=multi), patch(
        DIFF_PATCH,
        return_value="Kept two statements.",
    ):
        rewritten, _ = rewrite_policy(WILDCARD_POLICY)

    assert len(rewritten["Statement"]) == 2


def test_rewrite_policy_strict_prompt_used_on_retry():
    prompts_seen = []

    def capture_prompt(prompt):
        prompts_seen.append(prompt)
        if len(prompts_seen) == 1:
            return {"bad": "shape"}
        return VALID_LEAST_PRIVILEGE

    with patch(GROQ_PATCH, side_effect=capture_prompt), patch(
        DIFF_PATCH,
        return_value="ok",
    ):
        rewrite_policy(WILDCARD_POLICY)

    assert len(prompts_seen) == 2
    assert prompts_seen[0] != prompts_seen[1]
    assert "IMPORTANT" in prompts_seen[1]
