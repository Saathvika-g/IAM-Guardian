from unittest.mock import patch

import pytest
from pydantic import ValidationError

from iam_guardian.models import IAMPolicyModel
from iam_guardian.rewriter.rewriter import rewrite_policy

WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

VALID_REWRITTEN = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

PATCH = "iam_guardian.rewriter.rewriter._call_groq_json"
DIFF_PATCH = "iam_guardian.rewriter.rewriter._get_diff_summary"


def test_rewrite_returns_valid_policy():
    with patch(PATCH, return_value=VALID_REWRITTEN), patch(
        DIFF_PATCH,
        return_value="Replaced wildcard with specific S3 action.",
    ):
        rewritten, summary = rewrite_policy(WILDCARD_POLICY)

    assert "Statement" in rewritten
    assert rewritten["Statement"][0]["Action"] == ["s3:GetObject"]
    assert "wildcard" in summary.lower() or len(summary) > 0


def test_rewrite_retries_on_validation_error():
    call_count = {"n": 0}

    def side_effect(prompt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {"bad": "shape"}
        return VALID_REWRITTEN

    with patch(PATCH, side_effect=side_effect), patch(
        DIFF_PATCH,
        return_value="Fixed.",
    ):
        rewritten, summary = rewrite_policy(WILDCARD_POLICY)

    assert call_count["n"] == 2
    assert "Statement" in rewritten


def test_rewrite_returns_empty_dict_on_total_failure():
    with patch(PATCH, side_effect=Exception("Groq is down")), patch(
        DIFF_PATCH,
        return_value="",
    ):
        rewritten, summary = rewrite_policy(WILDCARD_POLICY)

    assert rewritten == {}
    assert "Rewrite failed" in summary


def test_iam_policy_model_validates_correct_structure():
    model = IAMPolicyModel.model_validate(VALID_REWRITTEN)

    assert len(model.Statement) == 1
    assert model.Statement[0].Effect == "Allow"


def test_iam_policy_model_rejects_missing_statement():
    with pytest.raises(ValidationError):
        IAMPolicyModel.model_validate({"Version": "2012-10-17"})


def test_rewrite_endpoint_404():
    pass
