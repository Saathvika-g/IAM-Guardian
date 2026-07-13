from unittest.mock import MagicMock, patch

PATCH = "iam_guardian.auditors.narrator.client"


def make_path(combo=None, severity="critical"):
    return {
        "principal_arn": "arn:aws:iam::123456789012:role/DevRole",
        "principal_type": "role",
        "principal_name": "DevRole",
        "matched_combo": combo or ["iam:passrole", "lambda:createfunction"],
        "effective_permissions": ["iam:passrole", "lambda:createfunction", "s3:getobject"],
        "severity": severity,
        "title": "Privilege escalation: iam:PassRole + lambda:CreateFunction",
        "description": "Can attach admin role to Lambda.",
        "attack_story": "Attacker creates Lambda with admin role.",
        "tags": ["privilege-escalation", "MITRE-T1098"],
        "narrative": "",
    }


def mock_groq_response(text: str):
    mock = MagicMock()
    mock.chat.completions.create.return_value.choices[0].message.content = text
    return mock


def test_generate_narrative_returns_string():
    from iam_guardian.auditors.narrator import generate_narrative

    with patch(PATCH, mock_groq_response("1. Attacker does X. 2. Attacker does Y.")):
        result = generate_narrative(make_path())

    assert isinstance(result, str)
    assert len(result) > 0


def test_generate_narrative_fallback_on_error():
    from iam_guardian.auditors.narrator import generate_narrative

    with patch(PATCH) as mock_client:
        mock_client.chat.completions.create.side_effect = Exception("rate limit")
        result = generate_narrative(make_path())

    assert "Narrative unavailable" in result
    assert "Exception" in result


def test_generate_narratives_batch_enriches_all():
    from iam_guardian.auditors.narrator import generate_narratives_batch

    paths = [make_path(), make_path(combo=["iam:createaccesskey"], severity="high")]
    call_count = {"n": 0}

    def side_effect(*args, **kwargs):
        call_count["n"] += 1
        response = MagicMock()
        response.choices[0].message.content = f"Narrative {call_count['n']}"
        return response

    with patch(PATCH) as mock_client:
        mock_client.chat.completions.create.side_effect = side_effect
        result = generate_narratives_batch(paths)

    assert len(result) == 2
    assert result[0]["narrative"] == "Narrative 1"
    assert result[1]["narrative"] == "Narrative 2"


def test_generate_narratives_batch_empty_list():
    from iam_guardian.auditors.narrator import generate_narratives_batch

    result = generate_narratives_batch([])

    assert result == []
