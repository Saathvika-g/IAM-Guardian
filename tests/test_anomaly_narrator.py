from unittest.mock import MagicMock, patch

from iam_guardian.cloudtrail.anomaly_narrator import (
    _build_narrative_prompt,
    generate_anomaly_narrative,
    generate_narratives_for_anomalies,
)

PATCH = "iam_guardian.cloudtrail.anomaly_narrator.client"


def make_anomalous_event(score=7, is_anomaly=True):
    return {
        "event_id": "evt-001",
        "event_name": "CreateAccessKey",
        "event_time": "2025-01-15T23:00:00+00:00",
        "region": "us-east-1",
        "source_ip": "99.99.99.99",
        "user_agent": "aws-cli",
        "identity_type": "IAMUser",
        "principal_id": "suspicious-user",
        "account_id": "123456789012",
        "actor_arn": "arn:aws:iam::123456789012:user/suspicious-user",
        "session_name": "",
        "weight": 3,
        "anomaly_score": score,
        "anomaly_reasons": [
            "Event occurred at 23:xx UTC, outside business hours",
            "New source IP address '99.99.99.99'",
        ],
        "is_anomaly": is_anomaly,
    }


def mock_groq(text="Attacker is harvesting keys. Check IAM logs. Rotate all keys."):
    mock = MagicMock()
    mock.chat.completions.create.return_value.choices[0].message.content = text
    return mock


def test_prompt_contains_event_name():
    prompt = _build_narrative_prompt(make_anomalous_event())

    assert "CreateAccessKey" in prompt


def test_prompt_contains_principal():
    prompt = _build_narrative_prompt(make_anomalous_event())

    assert "suspicious-user" in prompt


def test_prompt_contains_anomaly_score():
    prompt = _build_narrative_prompt(make_anomalous_event(score=9))

    assert "9" in prompt


def test_prompt_contains_reasons():
    prompt = _build_narrative_prompt(make_anomalous_event())

    assert "business hours" in prompt


def test_prompt_contains_source_ip():
    prompt = _build_narrative_prompt(make_anomalous_event())

    assert "99.99.99.99" in prompt


def test_prompt_contains_action_questions():
    prompt = _build_narrative_prompt(make_anomalous_event())

    assert "attacker" in prompt.lower()
    assert "security team" in prompt.lower()


def test_generate_returns_string():
    event = make_anomalous_event()

    with patch(PATCH, mock_groq("Attacker harvesting. Check logs. Rotate keys.")):
        result = generate_anomaly_narrative(event)

    assert isinstance(result, str)
    assert len(result) > 0


def test_generate_returns_groq_text():
    expected = "Attacker may be pivoting. Investigate immediately. Enable MFA."
    event = make_anomalous_event()

    with patch(PATCH, mock_groq(expected)):
        result = generate_anomaly_narrative(event)

    assert result == expected


def test_generate_fallback_on_exception():
    event = make_anomalous_event()

    with patch(PATCH) as mock_client:
        mock_client.chat.completions.create.side_effect = Exception("rate limit")
        result = generate_anomaly_narrative(event)

    assert "Narrative unavailable" in result
    assert "Exception" in result


def test_generate_fallback_mentions_signal_count():
    event = make_anomalous_event()

    with patch(PATCH) as mock_client:
        mock_client.chat.completions.create.side_effect = Exception("timeout")
        result = generate_anomaly_narrative(event)

    assert "2" in result or "signal" in result


def test_batch_skips_non_anomalies():
    events = [
        make_anomalous_event(is_anomaly=True),
        {**make_anomalous_event(is_anomaly=False), "anomaly_score": 1},
    ]

    with patch(PATCH, mock_groq("Narrative for anomaly.")):
        result = generate_narratives_for_anomalies(events)

    anomaly = next(item for item in result if item["is_anomaly"])
    non_anomaly = next(item for item in result if not item["is_anomaly"])
    assert anomaly["narrative"] is not None
    assert non_anomaly["narrative"] is None


def test_batch_calls_groq_once_per_anomaly():
    events = [make_anomalous_event(is_anomaly=True)] * 3
    call_count = {"n": 0}

    def side_effect(*args, **kwargs):
        call_count["n"] += 1
        mock_response = MagicMock()
        mock_response.choices[0].message.content = f"Narrative {call_count['n']}"
        return mock_response

    with patch(PATCH) as mock_client:
        mock_client.chat.completions.create.side_effect = side_effect
        generate_narratives_for_anomalies(events)

    assert call_count["n"] == 3


def test_batch_empty_list_returns_empty():
    assert generate_narratives_for_anomalies([]) == []


def test_batch_all_non_anomalies_no_groq_calls():
    events = [{**make_anomalous_event(is_anomaly=False), "anomaly_score": 0}] * 3

    with patch(PATCH) as mock_client:
        generate_narratives_for_anomalies(events)

    mock_client.chat.completions.create.assert_not_called()


def test_batch_preserves_all_event_fields():
    event = make_anomalous_event(is_anomaly=True)

    with patch(PATCH, mock_groq("Test narrative.")):
        result = generate_narratives_for_anomalies([event])

    enriched = result[0]
    assert enriched["event_id"] == event["event_id"]
    assert enriched["event_name"] == event["event_name"]
    assert enriched["principal_id"] == event["principal_id"]
    assert enriched["anomaly_score"] == event["anomaly_score"]
    assert "narrative" in enriched
