from iam_guardian.cloudtrail.anomaly_scorer import (
    ANOMALY_THRESHOLD,
    SCORE_AFTER_HOURS,
    SCORE_NEW_EVENT_TYPE,
    SCORE_NEW_IP,
    SCORE_ROOT_ACTIVITY,
    _is_after_hours,
    _parse_event_hour,
    score_all_events,
    score_event_anomaly,
)


def make_event(
    event_name="CreateAccessKey",
    identity_type="IAMUser",
    principal_id="alice",
    source_ip="10.0.0.1",
    event_time="2025-01-15T14:00:00+00:00",
    account_id="123456789012",
):
    return {
        "event_id": f"evt-{event_name}-{principal_id}",
        "event_name": event_name,
        "event_time": event_time,
        "region": "us-east-1",
        "source_ip": source_ip,
        "user_agent": "aws-cli",
        "error_code": None,
        "identity_type": identity_type,
        "principal_id": principal_id,
        "account_id": account_id,
        "actor_arn": f"arn:aws:iam::{account_id}:user/{principal_id}",
        "session_name": "",
        "weight": 3,
        "request_params": {},
        "raw": {},
    }


def test_parse_hour_iso_with_tz():
    assert _parse_event_hour("2025-01-15T23:00:00+00:00") == 23


def test_parse_hour_iso_z_suffix():
    assert _parse_event_hour("2025-01-15T05:00:00Z") == 5


def test_parse_hour_midnight():
    assert _parse_event_hour("2025-01-15T00:00:00+00:00") == 0


def test_parse_hour_noon():
    assert _parse_event_hour("2025-01-15T12:00:00+00:00") == 12


def test_parse_hour_invalid_returns_none():
    assert _parse_event_hour("not-a-date") is None


def test_parse_hour_empty_returns_none():
    assert _parse_event_hour("") is None


def test_after_hours_22_is_true():
    assert _is_after_hours(22) is True


def test_after_hours_23_is_true():
    assert _is_after_hours(23) is True


def test_after_hours_0_is_true():
    assert _is_after_hours(0) is True


def test_after_hours_5_is_true():
    assert _is_after_hours(5) is True


def test_business_hours_6_is_false():
    assert _is_after_hours(6) is False


def test_business_hours_14_is_false():
    assert _is_after_hours(14) is False


def test_business_hours_21_is_false():
    assert _is_after_hours(21) is False


def test_none_hour_is_false():
    assert _is_after_hours(None) is False


def test_no_signals_zero_score():
    event = make_event(event_time="2025-01-15T14:00:00+00:00")
    score, reasons = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert score == 0
    assert reasons == []


def test_after_hours_adds_score():
    event = make_event(event_time="2025-01-15T23:00:00+00:00")
    score, reasons = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert score >= SCORE_AFTER_HOURS
    assert any("business hours" in reason for reason in reasons)


def test_before_hours_adds_score():
    event = make_event(event_time="2025-01-15T03:00:00+00:00")
    score, _ = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert score >= SCORE_AFTER_HOURS


def test_boundary_22_00_is_after_hours():
    event = make_event(event_time="2025-01-15T22:00:00+00:00")
    score, _ = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert score >= SCORE_AFTER_HOURS


def test_boundary_06_00_is_not_after_hours():
    event = make_event(event_time="2025-01-15T06:00:00+00:00")
    _, reasons = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert not any("business hours" in reason for reason in reasons)


def test_new_ip_adds_score():
    event = make_event(source_ip="99.88.77.66")
    score, reasons = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert score >= SCORE_NEW_IP
    assert any("New source IP" in reason for reason in reasons)


def test_known_ip_no_score():
    event = make_event(source_ip="10.0.0.1")
    _, reasons = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert not any("New source IP" in reason for reason in reasons)


def test_root_activity_adds_score():
    event = make_event(identity_type="Root", principal_id="root")
    score, reasons = score_event_anomaly(
        event,
        seen_ips=set(),
        seen_event_types=set(),
    )

    assert score >= SCORE_ROOT_ACTIVITY
    assert any("root account" in reason for reason in reasons)


def test_iam_user_no_root_score():
    event = make_event(identity_type="IAMUser")
    _, reasons = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert not any("root account" in reason for reason in reasons)


def test_new_event_type_adds_score():
    event = make_event(event_name="AttachUserPolicy")
    score, reasons = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert score >= SCORE_NEW_EVENT_TYPE
    assert any("First time" in reason for reason in reasons)


def test_known_event_type_no_score():
    event = make_event(event_name="CreateAccessKey")
    _, reasons = score_event_anomaly(
        event,
        seen_ips={"10.0.0.1"},
        seen_event_types={"CreateAccessKey"},
    )

    assert not any("First time" in reason for reason in reasons)


def test_all_four_signals_max_score():
    event = make_event(
        event_name="CreateAccessKey",
        identity_type="Root",
        source_ip="99.99.99.99",
        event_time="2025-01-15T23:30:00+00:00",
    )
    score, reasons = score_event_anomaly(
        event,
        seen_ips=set(),
        seen_event_types=set(),
    )
    expected = (
        SCORE_AFTER_HOURS
        + SCORE_NEW_IP
        + SCORE_ROOT_ACTIVITY
        + SCORE_NEW_EVENT_TYPE
    )

    assert score == expected
    assert len(reasons) == 4


def test_score_does_not_mutate_seen_sets():
    event = make_event(source_ip="1.2.3.4", event_name="CreateUser")
    seen_ips = {"10.0.0.1"}
    seen_types = {"ConsoleLogin"}

    score_event_anomaly(event, seen_ips=seen_ips, seen_event_types=seen_types)

    assert seen_ips == {"10.0.0.1"}
    assert seen_types == {"ConsoleLogin"}


def test_score_all_empty_list():
    assert score_all_events([]) == []


def test_score_all_returns_same_count():
    events = [
        make_event(event_name="CreateAccessKey"),
        make_event(event_name="ConsoleLogin"),
    ]

    result = score_all_events(events)

    assert len(result) == 2


def test_score_all_enriches_with_anomaly_fields():
    result = score_all_events([make_event()])

    assert "anomaly_score" in result[0]
    assert "anomaly_reasons" in result[0]
    assert "is_anomaly" in result[0]


def test_score_all_first_event_always_gets_new_type_signal():
    event = make_event(event_name="CreateAccessKey", principal_id="new-user")
    result = score_all_events([event])

    assert any("First time" in reason for reason in result[0]["anomaly_reasons"])


def test_score_all_second_same_type_no_new_type_signal():
    first = make_event(
        event_name="CreateAccessKey",
        principal_id="alice",
        event_time="2025-01-15T10:00:00+00:00",
    )
    second = make_event(
        event_name="CreateAccessKey",
        principal_id="alice",
        event_time="2025-01-15T11:00:00+00:00",
    )

    result = score_all_events([first, second])
    second_result = next(
        item for item in result if item["event_time"] == "2025-01-15T11:00:00+00:00"
    )

    assert not any("First time" in reason for reason in second_result["anomaly_reasons"])


def test_score_all_first_ip_gets_new_ip_signal():
    event = make_event(
        source_ip="1.2.3.4",
        principal_id="newuser",
        event_time="2025-01-15T10:00:00+00:00",
    )

    result = score_all_events([event])

    assert any("New source IP" in reason for reason in result[0]["anomaly_reasons"])


def test_score_all_second_same_ip_no_new_ip_signal():
    first = make_event(
        source_ip="1.2.3.4",
        principal_id="alice",
        event_time="2025-01-15T10:00:00+00:00",
    )
    second = make_event(
        source_ip="1.2.3.4",
        principal_id="alice",
        event_time="2025-01-15T11:00:00+00:00",
        event_name="ConsoleLogin",
    )

    result = score_all_events([first, second])
    second_result = next(
        item for item in result if item["event_time"] == "2025-01-15T11:00:00+00:00"
    )

    assert not any("New source IP" in reason for reason in second_result["anomaly_reasons"])


def test_score_all_different_principals_isolated():
    alice = make_event(
        principal_id="alice",
        source_ip="1.2.3.4",
        event_time="2025-01-15T10:00:00+00:00",
    )
    bob = make_event(
        principal_id="bob",
        source_ip="1.2.3.4",
        event_time="2025-01-15T11:00:00+00:00",
    )

    result = score_all_events([alice, bob])
    alice_result = next(item for item in result if item["principal_id"] == "alice")
    bob_result = next(item for item in result if item["principal_id"] == "bob")

    assert any("New source IP" in reason for reason in alice_result["anomaly_reasons"])
    assert any("New source IP" in reason for reason in bob_result["anomaly_reasons"])


def test_score_all_sorted_descending_by_score():
    low = make_event(
        event_time="2025-01-15T14:00:00+00:00",
        source_ip="10.0.0.1",
        event_name="ConsoleLogin",
        principal_id="low-user",
    )
    high = make_event(
        identity_type="Root",
        principal_id="root",
        event_time="2025-01-15T23:30:00+00:00",
        source_ip="99.99.99.99",
        event_name="CreateAccessKey",
    )

    result = score_all_events([low, high])

    assert result[0]["anomaly_score"] >= result[1]["anomaly_score"]


def test_is_anomaly_flag_at_threshold():
    event = make_event(
        identity_type="Root",
        principal_id="root",
        event_time="2025-01-15T14:00:00+00:00",
        source_ip="10.0.0.1",
    )

    result = score_all_events([event])
    root_event = result[0]

    assert root_event["anomaly_score"] >= ANOMALY_THRESHOLD
    assert root_event["is_anomaly"] is True


def test_is_anomaly_false_below_threshold():
    first = make_event(
        source_ip="10.0.0.1",
        event_name="ConsoleLogin",
        principal_id="safe-user",
        event_time="2025-01-15T09:00:00+00:00",
    )
    second = make_event(
        source_ip="10.0.0.1",
        event_name="ConsoleLogin",
        principal_id="safe-user",
        event_time="2025-01-15T10:00:00+00:00",
    )

    result = score_all_events([first, second])
    second_result = next(
        item for item in result if item["event_time"] == "2025-01-15T10:00:00+00:00"
    )

    assert second_result["anomaly_score"] < ANOMALY_THRESHOLD
    assert second_result["is_anomaly"] is False


def test_score_all_does_not_mutate_input():
    events = [make_event()]
    original_keys = set(events[0].keys())

    score_all_events(events)

    assert set(events[0].keys()) == original_keys
