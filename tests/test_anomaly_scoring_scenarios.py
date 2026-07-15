from iam_guardian.cloudtrail.anomaly_scorer import (
    ANOMALY_THRESHOLD,
    SCORE_AFTER_HOURS,
    SCORE_NEW_EVENT_TYPE,
    SCORE_NEW_IP,
    SCORE_ROOT_ACTIVITY,
    score_all_events,
    score_event_anomaly,
)


def evt(
    event_name="CreateAccessKey",
    identity_type="IAMUser",
    principal_id="alice",
    source_ip="10.0.0.1",
    hour=14,
    account_id="123456789012",
    error_code=None,
    request_params=None,
):
    """Build a minimal parsed event dict for scoring tests."""
    event_time = f"2025-01-15T{hour:02d}:00:00+00:00"
    return {
        "event_id": f"evt-{event_name}-{principal_id}-{hour}",
        "event_name": event_name,
        "event_time": event_time,
        "region": "us-east-1",
        "source_ip": source_ip,
        "user_agent": "aws-cli",
        "error_code": error_code,
        "identity_type": identity_type,
        "principal_id": principal_id,
        "account_id": account_id,
        "actor_arn": f"arn:aws:iam::{account_id}:user/{principal_id}",
        "session_name": "",
        "weight": 3,
        "request_params": request_params or {},
        "raw": {},
    }


class TestKnownScores:
    def test_zero_score_repeated_known_event(self):
        e1 = evt(event_name="ConsoleLogin", source_ip="10.0.0.1", hour=10, principal_id="bob")
        e2 = evt(event_name="ConsoleLogin", source_ip="10.0.0.1", hour=11, principal_id="bob")
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if r["event_time"].startswith("2025-01-15T11"))
        assert e2_result["anomaly_score"] == 0
        assert e2_result["is_anomaly"] is False

    def test_score_2_after_hours_only(self):
        e1 = evt(event_name="ConsoleLogin", source_ip="10.0.0.1", hour=14, principal_id="carol")
        e2 = evt(event_name="ConsoleLogin", source_ip="10.0.0.1", hour=23, principal_id="carol")
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if r["event_time"].startswith("2025-01-15T23"))
        assert e2_result["anomaly_score"] == SCORE_AFTER_HOURS
        assert e2_result["anomaly_score"] == 2

    def test_score_3_new_ip_only(self):
        e1 = evt(event_name="ConsoleLogin", source_ip="10.0.0.1", hour=10, principal_id="dave")
        e2 = evt(event_name="ConsoleLogin", source_ip="99.88.77.66", hour=11, principal_id="dave")
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if r["event_time"].startswith("2025-01-15T11"))
        assert e2_result["anomaly_score"] == SCORE_NEW_IP
        assert e2_result["anomaly_score"] == 3

    def test_score_5_root_only(self):
        e1 = evt(event_name="ConsoleLogin", identity_type="Root", principal_id="root", source_ip="10.0.0.1", hour=14)
        e2 = evt(event_name="ConsoleLogin", identity_type="Root", principal_id="root", source_ip="10.0.0.1", hour=15)
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if r["event_time"].startswith("2025-01-15T15"))
        assert e2_result["anomaly_score"] == SCORE_ROOT_ACTIVITY
        assert e2_result["is_anomaly"] is True

    def test_score_5_new_ip_plus_after_hours(self):
        e1 = evt(event_name="ConsoleLogin", source_ip="10.0.0.1", hour=10, principal_id="eve")
        e2 = evt(event_name="ConsoleLogin", source_ip="99.0.0.1", hour=23, principal_id="eve")
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if r["event_time"].startswith("2025-01-15T23"))
        assert e2_result["anomaly_score"] == SCORE_NEW_IP + SCORE_AFTER_HOURS
        assert e2_result["anomaly_score"] == ANOMALY_THRESHOLD
        assert e2_result["is_anomaly"] is True

    def test_score_10_root_plus_after_hours_plus_new_ip(self):
        e1 = evt(event_name="ConsoleLogin", identity_type="Root", principal_id="root", source_ip="10.0.0.1", hour=14)
        e2 = evt(event_name="ConsoleLogin", identity_type="Root", principal_id="root", source_ip="99.0.0.1", hour=23)
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if r["event_time"].startswith("2025-01-15T23"))
        expected = SCORE_ROOT_ACTIVITY + SCORE_AFTER_HOURS + SCORE_NEW_IP
        assert e2_result["anomaly_score"] == expected
        assert e2_result["anomaly_score"] == 10

    def test_score_12_all_four_signals(self):
        e = evt(
            event_name="CreateAccessKey",
            identity_type="Root",
            principal_id="root",
            source_ip="1.2.3.4",
            hour=23,
        )
        results = score_all_events([e])
        assert results[0]["anomaly_score"] == (
            SCORE_ROOT_ACTIVITY + SCORE_AFTER_HOURS + SCORE_NEW_IP + SCORE_NEW_EVENT_TYPE
        )
        assert results[0]["anomaly_score"] == 12

    def test_score_5_new_event_type_plus_new_ip_is_anomaly(self):
        e = evt(event_name="AttachUserPolicy", source_ip="5.5.5.5", principal_id="frank", hour=10)
        results = score_all_events([e])
        assert results[0]["anomaly_score"] == SCORE_NEW_EVENT_TYPE + SCORE_NEW_IP
        assert results[0]["anomaly_score"] == 5
        assert results[0]["is_anomaly"] is True

    def test_score_4_below_threshold_not_anomaly(self):
        e1 = evt(event_name="ConsoleLogin", source_ip="10.0.0.1", hour=10, principal_id="grace")
        e2 = evt(event_name="AttachUserPolicy", source_ip="10.0.0.1", hour=23, principal_id="grace")
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if r["event_time"].startswith("2025-01-15T23"))
        assert e2_result["anomaly_score"] == SCORE_AFTER_HOURS + SCORE_NEW_EVENT_TYPE
        assert e2_result["anomaly_score"] == 4
        assert e2_result["is_anomaly"] is False


class TestAttackerScenario:
    def setup_method(self):
        self.baseline_events = [
            evt("ConsoleLogin", "IAMUser", "deploy-user", "10.0.0.1", 9),
            evt("ConsoleLogin", "IAMUser", "deploy-user", "10.0.0.1", 10),
            evt("CreateAccessKey", "IAMUser", "deploy-user", "10.0.0.1", 11),
        ]
        self.attack_events = [
            evt("ConsoleLogin", "IAMUser", "deploy-user", "203.0.113.99", 23),
            evt("CreateAccessKey", "IAMUser", "deploy-user", "203.0.113.99", 23),
            evt("AttachUserPolicy", "IAMUser", "deploy-user", "203.0.113.99", 23),
            evt("AttachRolePolicy", "IAMUser", "deploy-user", "203.0.113.99", 0),
        ]

    def test_baseline_events_not_anomalous(self):
        results = score_all_events(self.baseline_events)
        repeated_logins = [
            r for r in results
            if r["event_name"] == "ConsoleLogin" and not r["is_anomaly"]
        ]
        assert len(repeated_logins) >= 1

    def test_attack_events_flagged_as_anomalous(self):
        results = score_all_events(self.baseline_events + self.attack_events)
        attack_results = [r for r in results if r["source_ip"] == "203.0.113.99"]
        assert any(r["is_anomaly"] for r in attack_results)

    def test_attack_new_ip_flagged(self):
        results = score_all_events(self.baseline_events + self.attack_events)
        first_attack = next(
            r for r in sorted(results, key=lambda x: x["event_time"])
            if r["source_ip"] == "203.0.113.99"
        )
        assert any("New source IP" in reason for reason in first_attack["anomaly_reasons"])

    def test_attack_after_hours_flagged(self):
        results = score_all_events(self.baseline_events + self.attack_events)
        after_hours = [
            r for r in results
            if "23:00" in r["event_time"] or "00:00" in r["event_time"]
        ]
        assert any(
            any("business hours" in reason for reason in r["anomaly_reasons"])
            for r in after_hours
        )

    def test_attack_total_anomaly_count(self):
        results = score_all_events(self.baseline_events + self.attack_events)
        attack_anomalies = [
            r for r in results
            if r["source_ip"] == "203.0.113.99" and r["is_anomaly"]
        ]
        assert len(attack_anomalies) >= 1

    def test_highest_score_is_attack_event(self):
        results = score_all_events(self.baseline_events + self.attack_events)
        top = results[0]
        assert top["source_ip"] == "203.0.113.99" or top["identity_type"] == "Root"


class TestRootActivityScenario:
    def test_root_console_login_always_anomaly(self):
        events = [evt("ConsoleLogin", "Root", "root", "10.0.0.1", 10)]
        results = score_all_events(events)
        assert results[0]["is_anomaly"] is True
        assert results[0]["anomaly_score"] >= SCORE_ROOT_ACTIVITY

    def test_root_create_access_key_high_score(self):
        events = [evt("CreateAccessKey", "Root", "root", "10.0.0.1", 14)]
        results = score_all_events(events)
        assert results[0]["anomaly_score"] >= SCORE_ROOT_ACTIVITY
        assert any("root account" in r for r in results[0]["anomaly_reasons"])

    def test_root_activity_reason_text(self):
        events = [evt("ConsoleLogin", "Root", "root", "10.0.0.1", 10)]
        results = score_all_events(events)
        reasons = results[0]["anomaly_reasons"]
        assert any("root" in r.lower() for r in reasons)

    def test_multiple_root_events_all_anomalous(self):
        events = [
            evt("ConsoleLogin", "Root", "root", "10.0.0.1", 14),
            evt("CreateAccessKey", "Root", "root", "10.0.0.1", 14),
            evt("AttachUserPolicy", "Root", "root", "10.0.0.1", 14),
        ]
        results = score_all_events(events)
        assert all(r["is_anomaly"] for r in results)


class TestMultiplePrincipalsIsolated:
    def test_principals_do_not_share_ip_history(self):
        alice = evt("ConsoleLogin", "IAMUser", "alice", "10.0.0.1", 10)
        bob = evt("ConsoleLogin", "IAMUser", "bob", "10.0.0.1", 11)
        results = score_all_events([alice, bob])
        bob_result = next(r for r in results if r["principal_id"] == "bob")
        assert any("New source IP" in reason for reason in bob_result["anomaly_reasons"])

    def test_principals_do_not_share_event_type_history(self):
        alice = evt("CreateAccessKey", "IAMUser", "alice", "10.0.0.1", 10)
        bob = evt("CreateAccessKey", "IAMUser", "bob", "10.0.0.1", 11)
        results = score_all_events([alice, bob])
        bob_result = next(r for r in results if r["principal_id"] == "bob")
        assert any("First time" in reason for reason in bob_result["anomaly_reasons"])

    def test_large_group_of_principals_all_scored(self):
        events = [
            evt("ConsoleLogin", "IAMUser", f"user-{i}", f"10.0.0.{i}", 14)
            for i in range(20)
        ]
        results = score_all_events(events)
        assert len(results) == 20
        principal_ids = {r["principal_id"] for r in results}
        assert len(principal_ids) == 20


class TestEdgeCases:
    def test_empty_source_ip_no_new_ip_signal(self):
        e = evt("ConsoleLogin", source_ip="", principal_id="henry", hour=14)
        score, reasons = score_event_anomaly(e, seen_ips=set(), seen_event_types=set())
        assert score == SCORE_NEW_EVENT_TYPE
        assert not any("New source IP" in r for r in reasons)

    def test_events_processed_chronologically(self):
        early = evt("ConsoleLogin", source_ip="10.0.0.1", hour=8, principal_id="ivan")
        late = evt("ConsoleLogin", source_ip="10.0.0.1", hour=16, principal_id="ivan")
        results = score_all_events([late, early])
        late_result = next(r for r in results if "16:00" in r["event_time"])
        assert not any("New source IP" in r for r in late_result["anomaly_reasons"])

    def test_single_event_always_gets_new_type_and_new_ip(self):
        e = evt("CreateAccessKey", source_ip="1.2.3.4", principal_id="jane", hour=14)
        results = score_all_events([e])
        reasons = results[0]["anomaly_reasons"]
        assert any("New source IP" in r for r in reasons)
        assert any("First time" in r for r in reasons)

    def test_results_sorted_descending_by_score(self):
        events = [
            evt("ConsoleLogin", "IAMUser", "low", "10.0.0.1", 10),
            evt("ConsoleLogin", "Root", "root", "1.2.3.4", 23),
        ]
        results = score_all_events(events)
        scores = [r["anomaly_score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_anomaly_threshold_boundary(self):
        e1 = evt("ConsoleLogin", "Root", "root", "10.0.0.1", 14)
        e2 = evt("ConsoleLogin", "Root", "root", "10.0.0.1", 15)
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if "15:00" in r["event_time"])
        assert e2_result["anomaly_score"] == SCORE_ROOT_ACTIVITY
        assert e2_result["is_anomaly"] is True

    def test_score_4_is_not_anomaly(self):
        e1 = evt("ConsoleLogin", source_ip="10.0.0.1", hour=10, principal_id="k")
        e2 = evt("AttachUserPolicy", source_ip="10.0.0.1", hour=23, principal_id="k")
        results = score_all_events([e1, e2])
        e2_result = next(r for r in results if "23:00" in r["event_time"])
        assert e2_result["anomaly_score"] == 4
        assert e2_result["is_anomaly"] is False
