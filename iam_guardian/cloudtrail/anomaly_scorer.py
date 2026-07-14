from collections import defaultdict
from datetime import datetime
from typing import Optional

ANOMALY_THRESHOLD = 5

AFTER_HOURS_START = 22
AFTER_HOURS_END = 6

SCORE_AFTER_HOURS = 2
SCORE_NEW_IP = 3
SCORE_ROOT_ACTIVITY = 5
SCORE_NEW_EVENT_TYPE = 2


def _parse_event_hour(event_time: str) -> Optional[int]:
    try:
        try:
            parsed = datetime.fromisoformat(event_time)
        except ValueError:
            parsed = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        return parsed.hour
    except Exception:
        return None


def _is_after_hours(hour: Optional[int]) -> bool:
    if hour is None:
        return False
    return hour >= AFTER_HOURS_START or hour < AFTER_HOURS_END


def score_event_anomaly(
    event: dict,
    seen_ips: set[str],
    seen_event_types: set[str],
) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    hour = _parse_event_hour(event.get("event_time", ""))
    if _is_after_hours(hour):
        score += SCORE_AFTER_HOURS
        reasons.append(
            f"Event occurred at {hour:02d}:xx UTC, outside business hours "
            f"(before 06:00 or after 22:00)"
        )

    source_ip = event.get("source_ip", "")
    if source_ip and source_ip not in seen_ips:
        score += SCORE_NEW_IP
        reasons.append(
            f"New source IP address {source_ip!r} — not previously seen "
            f"for principal {event.get('principal_id', 'unknown')!r}"
        )

    if event.get("identity_type") == "Root":
        score += SCORE_ROOT_ACTIVITY
        reasons.append(
            "Event performed by the AWS root account — root activity "
            "should be extremely rare and is a high-risk signal"
        )

    event_name = event.get("event_name", "")
    if event_name and event_name not in seen_event_types:
        score += SCORE_NEW_EVENT_TYPE
        reasons.append(
            f"First time principal {event.get('principal_id', 'unknown')!r} "
            f"has performed {event_name!r} — new behavior pattern"
        )

    return score, reasons


def score_all_events(events: list[dict]) -> list[dict]:
    try:
        sorted_events = sorted(events, key=lambda event: event.get("event_time", ""))
    except Exception:
        sorted_events = events

    principal_seen_ips: dict[str, set[str]] = defaultdict(set)
    principal_seen_event_types: dict[str, set[str]] = defaultdict(set)
    scored: list[dict] = []

    for event in sorted_events:
        principal_id = event.get("principal_id", "")
        score, reasons = score_event_anomaly(
            event,
            seen_ips=principal_seen_ips[principal_id],
            seen_event_types=principal_seen_event_types[principal_id],
        )

        source_ip = event.get("source_ip", "")
        if source_ip:
            principal_seen_ips[principal_id].add(source_ip)
        event_name = event.get("event_name", "")
        if event_name:
            principal_seen_event_types[principal_id].add(event_name)

        scored.append(
            {
                **event,
                "anomaly_score": score,
                "anomaly_reasons": reasons,
                "is_anomaly": score >= ANOMALY_THRESHOLD,
            }
        )

    return sorted(scored, key=lambda event: event["anomaly_score"], reverse=True)

