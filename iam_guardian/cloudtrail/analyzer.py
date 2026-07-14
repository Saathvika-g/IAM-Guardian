from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

HIGH_WEIGHT_THRESHOLD = 5

ROOT_FLAG_EVENTS = {
    "ConsoleLogin",
    "CreateAccessKey",
    "AttachUserPolicy",
    "PutUserPolicy",
    "UpdateAssumeRolePolicy",
}


@dataclass
class PrincipalSummary:
    principal_id: str
    identity_type: str
    account_id: str
    actor_arn: str
    event_count: int = 0
    high_weight_count: int = 0
    total_score: int = 0
    events: list[dict] = field(default_factory=list)
    flagged_events: list[dict] = field(default_factory=list)
    anomaly_flags: list[str] = field(default_factory=list)


@dataclass
class CloudTrailReport:
    account_id: str
    period_days: int
    total_events: int
    watched_event_counts: dict[str, int]
    principals: list[PrincipalSummary]
    root_activity: list[dict]
    high_score_principals: list[PrincipalSummary]
    error_events: list[dict]
    report_generated_at: str


def _flag_anomalies(summary: PrincipalSummary) -> list[str]:
    flags = []

    if summary.identity_type == "Root":
        flagged_names = {event["event_name"] for event in summary.events}
        concerning = flagged_names & ROOT_FLAG_EVENTS
        if concerning:
            flags.append(
                "Root account performed sensitive action(s): "
                f"{', '.join(sorted(concerning))}"
            )

    if summary.high_weight_count >= HIGH_WEIGHT_THRESHOLD:
        flags.append(
            f"Principal performed {summary.high_weight_count} high-sensitivity "
            f"IAM actions (threshold: {HIGH_WEIGHT_THRESHOLD})"
        )

    event_names = [event["event_name"] for event in summary.events]
    if "CreateAccessKey" in event_names and "AttachUserPolicy" in event_names:
        flags.append(
            "Principal both created access keys and attached policies — "
            "possible privilege escalation activity"
        )

    if "CreateLoginProfile" in event_names and "ConsoleLogin" in event_names:
        flags.append(
            "Principal created a login profile and then logged into the console — "
            "review whether both actions were authorized"
        )

    if "CreateAccessKey" in event_names:
        targets = set()
        for event in summary.events:
            if event["event_name"] == "CreateAccessKey":
                params = event.get("request_params", {})
                target = params.get("userName", "")
                if target and target != summary.principal_id:
                    targets.add(target)
        if len(targets) >= 3:
            flags.append(
                f"Principal created access keys for {len(targets)} different users "
                f"({', '.join(sorted(targets)[:3])}...) — credential harvesting risk"
            )

    return flags


def score_events(
    events: list[dict],
    account_id: str,
    period_days: int = 90,
) -> CloudTrailReport:
    event_counts: dict[str, int] = defaultdict(int)
    for event in events:
        event_counts[event["event_name"]] += 1

    principal_map: dict[str, PrincipalSummary] = {}
    for event in events:
        principal_id = event["principal_id"]
        if principal_id not in principal_map:
            principal_map[principal_id] = PrincipalSummary(
                principal_id=principal_id,
                identity_type=event["identity_type"],
                account_id=event["account_id"],
                actor_arn=event["actor_arn"],
            )
        summary = principal_map[principal_id]
        summary.event_count += 1
        summary.total_score += event["weight"]
        if event["weight"] >= 3:
            summary.high_weight_count += 1
            summary.flagged_events.append(event)
        summary.events.append(event)

    for summary in principal_map.values():
        summary.anomaly_flags = _flag_anomalies(summary)

    root_activity = [event for event in events if event["identity_type"] == "Root"]
    all_principals = list(principal_map.values())
    high_score = sorted(
        all_principals,
        key=lambda principal: principal.total_score,
        reverse=True,
    )[:10]
    error_events = [event for event in events if event.get("error_code")]

    return CloudTrailReport(
        account_id=account_id,
        period_days=period_days,
        total_events=len(events),
        watched_event_counts=dict(event_counts),
        principals=all_principals,
        root_activity=root_activity,
        high_score_principals=high_score,
        error_events=error_events,
        report_generated_at=datetime.utcnow().isoformat(),
    )
