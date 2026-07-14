import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError, NoCredentialsError

from iam_guardian.cloudtrail.analyzer import (
    HIGH_WEIGHT_THRESHOLD,
    PrincipalSummary,
    _flag_anomalies,
    score_events,
)
from iam_guardian.cloudtrail.cloudtrail import (
    EVENT_WEIGHTS,
    WATCHED_EVENTS,
    _parse_user_identity,
    fetch_iam_events,
    parse_event,
)

CT_PATCH = "iam_guardian.cloudtrail.cloudtrail.boto3.client"


def make_raw_event(
    event_name="CreateAccessKey",
    identity_type="IAMUser",
    username="dev-user",
    account_id="123456789012",
    source_ip="203.0.113.10",
    error_code=None,
    request_params=None,
    arn=None,
):
    detail = {
        "awsRegion": "us-east-1",
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.0",
        "userIdentity": {
            "type": identity_type,
            "accountId": account_id,
            "arn": arn or f"arn:aws:iam::{account_id}:user/{username}",
        },
        "requestParameters": request_params or {},
        "responseElements": {},
    }
    if identity_type == "IAMUser":
        detail["userIdentity"]["userName"] = username
    if error_code:
        detail["errorCode"] = error_code
        detail["errorMessage"] = "Access denied"

    return {
        "EventId": "evt-001",
        "EventName": event_name,
        "EventTime": datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps(detail),
    }


def make_assumed_role_event(
    role_name="DevRole",
    session_name="my-session",
    account_id="123456789012",
):
    arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    detail = {
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.0.0.1",
        "userAgent": "aws-sdk-python",
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": account_id,
            "arn": arn,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "userName": role_name,
                    "arn": f"arn:aws:iam::{account_id}:role/{role_name}",
                }
            },
        },
        "requestParameters": {},
        "responseElements": {},
    }
    return {
        "EventId": "evt-role-001",
        "EventName": "AttachRolePolicy",
        "EventTime": datetime(2025, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps(detail),
    }


def make_mock_cloudtrail_client(events: list[dict], next_token=None):
    mock = MagicMock()
    response = {"Events": events}
    if next_token:
        response["NextToken"] = next_token
    mock.lookup_events.return_value = response
    return mock


def make_parsed_event(
    event_name="CreateAccessKey",
    identity_type="IAMUser",
    principal_id="dev-user",
    account_id="123456789012",
    weight=None,
    error_code=None,
    request_params=None,
):
    return {
        "event_id": "x",
        "event_name": event_name,
        "event_time": "2025-01-15T10:30:00+00:00",
        "region": "us-east-1",
        "source_ip": "10.0.0.1",
        "user_agent": "aws-cli",
        "error_code": error_code,
        "error_message": None,
        "identity_type": identity_type,
        "principal_id": principal_id,
        "account_id": account_id,
        "actor_arn": f"arn:aws:iam::{account_id}:user/{principal_id}",
        "session_name": "",
        "weight": weight if weight is not None else EVENT_WEIGHTS.get(event_name, 0),
        "request_params": request_params or {},
        "raw": {},
    }


def make_summary(events: list[dict], identity_type="IAMUser", principal_id="alice"):
    summary = PrincipalSummary(
        principal_id=principal_id,
        identity_type=identity_type,
        account_id="123456789012",
        actor_arn=f"arn:aws:iam::123456789012:user/{principal_id}",
    )
    summary.events = events
    summary.high_weight_count = sum(
        1 for event in events if event.get("weight", 0) >= 3
    )
    summary.flagged_events = [
        event for event in events if event.get("weight", 0) >= 3
    ]
    return summary


def test_parse_root_identity():
    identity = _parse_user_identity({"type": "Root", "accountId": "123456789012"})

    assert identity["type"] == "Root"
    assert identity["principal_id"] == "root"
    assert identity["account_id"] == "123456789012"


def test_parse_iam_user_identity():
    identity = _parse_user_identity(
        {
            "type": "IAMUser",
            "userName": "alice",
            "accountId": "123456789012",
            "arn": "arn:aws:iam::123456789012:user/alice",
        }
    )

    assert identity["type"] == "IAMUser"
    assert identity["principal_id"] == "alice"


def test_parse_assumed_role_identity():
    arn = "arn:aws:sts::123456789012:assumed-role/DevRole/my-session"
    identity = _parse_user_identity(
        {
            "type": "AssumedRole",
            "accountId": "123456789012",
            "arn": arn,
            "sessionContext": {
                "sessionIssuer": {
                    "userName": "DevRole",
                    "arn": "arn:aws:iam::123456789012:role/DevRole",
                }
            },
        }
    )

    assert identity["type"] == "AssumedRole"
    assert "DevRole" in identity["principal_id"]
    assert identity["session_name"] == "my-session"


def test_parse_aws_service_identity():
    identity = _parse_user_identity(
        {"type": "AWSService", "invokedBy": "cloudformation.amazonaws.com"}
    )

    assert identity["type"] == "AWSService"
    assert identity["principal_id"] == "cloudformation.amazonaws.com"


def test_parse_federated_user_identity():
    identity = _parse_user_identity(
        {"type": "FederatedUser", "principalId": "123456789012:alice"}
    )

    assert identity["type"] == "FederatedUser"
    assert identity["principal_id"] == "123456789012:alice"


def test_parse_unknown_identity_type():
    identity = _parse_user_identity({"type": "Unknown", "principalId": "x"})

    assert identity["type"] == "Unknown"


def test_parse_identity_missing_fields_no_crash():
    identity = _parse_user_identity({})

    assert identity["type"] == "Unknown"
    assert identity["principal_id"] == "unknown"


def test_parse_event_basic_fields():
    parsed = parse_event(make_raw_event())

    assert parsed["event_name"] == "CreateAccessKey"
    assert parsed["identity_type"] == "IAMUser"
    assert parsed["principal_id"] == "dev-user"
    assert parsed["region"] == "us-east-1"
    assert parsed["source_ip"] == "203.0.113.10"


def test_parse_event_time_is_isoformat():
    parsed = parse_event(make_raw_event())
    parsed_time = datetime.fromisoformat(parsed["event_time"])

    assert parsed_time.year == 2025


def test_parse_event_weight_from_map():
    parsed = parse_event(make_raw_event(event_name="AttachUserPolicy"))

    assert parsed["weight"] == EVENT_WEIGHTS["AttachUserPolicy"]


def test_parse_event_unknown_event_weight_zero():
    parsed = parse_event(make_raw_event(event_name="UnknownEvent"))

    assert parsed["weight"] == 0


def test_parse_event_error_code_captured():
    parsed = parse_event(make_raw_event(error_code="AccessDenied"))

    assert parsed["error_code"] == "AccessDenied"
    assert parsed["error_message"] == "Access denied"


def test_parse_event_no_error_is_none():
    parsed = parse_event(make_raw_event())

    assert parsed["error_code"] is None


def test_parse_event_root_identity():
    parsed = parse_event(make_raw_event(identity_type="Root", username="root"))

    assert parsed["identity_type"] == "Root"
    assert parsed["principal_id"] == "root"


def test_parse_event_assumed_role():
    parsed = parse_event(make_assumed_role_event())

    assert parsed["identity_type"] == "AssumedRole"
    assert "DevRole" in parsed["principal_id"]
    assert parsed["session_name"] == "my-session"


def test_parse_event_request_params_captured():
    parsed = parse_event(make_raw_event(request_params={"userName": "target-user"}))

    assert parsed["request_params"]["userName"] == "target-user"


def test_parse_event_raw_preserved():
    raw = make_raw_event()
    parsed = parse_event(raw)

    assert parsed["raw"] is raw


def test_parse_event_malformed_cloudtrail_json_no_crash():
    raw = {
        "EventId": "x",
        "EventName": "CreateAccessKey",
        "EventTime": datetime.now(timezone.utc),
        "CloudTrailEvent": "NOT VALID JSON {{{",
    }

    parsed = parse_event(raw)

    assert parsed["event_name"] == "CreateAccessKey"
    assert parsed["identity_type"] == "Unknown"


def test_parse_event_missing_cloudtrail_event_no_crash():
    raw = {
        "EventId": "x",
        "EventName": "CreateAccessKey",
        "EventTime": datetime.now(timezone.utc),
    }

    parsed = parse_event(raw)

    assert parsed["event_name"] == "CreateAccessKey"


def test_fetch_returns_parsed_events():
    raw = make_raw_event("CreateAccessKey")

    with patch(CT_PATCH, return_value=make_mock_cloudtrail_client([raw])):
        result = fetch_iam_events("123456789012", days=7)

    assert len(result) == 1
    assert result[0]["event_name"] == "CreateAccessKey"


def test_fetch_filters_unwatched_events():
    watched = make_raw_event("CreateAccessKey")
    unwatched = make_raw_event("ListBuckets")

    with patch(CT_PATCH, return_value=make_mock_cloudtrail_client([watched, unwatched])):
        result = fetch_iam_events("123456789012", days=7)

    assert len(result) == 1
    assert result[0]["event_name"] == "CreateAccessKey"


def test_fetch_all_watched_events_passthrough():
    events = [make_raw_event(name) for name in list(WATCHED_EVENTS)[:5]]

    with patch(CT_PATCH, return_value=make_mock_cloudtrail_client(events)):
        result = fetch_iam_events("123456789012", days=7)

    assert len(result) == 5


def test_fetch_returns_empty_on_no_credentials():
    with patch(CT_PATCH, side_effect=NoCredentialsError()):
        result = fetch_iam_events("123456789012")

    assert result == []


def test_fetch_returns_empty_on_client_error():
    error = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "lookup_events",
    )
    mock = MagicMock()
    mock.lookup_events.side_effect = error

    with patch(CT_PATCH, return_value=mock):
        result = fetch_iam_events("123456789012")

    assert result == []


def test_fetch_returns_empty_on_unexpected_error():
    with patch(CT_PATCH, side_effect=RuntimeError("boom")):
        result = fetch_iam_events("123456789012")

    assert result == []


def test_fetch_empty_trail_returns_empty():
    with patch(CT_PATCH, return_value=make_mock_cloudtrail_client([])):
        result = fetch_iam_events("123456789012")

    assert result == []


def test_fetch_passes_correct_event_source_attribute():
    mock = make_mock_cloudtrail_client([])

    with patch(CT_PATCH, return_value=mock):
        fetch_iam_events("123456789012", days=7)

    call_kwargs = mock.lookup_events.call_args[1]
    attrs = call_kwargs["LookupAttributes"]
    assert any(
        attr["AttributeKey"] == "EventSource"
        and attr["AttributeValue"] == "iam.amazonaws.com"
        for attr in attrs
    )


def test_score_empty_events():
    report = score_events([], "123456789012")

    assert report.total_events == 0
    assert report.principals == []
    assert report.root_activity == []


def test_score_groups_by_principal():
    events = [
        make_parsed_event("CreateAccessKey", principal_id="alice"),
        make_parsed_event("AttachUserPolicy", principal_id="alice"),
        make_parsed_event("CreateAccessKey", principal_id="bob"),
    ]

    report = score_events(events, "123456789012")
    principal_ids = {principal.principal_id for principal in report.principals}

    assert "alice" in principal_ids
    assert "bob" in principal_ids


def test_score_event_counts_per_principal():
    events = [make_parsed_event("CreateAccessKey", principal_id="alice")] * 3

    report = score_events(events, "123456789012")
    alice = next(principal for principal in report.principals if principal.principal_id == "alice")

    assert alice.event_count == 3


def test_score_total_score_accumulates():
    events = [
        make_parsed_event("CreateAccessKey", weight=3, principal_id="alice"),
        make_parsed_event("AttachUserPolicy", weight=4, principal_id="alice"),
    ]

    report = score_events(events, "123456789012")
    alice = next(principal for principal in report.principals if principal.principal_id == "alice")

    assert alice.total_score == 7


def test_score_root_activity_isolated():
    events = [
        make_parsed_event("ConsoleLogin", identity_type="Root", principal_id="root"),
        make_parsed_event(
            "CreateAccessKey",
            identity_type="IAMUser",
            principal_id="alice",
        ),
    ]

    report = score_events(events, "123456789012")

    assert len(report.root_activity) == 1
    assert report.root_activity[0]["identity_type"] == "Root"


def test_score_error_events_isolated():
    events = [
        make_parsed_event("CreateAccessKey", error_code="AccessDenied"),
        make_parsed_event("AttachUserPolicy", error_code=None),
    ]

    report = score_events(events, "123456789012")

    assert len(report.error_events) == 1
    assert report.error_events[0]["error_code"] == "AccessDenied"


def test_score_high_score_principals_sorted():
    events = (
        [
            make_parsed_event(
                "AttachUserPolicy",
                weight=4,
                principal_id="high-scorer",
            )
            for _ in range(5)
        ]
        + [
            make_parsed_event(
                "CreateAccessKey",
                weight=3,
                principal_id="low-scorer",
            )
        ]
    )

    report = score_events(events, "123456789012")

    assert report.high_score_principals[0].principal_id == "high-scorer"


def test_score_watched_event_counts():
    events = [
        make_parsed_event("CreateAccessKey"),
        make_parsed_event("CreateAccessKey"),
        make_parsed_event("AttachUserPolicy"),
    ]

    report = score_events(events, "123456789012")

    assert report.watched_event_counts["CreateAccessKey"] == 2
    assert report.watched_event_counts["AttachUserPolicy"] == 1


def test_score_period_days_preserved():
    report = score_events([], "123456789012", period_days=30)

    assert report.period_days == 30


def test_flag_root_sensitive_action():
    events = [
        make_parsed_event("ConsoleLogin", identity_type="Root", principal_id="root")
    ]
    summary = make_summary(events, identity_type="Root", principal_id="root")

    flags = _flag_anomalies(summary)

    assert any("Root" in flag for flag in flags)


def test_flag_high_weight_count_threshold():
    events = [
        make_parsed_event("AttachUserPolicy", weight=4)
        for _ in range(HIGH_WEIGHT_THRESHOLD)
    ]
    summary = make_summary(events)

    flags = _flag_anomalies(summary)

    assert any("high-sensitivity" in flag for flag in flags)


def test_no_flag_below_threshold():
    events = [
        make_parsed_event("AttachUserPolicy", weight=4)
        for _ in range(HIGH_WEIGHT_THRESHOLD - 1)
    ]
    summary = make_summary(events)

    flags = _flag_anomalies(summary)
    high_sensitivity_flags = [
        flag for flag in flags if "high-sensitivity" in flag
    ]

    assert len(high_sensitivity_flags) == 0


def test_flag_createaccesskey_plus_attachpolicy():
    events = [
        make_parsed_event("CreateAccessKey", weight=3),
        make_parsed_event("AttachUserPolicy", weight=4),
    ]
    summary = make_summary(events)

    flags = _flag_anomalies(summary)

    assert any("privilege escalation" in flag for flag in flags)


def test_flag_createloginprofile_plus_consolelogin():
    events = [
        make_parsed_event("CreateLoginProfile", weight=3),
        make_parsed_event("ConsoleLogin", weight=1),
    ]
    summary = make_summary(events)

    flags = _flag_anomalies(summary)

    assert any("login profile" in flag.lower() for flag in flags)


def test_flag_createaccesskey_multiple_targets():
    events = [
        make_parsed_event(
            "CreateAccessKey",
            weight=3,
            request_params={"userName": f"victim-{index}"},
        )
        for index in range(3)
    ]
    summary = make_summary(events)

    flags = _flag_anomalies(summary)

    assert any("credential harvesting" in flag for flag in flags)


def test_no_anomaly_flags_for_safe_principal():
    events = [make_parsed_event("ConsoleLogin", weight=1)]
    summary = make_summary(events)

    flags = _flag_anomalies(summary)

    assert flags == []


async def test_cloudtrail_endpoint_no_credentials(client, auth_token):
    token = await auth_token()

    with patch("iam_guardian.api.routes.fetch_iam_events", return_value=[]):
        response = await client.get(
            "/audit/cloudtrail?account_id=123456789012&days=7",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] == 0
    assert data["principals"] == []
    assert data["root_activity"] == []


async def test_cloudtrail_endpoint_with_events(client, auth_token):
    token = await auth_token()
    mock_events = [
        {
            "event_id": "e1",
            "event_name": "CreateAccessKey",
            "event_time": "2025-01-15T10:00:00",
            "region": "us-east-1",
            "source_ip": "10.0.0.1",
            "user_agent": "aws-cli",
            "error_code": None,
            "error_message": None,
            "identity_type": "IAMUser",
            "principal_id": "alice",
            "account_id": "123456789012",
            "actor_arn": "arn:aws:iam::123456789012:user/alice",
            "session_name": "",
            "weight": 3,
            "request_params": {},
            "raw": {},
        }
    ]

    with patch("iam_guardian.api.routes.fetch_iam_events", return_value=mock_events):
        response = await client.get(
            "/audit/cloudtrail?account_id=123456789012&days=7",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] == 1
    assert len(data["principals"]) == 1
    assert data["principals"][0]["principal_id"] == "alice"
    assert data["watched_event_counts"]["CreateAccessKey"] == 1


async def test_cloudtrail_endpoint_requires_auth(client):
    response = await client.get("/audit/cloudtrail")

    assert response.status_code == 401


async def test_cloudtrail_endpoint_root_activity_separated(client, auth_token):
    token = await auth_token()
    mock_events = [
        {
            "event_id": "r1",
            "event_name": "ConsoleLogin",
            "event_time": "2025-01-15T10:00:00",
            "region": "us-east-1",
            "source_ip": "1.2.3.4",
            "user_agent": "browser",
            "error_code": None,
            "error_message": None,
            "identity_type": "Root",
            "principal_id": "root",
            "account_id": "123456789012",
            "actor_arn": "arn:aws:iam::123456789012:root",
            "session_name": "",
            "weight": 1,
            "request_params": {},
            "raw": {},
        }
    ]

    with patch("iam_guardian.api.routes.fetch_iam_events", return_value=mock_events):
        response = await client.get(
            "/audit/cloudtrail?account_id=123456789012",
            headers={"Authorization": f"Bearer {token}"},
        )

    data = response.json()
    assert len(data["root_activity"]) == 1
    assert data["root_activity"][0]["identity_type"] == "Root"


async def test_cloudtrail_endpoint_error_events_separated(client, auth_token):
    token = await auth_token()
    mock_events = [
        {
            "event_id": "e1",
            "event_name": "CreateAccessKey",
            "event_time": "2025-01-15T10:00:00",
            "region": "us-east-1",
            "source_ip": "1.2.3.4",
            "user_agent": "aws-cli",
            "error_code": "AccessDenied",
            "error_message": "User is not authorized",
            "identity_type": "IAMUser",
            "principal_id": "attacker",
            "account_id": "123456789012",
            "actor_arn": "arn:aws:iam::123456789012:user/attacker",
            "session_name": "",
            "weight": 3,
            "request_params": {},
            "raw": {},
        }
    ]

    with patch("iam_guardian.api.routes.fetch_iam_events", return_value=mock_events):
        response = await client.get(
            "/audit/cloudtrail?account_id=123456789012",
            headers={"Authorization": f"Bearer {token}"},
        )

    data = response.json()
    assert len(data["error_events"]) == 1
    assert data["error_events"][0]["error_code"] == "AccessDenied"
