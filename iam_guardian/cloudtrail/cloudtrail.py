import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

WATCHED_EVENTS = {
    "CreateAccessKey",
    "DeleteAccessKey",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeleteLoginProfile",
    "UpdateAssumeRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "DeleteUserPolicy",
    "DeleteRolePolicy",
    "ConsoleLogin",
    "CreateUser",
    "DeleteUser",
    "CreateRole",
    "DeleteRole",
    "AddUserToGroup",
}

EVENT_WEIGHTS = {
    "CreateAccessKey": 3,
    "AttachUserPolicy": 4,
    "AttachRolePolicy": 4,
    "PutUserPolicy": 4,
    "PutRolePolicy": 4,
    "UpdateAssumeRolePolicy": 4,
    "CreateLoginProfile": 3,
    "UpdateLoginProfile": 3,
    "ConsoleLogin": 1,
    "CreateUser": 2,
    "DeleteUser": 3,
    "DeleteAccessKey": 2,
    "DetachUserPolicy": 2,
    "DetachRolePolicy": 2,
    "DeleteUserPolicy": 2,
    "DeleteRolePolicy": 2,
    "DeleteLoginProfile": 2,
    "CreateRole": 2,
    "DeleteRole": 3,
    "AddUserToGroup": 2,
}


def _parse_user_identity(user_identity: dict) -> dict:
    identity_type = user_identity.get("type", "Unknown")
    account_id = user_identity.get("accountId", "")
    arn = user_identity.get("arn", "")

    if identity_type == "Root":
        principal_id = "root"
    elif identity_type == "IAMUser":
        principal_id = user_identity.get("userName", "unknown-iam-user")
    elif identity_type == "AssumedRole":
        session_context = user_identity.get("sessionContext", {})
        session_issuer = session_context.get("sessionIssuer", {})
        role_name = session_issuer.get("userName", "")
        session_name = ""
        if arn:
            parts = arn.split("/")
            if len(parts) >= 3:
                session_name = parts[-1]
        principal_id = f"{role_name}/{session_name}" if session_name else role_name
    elif identity_type == "AWSService":
        principal_id = user_identity.get("invokedBy", "aws-service")
    elif identity_type == "FederatedUser":
        principal_id = user_identity.get("principalId", "federated-user")
    else:
        principal_id = user_identity.get("principalId", "unknown")

    return {
        "type": identity_type,
        "principal_id": principal_id,
        "account_id": account_id,
        "arn": arn,
        "session_name": (
            arn.split("/")[-1]
            if identity_type == "AssumedRole" and arn
            else ""
        ),
    }


def parse_event(raw_event: dict) -> dict:
    try:
        event_name = raw_event.get("EventName", "")
        event_time = raw_event.get("EventTime")
        cloud_trail_event = raw_event.get("CloudTrailEvent")

        detail = {}
        if cloud_trail_event:
            try:
                detail = json.loads(cloud_trail_event)
            except (json.JSONDecodeError, TypeError):
                detail = {}

        user_identity = detail.get("userIdentity", {})
        identity = _parse_user_identity(user_identity)

        return {
            "event_id": raw_event.get("EventId", ""),
            "event_name": event_name,
            "event_time": (
                event_time.isoformat()
                if isinstance(event_time, datetime)
                else str(event_time)
            ),
            "region": detail.get("awsRegion", ""),
            "source_ip": detail.get("sourceIPAddress", ""),
            "user_agent": detail.get("userAgent", ""),
            "error_code": detail.get("errorCode"),
            "error_message": detail.get("errorMessage"),
            "request_params": detail.get("requestParameters") or {},
            "response_elements": detail.get("responseElements") or {},
            "identity_type": identity["type"],
            "principal_id": identity["principal_id"],
            "account_id": identity["account_id"],
            "actor_arn": identity["arn"],
            "session_name": identity["session_name"],
            "weight": EVENT_WEIGHTS.get(event_name, 0),
            "raw": raw_event,
        }
    except Exception as e:
        print(f"[cloudtrail] parse error: {e}", file=sys.stderr)
        return {
            "event_id": raw_event.get("EventId", "") if isinstance(raw_event, dict) else "",
            "event_name": raw_event.get("EventName", "") if isinstance(raw_event, dict) else "",
            "event_time": str(raw_event.get("EventTime", "")) if isinstance(raw_event, dict) else "",
            "region": "",
            "source_ip": "",
            "user_agent": "",
            "error_code": None,
            "error_message": None,
            "request_params": {},
            "response_elements": {},
            "identity_type": "Unknown",
            "principal_id": "unknown",
            "account_id": "",
            "actor_arn": "",
            "session_name": "",
            "weight": 0,
            "raw": raw_event,
        }


def fetch_iam_events(
    account_id: str,
    days: int = 90,
    region: str = "us-east-1",
    max_results: int = 1000,
) -> list[dict]:
    try:
        client = boto3.client("cloudtrail", region_name=region)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        parsed_events: list[dict] = []
        next_token: Optional[str] = None
        fetched = 0

        while fetched < max_results:
            kwargs: dict = {
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventSource",
                        "AttributeValue": "iam.amazonaws.com",
                    }
                ],
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": min(50, max_results - fetched),
            }
            if next_token:
                kwargs["NextToken"] = next_token

            try:
                response = client.lookup_events(**kwargs)
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "InvalidLookupAttributesException":
                    print(f"[cloudtrail] lookup attribute error: {e}", file=sys.stderr)
                    break
                raise

            raw_events = response.get("Events", [])
            for raw in raw_events:
                if raw.get("EventName") in WATCHED_EVENTS:
                    parsed_events.append(parse_event(raw))

            fetched += len(raw_events)
            next_token = response.get("NextToken")
            if not next_token:
                break

        return parsed_events
    except NoCredentialsError:
        print("[cloudtrail] no AWS credentials configured", file=sys.stderr)
        return []
    except ClientError as e:
        print(f"[cloudtrail] ClientError: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[cloudtrail] unexpected error: {e}", file=sys.stderr)
        return []

