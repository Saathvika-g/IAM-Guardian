import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def _extract_actions(policy_doc: dict) -> list[str]:
    actions = []
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", [])
        if isinstance(action, str):
            actions.append(action)
        elif isinstance(action, list):
            actions.extend(action)
    return list(set(actions))


def _extract_resources(policy_doc: dict) -> list[str]:
    resources = []
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        resource = stmt.get("Resource", [])
        if resource == "*":
            return ["*"]
        if isinstance(resource, str):
            resources.append(resource)
        elif isinstance(resource, list):
            if "*" in resource:
                return ["*"]
            resources.extend(resource)
    return list(set(resources)) or ["*"]


def simulate_rewrite(
    original_policy: dict,
    rewritten_policy: dict,
    account_id: str,
) -> dict:
    """
    Compare what the rewritten policy allows vs the original.
    Uses boto3 simulate_custom_policy in sandbox/custom-policy mode.
    """
    try:
        original_actions = _extract_actions(original_policy)
        resources = _extract_resources(rewritten_policy)

        if not original_actions:
            return {
                "status": "simulation_unavailable",
                "original_actions": [],
                "denied_actions": [],
                "allowed_actions": [],
                "detail": "No Allow actions found in original policy to simulate.",
            }

        if "*" in original_actions:
            return {
                "status": "simulation_unavailable",
                "original_actions": original_actions,
                "denied_actions": [],
                "allowed_actions": [],
                "detail": (
                    "Original policy contains Action: *, which AWS IAM simulation "
                    "does not accept as an ActionNames value. Rewrite completed, "
                    "but simulation was skipped for the wildcard action."
                ),
            }

        iam = boto3.client("iam", region_name="us-east-1")

        policy_input_doc = __import__("json").dumps(rewritten_policy)

        denied_actions = []
        allowed_actions = []

        for action in original_actions:
            try:
                resp = iam.simulate_custom_policy(
                    PolicyInputList=[policy_input_doc],
                    ActionNames=[action],
                    ResourceArns=resources if resources != ["*"] else ["*"],
                )
                for result in resp.get("EvaluationResults", []):
                    if result["EvalDecision"] == "allowed":
                        allowed_actions.append(action)
                    else:
                        denied_actions.append(action)
            except ClientError as ce:
                error_code = ce.response["Error"]["Code"]
                if error_code in ("InvalidInput", "ValidationError"):
                    continue
                raise

        status = "needs_review" if denied_actions else "verified"
        detail = (
            f"Rewrite verified: all {len(allowed_actions)} original actions still permitted."
            if status == "verified"
            else (
                f"Rewrite needs review: {len(denied_actions)} action(s) from the original "
                f"policy are now denied — {', '.join(denied_actions[:5])}."
                f"{'...' if len(denied_actions) > 5 else ''} "
                f"Verify these are intentionally removed."
            )
        )

        return {
            "status": status,
            "original_actions": original_actions,
            "denied_actions": denied_actions,
            "allowed_actions": allowed_actions,
            "detail": detail,
        }

    except NoCredentialsError:
        return {
            "status": "simulation_unavailable",
            "original_actions": [],
            "denied_actions": [],
            "allowed_actions": [],
            "detail": (
                "AWS credentials not configured. "
                "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or run on an EC2/App Runner "
                "instance with an IAM role attached. Simulation skipped."
            ),
        }
    except Exception as e:
        print(f"[simulator] unexpected error: {e}", file=sys.stderr)
        return {
            "status": "simulation_unavailable",
            "original_actions": [],
            "denied_actions": [],
            "allowed_actions": [],
            "detail": f"Simulation error: {type(e).__name__}: {e}",
        }
