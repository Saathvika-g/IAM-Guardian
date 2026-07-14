from dataclasses import dataclass
from typing import Optional

from botocore.exceptions import ClientError

from iam_guardian.core.logging_config import get_logger

logger = get_logger("aws_resilience")

PERMISSION_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedAccess",
    "AuthFailure",
    "NoCredentialsError",
    "InvalidClientTokenId",
    "OptInRequired",
    "SubscriptionRequiredException",
}

TRANSIENT_ERROR_CODES = {
    "RequestExpired",
    "ServiceUnavailable",
    "ThrottlingException",
    "RequestThrottled",
    "TooManyRequestsException",
    "Throttling",
}


@dataclass
class SkippedCheck:
    """
    Internal result for AWS checks that cannot be performed.
    """

    check_name: str
    resource_arn: str
    reason: str
    error_code: Optional[str] = None
    is_permission_error: bool = False


def classify_client_error(error: ClientError) -> tuple[str, bool]:
    """
    Classify a boto3 ClientError.
    Returns (reason_string, is_permission_error).
    """
    code = error.response["Error"]["Code"]
    message = error.response["Error"].get("Message", "")

    if code in PERMISSION_ERROR_CODES:
        return (
            f"Insufficient AWS permissions ({code}): {message}. "
            f"Attach the required IAM policy to the audit role.",
            True,
        )

    if code in TRANSIENT_ERROR_CODES:
        return (
            f"AWS API throttled or temporarily unavailable ({code}): {message}.",
            False,
        )

    return (
        f"AWS ClientError ({code}): {message}.",
        False,
    )


def handle_client_error(
    error: ClientError,
    check_name: str,
    resource_arn: str,
    context: Optional[str] = None,
) -> SkippedCheck:
    """
    Convert a boto3 ClientError into a SkippedCheck and log it.
    """
    reason, is_permission = classify_client_error(error)
    code = error.response["Error"]["Code"]

    log_fn = logger.warning if is_permission else logger.error
    log_fn(
        "aws_check_skipped",
        check_name=check_name,
        resource_arn=resource_arn,
        error_code=code,
        reason=reason,
        context=context,
    )

    return SkippedCheck(
        check_name=check_name,
        resource_arn=resource_arn,
        reason=reason,
        error_code=code,
        is_permission_error=is_permission,
    )
