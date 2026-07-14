from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


def make_client_error(code: str, message: str = "test error") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "operation_name",
    )


def test_is_retryable_rate_limit():
    from groq import RateLimitError

    from iam_guardian.core.retry import _is_retryable_groq_error

    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {}
    mock_resp.text = "rate limited"
    exc = RateLimitError(message="rate limited", response=mock_resp, body=None)
    assert _is_retryable_groq_error(exc) is True


def test_is_retryable_connection_error():
    from groq import APIConnectionError

    from iam_guardian.core.retry import _is_retryable_groq_error

    exc = APIConnectionError(request=MagicMock())
    assert _is_retryable_groq_error(exc) is True


def test_is_retryable_500():
    from groq import APIStatusError

    from iam_guardian.core.retry import _is_retryable_groq_error

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.headers = {}
    exc = APIStatusError(message="server error", response=mock_resp, body=None)
    assert _is_retryable_groq_error(exc) is True


def test_is_not_retryable_400():
    from groq import APIStatusError

    from iam_guardian.core.retry import _is_retryable_groq_error

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.headers = {}
    exc = APIStatusError(message="bad request", response=mock_resp, body=None)
    assert _is_retryable_groq_error(exc) is False


def test_is_not_retryable_401():
    from groq import APIStatusError

    from iam_guardian.core.retry import _is_retryable_groq_error

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.headers = {}
    exc = APIStatusError(message="unauthorized", response=mock_resp, body=None)
    assert _is_retryable_groq_error(exc) is False


def test_is_not_retryable_generic_exception():
    from iam_guardian.core.retry import _is_retryable_groq_error

    assert _is_retryable_groq_error(ValueError("not groq")) is False
    assert _is_retryable_groq_error(RuntimeError("boom")) is False


def test_with_groq_retry_succeeds_first_attempt():
    from iam_guardian.core.retry import with_groq_retry

    call_count = {"n": 0}

    @with_groq_retry
    def succeed_immediately():
        call_count["n"] += 1
        return "ok"

    result = succeed_immediately()
    assert result == "ok"
    assert call_count["n"] == 1


def test_with_groq_retry_retries_on_rate_limit():
    from groq import RateLimitError

    from iam_guardian.core.retry import with_groq_retry

    call_count = {"n": 0}
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {}
    mock_resp.text = "rate limited"

    @with_groq_retry
    def fail_twice_then_succeed():
        call_count["n"] += 1
        if call_count["n"] < 3:
            raise RateLimitError(message="rate limited", response=mock_resp, body=None)
        return "success on attempt 3"

    with patch("tenacity.nap.time.sleep"):
        result = fail_twice_then_succeed()
    assert result == "success on attempt 3"
    assert call_count["n"] == 3


def test_with_groq_retry_gives_up_after_3_attempts():
    from groq import RateLimitError

    from iam_guardian.core.retry import with_groq_retry

    call_count = {"n": 0}
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {}
    mock_resp.text = "always rate limited"

    @with_groq_retry
    def always_fail():
        call_count["n"] += 1
        raise RateLimitError(
            message="always rate limited",
            response=mock_resp,
            body=None,
        )

    with patch("tenacity.nap.time.sleep"):
        with pytest.raises(RateLimitError):
            always_fail()
    assert call_count["n"] == 3


def test_with_groq_retry_does_not_retry_non_retryable():
    from iam_guardian.core.retry import with_groq_retry

    call_count = {"n": 0}

    @with_groq_retry
    def fail_with_value_error():
        call_count["n"] += 1
        raise ValueError("not retryable")

    with pytest.raises(ValueError):
        fail_with_value_error()
    assert call_count["n"] == 1


def test_classify_permission_error():
    from iam_guardian.core.aws_resilience import classify_client_error

    err = make_client_error("AccessDenied", "User is not authorized")
    reason, is_perm = classify_client_error(err)
    assert is_perm is True
    assert "AccessDenied" in reason
    assert "permissions" in reason.lower()


def test_classify_throttle_error():
    from iam_guardian.core.aws_resilience import classify_client_error

    err = make_client_error("ThrottlingException", "Rate exceeded")
    reason, is_perm = classify_client_error(err)
    assert is_perm is False
    assert "throttl" in reason.lower()


def test_classify_unknown_error():
    from iam_guardian.core.aws_resilience import classify_client_error

    err = make_client_error("SomeUnknownError", "Something went wrong")
    reason, is_perm = classify_client_error(err)
    assert is_perm is False
    assert "SomeUnknownError" in reason


def test_handle_client_error_returns_skipped_check():
    from iam_guardian.core.aws_resilience import SkippedCheck, handle_client_error

    err = make_client_error("AccessDenied")
    result = handle_client_error(
        err,
        check_name="list_users",
        resource_arn="arn:aws:iam::123456789012:*",
    )
    assert isinstance(result, SkippedCheck)
    assert result.check_name == "list_users"
    assert result.resource_arn == "arn:aws:iam::123456789012:*"
    assert result.is_permission_error is True
    assert result.error_code == "AccessDenied"


def test_handle_client_error_permission_flag():
    from iam_guardian.core.aws_resilience import handle_client_error

    for code in ["AccessDenied", "AccessDeniedException", "AuthFailure"]:
        result = handle_client_error(
            make_client_error(code),
            check_name="test",
            resource_arn="arn:test",
        )
        assert result.is_permission_error is True, f"Expected perm error for {code}"


def test_handle_client_error_non_permission_flag():
    from iam_guardian.core.aws_resilience import handle_client_error

    result = handle_client_error(
        make_client_error("ThrottlingException"),
        check_name="test",
        resource_arn="arn:test",
    )
    assert result.is_permission_error is False


def test_skipped_check_dataclass_fields():
    from iam_guardian.core.aws_resilience import SkippedCheck

    skipped = SkippedCheck(
        check_name="test_check",
        resource_arn="arn:aws:iam:::role/R",
        reason="Access denied",
        error_code="AccessDenied",
        is_permission_error=True,
    )
    assert skipped.check_name == "test_check"
    assert skipped.is_permission_error is True
    assert skipped.error_code == "AccessDenied"


def test_skipped_check_optional_fields_default_none():
    from iam_guardian.core.aws_resilience import SkippedCheck

    skipped = SkippedCheck(check_name="c", resource_arn="arn", reason="r")
    assert skipped.error_code is None
    assert skipped.is_permission_error is False


async def test_unhandled_exception_returns_500(client, auth_token):
    from httpx import ASGITransport, AsyncClient

    async def boom():
        raise RuntimeError("unexpected boom")

    app = client._transport.app
    before_count = len(app.router.routes)
    app.router.add_api_route("/__boom", boom, methods=["GET"])
    try:
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get("/__boom")
    finally:
        del app.router.routes[before_count:]

    assert response.status_code == 500
    data = response.json()
    assert data["error"] == "internal_server_error"
    assert "request_id" in data
    assert "traceback" not in data
    assert data["detail"] is None


async def test_404_returns_structured_json(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/nonexistent-endpoint",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
    data = response.json()
    assert data["error"] == "not_found"
    assert "request_id" in data


async def test_401_returns_structured_json(client):
    response = await client.get("/audit/findings")
    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "unauthorized"
    assert "request_id" in data


async def test_422_returns_structured_json_with_detail(client, auth_token):
    token = await auth_token()
    response = await client.post(
        "/audit/run",
        content="not json at all",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "validation_error"
    assert "request_id" in data
    assert "detail" in data
    assert data["detail"] is not None


async def test_exception_response_has_message(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/nonexistent",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = response.json()
    assert "message" in data
    assert len(data["message"]) > 0


def test_status_to_error_code_mapping():
    from iam_guardian.core.exception_handlers import _status_to_error_code

    assert _status_to_error_code(401) == "unauthorized"
    assert _status_to_error_code(403) == "forbidden"
    assert _status_to_error_code(404) == "not_found"
    assert _status_to_error_code(422) == "validation_error"
    assert _status_to_error_code(429) == "rate_limit_exceeded"
    assert _status_to_error_code(500) == "internal_server_error"
    assert _status_to_error_code(418) == "http_418"


def test_explain_finding_returns_fallback_after_retry_exhausted():
    from iam_guardian.explainer.explainer import explain_finding

    with patch(
        "iam_guardian.explainer.explainer._call_groq_explain",
        side_effect=Exception("network down"),
    ):
        result = explain_finding(
            {
                "title": "test",
                "severity": "high",
                "resource": "arn:test",
                "description": "desc",
            }
        )
    assert isinstance(result, str)
    assert "unavailable" in result.lower()


def test_explain_finding_returns_result_on_success():
    from iam_guardian.explainer.explainer import explain_finding

    with patch(
        "iam_guardian.explainer.explainer._call_groq_explain",
        return_value="This is dangerous because...",
    ):
        result = explain_finding(
            {
                "title": "test",
                "severity": "high",
                "resource": "arn:test",
                "description": "desc",
            }
        )
    assert result == "This is dangerous because..."
