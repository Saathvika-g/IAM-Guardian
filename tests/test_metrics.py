from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch


async def test_metrics_requires_auth(client):
    response = await client.get("/metrics")
    assert response.status_code == 401


async def test_metrics_returns_200(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


async def test_metrics_has_required_fields(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = response.json()
    required = [
        "generated_at",
        "total_scans",
        "total_findings",
        "open_findings",
        "resolved_findings",
        "open_findings_by_severity",
        "all_findings_by_severity",
        "total_escalation_paths",
        "critical_escalation_paths",
        "total_requests",
        "requests_last_24h",
        "avg_latency_ms",
        "p95_latency_ms",
        "error_count",
        "error_rate",
        "top_endpoints",
        "total_chat_turns",
        "unique_chat_sessions",
        "total_rewrites",
        "verified_rewrites",
        "needs_review_rewrites",
    ]
    for field in required:
        assert field in data, f"Missing field: {field}"


async def test_metrics_zero_state_on_empty_db(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = response.json()
    assert data["total_scans"] == 0
    assert data["total_findings"] == 0
    assert data["open_findings"] == 0
    assert data["total_escalation_paths"] == 0
    assert data["error_rate"] == 0.0


async def test_metrics_counts_findings_after_run(client, auth_token):
    token = await auth_token()
    with patch("iam_guardian.api.routes.explain_finding", return_value="mocked"):
        await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
            headers={"Authorization": f"Bearer {token}"},
        )
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = response.json()
    assert data["total_findings"] >= 1
    assert data["total_scans"] >= 1


async def test_metrics_open_findings_by_severity_is_dict(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert isinstance(response.json()["open_findings_by_severity"], dict)


async def test_metrics_error_rate_between_0_and_1(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = response.json()
    assert 0.0 <= data["error_rate"] <= 1.0


async def test_metrics_top_endpoints_is_list(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert isinstance(response.json()["top_endpoints"], list)


async def test_metrics_latency_non_negative(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = response.json()
    assert data["avg_latency_ms"] >= 0
    assert data["p95_latency_ms"] >= 0


async def test_metrics_generated_at_is_iso(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    ts = response.json()["generated_at"]
    datetime.fromisoformat(ts)


async def test_metrics_chat_turns_after_conversation(client, auth_token):
    token = await auth_token()
    with patch(
        "iam_guardian.api.chat_routes.run_chat_agent",
        new_callable=AsyncMock,
        return_value="answer",
    ):
        await client.post(
            "/chat",
            json={"message": "hello", "session_id": "metrics-test"},
            headers={"Authorization": f"Bearer {token}"},
        )
    response = await client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = response.json()
    assert data["total_chat_turns"] >= 1
    assert data["unique_chat_sessions"] >= 1


def test_rate_limiter_key_uses_username_when_authed():
    from iam_guardian.auth import create_access_token
    from iam_guardian.core.rate_limiter import _get_user_id_for_limit

    token = create_access_token({"sub": "admin"}, timedelta(minutes=60))
    mock_request = MagicMock()
    mock_request.headers = {"Authorization": f"Bearer {token}"}
    mock_request.client.host = "127.0.0.1"

    key = _get_user_id_for_limit(mock_request)
    assert key == "user:admin"


def test_rate_limiter_key_falls_back_to_ip():
    from iam_guardian.core.rate_limiter import _get_user_id_for_limit

    mock_request = MagicMock()
    mock_request.headers = {"Authorization": ""}
    mock_request.client.host = "203.0.113.5"

    key = _get_user_id_for_limit(mock_request)
    assert key.startswith("ip:")


def test_rate_limiter_key_invalid_token_falls_back_to_ip():
    from iam_guardian.core.rate_limiter import _get_user_id_for_limit

    mock_request = MagicMock()
    mock_request.headers = {"Authorization": "Bearer not.a.valid.token"}
    mock_request.client.host = "10.0.0.1"

    key = _get_user_id_for_limit(mock_request)
    assert key.startswith("ip:")


def test_logging_config_runs_without_error():
    from iam_guardian.core.logging_config import configure_logging, get_logger

    configure_logging()
    log = get_logger("test")
    log.info("test_event", key="value")


async def test_request_has_x_request_id_header(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/health",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert "x-request-id" in response.headers


async def test_x_request_id_is_uuid(client, auth_token):
    import uuid

    token = await auth_token()
    response = await client.get(
        "/health",
        headers={"Authorization": f"Bearer {token}"},
    )
    request_id = response.headers.get("x-request-id", "")
    parsed = uuid.UUID(request_id)
    assert str(parsed) == request_id


async def test_different_requests_have_different_request_ids(client, auth_token):
    token = await auth_token()
    r1 = await client.get("/health", headers={"Authorization": f"Bearer {token}"})
    r2 = await client.get("/health", headers={"Authorization": f"Bearer {token}"})
    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]


async def test_request_log_persisted_after_request(client, auth_token):
    token = await auth_token()
    with patch("iam_guardian.api.routes.explain_finding", return_value="mocked"):
        await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
            headers={"Authorization": f"Bearer {token}"},
        )

    metrics = (
        await client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    assert metrics["total_requests"] >= 1


async def test_request_log_latency_is_positive(client, auth_token):
    token = await auth_token()
    await client.get("/health")
    metrics = (
        await client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    if metrics["total_requests"] > 0:
        assert metrics["avg_latency_ms"] >= 0
