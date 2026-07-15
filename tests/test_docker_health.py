"""
Docker integration smoke tests.

These tests assume `docker compose up` is already running.
Run with:
  DOCKER_TEST=true pytest tests/test_docker_health.py -v

They are skipped in normal pytest runs to avoid requiring Docker in CI.
"""

import os

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("DOCKER_TEST") != "true",
    reason="Set DOCKER_TEST=true to run Docker integration tests",
)

BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")


@pytest.fixture(scope="module")
def http_client():
    """Sync httpx client pointing at the running Docker app."""
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        yield client


@pytest.fixture(scope="module")
def auth_headers(http_client):
    """Get a JWT from the running app."""
    response = http_client.post(
        "/auth/token",
        data={"username": "admin", "password": "guardian123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200, (
        f"Auth failed: {response.status_code} {response.text}"
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health_endpoint_reachable(http_client):
    """App is up and /health returns 200."""
    response = http_client.get("/health")
    assert response.status_code == 200


def test_health_response_body(http_client):
    """Health check returns expected JSON."""
    response = http_client.get("/health")
    data = response.json()
    assert data["status"] == "ok"
    assert "service" in data


def test_health_has_request_id_header(http_client):
    """Middleware is active: X-Request-ID is present on every response."""
    response = http_client.get("/health")
    assert "x-request-id" in response.headers


def test_docs_endpoint_reachable(http_client):
    """Swagger UI is served for demos."""
    response = http_client.get("/docs")
    assert response.status_code == 200


def test_auth_token_endpoint(http_client):
    """Can obtain a JWT from the running app."""
    response = http_client.post(
        "/auth/token",
        data={"username": "admin", "password": "guardian123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_invalid_credentials_rejected(http_client):
    """Wrong password returns 401."""
    response = http_client.post(
        "/auth/token",
        data={"username": "admin", "password": "wrongpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 401


def test_protected_endpoint_requires_auth(http_client):
    """Protected endpoint returns 401 without token."""
    response = http_client.get("/audit/findings")
    assert response.status_code == 401


def test_findings_endpoint_reachable(http_client, auth_headers):
    """DB is connected: /audit/findings returns 200, not 500."""
    response = http_client.get("/audit/findings", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_scans_endpoint_reachable(http_client, auth_headers):
    """/audit/scans returns 200: scans table exists and is queryable."""
    response = http_client.get("/audit/scans", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_metrics_endpoint_reachable(http_client, auth_headers):
    """/metrics returns 200: all DB queries complete without error."""
    response = http_client.get("/metrics", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_findings" in data
    assert "total_scans" in data


def test_404_returns_structured_json(http_client):
    """Global error handler is active: 404 returns structured JSON."""
    response = http_client.get("/nonexistent-endpoint")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert "request_id" in data


def test_401_returns_structured_json(http_client):
    """401 from protected endpoint returns structured JSON with request_id."""
    response = http_client.get("/audit/findings")
    data = response.json()
    assert "error" in data
    assert "request_id" in data


def test_run_audit_end_to_end(http_client, auth_headers):
    """
    Full smoke: POST /audit/run -> check response -> GET /audit/findings.
    This makes real Groq API calls and requires GROQ_API_KEY in .env.
    """
    run_response = http_client.post(
        "/audit/run",
        json={"account_id": "123456789012"},
        headers=auth_headers,
        timeout=60.0,
    )
    assert run_response.status_code == 200, (
        f"audit/run failed: {run_response.status_code} {run_response.text}"
    )

    data = run_response.json()
    assert data["status"] == "completed"
    assert data["total_findings"] >= 1
    scan_id = data["audit_id"]

    findings_response = http_client.get(
        f"/audit/findings?scan_id={scan_id}",
        headers=auth_headers,
    )
    assert findings_response.status_code == 200
    findings = findings_response.json()
    assert len(findings) >= 1
    assert all(f["scan_id"] == scan_id for f in findings)
