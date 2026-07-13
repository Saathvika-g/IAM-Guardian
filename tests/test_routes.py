from unittest.mock import patch

import pytest

PATCH_TARGET = "iam_guardian.api.routes.explain_finding"


@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "iam-guardian"


@pytest.mark.asyncio
async def test_login_success(client):
    response = await client.post(
        "/auth/token",
        data={"username": "admin", "password": "guardian123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    response = await client.post(
        "/auth/token",
        data={"username": "admin", "password": "wrong-password"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_audit_run_requires_auth(client):
    response = await client.post("/audit/run", json={"account_id": "123456789012"})

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_audit_run_stores_findings(client, auth_token):
    token = await auth_token()

    with patch(
        PATCH_TARGET,
        return_value="mocked explanation",
    ):
        response = await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["total_findings"] >= 1
    assert "audit_id" in data


@pytest.mark.asyncio
async def test_audit_findings_requires_auth(client):
    response = await client.get("/audit/findings")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_audit_findings_returns_list(client, auth_token):
    token = await auth_token()

    with patch(
        PATCH_TARGET,
        return_value="mocked explanation",
    ):
        await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
            headers={"Authorization": f"Bearer {token}"},
        )

    response = await client.get(
        "/audit/findings",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert all(item["llm_explanation"] == "mocked explanation" for item in data)


@pytest.mark.asyncio
async def test_audit_findings_filter_by_severity(client, auth_token):
    token = await auth_token()

    with patch(
        PATCH_TARGET,
        return_value="mocked explanation",
    ):
        await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
            headers={"Authorization": f"Bearer {token}"},
        )

    response = await client.get(
        "/audit/findings?severity=critical",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert all(item["severity"] == "critical" for item in data)


@pytest.mark.asyncio
async def test_audit_run_invalid_account(client, auth_token):
    token = await auth_token()

    with patch(
        PATCH_TARGET,
        return_value="mocked explanation",
    ):
        response = await client.post(
            "/audit/run",
            json={"account_id": ""},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
