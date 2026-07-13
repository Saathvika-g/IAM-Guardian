from unittest.mock import patch

import pytest

PATCH_TARGET = "iam_guardian.api.routes.explain_finding"
REWRITE_PATCH_TARGET = "iam_guardian.api.routes.rewrite_policy"
SIMULATE_PATCH_TARGET = "iam_guardian.api.routes.simulate_rewrite"


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


@pytest.mark.asyncio
async def test_rewrite_finding_404(client, auth_token):
    token = await auth_token()

    response = await client.post(
        "/audit/rewrite/nonexistent-id-000",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_rewrite_finding_success(client, auth_token):
    token = await auth_token()

    with patch(PATCH_TARGET, return_value="mocked explanation"):
        await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
            headers={"Authorization": f"Bearer {token}"},
        )

    findings_resp = await client.get(
        "/audit/findings",
        headers={"Authorization": f"Bearer {token}"},
    )
    finding_id = findings_resp.json()[0]["id"]

    mock_sim = {
        "status": "verified",
        "original_actions": ["s3:GetObject"],
        "denied_actions": [],
        "allowed_actions": ["s3:GetObject"],
        "detail": "All actions permitted.",
    }
    with patch(
        REWRITE_PATCH_TARGET,
        return_value=(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "arn:aws:s3:::bucket/*",
                    }
                ],
            },
            "Replaced wildcard Action with s3:GetObject scoped to a specific bucket.",
        ),
    ), patch(SIMULATE_PATCH_TARGET, return_value=mock_sim):
        response = await client.post(
            f"/audit/rewrite/{finding_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert "original_policy" in data
    assert "rewritten_policy" in data
    assert "diff_summary" in data
    assert "simulation_result" in data
    assert data["rewrite_status"] == "verified"
    assert data["finding_id"] == finding_id


@pytest.mark.asyncio
async def test_rewrite_includes_simulation_result(client, auth_token):
    token = await auth_token()

    with patch(PATCH_TARGET, return_value="mocked"):
        await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
            headers={"Authorization": f"Bearer {token}"},
        )

    findings = (
        await client.get(
            "/audit/findings",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    finding_id = findings[0]["id"]

    mock_sim = {
        "status": "verified",
        "original_actions": ["s3:GetObject"],
        "denied_actions": [],
        "allowed_actions": ["s3:GetObject"],
        "detail": "All actions permitted.",
    }
    with patch(
        REWRITE_PATCH_TARGET,
        return_value=(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "arn:aws:s3:::b/*",
                    }
                ],
            },
            "Replaced wildcard with s3:GetObject.",
        ),
    ), patch(SIMULATE_PATCH_TARGET, return_value=mock_sim):
        response = await client.post(
            f"/audit/rewrite/{finding_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert "simulation_result" in data
    assert data["simulation_result"]["status"] == "verified"
    assert data["rewrite_status"] == "verified"
    assert "diff_summary" in data


@pytest.mark.asyncio
async def test_get_rewrites_empty(client, auth_token):
    token = await auth_token()

    response = await client.get(
        "/audit/rewrites",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_get_rewrites_filter_by_status(client, auth_token):
    token = await auth_token()

    response = await client.get(
        "/audit/rewrites?status=verified",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    for rewrite in response.json():
        assert rewrite["rewrite_status"] == "verified"
