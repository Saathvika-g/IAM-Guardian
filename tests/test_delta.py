from unittest.mock import patch

import pytest
from sqlalchemy import select

from iam_guardian.db_models import FindingORM

PATCH_TARGET = "iam_guardian.api.routes.explain_finding"


async def _run_audit(client, token, account_id="123456789012"):
    with patch(PATCH_TARGET, return_value="mocked explanation"):
        response = await client.post(
            "/audit/run",
            json={"account_id": account_id},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    return response.json()["audit_id"]


@pytest.mark.asyncio
async def test_list_scans_empty(client, auth_token):
    token = await auth_token()

    response = await client.get(
        "/audit/scans",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_scans_list_records(client, auth_token):
    token = await auth_token()
    scan_id = await _run_audit(client, token)

    response = await client.get(
        "/audit/scans",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    scans = response.json()
    assert any(scan["id"] == scan_id for scan in scans)
    assert all("total_findings" in scan for scan in scans)


@pytest.mark.asyncio
async def test_scans_filter_by_account_id(client, auth_token):
    token = await auth_token()
    await _run_audit(client, token, account_id="123456789012")

    response = await client.get(
        "/audit/scans?account_id=123456789012",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert len(response.json()) >= 1
    assert all(scan["account_id"] == "123456789012" for scan in response.json())


@pytest.mark.asyncio
async def test_list_scans_requires_auth(client):
    response = await client.get("/audit/scans")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_status_update_success(client, auth_token):
    token = await auth_token()
    scan_id = await _run_audit(client, token)

    findings_response = await client.get(
        f"/audit/findings?scan_id={scan_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    finding_id = findings_response.json()[0]["id"]

    response = await client.patch(
        f"/audit/findings/{finding_id}/status",
        json={"status": "in_progress"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == finding_id
    assert response.json()["status"] == "in_progress"


@pytest.mark.asyncio
async def test_status_update_rejects_invalid_status(client, auth_token):
    token = await auth_token()
    scan_id = await _run_audit(client, token)

    findings_response = await client.get(
        f"/audit/findings?scan_id={scan_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    finding_id = findings_response.json()[0]["id"]

    response = await client.patch(
        f"/audit/findings/{finding_id}/status",
        json={"status": "closed"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_status_update_404(client, auth_token):
    token = await auth_token()

    response = await client.patch(
        "/audit/findings/nonexistent-id/status",
        json={"status": "resolved"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_status_update_requires_auth(client):
    response = await client.patch(
        "/audit/findings/some-id/status",
        json={"status": "resolved"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delta_requires_auth(client):
    response = await client.get("/audit/delta?scan_a=a&scan_b=b")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delta_between_identical_mock_scans(client, auth_token):
    token = await auth_token()
    scan_a = await _run_audit(client, token)
    scan_b = await _run_audit(client, token)

    response = await client.get(
        f"/audit/delta?scan_a={scan_a}&scan_b={scan_b}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["scan_a"] == scan_a
    assert data["scan_b"] == scan_b
    assert data["new_findings"] == []
    assert data["resolved_findings"] == []
    assert len(data["persisted_findings"]) >= 1
    assert data["regressed_findings"] == []
    assert data["summary"] == "0 new, 0 resolved, 0 regression(s)"


@pytest.mark.asyncio
async def test_delta_detects_new_finding(client, auth_token, db_session):
    token = await auth_token()
    scan_a = await _run_audit(client, token)
    scan_b = await _run_audit(client, token)

    result = await db_session.execute(
        select(FindingORM).where(FindingORM.scan_id == scan_b)
    )
    finding = result.scalars().first()
    finding.check_name = "New finding only in scan B"
    await db_session.commit()

    response = await client.get(
        f"/audit/delta?scan_a={scan_a}&scan_b={scan_b}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert any(
        item["check_name"] == "New finding only in scan B"
        for item in data["new_findings"]
    )
    assert "new" in data["summary"]


@pytest.mark.asyncio
async def test_delta_detects_regressed_severity(client, auth_token, db_session):
    token = await auth_token()
    scan_a = await _run_audit(client, token)
    scan_b = await _run_audit(client, token)

    result = await db_session.execute(
        select(FindingORM).where(FindingORM.scan_id == scan_a)
    )
    finding_a = result.scalars().first()

    result = await db_session.execute(
        select(FindingORM).where(
            FindingORM.scan_id == scan_b,
            FindingORM.check_name == finding_a.check_name,
            FindingORM.resource_arn == finding_a.resource_arn,
        )
    )
    finding_b = result.scalars().first()

    finding_a.severity = "low"
    finding_b.severity = "critical"
    await db_session.commit()

    response = await client.get(
        f"/audit/delta?scan_a={scan_a}&scan_b={scan_b}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert any(
        item["check_name"] == finding_b.check_name
        for item in response.json()["regressed_findings"]
    )


@pytest.mark.asyncio
async def test_delta_404_for_missing_scan(client, auth_token):
    token = await auth_token()
    scan_id = await _run_audit(client, token)

    response = await client.get(
        f"/audit/delta?scan_a={scan_id}&scan_b=missing-scan",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delta_response_shape(client, auth_token):
    token = await auth_token()
    scan_a = await _run_audit(client, token)
    scan_b = await _run_audit(client, token)

    response = await client.get(
        f"/audit/delta?scan_a={scan_a}&scan_b={scan_b}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "new_findings" in data
    assert "resolved_findings" in data
    assert "persisted_findings" in data
    assert "regressed_findings" in data
    assert "summary" in data
    assert isinstance(data["new_findings"], list)
    assert isinstance(data["summary"], str)


@pytest.mark.asyncio
async def test_delta_summary_format(client, auth_token):
    token = await auth_token()
    scan_a = await _run_audit(client, token)
    scan_b = await _run_audit(client, token)

    response = await client.get(
        f"/audit/delta?scan_a={scan_a}&scan_b={scan_b}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    summary = response.json()["summary"]
    assert "new" in summary
    assert "resolved" in summary
    assert "regression" in summary


@pytest.mark.asyncio
async def test_status_update_all_valid_values(client, auth_token):
    token = await auth_token()
    scan_id = await _run_audit(client, token)

    findings_response = await client.get(
        f"/audit/findings?scan_id={scan_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    finding_id = findings_response.json()[0]["id"]

    for status in ["in_progress", "resolved", "accepted_risk", "open"]:
        response = await client.patch(
            f"/audit/findings/{finding_id}/status",
            json={"status": status},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == status


@pytest.mark.asyncio
async def test_delta_finding_fields(client, auth_token):
    token = await auth_token()
    scan_a = await _run_audit(client, token)
    scan_b = await _run_audit(client, token)

    response = await client.get(
        f"/audit/delta?scan_a={scan_a}&scan_b={scan_b}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    if data["persisted_findings"]:
        finding = data["persisted_findings"][0]
        assert "id" in finding
        assert "scan_id" in finding
        assert "check_name" in finding
        assert "severity" in finding
        assert "resource_arn" in finding
        assert "status" in finding
        assert "created_at" in finding
