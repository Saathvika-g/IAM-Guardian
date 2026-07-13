from unittest.mock import patch

import pytest

from iam_guardian.models import ComplianceReport, ControlResult, FrameworkSection

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


@pytest.mark.asyncio
async def test_escalation_paths_no_credentials(client, auth_token):
    token = await auth_token()

    with patch(
        "iam_guardian.api.routes.enumerate_escalation_paths",
        return_value=[],
    ):
        response = await client.get(
            "/audit/escalation-paths?account_id=123456789012",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["total_paths"] == 0
    assert data["paths"] == []


@pytest.mark.asyncio
async def test_escalation_paths_with_findings(client, auth_token):
    token = await auth_token()
    mock_paths = [
        {
            "principal_arn": "arn:aws:iam::123456789012:role/DevRole",
            "principal_type": "role",
            "principal_name": "DevRole",
            "matched_combo": ["iam:passrole", "lambda:createfunction"],
            "effective_permissions": ["iam:passrole", "lambda:createfunction"],
            "severity": "critical",
            "title": "Privilege escalation: iam:PassRole + lambda:CreateFunction",
            "description": "Can attach admin role to Lambda.",
            "attack_story": "Attacker creates Lambda.",
            "tags": ["privilege-escalation", "MITRE-T1098"],
            "narrative": "",
        }
    ]

    with patch(
        "iam_guardian.api.routes.enumerate_escalation_paths",
        return_value=mock_paths,
    ), patch(
        "iam_guardian.api.routes.generate_narratives_batch",
        side_effect=lambda paths: [
            {**path, "narrative": "Mocked narrative."} for path in paths
        ],
    ):
        response = await client.get(
            "/audit/escalation-paths?account_id=123456789012",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["total_paths"] == 1
    assert data["critical_count"] == 1
    assert data["paths"][0]["narrative"] == "Mocked narrative."
    assert data["paths"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_escalation_paths_requires_auth(client):
    response = await client.get("/audit/escalation-paths")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_escalation_paths_sorted_critical_first(client, auth_token):
    token = await auth_token()
    mock_paths = [
        {
            **_base_path(),
            "severity": "high",
            "title": "High path",
            "matched_combo": ["iam:createaccesskey"],
            "narrative": "",
        },
        {
            **_base_path(),
            "severity": "critical",
            "title": "Critical path",
            "matched_combo": ["iam:passrole", "lambda:createfunction"],
            "narrative": "",
        },
    ]

    with patch(
        "iam_guardian.api.routes.enumerate_escalation_paths",
        return_value=mock_paths,
    ), patch(
        "iam_guardian.api.routes.generate_narratives_batch",
        side_effect=lambda paths: [{**path, "narrative": "n"} for path in paths],
    ):
        response = await client.get(
            "/audit/escalation-paths?account_id=123456789012",
            headers={"Authorization": f"Bearer {token}"},
        )

    data = response.json()
    assert data["paths"][0]["severity"] == "critical"
    assert data["paths"][1]["severity"] == "high"


def _base_path():
    return {
        "principal_arn": "arn:aws:iam::123456789012:role/R",
        "principal_type": "role",
        "principal_name": "R",
        "effective_permissions": ["iam:passrole"],
        "description": "desc",
        "attack_story": "story",
        "tags": [],
    }


@pytest.mark.asyncio
async def test_compliance_report_requires_auth(client):
    response = await client.get("/audit/compliance-report")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_compliance_report_empty_db(client, auth_token):
    token = await auth_token()

    with patch(
        "iam_guardian.api.routes.build_compliance_report",
        return_value=ComplianceReport(
            account_id="123456789012",
            report_id="test-report-id",
            generated_at="2025-01-15T00:00:00",
            total_findings_analyzed=0,
            frameworks=[],
            overall_pass_rate=1.0,
        ),
    ):
        response = await client.get(
            "/audit/compliance-report?account_id=123456789012",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["overall_pass_rate"] == 1.0
    assert data["total_findings_analyzed"] == 0


@pytest.mark.asyncio
async def test_compliance_report_with_findings(client, auth_token):
    token = await auth_token()

    with patch(PATCH_TARGET, return_value="mocked"):
        await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
            headers={"Authorization": f"Bearer {token}"},
        )

    mock_report = ComplianceReport(
        account_id="123456789012",
        report_id="abc-123",
        generated_at="2025-01-15T00:00:00",
        total_findings_analyzed=3,
        frameworks=[
            FrameworkSection(
                framework="CIS",
                total_controls=5,
                passing_controls=3,
                failing_controls=2,
                pass_rate=0.6,
                controls=[
                    ControlResult(
                        control_id="CIS-1.16",
                        control_title="Ensure IAM policies...",
                        status="fail",
                        finding_count=2,
                        findings=["Overly permissive IAM policy: wildcard Action"],
                    )
                ],
                executive_summary=(
                    "Two CIS controls are failing. Remediate CIS-1.16 immediately."
                ),
            )
        ],
        overall_pass_rate=0.6,
    )

    with patch(
        "iam_guardian.api.routes.build_compliance_report",
        return_value=mock_report,
    ):
        response = await client.get(
            "/audit/compliance-report?account_id=123456789012",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["total_findings_analyzed"] == 3
    assert len(data["frameworks"]) == 1
    assert data["frameworks"][0]["framework"] == "CIS"
    assert data["frameworks"][0]["pass_rate"] == 0.6
    assert "executive_summary" in data["frameworks"][0]
    assert data["overall_pass_rate"] == 0.6
