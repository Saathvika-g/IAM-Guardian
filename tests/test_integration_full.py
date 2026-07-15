from unittest.mock import patch

EXPLAIN_PATCH = "iam_guardian.api.routes.explain_finding"
MOCK_EXPLANATION = "This is a test explanation for integration testing."


class TestFullAuditWorkflow:
    async def test_auth_flow(self, client):
        response = await client.post(
            "/auth/token",
            data={"username": "admin", "password": "guardian123"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert len(data["access_token"]) > 20

    async def test_full_audit_to_delta_workflow(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value=MOCK_EXPLANATION):
            run_a = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )
        assert run_a.status_code == 200
        scan_a_id = run_a.json()["audit_id"]
        assert len(scan_a_id) == 36

        findings_a = await client.get(
            f"/audit/findings?scan_id={scan_a_id}",
            headers=headers,
        )
        assert findings_a.status_code == 200
        findings_a_data = findings_a.json()
        assert len(findings_a_data) >= 1
        assert all(f["scan_id"] == scan_a_id for f in findings_a_data)
        assert all(f["llm_explanation"] == MOCK_EXPLANATION for f in findings_a_data)
        assert all(f["status"] == "open" for f in findings_a_data)

        severities = {f["severity"] for f in findings_a_data}
        assert "critical" in severities, f"Expected critical findings, got severities: {severities}"

        scans = await client.get("/audit/scans", headers=headers)
        assert scans.status_code == 200
        scan_a_record = next((s for s in scans.json() if s["id"] == scan_a_id), None)
        assert scan_a_record is not None, f"Scan {scan_a_id} not in /audit/scans"
        assert scan_a_record["total_findings"] == len(findings_a_data)
        assert scan_a_record["status"] == "completed"

        finding_id = findings_a_data[0]["id"]
        status_update = await client.patch(
            f"/audit/findings/{finding_id}/status",
            json={"status": "in_progress"},
            headers=headers,
        )
        assert status_update.status_code == 200
        assert status_update.json()["status"] == "in_progress"

        finding_check = await client.get(
            f"/audit/findings?scan_id={scan_a_id}",
            headers=headers,
        )
        updated = next(f for f in finding_check.json() if f["id"] == finding_id)
        assert updated["status"] == "in_progress"

        with patch(EXPLAIN_PATCH, return_value=MOCK_EXPLANATION):
            run_b = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )
        assert run_b.status_code == 200
        scan_b_id = run_b.json()["audit_id"]
        assert scan_b_id != scan_a_id

        findings_b = await client.get(
            f"/audit/findings?scan_id={scan_b_id}",
            headers=headers,
        )
        findings_b_data = findings_b.json()
        assert len(findings_b_data) >= 1
        assert all(f["scan_id"] == scan_b_id for f in findings_b_data)

        delta = await client.get(
            f"/audit/delta?scan_a={scan_a_id}&scan_b={scan_b_id}",
            headers=headers,
        )
        assert delta.status_code == 200
        delta_data = delta.json()

        assert "new_findings" in delta_data
        assert "resolved_findings" in delta_data
        assert "persisted_findings" in delta_data
        assert "regressed_findings" in delta_data
        assert "summary" in delta_data
        assert delta_data["scan_a"] == scan_a_id
        assert delta_data["scan_b"] == scan_b_id

        assert len(delta_data["new_findings"]) == 0
        assert len(delta_data["resolved_findings"]) == 0
        assert len(delta_data["persisted_findings"]) >= 1
        assert len(delta_data["regressed_findings"]) == 0

        assert "0 new" in delta_data["summary"]
        assert "0 resolved" in delta_data["summary"]
        assert "regression" in delta_data["summary"]

        all_findings = await client.get(
            "/audit/findings?limit=200",
            headers=headers,
        )
        scan_ids_in_db = {f["scan_id"] for f in all_findings.json()}
        assert scan_a_id in scan_ids_in_db
        assert scan_b_id in scan_ids_in_db

    async def test_findings_severity_filter_works(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value=MOCK_EXPLANATION):
            run = await client.post(
                "/audit/run",
                json={"account_id": "111111111111"},
                headers=headers,
            )
        scan_id = run.json()["audit_id"]

        critical_only = await client.get(
            f"/audit/findings?severity=critical&scan_id={scan_id}",
            headers=headers,
        )
        assert critical_only.status_code == 200
        for finding in critical_only.json():
            assert finding["severity"] == "critical"

    async def test_delta_404_on_invalid_scan(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value=MOCK_EXPLANATION):
            run = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )
        real_scan_id = run.json()["audit_id"]

        response = await client.get(
            f"/audit/delta?scan_a={real_scan_id}&scan_b=fake-scan-id-000",
            headers=headers,
        )
        assert response.status_code == 404

    async def test_health_always_available(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_scan_record_counts_match_findings(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value=MOCK_EXPLANATION):
            run = await client.post(
                "/audit/run",
                json={"account_id": "999999999999"},
                headers=headers,
            )
        scan_id = run.json()["audit_id"]

        findings = await client.get(
            f"/audit/findings?scan_id={scan_id}&limit=200",
            headers=headers,
        )
        actual_count = len(findings.json())

        scans = await client.get("/audit/scans", headers=headers)
        scan_record = next((s for s in scans.json() if s["id"] == scan_id), None)
        assert scan_record is not None
        assert scan_record["total_findings"] == actual_count

    async def test_status_lifecycle(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value=MOCK_EXPLANATION):
            run = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )
        scan_id = run.json()["audit_id"]
        finding_id = (
            await client.get(
                f"/audit/findings?scan_id={scan_id}",
                headers=headers,
            )
        ).json()[0]["id"]

        for status in ["in_progress", "resolved", "accepted_risk", "open"]:
            response = await client.patch(
                f"/audit/findings/{finding_id}/status",
                json={"status": status},
                headers=headers,
            )
            assert response.status_code == 200, (
                f"Status transition to {status!r} failed: {response.json()}"
            )
            assert response.json()["status"] == status

    async def test_audit_run_response_structure(self, client, auth_token):
        token = await auth_token()
        with patch(EXPLAIN_PATCH, return_value=MOCK_EXPLANATION):
            response = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers={"Authorization": f"Bearer {token}"},
            )
        data = response.json()
        assert "audit_id" in data
        assert "account_id" in data
        assert "status" in data
        assert "findings" in data
        assert "total_findings" in data
        assert "run_at" in data
        assert data["status"] == "completed"
        assert data["account_id"] == "123456789012"
        assert isinstance(data["findings"], list)
        assert data["total_findings"] == len(data["findings"])
