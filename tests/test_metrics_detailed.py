from unittest.mock import AsyncMock, patch

EXPLAIN_PATCH = "iam_guardian.api.routes.explain_finding"


class TestMetricsAggregation:
    async def test_metrics_reflects_multiple_scans(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            for _ in range(3):
                response = await client.post(
                    "/audit/run",
                    json={"account_id": "123456789012"},
                    headers=headers,
                )
                assert response.status_code == 200

        metrics = (await client.get("/metrics", headers=headers)).json()
        assert metrics["total_scans"] == 3
        assert metrics["total_findings"] >= 3

    async def test_metrics_severity_breakdown_sums_correctly(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )

        metrics = (await client.get("/metrics", headers=headers)).json()
        severity_sum = sum(metrics["all_findings_by_severity"].values())
        assert severity_sum == metrics["total_findings"]

    async def test_metrics_open_count_matches_severity_breakdown(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )

        metrics = (await client.get("/metrics", headers=headers)).json()
        open_sum = sum(metrics["open_findings_by_severity"].values())
        assert open_sum == metrics["open_findings"]

    async def test_metrics_resolved_findings_tracked(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )

        findings = (await client.get("/audit/findings", headers=headers)).json()
        finding_id = findings[0]["id"]
        await client.patch(
            f"/audit/findings/{finding_id}/status",
            json={"status": "resolved"},
            headers=headers,
        )

        metrics = (await client.get("/metrics", headers=headers)).json()
        assert metrics["resolved_findings"] >= 1
        assert metrics["open_findings"] == (
            metrics["total_findings"] - metrics["resolved_findings"]
        )

    async def test_metrics_error_rate_calculation(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        await client.get("/nonexistent-xyz", headers=headers)

        metrics = (await client.get("/metrics", headers=headers)).json()
        assert 0.0 <= metrics["error_rate"] <= 1.0
        assert metrics["error_count"] >= 0

    async def test_metrics_top_endpoints_structure(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        for _ in range(3):
            await client.get("/audit/findings", headers=headers)

        metrics = (await client.get("/metrics", headers=headers)).json()
        assert isinstance(metrics["top_endpoints"], list)
        if metrics["top_endpoints"]:
            endpoint = metrics["top_endpoints"][0]
            assert "endpoint" in endpoint
            assert "count" in endpoint
            assert "avg_latency" in endpoint

    async def test_metrics_rewrite_counts(self, client, auth_token):
        token = await auth_token()
        metrics = (
            await client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
        ).json()
        assert "total_rewrites" in metrics
        assert "verified_rewrites" in metrics
        assert "needs_review_rewrites" in metrics
        assert metrics["total_rewrites"] >= 0

    async def test_metrics_chat_counts(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}

        with patch(
            "iam_guardian.api.chat_routes.run_chat_agent",
            new_callable=AsyncMock,
            return_value="answer",
        ):
            await client.post(
                "/chat",
                json={"message": "test", "session_id": "metrics-chat"},
                headers=headers,
            )

        metrics = (await client.get("/metrics", headers=headers)).json()
        assert metrics["total_chat_turns"] >= 1
        assert metrics["unique_chat_sessions"] >= 1

    async def test_metrics_latency_fields_present(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}
        await client.get("/audit/findings", headers=headers)

        metrics = (await client.get("/metrics", headers=headers)).json()
        assert "avg_latency_ms" in metrics
        assert "p95_latency_ms" in metrics
        assert metrics["avg_latency_ms"] >= 0
        assert metrics["p95_latency_ms"] >= 0

    async def test_metrics_requests_24h_bounded(self, client, auth_token):
        token = await auth_token()
        headers = {"Authorization": f"Bearer {token}"}
        await client.get("/audit/findings", headers=headers)

        metrics = (await client.get("/metrics", headers=headers)).json()
        assert metrics["requests_last_24h"] <= metrics["total_requests"]


class TestMetricsEmptyState:
    async def test_all_zeros_on_empty_db(self, client, auth_token):
        token = await auth_token()
        metrics = (
            await client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
        ).json()
        assert metrics["total_scans"] == 0
        assert metrics["total_findings"] == 0
        assert metrics["total_escalation_paths"] == 0
        assert metrics["error_rate"] == 0.0
        assert metrics["latest_scan_at"] is None

    async def test_empty_severity_dicts(self, client, auth_token):
        token = await auth_token()
        metrics = (
            await client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
        ).json()
        assert isinstance(metrics["open_findings_by_severity"], dict)
        assert isinstance(metrics["all_findings_by_severity"], dict)
