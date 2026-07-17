from pathlib import Path


class TestDashboardRoute:
    async def test_root_returns_200(self, client):
        response = await client.get("/")
        assert response.status_code == 200

    async def test_root_returns_html(self, client):
        response = await client.get("/")
        content_type = response.headers.get("content-type", "")
        assert "html" in content_type.lower()

    async def test_root_contains_dashboard_markup(self, client):
        response = await client.get("/")
        body = response.text
        assert "IAM Guardian" in body or "iam guardian" in body.lower()
        assert "fetch" in body.lower()

    async def test_root_not_in_openapi_schema(self, client):
        response = await client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "/" not in schema.get("paths", {})

    async def test_root_no_auth_required(self, client):
        response = await client.get("/")
        assert response.status_code == 200

    async def test_health_still_works_alongside_dashboard(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_docs_still_works_alongside_dashboard(self, client):
        response = await client.get("/docs")
        assert response.status_code == 200


class TestDashboardFileExists:
    def test_dashboard_html_file_present(self):
        dashboard = Path("iam_guardian/static/dashboard.html")
        assert dashboard.exists(), "dashboard.html must exist at iam_guardian/static/"

    def test_dashboard_html_not_empty(self):
        dashboard = Path("iam_guardian/static/dashboard.html")
        content = dashboard.read_text()
        assert len(content) > 500, "dashboard.html seems too small to be complete"

    def test_dashboard_references_correct_endpoints(self):
        dashboard = Path("iam_guardian/static/dashboard.html")
        content = dashboard.read_text()
        assert "/metrics" in content
        assert "/audit/findings" in content
        assert "/auth/token" in content
