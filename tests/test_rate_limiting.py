from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

EXPLAIN_PATCH = "iam_guardian.api.routes.explain_finding"
CHAT_AGENT_PATCH = "iam_guardian.api.chat_routes.run_chat_agent"


def make_token_for_user(username: str) -> str:
    """Create a JWT for a unique username to get an isolated rate limit bucket."""
    from iam_guardian.auth import FAKE_USERS, create_access_token

    FAKE_USERS.setdefault(
        username,
        {
            "username": username,
            "hashed_password": FAKE_USERS["admin"]["hashed_password"],
            "role": "admin",
        },
    )
    return create_access_token({"sub": username}, timedelta(hours=1))


class TestAuditRunRateLimit:
    async def test_fifth_request_succeeds(self, client):
        username = "ratelimit-user-5"
        token = make_token_for_user(username)
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            for i in range(5):
                response = await client.post(
                    "/audit/run",
                    json={"account_id": "123456789012"},
                    headers=headers,
                )
                assert response.status_code == 200, (
                    f"Request {i + 1} should succeed, got {response.status_code}"
                )

    async def test_sixth_request_returns_429(self, client):
        username = "ratelimit-user-6th"
        token = make_token_for_user(username)
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            for i in range(5):
                response = await client.post(
                    "/audit/run",
                    json={"account_id": "123456789012"},
                    headers=headers,
                )
                assert response.status_code == 200, f"Setup request {i + 1} failed"

            sixth = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )
        assert sixth.status_code == 429

    async def test_rate_limit_per_user_not_global(self, client):
        user_a_token = make_token_for_user("ratelimit-user-a-isolated")
        user_b_token = make_token_for_user("ratelimit-user-b-isolated")

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            for _ in range(5):
                response = await client.post(
                    "/audit/run",
                    json={"account_id": "123456789012"},
                    headers={"Authorization": f"Bearer {user_a_token}"},
                )
                assert response.status_code == 200

            user_b_response = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers={"Authorization": f"Bearer {user_b_token}"},
            )
        assert user_b_response.status_code == 200

    async def test_rate_limit_response_body(self, client):
        username = "ratelimit-body-test"
        token = make_token_for_user(username)
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            for _ in range(5):
                await client.post(
                    "/audit/run",
                    json={"account_id": "123456789012"},
                    headers=headers,
                )
            sixth = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )
        assert sixth.status_code == 429
        assert len(sixth.content) > 0

    async def test_unauthenticated_requests_use_ip_bucket(self, client):
        response = await client.post(
            "/audit/run",
            json={"account_id": "123456789012"},
        )
        assert response.status_code == 401


class TestChatRateLimit:
    async def test_twentieth_chat_request_succeeds(self, client):
        username = "chat-ratelimit-20"
        token = make_token_for_user(username)
        headers = {"Authorization": f"Bearer {token}"}

        with patch(CHAT_AGENT_PATCH, new_callable=AsyncMock, return_value="ok"):
            for i in range(20):
                response = await client.post(
                    "/chat",
                    json={"message": f"question {i}", "session_id": "rl-chat"},
                    headers=headers,
                )
                assert response.status_code == 200, (
                    f"Chat request {i + 1} should succeed, got {response.status_code}"
                )

    async def test_twenty_first_chat_returns_429(self, client):
        username = "chat-ratelimit-21st"
        token = make_token_for_user(username)
        headers = {"Authorization": f"Bearer {token}"}

        with patch(CHAT_AGENT_PATCH, new_callable=AsyncMock, return_value="ok"):
            for i in range(20):
                response = await client.post(
                    "/chat",
                    json={"message": f"q{i}", "session_id": "rl-21"},
                    headers=headers,
                )
                assert response.status_code == 200

            twenty_first = await client.post(
                "/chat",
                json={"message": "one too many", "session_id": "rl-21"},
                headers=headers,
            )
        assert twenty_first.status_code == 429

    async def test_chat_and_audit_limits_independent(self, client):
        username = "limits-independent-user"
        token = make_token_for_user(username)
        headers = {"Authorization": f"Bearer {token}"}

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            for _ in range(3):
                response = await client.post(
                    "/audit/run",
                    json={"account_id": "123456789012"},
                    headers=headers,
                )
                assert response.status_code == 200

        with patch(CHAT_AGENT_PATCH, new_callable=AsyncMock, return_value="ok"):
            for i in range(20):
                await client.post(
                    "/chat",
                    json={"message": f"q{i}", "session_id": "limit-test"},
                    headers=headers,
                )

        with patch(EXPLAIN_PATCH, return_value="mocked"):
            response = await client.post(
                "/audit/run",
                json={"account_id": "123456789012"},
                headers=headers,
            )
        assert response.status_code == 200


class TestRateLimiterKeyFunction:
    def test_authenticated_user_gets_user_key(self):
        from iam_guardian.auth import create_access_token
        from iam_guardian.core.rate_limiter import _get_user_id_for_limit

        token = create_access_token({"sub": "testuser"}, timedelta(minutes=60))
        mock_request = MagicMock()
        mock_request.headers = {"Authorization": f"Bearer {token}"}
        mock_request.client.host = "127.0.0.1"
        mock_request.app.dependency_overrides = {}

        key = _get_user_id_for_limit(mock_request)
        assert key == "user:testuser"

    def test_unauthenticated_gets_ip_key(self):
        from iam_guardian.core.rate_limiter import _get_user_id_for_limit

        mock_request = MagicMock()
        mock_request.headers = {"Authorization": ""}
        mock_request.client.host = "10.0.0.5"
        mock_request.app.dependency_overrides = {}

        key = _get_user_id_for_limit(mock_request)
        assert key.startswith("ip:")

    def test_bearer_prefix_without_token_falls_back_to_ip(self):
        from iam_guardian.core.rate_limiter import _get_user_id_for_limit

        mock_request = MagicMock()
        mock_request.headers = {"Authorization": "Bearer "}
        mock_request.client.host = "10.0.0.5"
        mock_request.app.dependency_overrides = {}

        key = _get_user_id_for_limit(mock_request)
        assert key.startswith("ip:")

    def test_different_users_get_different_keys(self):
        from iam_guardian.auth import create_access_token
        from iam_guardian.core.rate_limiter import _get_user_id_for_limit

        token_a = create_access_token({"sub": "alice"}, timedelta(minutes=60))
        token_b = create_access_token({"sub": "bob"}, timedelta(minutes=60))

        request_a = MagicMock()
        request_a.headers = {"Authorization": f"Bearer {token_a}"}
        request_a.client.host = "127.0.0.1"
        request_a.app.dependency_overrides = {}

        request_b = MagicMock()
        request_b.headers = {"Authorization": f"Bearer {token_b}"}
        request_b.client.host = "127.0.0.1"
        request_b.app.dependency_overrides = {}

        assert _get_user_id_for_limit(request_a) != _get_user_id_for_limit(request_b)
