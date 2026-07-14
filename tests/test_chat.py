import json
from unittest.mock import AsyncMock, patch

AGENT_PATCH = "iam_guardian.api.chat_routes.run_chat_agent"


async def test_chat_requires_auth(client):
    response = await client.post("/chat", json={"message": "hello", "session_id": "s1"})
    assert response.status_code == 401


async def test_chat_basic_response(client, auth_token):
    token = await auth_token()
    with patch(
        AGENT_PATCH,
        new_callable=AsyncMock,
        return_value="There are 3 HIGH findings.",
    ):
        response = await client.post(
            "/chat",
            json={"message": "what high findings exist?", "session_id": "test-session"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["response"] == "There are 3 HIGH findings."
    assert data["session_id"] == "test-session"
    assert data["message"] == "what high findings exist?"
    assert data["username"] == "admin"
    assert "turn_number" in data


async def test_chat_empty_message_rejected(client, auth_token):
    token = await auth_token()
    response = await client.post(
        "/chat",
        json={"message": "   ", "session_id": "s1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


async def test_chat_default_session_id(client, auth_token):
    token = await auth_token()
    with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="Hello!"):
        response = await client.post(
            "/chat",
            json={"message": "hello"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    assert response.json()["session_id"] == "default"


async def test_chat_agent_error_returns_200(client, auth_token):
    token = await auth_token()
    with patch(
        AGENT_PATCH,
        new_callable=AsyncMock,
        return_value="I encountered an error: TimeoutError",
    ):
        response = await client.post(
            "/chat",
            json={"message": "test", "session_id": "s1"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    assert "error" in response.json()["response"].lower()


async def test_chat_different_sessions_independent(client, auth_token):
    token = await auth_token()
    responses = ["Response for session A.", "Response for session B."]
    call_count = {"n": 0}

    async def side_effect(*args, **kwargs):
        response = responses[call_count["n"] % 2]
        call_count["n"] += 1
        return response

    with patch(AGENT_PATCH, side_effect=side_effect):
        r1 = await client.post(
            "/chat",
            json={"message": "question", "session_id": "session-A"},
            headers={"Authorization": f"Bearer {token}"},
        )
        r2 = await client.post(
            "/chat",
            json={"message": "question", "session_id": "session-B"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r1.json()["response"] != r2.json()["response"]


async def test_chat_turn_number_increments(client, auth_token):
    token = await auth_token()
    with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="Answer 1."):
        r1 = await client.post(
            "/chat",
            json={"message": "q1", "session_id": "count-session"},
            headers={"Authorization": f"Bearer {token}"},
        )
    with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="Answer 2."):
        r2 = await client.post(
            "/chat",
            json={"message": "q2", "session_id": "count-session"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r2.json()["turn_number"] > r1.json()["turn_number"]


async def test_get_history_requires_auth(client):
    response = await client.get("/chat/history/my-session")
    assert response.status_code == 401


async def test_get_history_empty(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/chat/history/nonexistent-session",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json() == []


async def test_get_history_after_chat(client, auth_token):
    token = await auth_token()
    session_id = "history-test-session"

    with patch(
        AGENT_PATCH,
        new_callable=AsyncMock,
        return_value="I found 2 findings.",
    ):
        await client.post(
            "/chat",
            json={"message": "how many findings?", "session_id": session_id},
            headers={"Authorization": f"Bearer {token}"},
        )

    response = await client.get(
        f"/chat/history/{session_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    history = response.json()
    assert len(history) == 2
    roles = [h["role"] for h in history]
    assert "user" in roles
    assert "assistant" in roles


def _find_by_role(history, role):
    return next((h for h in history if h["role"] == role), None)


async def test_get_history_preserves_content(client, auth_token):
    token = await auth_token()
    session_id = "content-test-session"

    with patch(
        AGENT_PATCH,
        new_callable=AsyncMock,
        return_value="The answer is 42.",
    ):
        await client.post(
            "/chat",
            json={"message": "what is the answer?", "session_id": session_id},
            headers={"Authorization": f"Bearer {token}"},
        )

    history = (
        await client.get(
            f"/chat/history/{session_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()

    user_msg = _find_by_role(history, "user")
    asst_msg = _find_by_role(history, "assistant")
    assert user_msg["content"] == "what is the answer?"
    assert asst_msg["content"] == "The answer is 42."


async def test_list_sessions_requires_auth(client):
    response = await client.get("/chat/sessions")
    assert response.status_code == 401


async def test_list_sessions_empty(client, auth_token):
    token = await auth_token()
    response = await client.get(
        "/chat/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)


async def test_list_sessions_after_chat(client, auth_token):
    token = await auth_token()
    with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="ok"):
        await client.post(
            "/chat",
            json={"message": "hello", "session_id": "session-list-test"},
            headers={"Authorization": f"Bearer {token}"},
        )
    response = await client.get(
        "/chat/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    sessions = response.json()
    assert any(s["session_id"] == "session-list-test" for s in sessions)


async def test_list_sessions_has_required_fields(client, auth_token):
    token = await auth_token()
    with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="ok"):
        await client.post(
            "/chat",
            json={"message": "field test", "session_id": "field-test-session"},
            headers={"Authorization": f"Bearer {token}"},
        )
    sessions = (
        await client.get(
            "/chat/sessions",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    session = next(
        (s for s in sessions if s["session_id"] == "field-test-session"),
        None,
    )
    assert session is not None
    assert "total_turns" in session
    assert "last_message_at" in session
    assert "preview" in session


async def test_clear_history_requires_auth(client):
    response = await client.delete("/chat/history/my-session")
    assert response.status_code == 401


async def test_clear_history_returns_204(client, auth_token):
    token = await auth_token()
    response = await client.delete(
        "/chat/history/nonexistent",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 204


async def test_clear_history_removes_messages(client, auth_token):
    token = await auth_token()
    session_id = "clear-test-session"

    with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="response"):
        await client.post(
            "/chat",
            json={"message": "hello", "session_id": session_id},
            headers={"Authorization": f"Bearer {token}"},
        )

    history = (
        await client.get(
            f"/chat/history/{session_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    assert len(history) == 2

    await client.delete(
        f"/chat/history/{session_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    history_after = (
        await client.get(
            f"/chat/history/{session_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    assert history_after == []


def test_get_findings_tool_filters_severity():
    from iam_guardian.agent.tools import make_get_findings_tool

    data = [
        {
            "id": "1",
            "check_name": "A",
            "severity": "critical",
            "resource_arn": "arn:1",
            "llm_explanation": "x",
            "status": "open",
            "created_at": "",
            "scan_id": None,
        },
        {
            "id": "2",
            "check_name": "B",
            "severity": "high",
            "resource_arn": "arn:2",
            "llm_explanation": "y",
            "status": "open",
            "created_at": "",
            "scan_id": None,
        },
    ]
    tool_fn = make_get_findings_tool(data)
    result = json.loads(tool_fn.invoke({"severity": "high"}))
    assert result["count"] == 1
    assert result["findings"][0]["severity"] == "high"


def test_get_findings_tool_all_severity():
    from iam_guardian.agent.tools import make_get_findings_tool

    data = [
        {
            "id": str(i),
            "check_name": f"C{i}",
            "severity": "critical",
            "resource_arn": "arn:x",
            "llm_explanation": "",
            "status": "open",
            "created_at": "",
            "scan_id": None,
        }
        for i in range(3)
    ]
    tool_fn = make_get_findings_tool(data)
    result = json.loads(tool_fn.invoke({"severity": ""}))
    assert result["count"] == 3


def test_get_findings_tool_truncates_explanation():
    from iam_guardian.agent.tools import make_get_findings_tool

    data = [
        {
            "id": "1",
            "check_name": "A",
            "severity": "high",
            "resource_arn": "arn:1",
            "llm_explanation": "X" * 500,
            "status": "open",
            "created_at": "",
            "scan_id": None,
        }
    ]
    tool_fn = make_get_findings_tool(data)
    result = json.loads(tool_fn.invoke({"severity": "high"}))
    assert len(result["findings"][0]["llm_explanation"]) <= 300


def test_get_escalation_paths_tool_filters():
    from iam_guardian.agent.tools import make_get_escalation_paths_tool

    data = [
        {
            "id": "e1",
            "principal_arn": "arn:r1",
            "principal_type": "role",
            "principal_name": "R1",
            "matched_combo": ["iam:PassRole"],
            "severity": "critical",
            "title": "Esc 1",
            "description": "d",
            "narrative": "n",
            "tags": [],
            "account_id": "123",
            "created_at": "",
        },
        {
            "id": "e2",
            "principal_arn": "arn:r2",
            "principal_type": "role",
            "principal_name": "R2",
            "matched_combo": ["iam:AttachRolePolicy"],
            "severity": "high",
            "title": "Esc 2",
            "description": "d",
            "narrative": "n",
            "tags": [],
            "account_id": "123",
            "created_at": "",
        },
    ]
    tool_fn = make_get_escalation_paths_tool(data)
    result = json.loads(tool_fn.invoke({"severity": "critical"}))
    assert result["count"] == 1
    assert result["paths"][0]["severity"] == "critical"


def test_rewrite_policy_tool_found():
    from iam_guardian.agent.tools import make_rewrite_policy_tool

    data = [
        {
            "id": "rw1",
            "finding_id": "finding-abc",
            "original_policy": {"Statement": []},
            "rewritten_policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:Get*"],
                        "Resource": "arn:s3:::b",
                    }
                ]
            },
            "diff_summary": "Replaced wildcard.",
            "simulation_result": {"status": "verified"},
            "rewrite_status": "verified",
            "created_at": "2025-01-15",
        }
    ]
    tool_fn = make_rewrite_policy_tool(data)
    result = json.loads(tool_fn.invoke({"finding_id": "finding-abc"}))
    assert result["rewrite_status"] == "verified"
    assert result["diff_summary"] == "Replaced wildcard."


def test_rewrite_policy_tool_not_found():
    from iam_guardian.agent.tools import make_rewrite_policy_tool

    tool_fn = make_rewrite_policy_tool([])
    result = json.loads(tool_fn.invoke({"finding_id": "nonexistent"}))
    assert "error" in result


def test_get_cloudtrail_anomalies_tool_filters_by_score():
    from iam_guardian.agent.tools import make_get_cloudtrail_anomalies_tool

    data = [
        {
            "event_name": "CreateAccessKey",
            "event_time": "2025-01-15T23:00:00",
            "principal_id": "alice",
            "identity_type": "IAMUser",
            "source_ip": "1.2.3.4",
            "region": "us-east-1",
            "anomaly_score": 7,
            "is_anomaly": True,
            "anomaly_reasons": ["After hours"],
            "narrative": "",
        },
        {
            "event_name": "ConsoleLogin",
            "event_time": "2025-01-15T14:00:00",
            "principal_id": "bob",
            "identity_type": "IAMUser",
            "source_ip": "10.0.0.1",
            "region": "us-east-1",
            "anomaly_score": 2,
            "is_anomaly": False,
            "anomaly_reasons": [],
            "narrative": "",
        },
    ]
    tool_fn = make_get_cloudtrail_anomalies_tool(data)
    result = json.loads(tool_fn.invoke({"min_score": 5}))
    assert result["count"] == 1
    assert result["anomalies"][0]["anomaly_score"] == 7


def test_get_cloudtrail_anomalies_empty_data():
    from iam_guardian.agent.tools import make_get_cloudtrail_anomalies_tool

    tool_fn = make_get_cloudtrail_anomalies_tool([])
    result = json.loads(tool_fn.invoke({"min_score": 5}))
    assert result["count"] == 0
    assert "message" in result


def test_all_tool_factories_return_tools():
    from langchain.tools import BaseTool

    from iam_guardian.agent.tools import (
        make_get_cloudtrail_anomalies_tool,
        make_get_escalation_paths_tool,
        make_get_findings_tool,
        make_rewrite_policy_tool,
    )

    assert isinstance(make_get_findings_tool([]), BaseTool)
    assert isinstance(make_get_escalation_paths_tool([]), BaseTool)
    assert isinstance(make_rewrite_policy_tool([]), BaseTool)
    assert isinstance(make_get_cloudtrail_anomalies_tool([]), BaseTool)


def test_format_history_empty():
    from iam_guardian.agent.chat_agent import format_history_for_prompt

    result = format_history_for_prompt([])
    assert result == "No previous conversation."


def test_format_history_formats_correctly():
    from iam_guardian.agent.chat_agent import format_history_for_prompt

    history = [
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi there!"},
    ]
    result = format_history_for_prompt(history)
    assert "User: Hello" in result
    assert "Assistant: Hi there!" in result


def test_format_history_order_preserved():
    from iam_guardian.agent.chat_agent import format_history_for_prompt

    history = [
        {"role": "user", "content": "First"},
        {"role": "assistant", "content": "Second"},
        {"role": "user", "content": "Third"},
    ]
    result = format_history_for_prompt(history)
    assert result.index("First") < result.index("Second") < result.index("Third")
