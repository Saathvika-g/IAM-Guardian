import json
from unittest.mock import AsyncMock, patch

AGENT_PATCH = "iam_guardian.api.chat_routes.run_chat_agent"


class TestChatRouting:
    async def test_findings_question_routed(self, client, auth_token):
        token = await auth_token()
        with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="Found 3 HIGH findings: ..."):
            response = await client.post(
                "/chat",
                json={"message": "what high severity findings exist?", "session_id": "routing-test"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert response.status_code == 200
        assert "high" in response.json()["response"].lower()

    async def test_escalation_question_routed(self, client, auth_token):
        token = await auth_token()
        with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="2 escalation paths found: PassRole + Lambda..."):
            response = await client.post(
                "/chat",
                json={"message": "what privilege escalation paths exist?", "session_id": "esc-test"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert response.status_code == 200
        assert "escalation" in response.json()["response"].lower()

    async def test_rewrite_question_routed(self, client, auth_token):
        token = await auth_token()
        with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="The rewritten policy replaces Action: * with s3:GetObject"):
            response = await client.post(
                "/chat",
                json={"message": "show me the rewrite for finding abc-123", "session_id": "rewrite-test"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert response.status_code == 200

    async def test_anomaly_question_routed(self, client, auth_token):
        token = await auth_token()
        with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="3 CloudTrail anomalies detected after hours"):
            response = await client.post(
                "/chat",
                json={"message": "any suspicious CloudTrail activity?", "session_id": "ct-test"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert response.status_code == 200
        assert "anomal" in response.json()["response"].lower()

    async def test_multi_turn_preserves_session(self, client, auth_token):
        token = await auth_token()
        session_id = "multi-turn-session"

        with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="There are 5 findings."):
            r1 = await client.post(
                "/chat",
                json={"message": "how many findings?", "session_id": session_id},
                headers={"Authorization": f"Bearer {token}"},
            )

        with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="The critical one is..."):
            r2 = await client.post(
                "/chat",
                json={"message": "tell me about the critical one", "session_id": session_id},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r2.json()["turn_number"] > r1.json()["turn_number"]

    async def test_chat_response_fields(self, client, auth_token):
        token = await auth_token()
        with patch(AGENT_PATCH, new_callable=AsyncMock, return_value="Hello!"):
            response = await client.post(
                "/chat",
                json={"message": "hello", "session_id": "fields-test"},
                headers={"Authorization": f"Bearer {token}"},
            )
        data = response.json()
        assert "response" in data
        assert "session_id" in data
        assert "message" in data
        assert "username" in data
        assert "turn_number" in data
        assert data["username"] == "admin"

    async def test_empty_message_rejected(self, client, auth_token):
        token = await auth_token()
        response = await client.post(
            "/chat",
            json={"message": "", "session_id": "empty-test"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    async def test_whitespace_only_message_rejected(self, client, auth_token):
        token = await auth_token()
        response = await client.post(
            "/chat",
            json={"message": "   \t\n  ", "session_id": "ws-test"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422


class TestToolFunctionRouting:
    def _findings_data(self):
        return [
            {
                "id": f"f-{i}",
                "scan_id": "s1",
                "check_name": f"Check {i}",
                "severity": "critical" if i % 2 == 0 else "high",
                "resource_arn": f"arn:test:{i}",
                "llm_explanation": f"Explanation {i}",
                "status": "open",
                "created_at": "2025-01-15",
            }
            for i in range(5)
        ]

    def test_get_findings_tool_filters_correctly(self):
        from iam_guardian.agent.tools import make_get_findings_tool

        tool = make_get_findings_tool(self._findings_data())
        result = json.loads(tool.invoke({"severity": "critical"}))
        assert all(f["severity"] == "critical" for f in result["findings"])

    def test_get_findings_tool_all_returns_all(self):
        from iam_guardian.agent.tools import make_get_findings_tool

        data = self._findings_data()
        tool = make_get_findings_tool(data)
        result = json.loads(tool.invoke({"severity": ""}))
        assert result["count"] == len(data)

    def test_get_findings_tool_unknown_severity_returns_empty(self):
        from iam_guardian.agent.tools import make_get_findings_tool

        tool = make_get_findings_tool(self._findings_data())
        result = json.loads(tool.invoke({"severity": "nonexistent"}))
        assert result["count"] == 0

    def test_get_escalation_paths_empty(self):
        from iam_guardian.agent.tools import make_get_escalation_paths_tool

        tool = make_get_escalation_paths_tool([])
        result = json.loads(tool.invoke({"severity": ""}))
        assert result["count"] == 0
        assert "message" in result

    def test_get_escalation_paths_filters_severity(self):
        from iam_guardian.agent.tools import make_get_escalation_paths_tool

        data = [
            {
                "id": "e1",
                "principal_arn": "arn:1",
                "principal_type": "role",
                "principal_name": "R1",
                "matched_combo": ["iam:PassRole"],
                "severity": "critical",
                "title": "T1",
                "description": "D1",
                "narrative": "N1",
                "tags": [],
                "account_id": "123",
                "created_at": "",
            },
            {
                "id": "e2",
                "principal_arn": "arn:2",
                "principal_type": "user",
                "principal_name": "U1",
                "matched_combo": ["iam:CreateAccessKey"],
                "severity": "high",
                "title": "T2",
                "description": "D2",
                "narrative": "N2",
                "tags": [],
                "account_id": "123",
                "created_at": "",
            },
        ]
        tool = make_get_escalation_paths_tool(data)
        result = json.loads(tool.invoke({"severity": "critical"}))
        assert result["count"] == 1
        assert result["paths"][0]["severity"] == "critical"

    def test_rewrite_policy_tool_found(self):
        from iam_guardian.agent.tools import make_rewrite_policy_tool

        data = [
            {
                "id": "rw1",
                "finding_id": "f-abc",
                "original_policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
                "rewritten_policy": {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:s3:::b/*"}]},
                "diff_summary": "Replaced wildcard.",
                "simulation_result": {"status": "verified"},
                "rewrite_status": "verified",
                "created_at": "2025-01-15",
            }
        ]
        tool = make_rewrite_policy_tool(data)
        result = json.loads(tool.invoke({"finding_id": "f-abc"}))
        assert result["rewrite_status"] == "verified"
        assert result["diff_summary"] == "Replaced wildcard."

    def test_rewrite_policy_tool_not_found_returns_error(self):
        from iam_guardian.agent.tools import make_rewrite_policy_tool

        tool = make_rewrite_policy_tool([])
        result = json.loads(tool.invoke({"finding_id": "nonexistent"}))
        assert "error" in result

    def test_cloudtrail_anomalies_tool_filters_score(self):
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
                "event_time": "2025-01-15T10:00:00",
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
        tool = make_get_cloudtrail_anomalies_tool(data)
        result = json.loads(tool.invoke({"min_score": 5}))
        assert result["count"] == 1
        assert result["anomalies"][0]["anomaly_score"] == 7

    def test_all_tools_are_langchain_tools(self):
        from iam_guardian.agent.tools import (
            make_get_cloudtrail_anomalies_tool,
            make_get_escalation_paths_tool,
            make_get_findings_tool,
            make_rewrite_policy_tool,
        )
        from langchain.tools import BaseTool

        for factory, args in [
            (make_get_findings_tool, [[]]),
            (make_get_escalation_paths_tool, [[]]),
            (make_rewrite_policy_tool, [[]]),
            (make_get_cloudtrail_anomalies_tool, [[]]),
        ]:
            tool = factory(*args)
            assert isinstance(tool, BaseTool), f"{factory.__name__} must return BaseTool"

    def test_tool_descriptions_are_non_empty(self):
        from iam_guardian.agent.tools import (
            make_get_cloudtrail_anomalies_tool,
            make_get_escalation_paths_tool,
            make_get_findings_tool,
            make_rewrite_policy_tool,
        )

        for factory in [
            make_get_findings_tool,
            make_get_escalation_paths_tool,
            make_rewrite_policy_tool,
            make_get_cloudtrail_anomalies_tool,
        ]:
            tool = factory([])
            assert len(tool.description) > 30, f"{factory.__name__} description too short for LLM routing"


class TestHistoryFormatting:
    def test_format_empty_history(self):
        from iam_guardian.agent.chat_agent import format_history_for_prompt

        result = format_history_for_prompt([])
        assert result == "No previous conversation."
        assert len(result) > 0

    def test_format_single_turn(self):
        from iam_guardian.agent.chat_agent import format_history_for_prompt

        history = [
            {"role": "user", "content": "how many findings?"},
            {"role": "assistant", "content": "There are 5 findings."},
        ]
        result = format_history_for_prompt(history)
        assert "User: how many findings?" in result
        assert "Assistant: There are 5 findings." in result

    def test_format_multi_turn_order(self):
        from iam_guardian.agent.chat_agent import format_history_for_prompt

        history = [
            {"role": "user", "content": "A"},
            {"role": "assistant", "content": "B"},
            {"role": "user", "content": "C"},
            {"role": "assistant", "content": "D"},
        ]
        result = format_history_for_prompt(history)
        assert result.index("A") < result.index("B") < result.index("C") < result.index("D")

    def test_format_never_returns_empty_string(self):
        from iam_guardian.agent.chat_agent import format_history_for_prompt

        assert format_history_for_prompt([]) != ""
        assert format_history_for_prompt([{"role": "user", "content": "x"}]) != ""
