import json
from datetime import datetime
from unittest.mock import MagicMock, patch


def make_finding_row(
    id="finding-001",
    scan_id="scan-001",
    check_name="Overly permissive IAM policy: wildcard Action",
    severity="high",
    resource_arn="arn:aws:iam::123456789012:role/AdminRole",
    llm_explanation="This is dangerous because...",
    status="open",
    created_at=None,
):
    return (
        id,
        scan_id,
        check_name,
        severity,
        resource_arn,
        llm_explanation,
        status,
        created_at or datetime(2025, 1, 15),
    )


def make_mock_session(rows):
    mock_result = MagicMock()
    mock_result.fetchall.return_value = rows
    mock_result.fetchone.return_value = rows[0] if rows else None
    mock_session = MagicMock()
    mock_session.execute.return_value = mock_result
    return mock_session


SESSION_PATCH = "scripts.agent._get_session"


def test_get_findings_returns_json():
    from scripts.agent import get_findings

    row = make_finding_row(severity="high")
    with patch(SESSION_PATCH, return_value=make_mock_session([row])):
        result = get_findings.invoke({"severity": "high"})
    data = json.loads(result)
    assert "findings" in data
    assert data["count"] == 1
    assert data["findings"][0]["severity"] == "high"


def test_get_findings_all_severity():
    from scripts.agent import get_findings

    rows = [make_finding_row(severity="critical"), make_finding_row(severity="high")]
    with patch(SESSION_PATCH, return_value=make_mock_session(rows)):
        result = get_findings.invoke({"severity": "all"})
    data = json.loads(result)
    assert data["count"] == 2


def test_get_findings_empty_result():
    from scripts.agent import get_findings

    with patch(SESSION_PATCH, return_value=make_mock_session([])):
        result = get_findings.invoke({"severity": "low"})
    data = json.loads(result)
    assert data["count"] == 0
    assert data["findings"] == []
    assert "message" in data


def test_get_findings_db_error_returns_error_json():
    from scripts.agent import get_findings

    mock_session = MagicMock()
    mock_session.execute.side_effect = Exception("connection refused")
    with patch(SESSION_PATCH, return_value=mock_session):
        result = get_findings.invoke({"severity": "high"})
    data = json.loads(result)
    assert "error" in data


def test_get_findings_truncates_long_explanation():
    from scripts.agent import get_findings

    long_explanation = "A" * 1000
    row = make_finding_row(llm_explanation=long_explanation)
    with patch(SESSION_PATCH, return_value=make_mock_session([row])):
        result = get_findings.invoke({"severity": "high"})
    data = json.loads(result)
    assert len(data["findings"][0]["llm_explanation"]) <= 300


def test_get_findings_empty_severity_returns_all():
    from scripts.agent import get_findings

    row = make_finding_row()
    with patch(SESSION_PATCH, return_value=make_mock_session([row])):
        result = get_findings.invoke({"severity": ""})
    data = json.loads(result)
    assert "findings" in data


def test_get_finding_detail_found():
    from scripts.agent import get_finding_detail

    full_row = (
        "finding-001",
        "scan-001",
        "Wildcard Action",
        "critical",
        "arn:aws:iam::123456789012:role/Admin",
        {"Statement": []},
        "This is very dangerous.",
        "open",
        datetime(2025, 1, 15),
    )
    mock_result = MagicMock()
    mock_result.fetchone.return_value = full_row
    mock_session = MagicMock()
    mock_session.execute.return_value = mock_result
    with patch(SESSION_PATCH, return_value=mock_session):
        result = get_finding_detail.invoke({"finding_id": "finding-001"})
    data = json.loads(result)
    assert data["id"] == "finding-001"
    assert data["severity"] == "critical"
    assert data["llm_explanation"] == "This is very dangerous."


def test_get_finding_detail_not_found():
    from scripts.agent import get_finding_detail

    mock_result = MagicMock()
    mock_result.fetchone.return_value = None
    mock_session = MagicMock()
    mock_session.execute.return_value = mock_result
    with patch(SESSION_PATCH, return_value=mock_session):
        result = get_finding_detail.invoke({"finding_id": "nonexistent"})
    data = json.loads(result)
    assert "error" in data
    assert "not found" in data["error"]


def test_get_finding_detail_strips_whitespace():
    from scripts.agent import get_finding_detail

    mock_result = MagicMock()
    mock_result.fetchone.return_value = None
    mock_session = MagicMock()
    mock_session.execute.return_value = mock_result
    with patch(SESSION_PATCH, return_value=mock_session):
        result = get_finding_detail.invoke({"finding_id": "  finding-001  "})
    json.loads(result)


def test_get_scan_summary_all():
    from scripts.agent import get_scan_summary

    count_rows = [("critical", 2), ("high", 3)]
    check_rows = [("Wildcard Action", "critical"), ("Cross Account", "high")]
    call_count = {"n": 0}

    def execute_side_effect(query, params=None):
        call_count["n"] += 1
        mock_result = MagicMock()
        if call_count["n"] == 1:
            mock_result.fetchall.return_value = count_rows
        else:
            mock_result.fetchall.return_value = check_rows
        return mock_result

    mock_session = MagicMock()
    mock_session.execute.side_effect = execute_side_effect
    with patch(SESSION_PATCH, return_value=mock_session):
        result = get_scan_summary.invoke({"scan_id": ""})
    data = json.loads(result)
    assert data["total_findings"] == 5
    assert data["by_severity"]["critical"] == 2


def test_get_scan_summary_db_error():
    from scripts.agent import get_scan_summary

    mock_session = MagicMock()
    mock_session.execute.side_effect = Exception("DB down")
    with patch(SESSION_PATCH, return_value=mock_session):
        result = get_scan_summary.invoke({"scan_id": "some-scan"})
    data = json.loads(result)
    assert "error" in data


def test_list_scans_returns_scans():
    from scripts.agent import list_scans

    scan_row = (
        "scan-001",
        "123456789012",
        "completed",
        5,
        2,
        3,
        datetime(2025, 1, 15),
    )
    with patch(SESSION_PATCH, return_value=make_mock_session([scan_row])):
        result = list_scans.invoke({})
    data = json.loads(result)
    assert data["count"] == 1
    assert data["scans"][0]["id"] == "scan-001"
    assert data["scans"][0]["total_findings"] == 5


def test_list_scans_empty():
    from scripts.agent import list_scans

    with patch(SESSION_PATCH, return_value=make_mock_session([])):
        result = list_scans.invoke({})
    data = json.loads(result)
    assert data["scans"] == []
    assert "message" in data


def test_get_open_findings_valid_status():
    from scripts.agent import get_open_findings_by_status

    row = (
        "f-001",
        "Wildcard Action",
        "high",
        "arn:aws:iam::123456789012:role/R",
        "open",
        datetime(2025, 1, 15),
    )
    with patch(SESSION_PATCH, return_value=make_mock_session([row])):
        result = get_open_findings_by_status.invoke({"status": "open"})
    data = json.loads(result)
    assert data["count"] == 1
    assert data["status_filter"] == "open"


def test_get_open_findings_invalid_status():
    from scripts.agent import get_open_findings_by_status

    result = get_open_findings_by_status.invoke({"status": "wont_fix"})
    data = json.loads(result)
    assert "error" in data
    assert "Invalid status" in data["error"]


def test_get_open_findings_in_progress():
    from scripts.agent import get_open_findings_by_status

    row = ("f-002", "Cross Account", "high", "arn:test", "in_progress", datetime(2025, 1, 15))
    with patch(SESSION_PATCH, return_value=make_mock_session([row])):
        result = get_open_findings_by_status.invoke({"status": "in_progress"})
    data = json.loads(result)
    assert data["status_filter"] == "in_progress"


def test_get_open_findings_case_insensitive():
    from scripts.agent import get_open_findings_by_status

    row = ("f-003", "Test", "medium", "arn:test", "resolved", datetime(2025, 1, 15))
    with patch(SESSION_PATCH, return_value=make_mock_session([row])):
        result = get_open_findings_by_status.invoke({"status": "RESOLVED"})
    data = json.loads(result)
    assert "error" not in data


def test_all_tools_have_descriptions():
    from scripts.agent import TOOLS

    for tool_fn in TOOLS:
        assert tool_fn.description, f"Tool {tool_fn.name} has no description"
        assert len(tool_fn.description) > 20, f"Tool {tool_fn.name} description too short"


def test_all_tools_have_names():
    from scripts.agent import TOOLS

    names = {tool_fn.name for tool_fn in TOOLS}
    assert "get_findings" in names
    assert "get_finding_detail" in names
    assert "get_scan_summary" in names
    assert "list_scans" in names
    assert "get_open_findings_by_status" in names


def test_tool_count():
    from scripts.agent import TOOLS

    assert len(TOOLS) == 5


def test_build_agent_returns_executor():
    from scripts.agent import build_agent

    with patch("scripts.agent.ChatGroq") as mock_llm_cls:
        mock_llm_cls.return_value = MagicMock()
        executor = build_agent()
    assert hasattr(executor, "invoke")
    assert executor.max_iterations == 6


def test_build_agent_uses_correct_model():
    from scripts.agent import build_agent

    with patch("scripts.agent.ChatGroq") as mock_llm_cls:
        mock_llm_cls.return_value = MagicMock()
        build_agent()
    call_kwargs = mock_llm_cls.call_args[1]
    assert call_kwargs["model"] == "llama-3.3-70b-versatile"
    assert call_kwargs["temperature"] == 0


def test_build_agent_max_iterations():
    from scripts.agent import build_agent

    with patch("scripts.agent.ChatGroq") as mock_llm_cls:
        mock_llm_cls.return_value = MagicMock()
        executor = build_agent()
    assert executor.max_iterations == 6


def test_run_query_returns_string():
    from scripts.agent import run_query

    mock_executor = MagicMock()
    mock_executor.invoke.return_value = {"output": "There are 3 HIGH findings."}
    with patch("scripts.agent.build_agent", return_value=mock_executor):
        result = run_query("what high findings exist?")
    assert result == "There are 3 HIGH findings."


def test_run_query_handles_agent_exception():
    from scripts.agent import run_query

    mock_executor = MagicMock()
    mock_executor.invoke.side_effect = Exception("LLM timeout")
    with patch("scripts.agent.build_agent", return_value=mock_executor):
        result = run_query("what high findings exist?")
    assert "Agent error" in result
    assert "Exception" in result


def test_run_query_handles_missing_output_key():
    from scripts.agent import run_query

    mock_executor = MagicMock()
    mock_executor.invoke.return_value = {}
    with patch("scripts.agent.build_agent", return_value=mock_executor):
        result = run_query("test")
    assert result == "No answer returned."
