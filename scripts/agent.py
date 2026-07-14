#!/usr/bin/env python3
"""
IAM Guardian ReAct Agent — standalone script.

Run with:
  python scripts/agent.py
  python scripts/agent.py "what critical findings exist?"
  python scripts/agent.py "summarize findings for scan abc-123"
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv

load_dotenv()

from langchain.tools import tool
from langchain_core.prompts import PromptTemplate
from langchain_groq import ChatGroq
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from iam_guardian.core.secrets import get_database_url, get_groq_key

_async_url = get_database_url()
SYNC_DATABASE_URL = _async_url.replace(
    "postgresql+asyncpg://",
    "postgresql+psycopg2://",
)

try:
    engine = create_engine(SYNC_DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    _db_available = True
except Exception as e:
    print(f"[agent] DB connection failed: {e}", file=sys.stderr)
    _db_available = False


def _get_session():
    if not _db_available:
        raise RuntimeError(
            "Database not available. Is Postgres running and DATABASE_URL set?"
        )
    return SessionLocal()


@tool
def get_findings(severity: str = "") -> str:
    """
    Query IAM Guardian findings from the database.
    Use this to answer questions about security findings.

    Args:
        severity: filter by severity level — one of: critical, high, medium, low.
                  Leave empty or pass "all" to return all findings regardless of severity.

    Returns a JSON string listing findings with their id, check_name, severity,
    resource_arn, status, and llm_explanation.
    """
    session = _get_session()
    try:
        if severity and severity.lower() not in ("all", ""):
            rows = session.execute(
                text(
                    "SELECT id, scan_id, check_name, severity, resource_arn, "
                    "       llm_explanation, status, created_at "
                    "FROM findings "
                    "WHERE LOWER(severity) = LOWER(:sev) "
                    "ORDER BY created_at DESC "
                    "LIMIT 20"
                ),
                {"sev": severity.strip().lower()},
            ).fetchall()
        else:
            rows = session.execute(
                text(
                    "SELECT id, scan_id, check_name, severity, resource_arn, "
                    "       llm_explanation, status, created_at "
                    "FROM findings "
                    "ORDER BY created_at DESC "
                    "LIMIT 20"
                )
            ).fetchall()

        if not rows:
            return json.dumps(
                {
                    "count": 0,
                    "findings": [],
                    "message": f"No findings found for severity={severity!r}.",
                }
            )

        findings = [
            {
                "id": str(row[0]),
                "scan_id": str(row[1]) if row[1] else None,
                "check_name": row[2],
                "severity": row[3],
                "resource_arn": row[4],
                "llm_explanation": (row[5] or "")[:300],
                "status": row[6],
                "created_at": str(row[7]),
            }
            for row in rows
        ]
        return json.dumps({"count": len(findings), "findings": findings}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "findings": []})
    finally:
        session.close()


@tool
def get_finding_detail(finding_id: str) -> str:
    """
    Retrieve the full details of a single finding by its UUID.
    Use this when you need the complete llm_explanation or want to inspect
    one specific finding more closely.

    Args:
        finding_id: the UUID string of the finding (from get_findings output)

    Returns a JSON string with all fields for that finding.
    """
    session = _get_session()
    try:
        row = session.execute(
            text(
                "SELECT id, scan_id, check_name, severity, resource_arn, "
                "       raw_data, llm_explanation, status, created_at "
                "FROM findings WHERE id = :fid"
            ),
            {"fid": finding_id.strip()},
        ).fetchone()

        if not row:
            return json.dumps({"error": f"Finding {finding_id!r} not found."})

        return json.dumps(
            {
                "id": str(row[0]),
                "scan_id": str(row[1]) if row[1] else None,
                "check_name": row[2],
                "severity": row[3],
                "resource_arn": row[4],
                "raw_data": row[5],
                "llm_explanation": row[6],
                "status": row[7],
                "created_at": str(row[8]),
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        session.close()


@tool
def get_scan_summary(scan_id: str = "") -> str:
    """
    Summarize findings for a specific scan, or summarize all findings if no scan_id given.
    Use this to answer questions like "how many critical findings were in the last scan?"
    or "what does scan abc-123 contain?"

    Args:
        scan_id: the UUID of a specific scan. Leave empty to summarize across all scans.

    Returns a JSON string with counts by severity and a list of check names.
    """
    session = _get_session()
    try:
        if scan_id and scan_id.lower() not in ("", "all"):
            count_rows = session.execute(
                text(
                    "SELECT severity, COUNT(*) as cnt "
                    "FROM findings WHERE scan_id = :sid "
                    "GROUP BY severity ORDER BY cnt DESC"
                ),
                {"sid": scan_id.strip()},
            ).fetchall()
            check_rows = session.execute(
                text(
                    "SELECT DISTINCT check_name, severity "
                    "FROM findings WHERE scan_id = :sid "
                    "ORDER BY severity"
                ),
                {"sid": scan_id.strip()},
            ).fetchall()
        else:
            count_rows = session.execute(
                text(
                    "SELECT severity, COUNT(*) as cnt "
                    "FROM findings "
                    "GROUP BY severity ORDER BY cnt DESC"
                )
            ).fetchall()
            check_rows = session.execute(
                text(
                    "SELECT DISTINCT check_name, severity "
                    "FROM findings ORDER BY severity"
                )
            ).fetchall()

        severity_counts = {row[0]: row[1] for row in count_rows}
        checks = [{"check_name": row[0], "severity": row[1]} for row in check_rows]
        total = sum(severity_counts.values())

        return json.dumps(
            {
                "scan_id": scan_id or "all",
                "total_findings": total,
                "by_severity": severity_counts,
                "unique_checks": checks,
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        session.close()


@tool
def list_scans() -> str:
    """
    List all audit scans in the database with their finding counts.
    Use this when the user asks about scan history, how many scans have been run,
    or wants to compare scans.

    Returns a JSON string listing scans ordered by most recent first.
    """
    session = _get_session()
    try:
        rows = session.execute(
            text(
                "SELECT id, account_id, status, total_findings, "
                "       critical_count, high_count, created_at "
                "FROM scans "
                "ORDER BY created_at DESC "
                "LIMIT 10"
            )
        ).fetchall()

        if not rows:
            return json.dumps({"scans": [], "message": "No scans found."})

        scans = [
            {
                "id": str(row[0]),
                "account_id": row[1],
                "status": row[2],
                "total_findings": row[3],
                "critical_count": row[4],
                "high_count": row[5],
                "created_at": str(row[6]),
            }
            for row in rows
        ]
        return json.dumps({"count": len(scans), "scans": scans}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        session.close()


@tool
def get_open_findings_by_status(status: str = "open") -> str:
    """
    Get findings filtered by remediation status.
    Use this to answer questions like "what findings are still open?"
    or "what has been accepted as risk?"

    Args:
        status: one of: open, in_progress, resolved, accepted_risk.
                Defaults to "open".

    Returns JSON list of findings with that status.
    """
    allowed = {"open", "in_progress", "resolved", "accepted_risk"}
    clean = status.strip().lower()
    if clean not in allowed:
        return json.dumps(
            {
                "error": (
                    f"Invalid status {status!r}. Must be one of: {sorted(allowed)}"
                )
            }
        )

    session = _get_session()
    try:
        rows = session.execute(
            text(
                "SELECT id, check_name, severity, resource_arn, status, created_at "
                "FROM findings "
                "WHERE LOWER(status) = :st "
                "ORDER BY severity, created_at DESC "
                "LIMIT 20"
            ),
            {"st": clean},
        ).fetchall()

        findings = [
            {
                "id": str(row[0]),
                "check_name": row[1],
                "severity": row[2],
                "resource_arn": row[3],
                "status": row[4],
                "created_at": str(row[5]),
            }
            for row in rows
        ]
        return json.dumps(
            {
                "status_filter": clean,
                "count": len(findings),
                "findings": findings,
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        session.close()


TOOLS = [
    get_findings,
    get_finding_detail,
    get_scan_summary,
    list_scans,
    get_open_findings_by_status,
]

REACT_PROMPT = PromptTemplate.from_template(
    """You are an expert AWS IAM security analyst assistant.
You have access to an IAM Guardian database containing security audit findings.
Answer the user's security question accurately using the available tools.
Be specific: include finding IDs, severity levels, resource ARNs, and explanations where relevant.
If a question requires multiple tool calls, use them in sequence.

You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}"""
)


class FallbackAgentExecutor:
    """Small compatibility fallback when langchain.agents cannot import."""

    def __init__(self, max_iterations: int = 6):
        self.max_iterations = max_iterations

    def invoke(self, inputs):
        question = inputs.get("input", "")
        return {
            "output": (
                "LangChain ReAct AgentExecutor is unavailable in this Python "
                "environment. The database tools are available, but the full "
                f"agent loop could not run for question: {question}"
            )
        }


class ModernAgentExecutor:
    """Adapter for LangChain 1.x create_agent graphs."""

    def __init__(self, agent_graph, max_iterations: int = 6):
        self.agent_graph = agent_graph
        self.max_iterations = max_iterations

    def invoke(self, inputs):
        question = inputs.get("input", "")
        result = self.agent_graph.invoke(
            {"messages": [{"role": "user", "content": question}]},
            config={"recursion_limit": self.max_iterations * 4},
        )
        messages = result.get("messages", [])
        if not messages:
            return {"output": "No answer returned."}

        final_message = messages[-1]
        content = getattr(final_message, "content", final_message)
        return {"output": str(content)}


def _load_legacy_react_agent_components():
    try:
        from langchain.agents import AgentExecutor, create_react_agent

        return AgentExecutor, create_react_agent
    except Exception as e:
        print(
            f"[agent] Legacy LangChain ReAct API unavailable; trying LangChain 1.x create_agent: {e}",
            file=sys.stderr,
        )
        return None, None


def _build_modern_agent(llm):
    try:
        from langchain.agents import create_agent

        agent_graph = create_agent(
            model=llm,
            tools=TOOLS,
            system_prompt=(
                "You are an expert AWS IAM security analyst assistant. "
                "Use the available IAM Guardian database tools to answer "
                "questions with specific finding IDs, severities, resource ARNs, "
                "and explanations where relevant."
            ),
        )
        return ModernAgentExecutor(agent_graph=agent_graph, max_iterations=6)
    except Exception as e:
        print(f"[agent] LangChain 1.x agent unavailable: {e}", file=sys.stderr)
        return None


def build_agent():
    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=get_groq_key(),
        temperature=0,
        max_tokens=1024,
    )

    AgentExecutor, create_react_agent = _load_legacy_react_agent_components()
    if AgentExecutor is None or create_react_agent is None:
        modern_agent = _build_modern_agent(llm)
        if modern_agent is not None:
            return modern_agent
        return FallbackAgentExecutor(max_iterations=6)

    agent = create_react_agent(
        llm=llm,
        tools=TOOLS,
        prompt=REACT_PROMPT,
    )

    return AgentExecutor(
        agent=agent,
        tools=TOOLS,
        verbose=True,
        max_iterations=6,
        handle_parsing_errors=True,
        return_intermediate_steps=False,
    )


def run_query(question: str) -> str:
    executor = build_agent()
    try:
        result = executor.invoke({"input": question})
        return result.get("output", "No answer returned.")
    except Exception as e:
        return f"Agent error: {type(e).__name__}: {e}"


DEFAULT_QUESTIONS = [
    "What HIGH severity findings exist?",
    "How many critical findings are in the database?",
    "List all open findings.",
]


if __name__ == "__main__":
    question = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else DEFAULT_QUESTIONS[0]

    print(f"\n{'=' * 60}")
    print(f"Question: {question}")
    print(f"{'=' * 60}\n")

    answer = run_query(question)

    print(f"\n{'=' * 60}")
    print(f"Final Answer:\n{answer}")
    print(f"{'=' * 60}\n")
