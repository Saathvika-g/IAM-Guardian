import asyncio
import sys

from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam_guardian.agent.tools import (
    make_get_cloudtrail_anomalies_tool,
    make_get_escalation_paths_tool,
    make_get_findings_tool,
    make_rewrite_policy_tool,
)
from iam_guardian.core.secrets import get_groq_key
from iam_guardian.db_models import (
    ChatSessionORM,
    EscalationPathORM,
    FindingORM,
    PolicyRewriteORM,
)


REACT_PROMPT = PromptTemplate.from_template(
    """You are an expert AWS IAM security analyst assistant for IAM Guardian.
You have access to live security data: findings, escalation paths, policy rewrites,
and CloudTrail anomalies. Answer the user's question using the tools provided.
Be specific: include IDs, severity levels, resource ARNs, and explanations.
When asked to fix or remediate a finding, use the rewrite_policy tool.
When asked about suspicious behavior, use get_cloudtrail_anomalies.

Conversation so far:
{chat_history}

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


async def load_history(
    db: AsyncSession,
    session_id: str,
    username: str,
    limit: int = 20,
) -> list[dict]:
    """
    Load the last `limit` messages for this session from Postgres.
    Returns a list of dicts ordered oldest-first.
    """
    result = await db.execute(
        select(ChatSessionORM)
        .where(ChatSessionORM.session_id == session_id)
        .where(ChatSessionORM.username == username)
        .order_by(ChatSessionORM.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return [{"role": r.role, "content": r.content} for r in reversed(rows)]


async def save_message(
    db: AsyncSession,
    session_id: str,
    username: str,
    role: str,
    content: str,
) -> None:
    """Persist one message to the chat_sessions table."""
    msg = ChatSessionORM(
        session_id=session_id,
        username=username,
        role=role,
        content=content,
    )
    db.add(msg)
    await db.commit()


def format_history_for_prompt(history: list[dict]) -> str:
    """
    Format conversation history into a plain-text string for the prompt.
    Empty history returns a placeholder so the prompt variable is never blank.
    """
    if not history:
        return "No previous conversation."

    lines = []
    for msg in history:
        prefix = "User" if msg["role"] == "user" else "Assistant"
        lines.append(f"{prefix}: {msg['content']}")
    return "\n".join(lines)


async def _load_findings(db: AsyncSession) -> list[dict]:
    result = await db.execute(
        select(FindingORM).order_by(FindingORM.created_at.desc()).limit(100)
    )
    rows = result.scalars().all()
    return [
        {
            "id": str(r.id),
            "scan_id": r.scan_id,
            "check_name": r.check_name,
            "severity": r.severity,
            "resource_arn": r.resource_arn,
            "llm_explanation": r.llm_explanation,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else "",
        }
        for r in rows
    ]


async def _load_escalation_paths(db: AsyncSession) -> list[dict]:
    result = await db.execute(
        select(EscalationPathORM)
        .order_by(EscalationPathORM.created_at.desc())
        .limit(50)
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "account_id": r.account_id,
            "principal_arn": r.principal_arn,
            "principal_type": r.principal_type,
            "principal_name": r.principal_name,
            "matched_combo": r.matched_combo,
            "severity": r.severity,
            "title": r.title,
            "description": r.description,
            "narrative": r.narrative,
            "tags": r.tags,
            "created_at": r.created_at.isoformat() if r.created_at else "",
        }
        for r in rows
    ]


async def _load_rewrites(db: AsyncSession) -> list[dict]:
    result = await db.execute(
        select(PolicyRewriteORM)
        .order_by(PolicyRewriteORM.created_at.desc())
        .limit(50)
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "finding_id": r.finding_id,
            "original_policy": r.original_policy,
            "rewritten_policy": r.rewritten_policy,
            "diff_summary": r.diff_summary,
            "simulation_result": r.simulation_result,
            "rewrite_status": r.rewrite_status,
            "created_at": r.created_at.isoformat() if r.created_at else "",
        }
        for r in rows
    ]


def _build_legacy_executor(llm, tools):
    try:
        from langchain.agents import AgentExecutor, create_react_agent

        agent = create_react_agent(llm=llm, tools=tools, prompt=REACT_PROMPT)
        return AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=False,
            max_iterations=6,
            handle_parsing_errors=True,
            return_intermediate_steps=False,
        )
    except Exception as e:
        print(
            f"[chat_agent] legacy ReAct unavailable; trying LangChain 1.x create_agent: {e}",
            file=sys.stderr,
        )
        return None


def _build_modern_executor(llm, tools):
    try:
        from langchain.agents import create_agent

        return create_agent(
            model=llm,
            tools=tools,
            system_prompt=(
                "You are an expert AWS IAM security analyst assistant for IAM Guardian. "
                "Use the provided tools to answer with specific finding IDs, severities, "
                "resource ARNs, remediation context, and CloudTrail anomaly details."
            ),
        )
    except Exception as e:
        print(f"[chat_agent] LangChain 1.x agent unavailable: {e}", file=sys.stderr)
        return None


def _extract_modern_output(result) -> str:
    messages = result.get("messages", []) if isinstance(result, dict) else []
    if not messages:
        return "No response generated."

    final_message = messages[-1]
    content = getattr(final_message, "content", final_message)
    return str(content)


async def run_chat_agent(
    message: str,
    session_id: str,
    username: str,
    db: AsyncSession,
) -> str:
    """
    Run the security analyst agent for one user message.
    Never raises — all exceptions are caught and returned as response strings.
    """
    history = await load_history(db, session_id, username)
    history_text = format_history_for_prompt(history)

    try:
        findings_data = await _load_findings(db)
        escalation_data = await _load_escalation_paths(db)
        rewrites_data = await _load_rewrites(db)
        cloudtrail_data: list[dict] = []
    except Exception as e:
        print(f"[chat_agent] data load error: {e}", file=sys.stderr)
        findings_data = []
        escalation_data = []
        rewrites_data = []
        cloudtrail_data = []

    tools = [
        make_get_findings_tool(findings_data),
        make_get_escalation_paths_tool(escalation_data),
        make_rewrite_policy_tool(rewrites_data),
        make_get_cloudtrail_anomalies_tool(cloudtrail_data),
    ]

    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=get_groq_key(),
        temperature=0,
        max_tokens=1024,
    )

    legacy_executor = _build_legacy_executor(llm, tools)
    modern_executor = None if legacy_executor is not None else _build_modern_executor(
        llm,
        tools,
    )

    def _run_sync():
        try:
            if legacy_executor is not None:
                result = legacy_executor.invoke(
                    {
                        "input": message,
                        "chat_history": history_text,
                    }
                )
                return result.get("output", "No response generated.")

            if modern_executor is not None:
                result = modern_executor.invoke(
                    {
                        "messages": [
                            {
                                "role": "user",
                                "content": f"{history_text}\n\nUser: {message}",
                            }
                        ]
                    },
                    config={"recursion_limit": 24},
                )
                return _extract_modern_output(result)

            return "I encountered an error processing your request: no LangChain agent could be built."
        except Exception as e:
            print(f"[chat_agent] agent error: {e}", file=sys.stderr)
            return (
                "I encountered an error processing your request: "
                f"{type(e).__name__}: {e}"
            )

    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, _run_sync)

    await save_message(db, session_id, username, "user", message)
    await save_message(db, session_id, username, "assistant", response)

    return response
