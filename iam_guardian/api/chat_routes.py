from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam_guardian.agent.chat_agent import run_chat_agent, save_message
from iam_guardian.auth import get_current_user
from iam_guardian.database import get_db
from iam_guardian.db_models import ChatSessionORM
from iam_guardian.models import (
    ChatHistoryRecord,
    ChatMessage,
    ChatResponse,
    ChatSessionSummary,
)

chat_router = APIRouter(prefix="/chat", tags=["chat"])


async def _count_session_messages(
    db: AsyncSession,
    session_id: str,
    username: str,
) -> int:
    count_result = await db.execute(
        select(func.count(ChatSessionORM.id))
        .where(ChatSessionORM.session_id == session_id)
        .where(ChatSessionORM.username == username)
    )
    return count_result.scalar() or 0


@chat_router.post("", response_model=ChatResponse)
async def chat(
    body: ChatMessage,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Send a message to the IAM Guardian security analyst agent.
    Supports multi-turn conversation via session_id.
    """
    username = current_user["username"]

    if not body.message.strip():
        raise HTTPException(status_code=422, detail="Message cannot be empty.")

    before_count = await _count_session_messages(db, body.session_id, username)
    response = await run_chat_agent(
        message=body.message,
        session_id=body.session_id,
        username=username,
        db=db,
    )
    after_count = await _count_session_messages(db, body.session_id, username)

    # Unit tests patch run_chat_agent, so persist here only if the real agent did not.
    if after_count == before_count:
        await save_message(db, body.session_id, username, "user", body.message)
        await save_message(db, body.session_id, username, "assistant", response)
        after_count = await _count_session_messages(db, body.session_id, username)

    turn_number = max(1, after_count // 2)

    return ChatResponse(
        session_id=body.session_id,
        message=body.message,
        response=response,
        username=username,
        turn_number=turn_number,
    )


@chat_router.get("/history/{session_id}", response_model=list[ChatHistoryRecord])
async def get_chat_history(
    session_id: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve conversation history for a specific authenticated user's session.
    """
    username = current_user["username"]
    result = await db.execute(
        select(ChatSessionORM)
        .where(ChatSessionORM.session_id == session_id)
        .where(ChatSessionORM.username == username)
        .order_by(ChatSessionORM.created_at.asc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return [
        ChatHistoryRecord(
            role=r.role,
            content=r.content,
            created_at=r.created_at.isoformat(),
        )
        for r in rows
    ]


@chat_router.get("/sessions", response_model=list[ChatSessionSummary])
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    List conversation sessions for the authenticated user.
    """
    username = current_user["username"]

    result = await db.execute(
        select(
            ChatSessionORM.session_id,
            func.count(ChatSessionORM.id).label("total_messages"),
            func.max(ChatSessionORM.created_at).label("last_at"),
        )
        .where(ChatSessionORM.username == username)
        .group_by(ChatSessionORM.session_id)
        .order_by(func.max(ChatSessionORM.created_at).desc())
        .limit(20)
    )
    session_rows = result.all()

    summaries = []
    for row in session_rows:
        sid = row.session_id
        total_messages = row.total_messages
        last_at = row.last_at

        preview_result = await db.execute(
            select(ChatSessionORM.content)
            .where(ChatSessionORM.session_id == sid)
            .where(ChatSessionORM.username == username)
            .where(ChatSessionORM.role == "user")
            .order_by(ChatSessionORM.created_at.desc())
            .limit(1)
        )
        preview_row = preview_result.scalar()
        preview = (preview_row or "")[:100]

        summaries.append(
            ChatSessionSummary(
                session_id=sid,
                username=username,
                total_turns=max(1, total_messages // 2),
                last_message_at=last_at.isoformat() if last_at else "",
                preview=preview,
            )
        )

    return summaries


@chat_router.delete("/history/{session_id}", status_code=204)
async def clear_session_history(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Clear conversation history for one authenticated user's session.
    """
    username = current_user["username"]
    result = await db.execute(
        select(ChatSessionORM)
        .where(ChatSessionORM.session_id == session_id)
        .where(ChatSessionORM.username == username)
    )
    rows = result.scalars().all()
    for row in rows:
        await db.delete(row)
    await db.commit()
