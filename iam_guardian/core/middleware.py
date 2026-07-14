import time
import uuid

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from iam_guardian.core.logging_config import get_logger

logger = get_logger("middleware")

SKIP_LOGGING = {"/health", "/metrics", "/docs", "/openapi.json", "/redoc"}


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, db_factory=None):
        super().__init__(app)
        self._db_factory = db_factory

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        start_time = time.monotonic()

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        request.state.request_id = request_id

        response: Response = await call_next(request)

        latency_ms = int((time.monotonic() - start_time) * 1000)
        endpoint = request.url.path
        method = request.method
        status = response.status_code
        username = getattr(request.state, "username", None)

        if endpoint not in SKIP_LOGGING:
            logger.info(
                "request",
                endpoint=endpoint,
                method=method,
                status_code=status,
                latency_ms=latency_ms,
                username=username,
                request_id=request_id,
            )

            if self._db_factory:
                try:
                    await _persist_log(
                        request,
                        self._db_factory,
                        request_id=request_id,
                        username=username,
                        endpoint=endpoint,
                        method=method,
                        status_code=status,
                        latency_ms=latency_ms,
                    )
                except Exception as e:
                    logger.warning("log_persist_failed", error=str(e))

        response.headers["X-Request-ID"] = request_id
        return response


async def _persist_log(
    request: Request,
    db_factory,
    request_id: str,
    username: str | None,
    endpoint: str,
    method: str,
    status_code: int,
    latency_ms: int,
    llm_tokens_used: int | None = None,
    error_detail: str | None = None,
) -> None:
    """Persist one request log row. db_factory() returns an AsyncSession."""
    from iam_guardian.database import get_db
    from iam_guardian.db_models import RequestLogORM

    row = RequestLogORM(
        request_id=request_id,
        username=username,
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        latency_ms=latency_ms,
        llm_tokens_used=llm_tokens_used,
        error_detail=error_detail,
    )

    override = request.app.dependency_overrides.get(get_db)
    if override is not None:
        db_gen = override()
        session = await db_gen.__anext__()
        try:
            session.add(row)
            await session.commit()
        finally:
            await db_gen.aclose()
        return

    async with db_factory() as session:
        session.add(row)
        await session.commit()
