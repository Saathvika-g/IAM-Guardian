import traceback

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from iam_guardian.core.logging_config import get_logger

logger = get_logger("exception_handler")


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch any exception not handled by a route and return structured JSON.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    username = getattr(request.state, "username", "anonymous")

    logger.error(
        "unhandled_exception",
        request_id=request_id,
        username=username,
        endpoint=str(request.url.path),
        method=request.method,
        error_type=type(exc).__name__,
        error=str(exc),
        traceback=traceback.format_exc(),
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred. Please try again.",
            "request_id": request_id,
            "detail": None,
        },
    )


async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    """
    Handle known HTTP errors with a consistent JSON shape.
    """
    request_id = getattr(request.state, "request_id", "unknown")

    log_fn = logger.error if exc.status_code >= 500 else logger.warning
    log_fn(
        "http_exception",
        request_id=request_id,
        status_code=exc.status_code,
        detail=str(exc.detail),
        endpoint=str(request.url.path),
        method=request.method,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": _status_to_error_code(exc.status_code),
            "message": str(exc.detail),
            "request_id": request_id,
            "detail": None,
        },
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """
    Handle request validation errors with field-level detail.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    errors = _json_safe_errors(exc.errors())

    logger.warning(
        "validation_error",
        request_id=request_id,
        endpoint=str(request.url.path),
        errors=errors,
    )

    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "message": "Request validation failed.",
            "request_id": request_id,
            "detail": errors,
        },
    )


def _json_safe_errors(errors: list[dict]) -> list[dict]:
    safe_errors = []
    for error in errors:
        safe_error = dict(error)
        ctx = safe_error.get("ctx")
        if isinstance(ctx, dict):
            safe_error["ctx"] = {
                key: value
                if isinstance(value, (str, int, float, bool, type(None)))
                else str(value)
                for key, value in ctx.items()
            }
        safe_errors.append(safe_error)
    return safe_errors


def _status_to_error_code(status_code: int) -> str:
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        409: "conflict",
        422: "validation_error",
        429: "rate_limit_exceeded",
        500: "internal_server_error",
        502: "bad_gateway",
        503: "service_unavailable",
    }.get(status_code, f"http_{status_code}")
