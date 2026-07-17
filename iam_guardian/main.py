from dotenv import load_dotenv

load_dotenv()

from pathlib import Path

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from iam_guardian.core.logging_config import configure_logging

configure_logging()

from iam_guardian.api.auth_routes import auth_router
from iam_guardian.api.chat_routes import chat_router
from iam_guardian.api.metrics_routes import metrics_router
from iam_guardian.api.routes import router
from iam_guardian.core.exception_handlers import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from iam_guardian.core.middleware import RequestLoggingMiddleware
from iam_guardian.core.rate_limiter import limiter
from iam_guardian.database import AsyncSessionLocal

DASHBOARD_PATH = Path(__file__).parent / "static" / "dashboard.html"

app = FastAPI(
    title="IAM Guardian AI",
    version="0.1.0",
    description="AI-powered AWS IAM security auditing",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

app.add_middleware(
    RequestLoggingMiddleware,
    db_factory=AsyncSessionLocal,
)


@app.get("/", include_in_schema=False)
def dashboard():
    return HTMLResponse(DASHBOARD_PATH.read_text(encoding="utf-8"))


app.include_router(router)
app.include_router(auth_router)
app.include_router(chat_router)
app.include_router(metrics_router)
