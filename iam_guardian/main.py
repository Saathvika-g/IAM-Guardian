from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI

from iam_guardian.api.auth_routes import auth_router
from iam_guardian.api.chat_routes import chat_router
from iam_guardian.api.routes import router

app = FastAPI(title="IAM Guardian", version="0.1.0")
app.include_router(auth_router)
app.include_router(router)
app.include_router(chat_router)

# Run with:  uvicorn iam_guardian.main:app --reload --port 8000
#
# Test:
# curl http://localhost:8000/health
# curl -X POST http://localhost:8000/audit/run \
# -H "Content-Type: application/json" \
# -d '{"account_id": "123456789012", "region": "us-east-1"}'
