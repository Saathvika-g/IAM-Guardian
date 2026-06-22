from fastapi import FastAPI

from iam_guardian.api.routes import router

app = FastAPI(title="IAM Guardian", version="0.1.0")
app.include_router(router)

# Run with:  uvicorn iam_guardian.main:app --reload --port 8000
#
# Test:
# curl http://localhost:8000/health
# curl -X POST http://localhost:8000/audit/run \
# -H "Content-Type: application/json" \
# -d '{"account_id": "123456789012", "region": "us-east-1"}'
