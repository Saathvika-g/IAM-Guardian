## Live Demo

**Live API:** https://iam-guardian.onrender.com
**Interactive docs (Swagger UI):** https://iam-guardian.onrender.com/docs

> Hosted on Render's free tier — the first request after a period of inactivity
> may take 30–60 seconds to wake up. Subsequent requests are fast.

Try it live:
1. Open the [interactive docs](https://iam-guardian.onrender.com/docs)
2. Use `POST /auth/token` with the demo credentials shown on the dashboard login screen to get a JWT
3. Click "Authorize" in the top right, paste the token
4. Run `POST /audit/run` with `{"account_id": "123456789012"}` to generate findings
5. Explore `GET /audit/findings`, `GET /audit/compliance-report`, and `POST /chat`

### AI-powered AWS IAM security auditing — detect, explain, rewrite, simulate, track

IAM Guardian is a production-structured FastAPI service that audits AWS IAM
policies for security misconfigurations, explains each finding in plain English
using an LLM, rewrites vulnerable policies to least-privilege, simulates rewrites
against AWS's own policy engine, and tracks findings across scans with a full
delta/regression system.

Built to demonstrate the combination of deep IAM domain knowledge and LLM
integration patterns — not a generic RAG app or chatbot wrapper.

---

## Architecture

```text
Client (curl / dashboard)
  |
  v
FastAPI (JWT auth — python-jose)
  |
  |--> IAM Auditors ----------------------------------> Postgres
  |      wildcard_actions.py   (CIS-1.16)                findings table        (scan_id)
  |      cross_account.py      (AWS Well-Architected)     policy_rewrites table
  |      escalation.py         (MITRE ATT&CK T1098)       escalation_paths table
  |                                                        scans table
  |
  |--> Groq SDK (llama-3.3-70b-versatile)
  |      explainer.py          — plain-English finding explanations
  |      rewriter.py           — least-privilege policy rewrite (JSON mode)
  |      narrator.py           — step-by-step attack narratives
  |      compliance/summarizer — executive summaries per framework
  |
  |--> boto3 simulate_custom_policy
  |      simulator.py          — verify rewrite doesn't block original actions
  |
  `--> compliance/
         compliance_map.py     — CIS + NIST + MITRE control mappings
         report_builder.py     — grouped pass/fail report per framework
```

Secrets: all secrets in `.env` via python-dotenv locally.
Production path: swap `core/secrets.py` functions for boto3 Secrets Manager
calls — commented stub is already in the file.

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /health | No | Liveness check |
| POST | /auth/token | No | Get JWT (form: username/password) |
| POST | /audit/run | JWT | Run full audit, persist findings + LLM explanations |
| GET | /audit/findings | JWT | List findings (filter: severity, scan_id, limit) |
| PATCH | /audit/findings/{id}/status | JWT | Update status: open / in_progress / resolved / accepted_risk |
| POST | /audit/rewrite/{finding_id} | JWT | Rewrite policy to least-privilege + simulate + persist |
| GET | /audit/rewrites | JWT | List all rewrite records (filter: finding_id, status) |
| GET | /audit/escalation-paths | JWT | Enumerate IAM principals, detect escalation paths, generate narratives |
| GET | /audit/compliance-report | JWT | CIS + NIST + MITRE compliance report with executive summaries |
| GET | /audit/scans | JWT | List all scan records with finding counts |
| GET | /audit/delta | JWT | Diff two scans: new / resolved / persisted / regressed findings |

---

## What It Detects

| Check | Severity | Framework | Control |
|-------|----------|-----------|---------|
| Wildcard IAM Action (`Action: *`) | CRITICAL | CIS, NIST | CIS-1.16, AC-6 |
| Wildcard IAM Resource (`Resource: *`) | HIGH | CIS, NIST | CIS-1.16, AC-6 |
| Cross-account trust (external account) | HIGH | NIST | AC-3 |
| Wildcard trust principal (`Principal: *`) | CRITICAL | CIS, NIST | CIS-1.21, AC-3 |
| `iam:PassRole + lambda:CreateFunction` | CRITICAL | MITRE | T1098 |
| `iam:PassRole + ec2:RunInstances` | CRITICAL | MITRE | T1098 |
| `iam:CreateAccessKey` (on other users) | CRITICAL | MITRE | T1098 |
| `iam:CreateLoginProfile` (on other users) | HIGH | MITRE | T1078 |
| `iam:UpdateLoginProfile` (on other users) | HIGH | MITRE | T1078 |
| `iam:AttachUserPolicy` | CRITICAL | MITRE | T1098 |
| `iam:AttachRolePolicy` | CRITICAL | MITRE | T1098 |
| `iam:PassRole + glue:CreateJob` | HIGH | MITRE | T1098 |
| `iam:PassRole + cloudformation:CreateStack` | HIGH | MITRE | T1098 |
| `sts:AssumeRole + iam:PutRolePolicy` | CRITICAL | MITRE | T1098 |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API framework | FastAPI + Uvicorn |
| Database | PostgreSQL (Docker) + SQLAlchemy 2.x async |
| LLM | Groq SDK — llama-3.3-70b-versatile |
| Policy simulation | boto3 `simulate_custom_policy` |
| Auth | JWT — python-jose + passlib bcrypt |
| Secrets (local) | python-dotenv |
| Secrets (prod) | AWS Secrets Manager — stubbed in core/secrets.py |
| Testing | pytest, pytest-asyncio, httpx, moto, unittest.mock |

---

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/iam-guardian-ai
cd iam-guardian-ai
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start Postgres
docker run --name iam-pg \
  -e POSTGRES_PASSWORD=pass \
  -e POSTGRES_DB=iam_guardian \
  -p 5432:5432 -d postgres

# Create tables
python -m iam_guardian.init_db

# Configure secrets
cp .env.example .env
# Edit .env: set GROQ_API_KEY=gsk_...

# Start
uvicorn iam_guardian.main:app --reload --port 8000
```

`.env.example`:

```text
GROQ_API_KEY=gsk_your_key_here
DATABASE_URL=postgresql+asyncpg://postgres:pass@localhost:5432/iam_guardian
SECRET_KEY=dev-secret-key-change-in-prod
```

### Smoke Tests

```bash
# Auth
curl -X POST http://localhost:8000/auth/token \
  -d "username=<demo_username>&password=<demo_password>"
export TOKEN="<paste>"

# Run audit
curl -X POST http://localhost:8000/audit/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "123456789012"}'
export SCAN_A="<paste audit_id>"

# Get findings
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/audit/findings?scan_id=$SCAN_A" | python3 -m json.tool

# Update a finding status
export FID="<paste finding id>"
curl -X PATCH "http://localhost:8000/audit/findings/$FID/status" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "in_progress"}'

# Rewrite a finding
curl -X POST "http://localhost:8000/audit/rewrite/$FID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Compliance report
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/audit/compliance-report" | python3 -m json.tool

# Delta between two scans
export SCAN_B="<run audit again, paste second audit_id>"
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/audit/delta?scan_a=$SCAN_A&scan_b=$SCAN_B" \
  | python3 -m json.tool
```

Interactive docs: `http://localhost:8000/docs`

---

## Running Tests

```bash
pip install pytest pytest-asyncio httpx "moto[iam,secretsmanager]" aiosqlite pytest-cov

# Full suite
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=iam_guardian --cov-report=term-missing

# By category
pytest tests/test_wildcard_actions.py tests/test_cross_account.py -v  # auditor units
pytest tests/test_escalation.py tests/test_escalation_moto.py -v      # escalation + moto
pytest tests/test_rewriter.py tests/test_rewriter_extended.py -v      # rewriter
pytest tests/test_delta.py tests/test_delta_logic.py -v               # delta
pytest tests/test_routes.py -v                                        # route integration
pytest tests/test_compliance.py -v                                    # compliance
```

### Test architecture

| File | Type | Dependencies |
|------|------|-------------|
| test_wildcard_actions.py | Unit | None |
| test_cross_account.py | Unit | None |
| test_escalation.py | Unit | None |
| test_escalation_moto.py | Integration | moto[iam] — real boto3 against mock AWS |
| test_rewriter.py | Unit | unittest.mock |
| test_rewriter_extended.py | Unit | unittest.mock — Pydantic validation paths |
| test_simulator.py | Unit | unittest.mock |
| test_narrator.py | Unit | unittest.mock |
| test_compliance.py | Unit | unittest.mock |
| test_delta.py | Integration | httpx, SQLite in-memory |
| test_delta_logic.py | Unit | None — pure logic, no I/O |
| test_routes.py | Integration | httpx, SQLite in-memory, unittest.mock |

No test touches real Postgres, real AWS, or the real Groq API.
LLM calls are patched. AWS calls use moto. DB uses SQLite in-memory.

---

## Test Coverage

The full suite runs on SQLite in-memory with all LLM and AWS calls mocked —
no Postgres, no API keys, no AWS credentials required.

```bash
# Run with coverage
pytest tests/ --cov=iam_guardian --cov-report=html --cov-report=term-missing \
  --ignore=tests/test_docker_health.py

# Open the HTML report
open htmlcov/index.html
```

Coverage config lives in `.coveragerc`. The badge above updates automatically
on every push to main via GitHub Actions.

---

## Deployment

### CI — GitHub Actions

Every push to `main` and every pull request runs the full test suite
automatically via `.github/workflows/ci.yml`. Tests use SQLite in-memory
so no Postgres or real API keys are needed in CI.

### CD — Render

The app is deployed on [Render](https://render.com) using the `Dockerfile`.
Render auto-deploys on every merge to `main`.

**Environment variables set in Render dashboard (never in code):**

| Variable | Description |
|---|---|
| `GROQ_API_KEY` | Free key from console.groq.com |
| `DATABASE_URL` | Internal Render Postgres URL |
| `SECRET_KEY` | Random string for JWT signing |
| `USE_SECRETS_MANAGER` | `false` for Render deployment |

**Production secrets note:** In a full AWS deployment, `core/secrets.py`
would use boto3 `secretsmanager.get_secret_value()` — the commented stub
is already in place. Render env vars are used here for cost-free deployment.
The application code is unchanged either way.

### Local development (Docker)

```bash
cp .env.example .env    # fill in GROQ_API_KEY
docker compose up --build
```

### Local development (manual)

```bash
docker run --name iam-pg -e POSTGRES_PASSWORD=pass \
  -e POSTGRES_DB=iam_guardian -p 5432:5432 -d postgres
python -m iam_guardian.init_db
uvicorn iam_guardian.main:app --reload --port 8000
```

---

## Architecture Decisions

**In-process secret caching** — `_get_secret()` uses `@lru_cache` in the
production Secrets Manager path (see comment stub in `core/secrets.py`).
One API call per process lifetime. Rotation requires a restart — acceptable
for App Runner or ECS where restarts are cheap.

**Separate Pydantic and ORM models** — `models.py` holds Pydantic schemas,
`db_models.py` holds SQLAlchemy ORM classes. Each layer is independently
testable. The Pydantic `FindingRecord` uses `model_config = ConfigDict(from_attributes=True)`
to map from ORM rows without coupling the layers.

**Extensible auditor schema** — all auditors return `List[Finding]` against
the same schema. The LLM explainer loop, the compliance mapper, and the delta
system are all auditor-agnostic. Adding a new check requires zero changes
to any other layer.

**Delta identity by (check_name, resource_arn)** — finding UUIDs change between
scans. The logical identity of a vulnerability is the check type on a specific
resource. This lets the delta system correctly classify persisted vs new vs
resolved findings across arbitrary scans.

**Groq JSON mode for rewrites** — `response_format={"type": "json_object"}`
guarantees parseable output. Retry with strict prompt on Pydantic validation
failure. Never trust raw LLM output — always validate the schema before storing.

**Simulation as hallucination guard** — after rewriting, `simulate_custom_policy`
verifies the rewrite against AWS's own IAM evaluation engine. If original
actions are now denied, the rewrite is flagged `needs_review`. Interview line:
"I don't trust raw LLM output. I verify it against AWS's own simulator."

**Production secrets pattern** — In a full AWS deployment, `core/secrets.py`
would swap python-dotenv for boto3 `secretsmanager.get_secret_value()` — the
commented stub is already in place. For this deployment, Render's environment
variable dashboard replaces Secrets Manager at zero cost. The application code
is unchanged either way: `get_groq_key()` and `get_secret_key()` abstract the
source so the rest of the codebase never knows the difference.

---

## Roadmap

- [ ] Real boto3 IAM enumeration wired to `/audit/run` (currently uses mock policies)
- [ ] CloudTrail anomaly scoring — detect unusual API call patterns
- [ ] LangChain conversational agent with Postgres-backed memory
- [ ] Docker + GitHub Actions CI/CD → ECR → App Runner
- [ ] Single-file HTML dashboard — severity heatmap, finding timeline, delta view
- [ ] Slack/webhook notifications on new CRITICAL findings
- [ ] Scheduled scans via APScheduler or AWS EventBridge
