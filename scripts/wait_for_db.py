#!/usr/bin/env python3
"""
Wait for Postgres to be ready before starting the application.
Used in docker-compose command chain: wait_for_db -> init_db -> uvicorn.

Exit 0: DB is ready.
Exit 1: timed out after max_retries attempts.
"""

import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# Add repo root so local imports work if this script is run manually.
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv

load_dotenv()

MAX_RETRIES = 30
RETRY_INTERVAL = 2


def check_db() -> bool:
    """
    Attempt a synchronous Postgres connection.
    Returns True if connection succeeds, False otherwise.
    """
    try:
        import psycopg2

        db_url = os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://postgres:pass@localhost:5432/iam_guardian",
        )
        sync_url = db_url.replace("postgresql+asyncpg://", "postgresql://")
        parsed = urlparse(sync_url)

        conn = psycopg2.connect(
            host=parsed.hostname or "localhost",
            port=parsed.port or 5432,
            user=parsed.username or "postgres",
            password=parsed.password or "pass",
            dbname=parsed.path.lstrip("/") or "iam_guardian",
            connect_timeout=3,
        )
        conn.close()
        return True
    except Exception:
        return False


def main() -> int:
    print(f"Waiting for database (max {MAX_RETRIES * RETRY_INTERVAL}s)...")

    for attempt in range(1, MAX_RETRIES + 1):
        if check_db():
            print(f"Database ready after {attempt} attempt(s).")
            return 0
        print(
            f"Attempt {attempt}/{MAX_RETRIES}: DB not ready, "
            f"retrying in {RETRY_INTERVAL}s..."
        )
        time.sleep(RETRY_INTERVAL)

    print(f"ERROR: Database not ready after {MAX_RETRIES} attempts. Giving up.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
