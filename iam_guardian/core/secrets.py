import os
from dotenv import load_dotenv

load_dotenv()


def get_groq_key() -> str:
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY not set in environment or .env file")
    return key


def get_database_url() -> str:
    url = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:pass@localhost:5432/iam_guardian"
    )
    return url


def get_secret_key() -> str:
    return os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")


# Production: replace the functions above with boto3 secretsmanager.get_secret_value()
# Example production implementation:
#
# import boto3, json
# from functools import lru_cache
#
# @lru_cache(maxsize=1)
# def _get_secret(secret_name: str) -> dict:
#     client = boto3.client("secretsmanager", region_name="us-east-1")
#     response = client.get_secret_value(SecretId=secret_name)
#     return json.loads(response["SecretString"])
#
# def get_groq_key() -> str:
#     return _get_secret("iam-guardian/groq")["GROQ_API_KEY"]
#
# The lru_cache ensures only one Secrets Manager API call per process lifetime,
# avoiding per-request charges and rate limits on App Runner / ECS.
