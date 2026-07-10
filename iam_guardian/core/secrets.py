import json
from functools import lru_cache

import boto3

REGION = "us-east-1"


@lru_cache(maxsize=1)
def get_secret(secret_name: str) -> dict:
    """
    Fetch a secret from AWS Secrets Manager and return it parsed as a dict.
    Result is cached in-process, so each process only calls AWS once.
    """
    client = boto3.client("secretsmanager", region_name=REGION)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


def get_anthropic_key() -> str:
    """
    Return the Anthropic API key from the iam-guardian/anthropic secret.
    Secret value must be JSON: {"ANTHROPIC_API_KEY": "sk-ant-..."}.
    """
    secrets = get_secret("iam-guardian/anthropic")
    return secrets["ANTHROPIC_API_KEY"]
