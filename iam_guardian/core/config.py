import os

USE_SECRETS_MANAGER = os.getenv("USE_SECRETS_MANAGER", "false").lower() == "true"


def resolve_anthropic_key() -> str:
    if USE_SECRETS_MANAGER:
        from iam_guardian.core.secrets import get_anthropic_key

        return get_anthropic_key()
    return os.getenv("ANTHROPIC_API_KEY", "")


ANTHROPIC_API_KEY = resolve_anthropic_key()
