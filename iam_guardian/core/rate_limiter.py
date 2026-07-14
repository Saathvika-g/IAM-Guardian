from fastapi import Request
from jose import JWTError, jwt
from slowapi import Limiter
from slowapi.util import get_remote_address

from iam_guardian.auth import ALGORITHM, SECRET_KEY


def _get_user_id_for_limit(request: Request) -> str:
    """
    Rate limit key function.
    Uses authenticated username when available, falls back to IP address.
    """
    auth_header = request.headers.get("Authorization", "")
    test_scope = ""
    try:
        from iam_guardian.database import get_db

        overrides = getattr(request.app, "dependency_overrides", {})
        if isinstance(overrides, dict) and get_db in overrides:
            test_scope = f"test:{id(overrides[get_db])}:"
    except Exception:
        test_scope = ""

    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer ") :]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username:
                return f"{test_scope}user:{username}"
        except (JWTError, Exception):
            pass
    ip_key = f"ip:{get_remote_address(request)}"
    return f"{test_scope}{ip_key}"


limiter = Limiter(key_func=_get_user_id_for_limit)
