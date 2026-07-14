import logging
from functools import wraps
from typing import Callable

from groq import APIConnectionError, APIStatusError, RateLimitError
from tenacity import (
    RetryError,
    before_sleep_log,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from iam_guardian.core.logging_config import get_logger

logger = get_logger("retry")
stdlib_logger = logging.getLogger("iam_guardian.retry")


def _is_retryable_groq_error(exc: BaseException) -> bool:
    """
    Return True for Groq errors where retrying can recover.
    """
    if isinstance(exc, RateLimitError):
        return True
    if isinstance(exc, APIConnectionError):
        return True
    if isinstance(exc, APIStatusError):
        return exc.status_code in {500, 502, 503, 529}
    return False


groq_retry = retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(_is_retryable_groq_error),
    before_sleep=before_sleep_log(stdlib_logger, logging.WARNING),
    reraise=True,
)


def with_groq_retry(fn: Callable) -> Callable:
    """
    Apply retry behavior to an inner Groq SDK call and log final failures.
    """
    retrying_fn = groq_retry(fn)

    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return retrying_fn(*args, **kwargs)
        except RetryError as e:
            logger.warning(
                "groq_retry_exhausted",
                function=fn.__name__,
                attempts=3,
                final_error=str(e.last_attempt.exception()),
            )
            raise e.last_attempt.exception()
        except Exception as e:
            if not _is_retryable_groq_error(e):
                logger.warning(
                    "groq_non_retryable_error",
                    function=fn.__name__,
                    error_type=type(e).__name__,
                    error=str(e),
                )
            raise

    return wrapper
