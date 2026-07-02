import os
import sys

from anthropic import Anthropic

try:
    client = Anthropic()
    client_init_error = None
except Exception as e:
    client = None
    client_init_error = e
MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 400

SYSTEM_PROMPT = (
    "You are a cloud security engineer explaining AWS IAM findings to a developer\n\n"
    "who is not a security expert. Be direct and practical. No bullet headers,\n\n"
    "no markdown. Write in plain prose, 3-4 sentences maximum."
)


def explain_finding(finding: dict) -> str:
    """
    Takes a finding dict, calls Claude, and returns a plain-English explanation.
    Falls back to a safe default string on any exception.
    """
    try:
        if client_init_error is not None or client is None:
            raise client_init_error or RuntimeError("Anthropic client unavailable")

        user_prompt = (
            f"Finding: {finding['title']}\n\n"
            f"Severity: {finding['severity']}\n\n"
            f"Resource: {finding['resource']}\n\n"
            f"Description: {finding['description']}\n"
            "Explain: what this finding is, why it is dangerous, and the blast radius\n\n"
            "if an attacker exploited it."
        )

        message = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        if not message.content:
            return "Explanation unavailable: EmptyResponse"

        content = message.content[0]
        return getattr(content, "text", str(content))
    except Exception as e:
        print(f"[explainer] error: {e}", file=sys.stderr)
        return f"Explanation unavailable: {type(e).__name__}"
