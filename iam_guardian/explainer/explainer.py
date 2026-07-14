import sys
from groq import Groq
from iam_guardian.core.retry import with_groq_retry
from iam_guardian.core.secrets import get_groq_key

client = Groq(api_key=get_groq_key())

MODEL = "llama-3.3-70b-versatile"
MAX_TOKENS = 400

SYSTEM_PROMPT = (
    "You are a cloud security engineer explaining AWS IAM findings to a developer "
    "who is not a security expert. Be direct and practical. No bullet headers, "
    "no markdown. Write in plain prose, 3-4 sentences maximum."
)


@with_groq_retry
def _call_groq_explain(user_prompt: str) -> str:
    """Inner function retried on rate limit and transient Groq errors."""
    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    return response.choices[0].message.content


def explain_finding(finding: dict) -> str:
    user_prompt = (
        f"Finding: {finding.get('title', finding.get('check_name', 'Unknown'))}\n"
        f"Severity: {finding.get('severity', 'unknown')}\n"
        f"Resource: {finding.get('resource', finding.get('resource_arn', 'unknown'))}\n"
        f"Description: {finding.get('description', '')}\n\n"
        "Explain: what this finding is, why it is dangerous, and the blast radius "
        "if an attacker exploited it."
    )
    try:
        return _call_groq_explain(user_prompt)
    except Exception as e:
        print(f"[explainer] error after retries: {e}", file=sys.stderr)
        return f"Explanation unavailable: {type(e).__name__}"
