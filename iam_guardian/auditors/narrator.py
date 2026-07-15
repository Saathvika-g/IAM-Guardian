import sys

from groq import Groq

from iam_guardian.core.retry import with_groq_retry
from iam_guardian.core.secrets import get_groq_key

client = None
MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = (
    "You are a senior red team security engineer writing attack narratives for a "
    "blue team. Be specific, technical, and actionable. Use numbered steps. "
    "No markdown headers. Plain prose with numbered steps only."
)


def _get_client():
    global client
    if client is None:
        client = Groq(api_key=get_groq_key())
    return client


def _build_narrative_prompt(path: dict) -> str:
    return (
        f"A principal ({path['principal_type']}: {path['principal_arn']}) "
        f"holds the following AWS IAM permissions: {', '.join(path['matched_combo'])}.\n\n"
        f"This creates a privilege escalation path: {path['title']}.\n\n"
        f"Background: {path['description']}\n\n"
        "Narrate the attack step by step for a security team investigating this path. "
        "Include: exact AWS CLI or SDK calls the attacker would make, what credentials "
        "or access they gain at each step, and what the blast radius is if this path "
        "is exploited. Write 5-7 numbered steps. Be specific — name real AWS API calls."
    )


@with_groq_retry
def _call_groq_narrative(prompt: str) -> str:
    response = _get_client().chat.completions.create(
        model=MODEL,
        max_tokens=600,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content.strip()


def generate_narrative(path: dict) -> str:
    """
    Generate a step-by-step attack narrative for one escalation path dict.
    Returns the narrative string. Falls back gracefully on any error.
    """
    try:
        return _call_groq_narrative(_build_narrative_prompt(path))
    except Exception as e:
        print(f"[narrator] error after retries: {e}", file=sys.stderr)
        return f"Narrative unavailable: {type(e).__name__}"


def generate_narratives_batch(paths: list[dict]) -> list[dict]:
    """
    Enrich a list of path dicts with generated narratives in-place.
    Returns the same list with narrative field populated.
    Processes sequentially because Groq free tier has rate limits.
    """
    for path in paths:
        path["narrative"] = generate_narrative(path)
    return paths
