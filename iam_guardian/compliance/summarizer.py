import sys

from groq import Groq

from iam_guardian.core.retry import with_groq_retry
from iam_guardian.core.secrets import get_groq_key

client = None
MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = (
    "You are a cloud security compliance officer writing executive summaries "
    "for board-level and engineering leadership audiences. Be direct. "
    "No markdown, no bullet points. Two sentences only. "
    "First sentence: state the compliance posture. "
    "Second sentence: state the most urgent action required."
)


def _get_client():
    global client
    if client is None:
        client = Groq(api_key=get_groq_key())
    return client


def _build_summary_prompt(
    framework: str,
    passed_controls: list[str],
    failed_controls: list[str],
    failed_findings: list[dict],
) -> str:
    failed_titles = [finding.get("check_name", "") for finding in failed_findings]
    critical_count = sum(
        1 for finding in failed_findings if finding.get("severity") == "critical"
    )
    return (
        f"Framework: {framework}\n"
        f"Controls passing: {len(passed_controls)}\n"
        f"Controls failing: {len(failed_controls)}\n"
        f"Critical findings: {critical_count}\n"
        f"Failing checks: {', '.join(failed_titles[:5])}"
        f"{'...' if len(failed_titles) > 5 else ''}\n\n"
        f"Write a 2-sentence executive summary of this {framework} compliance section."
    )


@with_groq_retry
def _call_groq_summary(prompt: str) -> str:
    response = _get_client().chat.completions.create(
        model=MODEL,
        max_tokens=150,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content.strip()


def generate_section_summary(
    framework: str,
    passed_controls: list[str],
    failed_controls: list[str],
    failed_findings: list[dict],
) -> str:
    """
    Generate a 2-sentence executive summary for one framework section.
    Falls back gracefully on any error.
    """
    try:
        return _call_groq_summary(
            _build_summary_prompt(
                framework,
                passed_controls,
                failed_controls,
                failed_findings,
            )
        )
    except Exception as e:
        print(f"[summarizer] error after retries: {e}", file=sys.stderr)
        return (
            f"{framework} compliance assessment could not be summarized. "
            f"Review {len(failed_controls)} failing control(s) manually."
        )
