import sys

from groq import Groq

from iam_guardian.core.secrets import get_groq_key

client = Groq(api_key=get_groq_key())
MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = (
    "You are a senior cloud security analyst investigating unusual AWS CloudTrail "
    "activity. You are writing for a security operations team. Be specific and "
    "actionable. No markdown headers. No bullet points. Plain prose, 3-4 sentences. "
    "First sentence: what an attacker could be doing. "
    "Second sentence: what the security team should check immediately. "
    "Third sentence: what long-term hardening is recommended."
)


def _build_narrative_prompt(event: dict) -> str:
    reasons = event.get("anomaly_reasons", [])
    reasons_text = "; ".join(reasons) if reasons else "multiple anomaly signals detected"
    return (
        f"CloudTrail event with anomaly score {event.get('anomaly_score', 0)}:\n"
        f"Event: {event.get('event_name', 'unknown')}\n"
        f"Principal: {event.get('principal_id', 'unknown')} "
        f"({event.get('identity_type', 'unknown')})\n"
        f"Source IP: {event.get('source_ip', 'unknown')}\n"
        f"Time (UTC): {event.get('event_time', 'unknown')}\n"
        f"Region: {event.get('region', 'unknown')}\n"
        f"Anomaly signals: {reasons_text}\n\n"
        "This CloudTrail event has unusual characteristics. "
        "What could an attacker be doing? "
        "What should the security team check? "
        "What hardening is recommended?"
    )


def generate_anomaly_narrative(event: dict) -> str:
    try:
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=250,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_narrative_prompt(event)},
            ],
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[anomaly_narrator] error: {e}", file=sys.stderr)
        return (
            f"Narrative unavailable: {type(e).__name__}. "
            f"Review the {len(event.get('anomaly_reasons', []))} anomaly signal(s) manually."
        )


def generate_narratives_for_anomalies(events: list[dict]) -> list[dict]:
    result = []
    for event in events:
        if event.get("is_anomaly"):
            narrative = generate_anomaly_narrative(event)
        else:
            narrative = None
        result.append({**event, "narrative": narrative})
    return result
