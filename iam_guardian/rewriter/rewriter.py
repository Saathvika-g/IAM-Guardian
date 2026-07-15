import json
import sys

from groq import Groq
from pydantic import ValidationError

from iam_guardian.core.retry import with_groq_retry
from iam_guardian.core.secrets import get_groq_key
from iam_guardian.models import IAMPolicyModel

client = None
MODEL = "llama-3.3-70b-versatile"


def _build_rewrite_prompt(policy_doc: dict, strict: bool = False) -> str:
    policy_json = json.dumps(policy_doc, indent=2)
    strict_text = ""
    if strict:
        strict_text = (
            "IMPORTANT: Your previous response was not valid JSON. Return ONLY the raw JSON\n"
            "object. No text before it, no text after it, no markdown code fences.\n\n"
        )

    return (
        "You are an AWS IAM security expert. Rewrite the following IAM policy to follow\n"
        "least-privilege principles. Remove wildcard Actions and wildcard Resources.\n"
        "Replace them with the minimum specific permissions required for typical use of\n"
        "this resource type.\n\n"
        "Return ONLY a valid JSON object with this exact structure — no explanation, no markdown:\n"
        "{\n"
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        "    {\n"
        '      "Effect": "Allow",\n'
        '      "Action": ["service:SpecificAction"],\n'
        '      "Resource": "arn:aws:service:::specific-resource"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        f"{strict_text}"
        "Policy to rewrite:\n"
        f"{policy_json}"
    )


def _get_client():
    global client
    if client is None:
        client = Groq(api_key=get_groq_key())
    return client


@with_groq_retry
def _call_groq_json_inner(prompt: str) -> dict:
    """Retried inner call that returns a parsed dict."""
    response = _get_client().chat.completions.create(
        model=MODEL,
        max_tokens=800,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an AWS IAM security expert. You output only valid JSON. "
                    "Never include markdown, code fences, or explanation text."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    )
    raw = response.choices[0].message.content
    return json.loads(raw)


def _call_groq_json(prompt: str) -> dict:
    return _call_groq_json_inner(prompt)


def _build_diff_prompt(original: dict, rewritten: dict) -> str:
    original_json = json.dumps(original, indent=2)
    rewritten_json = json.dumps(rewritten, indent=2)
    return (
        "Compare these two IAM policies and write a 2-3 sentence plain-English summary\n"
        "of what changed and why the rewritten version is more secure. No markdown,\n"
        "no bullet points, just prose.\n\n"
        "Original:\n"
        f"{original_json}\n\n"
        "Rewritten:\n"
        f"{rewritten_json}"
    )


@with_groq_retry
def _call_groq_diff_inner(prompt: str) -> str:
    """Retried inner call for diff summary."""
    response = _get_client().chat.completions.create(
        model=MODEL,
        max_tokens=200,
        messages=[
            {
                "role": "system",
                "content": "You are a cloud security expert. Be concise and plain.",
            },
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content.strip()


def _get_diff_summary(original: dict, rewritten: dict) -> str:
    try:
        return _call_groq_diff_inner(_build_diff_prompt(original, rewritten))
    except Exception as e:
        print(f"[rewriter] diff error after retries: {e}", file=sys.stderr)
        return "Diff summary unavailable."


def rewrite_policy(policy_doc: dict) -> tuple[dict, str]:
    try:
        raw_result = _call_groq_json(_build_rewrite_prompt(policy_doc, strict=False))
        try:
            validated_model = IAMPolicyModel.model_validate(raw_result)
        except ValidationError as e:
            print(f"[rewriter] validation warning: {e}", file=sys.stderr)
            retry_result = _call_groq_json(
                _build_rewrite_prompt(policy_doc, strict=True)
            )
            validated_model = IAMPolicyModel.model_validate(retry_result)

        rewritten_dict = validated_model.model_dump(exclude_none=True)
        diff_summary = _get_diff_summary(policy_doc, rewritten_dict)
        return rewritten_dict, diff_summary
    except Exception as e:
        print(f"[rewriter] error: {e}", file=sys.stderr)
        return {}, f"Rewrite failed: {type(e).__name__}: {e}"
