import json
from typing import Union

from langchain.tools import tool


def make_get_findings_tool(findings_data: list[dict]):
    """
    Factory that returns a get_findings tool pre-loaded with findings data.
    findings_data: list of dicts with keys:
      id, scan_id, check_name, severity, resource_arn, llm_explanation, status, created_at
    """

    @tool
    def get_findings(severity: str = "") -> str:
        """
        Search IAM security findings by severity level.
        Use to answer questions about what security issues exist.

        Args:
            severity: filter by 'critical', 'high', 'medium', 'low', or '' for all.

        Returns JSON with count and list of findings.
        """
        clean = severity.strip().lower()
        if clean and clean != "all":
            filtered = [f for f in findings_data if f["severity"].lower() == clean]
        else:
            filtered = findings_data

        if not filtered:
            return json.dumps(
                {
                    "count": 0,
                    "findings": [],
                    "message": f"No findings found for severity={severity!r}.",
                }
            )

        output = [
            {**f, "llm_explanation": (f.get("llm_explanation") or "")[:300]}
            for f in filtered[:20]
        ]
        return json.dumps({"count": len(output), "findings": output}, indent=2)

    return get_findings


def make_get_escalation_paths_tool(escalation_data: list[dict]):
    """
    Factory that returns a get_escalation_paths tool pre-loaded with data.
    escalation_data: list of dicts from EscalationPathORM rows.
    """

    @tool
    def get_escalation_paths(severity: str = "") -> str:
        """
        Retrieve detected privilege escalation paths for IAM principals.
        Use to answer questions about which users or roles can escalate privileges,
        what attack chains exist, or which principals pose the highest risk.

        Args:
            severity: optional filter — 'critical', 'high', or '' for all.

        Returns JSON with escalation paths including principal ARN, matched combo,
        severity, and LLM-generated attack narrative.
        """
        clean = severity.strip().lower()
        if clean and clean != "all":
            filtered = [p for p in escalation_data if p["severity"].lower() == clean]
        else:
            filtered = escalation_data

        if not filtered:
            return json.dumps(
                {
                    "count": 0,
                    "paths": [],
                    "message": "No escalation paths found."
                    + (f" Severity filter: {severity!r}." if severity else ""),
                }
            )

        output = [
            {
                "id": p.get("id", ""),
                "principal_arn": p.get("principal_arn", ""),
                "principal_type": p.get("principal_type", ""),
                "principal_name": p.get("principal_name", ""),
                "matched_combo": p.get("matched_combo", []),
                "severity": p.get("severity", ""),
                "title": p.get("title", ""),
                "description": (p.get("description") or "")[:200],
                "narrative": (p.get("narrative") or "")[:300],
                "tags": p.get("tags", []),
            }
            for p in filtered[:15]
        ]
        return json.dumps({"count": len(output), "paths": output}, indent=2)

    return get_escalation_paths


def make_rewrite_policy_tool(rewrites_data: list[dict]):
    """
    Factory that returns a rewrite_policy tool pre-loaded with rewrite records.
    rewrites_data: list of dicts from PolicyRewriteORM rows.
    """

    @tool
    def rewrite_policy(finding_id: str) -> str:
        """
        Look up the least-privilege policy rewrite for a specific finding.
        Use when the user asks how to fix a finding, what the remediated policy
        looks like, or whether a finding has been rewritten.

        Args:
            finding_id: the UUID of the finding to look up rewrites for.

        Returns JSON with the original policy, rewritten policy, diff summary,
        simulation result, and rewrite status (verified / needs_review).
        """
        clean = finding_id.strip()
        matches = [r for r in rewrites_data if r.get("finding_id") == clean]

        if not matches:
            return json.dumps(
                {
                    "error": f"No rewrite found for finding_id={clean!r}. "
                    f"Run POST /audit/rewrite/{{id}} first to generate one.",
                    "finding_id": clean,
                }
            )

        latest = sorted(
            matches,
            key=lambda r: r.get("created_at", ""),
            reverse=True,
        )[0]
        return json.dumps(
            {
                "finding_id": latest.get("finding_id"),
                "original_policy": latest.get("original_policy"),
                "rewritten_policy": latest.get("rewritten_policy"),
                "diff_summary": latest.get("diff_summary"),
                "simulation_result": latest.get("simulation_result"),
                "rewrite_status": latest.get("rewrite_status"),
                "created_at": latest.get("created_at"),
            },
            indent=2,
            default=str,
        )

    return rewrite_policy


def make_get_cloudtrail_anomalies_tool(anomalies_data: list[dict]):
    """
    Factory that returns a get_cloudtrail_anomalies tool pre-loaded with data.
    anomalies_data: pre-scored anomaly event dicts (from score_all_events output
    filtered to is_anomaly=True).
    """

    @tool
    def get_cloudtrail_anomalies(min_score: Union[int, str] = "5") -> str:
        """
        Retrieve CloudTrail events flagged as anomalous based on behavioral signals:
        after-hours activity, new source IPs, root account usage, and new event types.
        Use when the user asks about suspicious activity, unusual behavior, or
        CloudTrail anomalies.

        Args:
            min_score: minimum anomaly score threshold (default "5").
                       Lower = more results, higher = only highest-risk events.

        Returns JSON with anomalous events, their scores, and reasons.
        """
        try:
            threshold = int(min_score)
        except (TypeError, ValueError):
            threshold = 5

        filtered = [
            e for e in anomalies_data if e.get("anomaly_score", 0) >= threshold
        ]

        if not filtered:
            return json.dumps(
                {
                    "count": 0,
                    "anomalies": [],
                    "message": f"No CloudTrail anomalies found with score >= {threshold}. "
                    f"This may mean no CloudTrail data is available (requires "
                    f"AWS credentials) or no events meet the threshold.",
                }
            )

        output = [
            {
                "event_name": e.get("event_name"),
                "event_time": e.get("event_time"),
                "principal_id": e.get("principal_id"),
                "identity_type": e.get("identity_type"),
                "source_ip": e.get("source_ip"),
                "region": e.get("region"),
                "anomaly_score": e.get("anomaly_score"),
                "anomaly_reasons": e.get("anomaly_reasons", []),
                "narrative": (e.get("narrative") or "")[:300],
            }
            for e in sorted(
                filtered,
                key=lambda x: x.get("anomaly_score", 0),
                reverse=True,
            )[:10]
        ]
        return json.dumps({"count": len(output), "anomalies": output}, indent=2)

    return get_cloudtrail_anomalies
