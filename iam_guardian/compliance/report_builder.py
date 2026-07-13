from datetime import datetime
from uuid import uuid4

from iam_guardian.compliance.compliance_map import (
    FRAMEWORK_INDEX,
    get_mapping,
)
from iam_guardian.compliance.summarizer import generate_section_summary
from iam_guardian.models import ComplianceReport, ControlResult, FrameworkSection


def _group_findings_by_framework(findings: list[dict]) -> dict[str, list[dict]]:
    """
    Given a list of finding dicts, return a dict keyed by framework name.
    """
    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        check_name = finding.get("check_name", "")
        mapping = get_mapping(check_name)
        if not mapping:
            continue
        for framework in mapping["frameworks"]:
            grouped.setdefault(framework, []).append(finding)
    return grouped


def _build_framework_section(
    framework: str,
    findings_in_framework: list[dict],
) -> FrameworkSection:
    """
    Build one FrameworkSection for a given framework and its relevant findings.
    """
    all_check_names = FRAMEWORK_INDEX.get(framework, [])

    control_id_to_checks: dict[str, list[str]] = {}
    for check_name in all_check_names:
        mapping = get_mapping(check_name)
        if not mapping:
            continue
        if framework == "CIS":
            control_id = mapping.get("cis_control_id") or "UNKNOWN"
        elif framework == "NIST":
            control_id = mapping.get("nist_control_id") or "UNKNOWN"
        else:
            control_id = check_name
        control_id_to_checks.setdefault(control_id, [])
        if check_name not in control_id_to_checks[control_id]:
            control_id_to_checks[control_id].append(check_name)

    failing_check_names: set[str] = {
        finding.get("check_name", "") for finding in findings_in_framework
    }

    control_results: list[ControlResult] = []
    passing_count = 0
    failing_count = 0

    for control_id, check_names in sorted(control_id_to_checks.items()):
        mapping = get_mapping(check_names[0])
        if framework == "CIS":
            title = mapping.get("cis_control_title", "") if mapping else ""
        elif framework == "NIST":
            title = mapping.get("nist_control_title", "") if mapping else ""
        else:
            title = check_names[0]

        failed_checks_for_control = [
            check_name for check_name in check_names if check_name in failing_check_names
        ]
        status = "fail" if failed_checks_for_control else "pass"
        if status == "pass":
            passing_count += 1
        else:
            failing_count += 1

        control_results.append(
            ControlResult(
                control_id=control_id,
                control_title=title,
                status=status,
                finding_count=len(failed_checks_for_control),
                findings=failed_checks_for_control,
            )
        )

    total_controls = len(control_results)
    pass_rate = passing_count / total_controls if total_controls > 0 else 1.0

    passed_ids = [control.control_id for control in control_results if control.status == "pass"]
    failed_ids = [control.control_id for control in control_results if control.status == "fail"]
    summary = generate_section_summary(
        framework,
        passed_ids,
        failed_ids,
        findings_in_framework,
    )

    return FrameworkSection(
        framework=framework,
        total_controls=total_controls,
        passing_controls=passing_count,
        failing_controls=failing_count,
        pass_rate=round(pass_rate, 3),
        controls=control_results,
        executive_summary=summary,
    )


def build_compliance_report(
    findings: list[dict],
    account_id: str,
) -> ComplianceReport:
    """
    Main entry point. Takes finding dicts and returns a full ComplianceReport.
    """
    grouped = _group_findings_by_framework(findings)

    all_frameworks = sorted(set(list(grouped.keys()) + ["CIS", "NIST"]))

    sections: list[FrameworkSection] = []
    for framework in all_frameworks:
        findings_for_framework = grouped.get(framework, [])
        section = _build_framework_section(framework, findings_for_framework)
        sections.append(section)

    total_controls = sum(section.total_controls for section in sections)
    total_passing = sum(section.passing_controls for section in sections)
    overall_pass_rate = (
        round(total_passing / total_controls, 3) if total_controls > 0 else 1.0
    )

    return ComplianceReport(
        account_id=account_id,
        report_id=str(uuid4()),
        generated_at=datetime.utcnow().isoformat(),
        total_findings_analyzed=len(findings),
        frameworks=sections,
        overall_pass_rate=overall_pass_rate,
    )
