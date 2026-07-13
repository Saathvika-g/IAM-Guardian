from unittest.mock import patch

from iam_guardian.compliance.compliance_map import (
    CIS_CONTROLS,
    COMPLIANCE_MAP,
    FRAMEWORK_INDEX,
    NIST_CONTROLS,
    get_checks_for_framework,
    get_frameworks_for_check,
    get_mapping,
)
from iam_guardian.compliance.report_builder import (
    _build_framework_section,
    _group_findings_by_framework,
    build_compliance_report,
)
from iam_guardian.models import ComplianceReport

SUMMARY_PATCH = "iam_guardian.compliance.summarizer.client"


def mock_groq(text="Mocked summary. Take action immediately."):
    from unittest.mock import MagicMock

    mock = MagicMock()
    mock.chat.completions.create.return_value.choices[0].message.content = text
    return mock


def test_all_check_names_have_mapping():
    for check_name, mapping in COMPLIANCE_MAP.items():
        assert mapping["check_name"] == check_name
        assert len(mapping["frameworks"]) >= 1


def test_framework_index_populated():
    assert "CIS" in FRAMEWORK_INDEX
    assert "NIST" in FRAMEWORK_INDEX
    assert len(FRAMEWORK_INDEX["CIS"]) >= 5


def test_get_mapping_returns_correct_entry():
    mapping = get_mapping("Overly permissive IAM policy: wildcard Action")

    assert mapping is not None
    assert mapping["cis_control_id"] == "CIS-1.16"
    assert mapping["nist_control_id"] == "AC-6"


def test_get_mapping_returns_none_for_unknown():
    assert get_mapping("nonexistent check name") is None


def test_get_frameworks_for_check_known():
    frameworks = get_frameworks_for_check(
        "Overly permissive IAM policy: wildcard Action"
    )

    assert "CIS" in frameworks
    assert "NIST" in frameworks


def test_get_frameworks_for_check_unknown():
    assert get_frameworks_for_check("bogus check") == []


def test_get_checks_for_framework_cis():
    checks = get_checks_for_framework("CIS")

    assert len(checks) >= 5
    assert "Overly permissive IAM policy: wildcard Action" in checks


def test_get_checks_for_framework_unknown():
    assert get_checks_for_framework("SOC2") == []


def test_cis_controls_dict_populated():
    assert len(CIS_CONTROLS) >= 3
    assert "CIS-1.16" in CIS_CONTROLS


def test_nist_controls_dict_populated():
    assert len(NIST_CONTROLS) >= 3
    assert "AC-6" in NIST_CONTROLS


def test_escalation_checks_in_mitre():
    mitre_checks = get_checks_for_framework("MITRE")

    assert any("escalation" in check.lower() for check in mitre_checks)


WILDCARD_FINDING = {
    "check_name": "Overly permissive IAM policy: wildcard Action",
    "severity": "critical",
    "resource_arn": "arn:aws:iam::123456789012:role/AdminRole",
    "status": "open",
}

CROSS_ACCOUNT_FINDING = {
    "check_name": "Trust policy allows any AWS principal",
    "severity": "critical",
    "resource_arn": "arn:aws:iam::123456789012:role/CrossRole",
    "status": "open",
}

UNKNOWN_FINDING = {
    "check_name": "Some unknown check not in compliance map",
    "severity": "medium",
    "resource_arn": "arn:aws:iam::123456789012:role/SomeRole",
    "status": "open",
}


def test_group_findings_by_framework_known_check():
    grouped = _group_findings_by_framework([WILDCARD_FINDING])

    assert "CIS" in grouped
    assert "NIST" in grouped
    assert WILDCARD_FINDING in grouped["CIS"]


def test_group_findings_by_framework_unknown_check_ignored():
    grouped = _group_findings_by_framework([UNKNOWN_FINDING])

    assert grouped == {}


def test_group_findings_empty_list():
    assert _group_findings_by_framework([]) == {}


def test_build_framework_section_fail_status():
    with patch(SUMMARY_PATCH, mock_groq()):
        section = _build_framework_section("CIS", [WILDCARD_FINDING])

    assert section.framework == "CIS"
    assert section.failing_controls >= 1
    failing = [control for control in section.controls if control.status == "fail"]
    assert len(failing) >= 1
    assert "CIS-1.16" in [control.control_id for control in failing]


def test_build_framework_section_pass_when_no_findings():
    with patch(SUMMARY_PATCH, mock_groq()):
        section = _build_framework_section("CIS", [])

    assert section.failing_controls == 0
    assert section.passing_controls == section.total_controls
    assert section.pass_rate == 1.0


def test_build_framework_section_has_executive_summary():
    with patch(SUMMARY_PATCH, mock_groq("Good posture. Fix AC-6 next.")):
        section = _build_framework_section("NIST", [WILDCARD_FINDING])

    assert section.executive_summary == "Good posture. Fix AC-6 next."


def test_build_compliance_report_structure():
    with patch(SUMMARY_PATCH, mock_groq()):
        report = build_compliance_report(
            [WILDCARD_FINDING, CROSS_ACCOUNT_FINDING],
            "123456789012",
        )

    assert isinstance(report, ComplianceReport)
    assert report.account_id == "123456789012"
    assert report.total_findings_analyzed == 2
    assert len(report.frameworks) >= 2
    framework_names = [section.framework for section in report.frameworks]
    assert "CIS" in framework_names
    assert "NIST" in framework_names


def test_build_compliance_report_overall_pass_rate_range():
    with patch(SUMMARY_PATCH, mock_groq()):
        report = build_compliance_report([WILDCARD_FINDING], "123456789012")

    assert 0.0 <= report.overall_pass_rate <= 1.0


def test_build_compliance_report_no_findings_all_pass():
    with patch(SUMMARY_PATCH, mock_groq()):
        report = build_compliance_report([], "123456789012")

    assert report.overall_pass_rate == 1.0
    for section in report.frameworks:
        assert section.failing_controls == 0


def test_build_compliance_report_has_report_id_and_timestamp():
    with patch(SUMMARY_PATCH, mock_groq()):
        report = build_compliance_report([], "123456789012")

    assert len(report.report_id) == 36
    assert "T" in report.generated_at


def test_control_result_finding_count_matches():
    with patch(SUMMARY_PATCH, mock_groq()):
        report = build_compliance_report(
            [WILDCARD_FINDING, WILDCARD_FINDING],
            "123456789012",
        )

    cis_section = next(section for section in report.frameworks if section.framework == "CIS")
    cis_116 = next(
        control for control in cis_section.controls if control.control_id == "CIS-1.16"
    )
    assert cis_116.status == "fail"
    assert cis_116.finding_count >= 1
