from unittest.mock import MagicMock, patch

from iam_guardian.compliance.compliance_map import get_mapping
from iam_guardian.compliance.report_builder import (
    _build_framework_section,
    _group_findings_by_framework,
    build_compliance_report,
)

SUMMARY_PATCH = "iam_guardian.compliance.summarizer.client"


def mock_groq(text="Posture summary. Action needed."):
    client = MagicMock()
    client.chat.completions.create.return_value.choices[0].message.content = text
    return client


WILDCARD = {
    "check_name": "Overly permissive IAM policy: wildcard Action",
    "severity": "critical",
    "resource_arn": "arn:aws:iam::123:role/A",
    "status": "open",
}
CROSS = {
    "check_name": "Trust policy allows any AWS principal",
    "severity": "critical",
    "resource_arn": "arn:aws:iam::123:role/B",
    "status": "open",
}
ESC = {
    "check_name": "Privilege escalation: iam:PassRole + lambda:CreateFunction",
    "severity": "critical",
    "resource_arn": "arn:aws:iam::123:role/C",
    "status": "open",
}


class TestGrouping:
    def test_wildcard_maps_to_cis_and_nist(self):
        grouped = _group_findings_by_framework([WILDCARD])
        assert "CIS" in grouped
        assert "NIST" in grouped

    def test_escalation_maps_to_mitre(self):
        grouped = _group_findings_by_framework([ESC])
        assert "MITRE" in grouped

    def test_finding_appears_in_all_its_frameworks(self):
        grouped = _group_findings_by_framework([ESC])
        mapping = get_mapping(ESC["check_name"])
        for framework in mapping["frameworks"]:
            assert framework in grouped
            assert ESC in grouped[framework]

    def test_unmapped_finding_excluded_from_all(self):
        unknown = {
            "check_name": "totally unknown check",
            "severity": "low",
            "resource_arn": "arn:x",
            "status": "open",
        }
        grouped = _group_findings_by_framework([unknown])
        assert grouped == {}

    def test_multiple_findings_grouped_together(self):
        grouped = _group_findings_by_framework([WILDCARD, CROSS, ESC])
        assert len(grouped.get("CIS", [])) == 3

    def test_empty_input_returns_empty(self):
        assert _group_findings_by_framework([]) == {}


class TestFrameworkSection:
    def test_failing_control_when_finding_present(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            section = _build_framework_section("CIS", [WILDCARD])
        assert section.failing_controls >= 1
        failing = [control for control in section.controls if control.status == "fail"]
        assert any(control.control_id == "CIS-1.16" for control in failing)

    def test_all_pass_when_no_findings(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            section = _build_framework_section("CIS", [])
        assert section.failing_controls == 0
        assert section.pass_rate == 1.0
        assert all(control.status == "pass" for control in section.controls)

    def test_pass_rate_between_0_and_1(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            section = _build_framework_section("NIST", [WILDCARD, CROSS])
        assert 0.0 <= section.pass_rate <= 1.0

    def test_executive_summary_populated(self):
        with patch(SUMMARY_PATCH, mock_groq("Two controls failing. Fix now.")):
            section = _build_framework_section("CIS", [WILDCARD])
        assert section.executive_summary == "Two controls failing. Fix now."

    def test_control_finding_count_accurate(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            section = _build_framework_section("CIS", [WILDCARD, ESC])
        cis_116 = next(
            (control for control in section.controls if control.control_id == "CIS-1.16"),
            None,
        )
        assert cis_116 is not None
        assert cis_116.status == "fail"
        assert cis_116.finding_count >= 1

    def test_mitre_section_uses_check_name_as_control(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            section = _build_framework_section("MITRE", [ESC])
        assert any(
            ESC["check_name"] in control.control_id
            or ESC["check_name"] == control.control_id
            for control in section.controls
        )


class TestFullReport:
    def test_report_has_cis_and_nist_always(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            report = build_compliance_report([], "123456789012")
        framework_names = {section.framework for section in report.frameworks}
        assert "CIS" in framework_names
        assert "NIST" in framework_names

    def test_report_overall_pass_rate_100_when_empty(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            report = build_compliance_report([], "123456789012")
        assert report.overall_pass_rate == 1.0

    def test_report_pass_rate_drops_with_findings(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            empty = build_compliance_report([], "123456789012")
            with_findings = build_compliance_report(
                [WILDCARD, CROSS, ESC],
                "123456789012",
            )
        assert with_findings.overall_pass_rate < empty.overall_pass_rate

    def test_report_total_findings_analyzed(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            report = build_compliance_report([WILDCARD, CROSS], "123456789012")
        assert report.total_findings_analyzed == 2

    def test_report_pass_rate_rounded_3dp(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            report = build_compliance_report([WILDCARD], "123456789012")
        for section in report.frameworks:
            decimals = str(section.pass_rate).split(".")
            if len(decimals) > 1:
                assert len(decimals[1]) <= 3

    def test_report_mitre_only_when_escalation_present(self):
        with patch(SUMMARY_PATCH, mock_groq()):
            no_esc = build_compliance_report([WILDCARD], "123456789012")
            with_esc = build_compliance_report([ESC], "123456789012")
        no_esc_frameworks = {section.framework for section in no_esc.frameworks}
        with_esc_frameworks = {section.framework for section in with_esc.frameworks}
        assert "MITRE" not in no_esc_frameworks
        assert "MITRE" in with_esc_frameworks
