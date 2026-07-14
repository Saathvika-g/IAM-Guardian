from datetime import datetime

import pytest
from pydantic import ValidationError

from iam_guardian.models import DeltaFinding, ScanDelta, ScanRecord, StatusUpdate

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


def make_delta_finding(
    check_name="Overly permissive IAM policy: wildcard Action",
    severity="critical",
    resource_arn="arn:aws:iam::123456789012:role/AdminRole",
    status="open",
    scan_id="scan-a",
):
    return DeltaFinding(
        id=f"finding-{check_name[:8]}",
        scan_id=scan_id,
        check_name=check_name,
        severity=severity,
        resource_arn=resource_arn,
        status=status,
        created_at=datetime.utcnow().isoformat(),
    )


def make_scan_delta(new=0, resolved=0, persisted=0, regressed=0):
    def findings(count, severity="critical", scan="scan-b", suffix=""):
        return [
            make_delta_finding(
                check_name=f"Check {index}{suffix}",
                severity=severity,
                scan_id=scan,
            )
            for index in range(count)
        ]

    return ScanDelta(
        scan_a="scan-a",
        scan_b="scan-b",
        new_findings=findings(new, suffix="-new"),
        resolved_findings=findings(resolved, scan="scan-a", suffix="-res"),
        persisted_findings=findings(persisted, suffix="-per"),
        regressed_findings=findings(regressed, suffix="-reg"),
        summary=f"{new} new, {resolved} resolved, {regressed} regression(s)",
    )


def check_regression(severity_a: str, severity_b: str) -> bool:
    return SEVERITY_RANK.get(severity_b, 0) > SEVERITY_RANK.get(severity_a, 0)


def test_delta_finding_required_fields():
    finding = make_delta_finding()

    assert finding.check_name == "Overly permissive IAM policy: wildcard Action"
    assert finding.severity == "critical"
    assert finding.status == "open"


def test_delta_finding_optional_scan_id():
    finding = DeltaFinding(
        id="x",
        check_name="test",
        severity="low",
        resource_arn="arn:test",
        status="open",
        created_at="2025-01-01T00:00:00",
    )

    assert finding.scan_id is None


def test_scan_delta_all_empty():
    delta = make_scan_delta()

    assert delta.new_findings == []
    assert delta.resolved_findings == []
    assert delta.persisted_findings == []
    assert delta.regressed_findings == []


def test_scan_delta_summary_string():
    delta = make_scan_delta(new=3, resolved=1, regressed=0)

    assert "3 new" in delta.summary
    assert "1 resolved" in delta.summary
    assert "0 regression" in delta.summary


def test_scan_delta_counts_correct():
    delta = make_scan_delta(new=2, resolved=1, persisted=3, regressed=1)

    assert len(delta.new_findings) == 2
    assert len(delta.resolved_findings) == 1
    assert len(delta.persisted_findings) == 3
    assert len(delta.regressed_findings) == 1


def test_delta_identity_key_is_check_name_plus_resource():
    check = "Overly permissive IAM policy: wildcard Action"
    resource = "arn:aws:iam::123456789012:role/AdminRole"
    findings_a = [
        {
            "check_name": check,
            "resource_arn": resource,
            "id": "id-a",
            "severity": "critical",
        }
    ]
    findings_b = [
        {
            "check_name": check,
            "resource_arn": resource,
            "id": "id-b",
            "severity": "critical",
        }
    ]

    keys_a = {(finding["check_name"], finding["resource_arn"]): finding for finding in findings_a}
    keys_b = {(finding["check_name"], finding["resource_arn"]): finding for finding in findings_b}
    set_a = set(keys_a.keys())
    set_b = set(keys_b.keys())

    assert len(set_b - set_a) == 0
    assert len(set_a - set_b) == 0
    assert len(set_a & set_b) == 1


def test_delta_new_finding_when_check_name_differs():
    findings_a = [
        {
            "check_name": "Check A",
            "resource_arn": "arn:test",
            "id": "1",
            "severity": "high",
        }
    ]
    findings_b = [
        {
            "check_name": "Check B",
            "resource_arn": "arn:test",
            "id": "2",
            "severity": "high",
        }
    ]

    keys_a = {(finding["check_name"], finding["resource_arn"]): finding for finding in findings_a}
    keys_b = {(finding["check_name"], finding["resource_arn"]): finding for finding in findings_b}

    assert len(set(keys_b.keys()) - set(keys_a.keys())) == 1
    assert len(set(keys_a.keys()) - set(keys_b.keys())) == 1


def test_delta_new_finding_when_resource_differs():
    findings_a = [
        {
            "check_name": "Check A",
            "resource_arn": "arn:resource-1",
            "id": "1",
            "severity": "high",
        }
    ]
    findings_b = [
        {
            "check_name": "Check A",
            "resource_arn": "arn:resource-2",
            "id": "2",
            "severity": "high",
        }
    ]

    keys_a = {(finding["check_name"], finding["resource_arn"]): finding for finding in findings_a}
    keys_b = {(finding["check_name"], finding["resource_arn"]): finding for finding in findings_b}

    assert len(set(keys_b.keys()) - set(keys_a.keys())) == 1


def test_regression_medium_to_high():
    assert check_regression("medium", "high") is True


def test_regression_high_to_critical():
    assert check_regression("high", "critical") is True


def test_no_regression_same_severity():
    assert check_regression("high", "high") is False


def test_no_regression_severity_decrease():
    assert check_regression("critical", "high") is False


def test_no_regression_low_to_low():
    assert check_regression("low", "low") is False


def test_regression_informational_to_critical():
    assert check_regression("informational", "critical") is True


def test_regression_all_transitions():
    severities = ["informational", "low", "medium", "high", "critical"]
    for index_a, severity_a in enumerate(severities):
        for index_b, severity_b in enumerate(severities):
            expected = index_b > index_a
            assert check_regression(severity_a, severity_b) == expected, (
                f"check_regression({severity_a!r}, {severity_b!r}) "
                f"should be {expected}"
            )


def test_status_update_open_valid():
    status = StatusUpdate(status="open")

    assert status.status == "open"


def test_status_update_in_progress_valid():
    status = StatusUpdate(status="in_progress")

    assert status.status == "in_progress"


def test_status_update_resolved_valid():
    status = StatusUpdate(status="resolved")

    assert status.status == "resolved"


def test_status_update_accepted_risk_valid():
    status = StatusUpdate(status="accepted_risk")

    assert status.status == "accepted_risk"


def test_status_update_invalid_raises():
    with pytest.raises(ValidationError):
        StatusUpdate(status="wont_fix")


def test_status_update_empty_string_raises():
    with pytest.raises(ValidationError):
        StatusUpdate(status="")


def test_status_update_uppercase_raises():
    with pytest.raises(ValidationError):
        StatusUpdate(status="OPEN")


def test_status_update_close_raises():
    with pytest.raises(ValidationError):
        StatusUpdate(status="closed")


def test_scan_record_fields():
    record = ScanRecord(
        id="scan-123",
        account_id="123456789012",
        status="completed",
        total_findings=5,
        critical_count=2,
        high_count=2,
        medium_count=1,
        low_count=0,
        created_at="2025-01-15T00:00:00",
    )

    assert record.total_findings == 5
    assert record.critical_count == 2
    assert record.account_id == "123456789012"


def test_scan_record_zero_counts():
    record = ScanRecord(
        id="scan-empty",
        account_id="123456789012",
        status="completed",
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        created_at="2025-01-15T00:00:00",
    )

    assert record.total_findings == 0
