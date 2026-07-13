from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    resource: str
    description: str
    recommendation: str
    tags: Optional[List[str]] = []


class AuditRequest(BaseModel):
    account_id: str
    region: Optional[str] = "us-east-1"
    dry_run: Optional[bool] = False


class AuditResponse(BaseModel):
    audit_id: str
    account_id: str
    status: str
    findings: List[Finding]
    total_findings: int
    run_at: str


class FindingRecord(BaseModel):
    id: str
    check_name: str
    severity: str
    resource_arn: str
    raw_data: dict
    llm_explanation: Optional[str] = None
    status: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class IAMStatement(BaseModel):
    Sid: Optional[str] = None
    Effect: str
    Action: Union[str, List[str]]
    Resource: Union[str, List[str]]
    Principal: Optional[Union[str, dict]] = None
    Condition: Optional[dict] = None


class IAMPolicyModel(BaseModel):
    Version: Optional[str] = "2012-10-17"
    Statement: List[IAMStatement]


class SimulationResult(BaseModel):
    status: str
    original_actions: List[str]
    denied_actions: List[str]
    allowed_actions: List[str]
    detail: str


class RewriteResponse(BaseModel):
    finding_id: str
    check_name: str
    original_policy: dict
    rewritten_policy: dict
    diff_summary: str
    simulation_result: SimulationResult
    rewrite_status: str


class PolicyRewriteRecord(BaseModel):
    id: str
    finding_id: str
    original_policy: dict
    rewritten_policy: dict
    diff_summary: Optional[str] = None
    simulation_result: Optional[dict] = None
    rewrite_status: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class EscalationPathRecord(BaseModel):
    id: str
    account_id: str
    principal_arn: str
    principal_type: str
    principal_name: str
    matched_combo: List[str]
    effective_permissions: Optional[List[str]] = None
    severity: str
    title: str
    description: Optional[str] = None
    attack_story: Optional[str] = None
    narrative: Optional[str] = None
    tags: Optional[List[str]] = None
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class EscalationScanResponse(BaseModel):
    account_id: str
    scan_id: str
    total_paths: int
    critical_count: int
    high_count: int
    paths: List[EscalationPathRecord]
    scanned_at: str


class ControlResult(BaseModel):
    control_id: str
    control_title: str
    status: str
    finding_count: int
    findings: List[str]


class FrameworkSection(BaseModel):
    framework: str
    total_controls: int
    passing_controls: int
    failing_controls: int
    pass_rate: float
    controls: List[ControlResult]
    executive_summary: str


class ComplianceReport(BaseModel):
    account_id: str
    report_id: str
    generated_at: str
    total_findings_analyzed: int
    frameworks: List[FrameworkSection]
    overall_pass_rate: float
