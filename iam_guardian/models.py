from enum import Enum
from typing import List, Optional

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
