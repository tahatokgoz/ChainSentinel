from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ScanCreate(BaseModel):
    scenario: str  # iot, portal, api
    target_host: str = "localhost"
    target_port: int


class FindingOut(BaseModel):
    id: int
    title: str
    severity: str
    category: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    scenario: str
    target_host: str
    target_port: int
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    findings: list[FindingOut] = []

    class Config:
        from_attributes = True


class ScanListOut(BaseModel):
    id: int
    scenario: str
    target_host: str
    target_port: int
    status: str
    findings_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime


class ReportOut(BaseModel):
    id: int
    scan_id: int
    file_path: str
    created_at: datetime

    class Config:
        from_attributes = True


class LabStatus(BaseModel):
    iot_device: str  # up / down
    supplier_portal: str
    wms_api: str
