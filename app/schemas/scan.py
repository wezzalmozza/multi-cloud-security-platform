"""
app/schemas/scan.py + finding.py
"""

from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


# ── Scan ──────────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    name:        str         = Field(..., min_length=1, max_length=128)
    provider:    str         = Field(..., pattern="^(aws|azure|gcp)$")
    credentials: dict        = Field(..., description="Cloud provider credentials")
    regions:     list[str]   = Field(default=["us-east-1"])
    module_ids:  list[str]   = Field(default=[])


class ScanResponse(BaseModel):
    id:             str
    name:           str
    provider:       str
    regions:        list[str]
    module_ids:     list[str]
    status:         str
    progress:       float
    current_module: str
    error_message:  str
    created_at:     datetime
    started_at:     Optional[datetime]
    completed_at:   Optional[datetime]
    owner_id:       str

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    id:           str
    name:         str
    provider:     str
    status:       str
    progress:     float
    created_at:   datetime
    completed_at: Optional[datetime]
    total_findings: int = 0
    critical_count: int = 0
    high_count:     int = 0

    class Config:
        from_attributes = True


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingSchema(BaseModel):
    id:                str
    scan_id:           str
    module_id:         str
    title:             str
    severity:          str
    description:       str
    affected_resource: str
    remediation:       str
    evidence:          dict[str, Any]
    cis_controls:      list[str]
    references:        list[str]
    cloud_provider:    str
    region:            str
    status:            str
    discovered_at:     datetime

    class Config:
        from_attributes = True


class FindingList(BaseModel):
    scan_id:  str
    total:    int
    findings: list[FindingSchema]


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|accepted|fixed)$")
