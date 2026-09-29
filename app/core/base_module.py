"""
app/core/base_module.py
Base classes shared by all 18 pentesting modules.
"""

from __future__ import annotations
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class CloudProvider(str, Enum):
    AWS   = "aws"
    AZURE = "azure"
    GCP   = "gcp"


@dataclass
class Finding:
    module_id:         str
    title:             str
    severity:          Severity
    description:       str
    affected_resource: str
    remediation:       str
    evidence:          dict[str, Any] = field(default_factory=dict)
    cis_controls:      list[str]      = field(default_factory=list)
    references:        list[str]      = field(default_factory=list)
    cloud_provider:    str = ""
    region:            str = ""
    discovered_at:     str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "module_id":         self.module_id,
            "title":             self.title,
            "severity":          self.severity.value,
            "description":       self.description,
            "affected_resource": self.affected_resource,
            "remediation":       self.remediation,
            "evidence":          self.evidence,
            "cis_controls":      self.cis_controls,
            "references":        self.references,
            "cloud_provider":    self.cloud_provider,
            "region":            self.region,
            "discovered_at":     self.discovered_at,
        }


@dataclass
class ModuleResult:
    module_id:         str
    module_name:       str
    status:            str   # completed | error | skipped
    findings:          list[Finding] = field(default_factory=list)
    resources_checked: int           = 0
    error_message:     str           = ""
    duration_seconds:  float         = 0.0
    started_at:        str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def finding_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "module_id":         self.module_id,
            "module_name":       self.module_name,
            "status":            self.status,
            "findings":          [f.to_dict() for f in self.findings],
            "finding_counts":    self.finding_counts,
            "resources_checked": self.resources_checked,
            "error_message":     self.error_message,
            "duration_seconds":  round(self.duration_seconds, 2),
            "started_at":        self.started_at,
        }


class BaseModule:
    """
    All 18 modules inherit from this.
    Subclasses implement run() and optionally override supports_provider().
    """
    MODULE_ID:    str       = "base"
    MODULE_NAME:  str       = "Base Module"
    CATEGORY:     str       = "general"
    CIS_CONTROLS: list[str] = []

    def __init__(self, provider: CloudProvider, credentials: dict, regions: list[str]):
        self.provider    = provider
        self.credentials = credentials
        self.regions     = regions
        self._findings:           list[Finding] = []
        self._resources_checked:  int           = 0
        self._log = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")

    def supports_provider(self, provider: CloudProvider) -> bool:
        return True

    def run(self) -> ModuleResult:
        raise NotImplementedError

    # ── Helpers for subclasses ────────────────────────────────────────────────

    def _add(self, **kwargs) -> None:
        """Add a finding. module_id and cloud_provider are auto-filled."""
        kwargs.setdefault("module_id",      self.MODULE_ID)
        kwargs.setdefault("cloud_provider", self.provider.value)
        kwargs.setdefault("cis_controls",   self.CIS_CONTROLS)
        self._findings.append(Finding(**kwargs))

    def _ok(self, duration: float = 0.0) -> ModuleResult:
        self._log.info(
            "[%s] completed: provider=%s, resources_checked=%d, findings=%d, duration=%.2fs",
            self.MODULE_ID, self.provider.value, self._resources_checked, len(self._findings), duration
        )
        return ModuleResult(
            module_id=self.MODULE_ID, module_name=self.MODULE_NAME,
            status="completed", findings=self._findings,
            resources_checked=self._resources_checked, duration_seconds=duration,
        )

    def _skip(self, reason: str) -> ModuleResult:
        self._log.info("[%s] skipped: %s", self.MODULE_ID, reason)
        return ModuleResult(
            module_id=self.MODULE_ID, module_name=self.MODULE_NAME,
            status="skipped", error_message=reason,
        )

    def _error(self, message: str) -> ModuleResult:
        self._log.error("[%s] error: %s", self.MODULE_ID, message)
        return ModuleResult(
            module_id=self.MODULE_ID, module_name=self.MODULE_NAME,
            status="error", error_message=message,
        )
