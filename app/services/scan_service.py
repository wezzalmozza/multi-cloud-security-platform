"""
app/services/scan_service.py
All business logic for creating, running, and persisting scans.
"""

from __future__ import annotations
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import select, update, insert, create_engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Scan, Finding
from app.modules.registry import load, all_ids, MODULE_META
from app.core.base_module import CloudProvider, ModuleResult
from app.core.config import settings

log = logging.getLogger(__name__)


# ── Run modules ───────────────────────────────────────────────────────────────

def run_modules(
    module_ids:  list[str],
    provider:    str,
    credentials: dict,
    regions:     list[str],
) -> Generator[dict, None, None]:
    """
    Yield progress events as each module completes.
    Each event: { module_id, status, progress, result | None }
    """
    cloud = CloudProvider(provider.lower())
    total = len(module_ids)
    for idx, mid in enumerate(module_ids, 1):
        yield {"module_id": mid, "status": "running",
               "progress": round((idx - 1) / total * 100, 1), "result": None}
        try:
            cls    = load(mid)
            result = cls(cloud, credentials, regions).run()
        except Exception as exc:
            result = ModuleResult(module_id=mid, module_name=mid,
                                  status="error", error_message=str(exc))
        yield {"module_id": mid, "status": result.status,
               "progress": round(idx / total * 100, 1), "result": result.to_dict()}


# ── In-memory scan state ──────────────────────────────────────────────────────

_RUNNING: dict[str, dict] = {}


def start_scan_background(
    scan_id:     str,
    module_ids:  list[str],
    provider:    str,
    credentials: dict,
    regions:     list[str],
    db_write_cb,          # async callback(scan_id, findings, status) → writes to DB
    owner_id:    str = "",
) -> None:
    """Launch scan in a daemon thread. Updates _RUNNING[scan_id] after each module."""
    _RUNNING[scan_id] = {
        "status": "running", "progress": 0.0,
        "current_module": None, "findings": [], "module_results": [],
        "owner_id": owner_id,
    }
    t = threading.Thread(
        target=_thread_body,
        args=(scan_id, module_ids, provider, credentials, regions, db_write_cb),
        daemon=True,
    )
    t.start()


def _thread_body(scan_id, module_ids, provider, credentials, regions, db_write_cb):
    store        = _RUNNING[scan_id]
    all_findings = []
    all_results  = []
    status       = "completed"

    try:
        for event in run_modules(module_ids, provider, credentials, regions):
            store["progress"]       = event["progress"]
            store["current_module"] = event["module_id"]
            if event["result"]:
                all_results.append(event["result"])
                new = event["result"].get("findings", [])
                all_findings.extend(new)
                # push findings into shared state immediately so WS can stream them
                store["findings"]        = list(all_findings)
                store["severity_counts"] = _count_severity(all_findings)

        log.info("[scan %s] modules completed, found %d findings", scan_id, len(all_findings))
        if not all_findings:
            log.info("[scan %s] no findings detected by selected modules", scan_id)

        store.update({
            "status":          "completed",
            "progress":        100.0,
            "findings":        all_findings,
            "module_results":  all_results,
            "severity_counts": _count_severity(all_findings),
        })

    except Exception as exc:
        status = "error"
        store.update({"status": "error", "error": str(exc)})
        log.error("[scan %s] thread error: %s", scan_id, exc, exc_info=True)

    # ── Persist findings to DB via the async callback ─────────────────────────
    import asyncio
    log.info("[scan %s] persisting %d findings to DB", scan_id, len(all_findings))
    try:
        asyncio.run(db_write_cb(scan_id, all_findings, status))
        log.info("[scan %s] DB persistence complete (status=%s)", scan_id, status)
    except Exception as exc:
        log.error("[scan %s] DB persist failed: %s", scan_id, exc, exc_info=True)


def get_scan_state(scan_id: str) -> dict | None:
    return _RUNNING.get(scan_id)


def _count_severity(findings: list[dict]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ── DB async helpers (used by other services if needed) ──────────────────────

async def get_scan_by_id(db: AsyncSession, scan_id: str) -> Scan | None:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    return result.scalar_one_or_none()


async def get_scans_for_user(db: AsyncSession, user_id: str) -> list[Scan]:
    result = await db.execute(
        select(Scan).where(Scan.owner_id == user_id).order_by(Scan.created_at.desc())
    )
    return list(result.scalars().all())


async def save_findings(db: AsyncSession, scan_id: str, findings: list[dict]) -> None:
    for f in findings:
        db.add(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            module_id=f.get("module_id", ""), title=f.get("title", ""),
            severity=f.get("severity", "INFO"), description=f.get("description", ""),
            affected_resource=f.get("affected_resource", ""),
            remediation=f.get("remediation", ""),
            evidence=f.get("evidence", {}), cis_controls=f.get("cis_controls", []),
            references=f.get("references", []), cloud_provider=f.get("cloud_provider", ""),
            region=f.get("region", ""),
        ))
    await db.commit()
