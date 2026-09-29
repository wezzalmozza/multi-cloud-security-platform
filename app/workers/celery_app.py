"""
app/workers/celery_app.py
Celery worker for async scan jobs.
Start with: celery -A app.workers.celery_app worker --loglevel=info
"""

from celery import Celery
from app.core.config import settings

celery = Celery(
    "mcpp",
    broker=settings.CELERY_BROKER,
    backend=settings.CELERY_BACKEND,
    include=["app.workers.celery_app"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


@celery.task(bind=True, name="run_scan")
def run_scan_task(self, scan_id: str, module_ids: list, provider: str,
                  credentials: dict, regions: list):
    """
    Celery task that runs a full scan and updates progress via task state.
    The FastAPI endpoint POSTs to /api/v1/scans which enqueues this task.
    """
    from app.services.scan_service import run_modules, _count_severity

    all_findings, all_results = [], []
    total = len(module_ids)

    for event in run_modules(module_ids, provider, credentials, regions):
        # Update task state so callers can poll progress
        self.update_state(state="PROGRESS", meta={
            "scan_id":        scan_id,
            "current_module": event["module_id"],
            "progress":       event["progress"],
            "status":         event["status"],
        })
        if event["result"]:
            all_results.append(event["result"])
            all_findings.extend(event["result"].get("findings", []))

    return {
        "scan_id":         scan_id,
        "status":          "completed",
        "total_findings":  len(all_findings),
        "severity_counts": _count_severity(all_findings),
        "module_results":  all_results,
        "findings":        all_findings,
    }
