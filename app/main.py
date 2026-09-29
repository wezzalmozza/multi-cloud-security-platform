"""
app/main.py
FastAPI application entry point.
All routers are registered here — nothing else lives here.
"""

import logging
import sys

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
import os

from app.core.config import settings


def _setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"
    ))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = [handler]                              # replace whatever uvicorn left on root
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)  # silence per-request noise


@asynccontextmanager
async def lifespan(app: FastAPI):
    _setup_logging()   # runs after uvicorn finishes its own logging setup
    logging.getLogger(__name__).info("MCPP startup — logging active")
    yield
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.scans import router as scans_router
from app.services.ai_report_service import generate_ai_report
from app.db.models import Scan, Finding
from app.db.session import AsyncSessionLocal
from sqlalchemy import select

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Multi-Cloud Penetration Testing Platform API",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["system"])
def health():
    logging.getLogger(__name__).info("health check called")
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "env": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ── Modules List ──────────────────────────────────────────────────────────────
@app.get("/api/v1/modules", tags=["modules"])
def list_all_modules():
    from app.modules.registry import all_ids, MODULE_META

    return {
        "modules": [
            {"module_id": mid, **MODULE_META[mid]}
            for mid in all_ids()
        ]
    }


@app.post("/api/debug/test-finding/{scan_id}")
async def test_finding(scan_id: str):
    """Debug endpoint to test database finding insertion"""
    import uuid
    from datetime import datetime, timezone
    import logging

    log = logging.getLogger(__name__)

    try:
        async with AsyncSessionLocal() as db:
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                module_id="test",
                title="Test Finding",
                severity="HIGH",
                description="This is a test finding",
                affected_resource="test-resource",
                remediation="Fix this test",
                cloud_provider="AWS",
                region="us-east-1"
            )
            db.add(finding)
            await db.commit()
            log.info(f"Test finding created for scan {scan_id}")

        return {"message": "Test finding created"}
    except Exception as e:
        log.error(f"Test finding error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=settings.API_WORKERS,
        reload=settings.DEBUG
    )