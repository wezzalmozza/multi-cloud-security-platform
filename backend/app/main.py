"""
app/main.py
FastAPI application entry point.
All routers are registered here — nothing else lives here.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
import os

from app.core.config import settings
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.scans import router as scans_router
from app.services.ai_report_service import generate_ai_report
from app.db.models import Scan
from app.db.session import SessionLocal

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Multi-Cloud Penetration Testing Platform API",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
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


# ── AI REPORT GENERATION ──────────────────────────────────────────────────────
@app.post("/api/report/{scan_id}/ai")
async def get_ai_report(scan_id: str):
    """
    Generate AI analysis for a completed scan
    """
    db = SessionLocal()

    try:
        # Get scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Ensure scan is completed
        if scan.status != "completed":
            raise HTTPException(
                status_code=400,
                detail="Scan is not completed yet"
            )

        # API key check
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise HTTPException(
                status_code=500,
                detail="ANTHROPIC_API_KEY not set"
            )

        # Safe serialization of findings
        safe_findings = []
        for f in getattr(scan, "findings", []):
            safe_findings.append({
                "title": getattr(f, "title", ""),
                "severity": getattr(f, "severity", ""),
                "description": getattr(f, "description", ""),
                "remediation": getattr(f, "remediation", ""),
                "affected_resource": getattr(f, "affected_resource", ""),
            })

        # Call AI service
        report = await generate_ai_report(
            {
                "scan_id": scan_id,
                "findings": safe_findings
            },
            api_key
        )

        return {
            "scan_id": scan_id,
            "ai_report": report
        }

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"AI report generation failed: {str(e)}"
        )

    finally:
        # Always close DB session
        db.close()


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