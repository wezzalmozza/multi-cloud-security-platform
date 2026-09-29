"""app/api/v1/endpoints/scans.py — Fixed: DB persistence, history endpoint, findings from DB"""
import uuid
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request
from app.api.deps.auth import get_current_user
from app.db.session import AsyncSessionLocal
from app.db.models import Scan, Finding
from sqlalchemy import select
from app.services.scan_service import (
    start_scan_background, get_scan_state,
    run_modules, _count_severity,
)
from app.modules.registry import all_ids, MODULE_META

router = APIRouter(prefix="/scans", tags=["scans"])
log = logging.getLogger(__name__)


def _preflight_auth(provider: str, credentials: dict) -> dict:
    p = (provider or "").lower().strip()
    creds = credentials or {}

    if p == "aws":
        from app.core.providers import aws
        try:
            sts = aws.get_client("sts", creds, "us-east-1")
            ident = sts.get_caller_identity()
            return {
                "provider": "aws",
                "account_id": ident.get("Account", ""),
                "arn": ident.get("Arn", ""),
            }
        except Exception as exc:
            role_arn = str(creds.get("role_arn", "")).strip()
            has_keys = bool(creds.get("access_key_id")) and bool(creds.get("secret_access_key"))
            has_profile = bool(str(creds.get("profile", "")).strip())
            if role_arn and not has_keys and not has_profile:
                raise RuntimeError(
                    "AWS preflight failed: role_arn provided but no source credentials. "
                    "Provide access_key_id+secret_access_key or profile, or configure AWS credentials on the API server environment."
                ) from exc
            raise RuntimeError(f"AWS preflight failed: {str(exc)}") from exc

    if p == "azure":
        from app.core.providers import azure
        token = azure.mgmt_token(creds)
        if not token:
            raise RuntimeError("could not obtain Azure management token")
        return {
            "provider": "azure",
            "subscription_id": creds.get("subscription_id", ""),
            "token_acquired": True,
        }

    if p == "gcp":
        from app.core.providers import gcp
        from google.auth.transport.requests import Request

        gcreds = gcp.credentials(creds)
        gcreds.refresh(Request())

        project = gcp.project(creds)
        if project:
            crm = gcp.build("cloudresourcemanager", "v1", creds)
            crm.projects().get(projectId=project).execute()

        return {
            "provider": "gcp",
            "project_id": project,
            "token_acquired": True,
        }

    raise RuntimeError(f"unsupported provider '{provider}'")


@router.get("/modules")
def list_modules(_: dict = Depends(get_current_user)):
    return {"modules": [{"module_id": mid, **MODULE_META.get(mid, {})} for mid in all_ids()]}


@router.post("/preflight-auth")
async def preflight_auth(request: Request, _: dict = Depends(get_current_user)):
    """Validate cloud credentials before starting a scan."""
    try:
        body = await request.json()
    except Exception as e:
        raise HTTPException(400, detail=f"Invalid JSON: {str(e)}")

    provider = body.get("provider", "")
    credentials = body.get("credentials", {})

    try:
        details = _preflight_auth(provider, credentials)
        return {"ok": True, "details": details}
    except Exception as e:
        log.warning("credential preflight failed for provider=%s: %s", provider, str(e))
        raise HTTPException(400, detail=f"Credential preflight failed: {str(e)}")


@router.post("", status_code=202)
async def start_scan(request: Request, user: dict = Depends(get_current_user)):
    """Start a scan — creates DB record immediately, runs in background, persists findings."""
    try:
        body        = await request.json()
    except Exception as e:
        raise HTTPException(400, detail=f"Invalid JSON: {str(e)}")

    try:
        scan_id     = str(uuid.uuid4())
        provider    = body.get("provider", "aws")
        credentials = body.get("credentials", {})
        regions     = body.get("regions", [])
        module_ids  = body.get("module_ids") or all_ids()
        scan_name   = body.get("name") or f"Scan {scan_id[:8]}"
        owner_id    = user.get("id", "unknown")

        unknown = [m for m in module_ids if m not in MODULE_META]
        if unknown:
            raise HTTPException(400, detail=f"Unknown module_ids: {unknown}")

        # Block scans that cannot authenticate to the selected cloud provider.
        try:
            _preflight_auth(provider, credentials)
        except Exception as e:
            log.warning("scan start blocked by preflight provider=%s: %s", provider, str(e))
            raise HTTPException(400, detail=f"Credential preflight failed: {str(e)}")

        # Create DB record immediately so it appears in history
        async with AsyncSessionLocal() as db:
            scan = Scan(
                id=scan_id, name=scan_name, provider=provider,
                regions=regions, module_ids=module_ids,
                status="running", owner_id=owner_id,
                started_at=datetime.now(timezone.utc),
            )
            db.add(scan)
            await db.commit()

        # Launch background thread with DB callback
        start_scan_background(
            scan_id=scan_id, module_ids=module_ids, provider=provider,
            credentials=credentials, regions=regions,
            db_write_cb=_persist_scan_results,
            owner_id=owner_id,
        )
        return {"scan_id": scan_id, "status": "running",
                "message": f"Scan started. Poll GET /api/v1/scans/{scan_id} for status."}
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, detail=f"Error starting scan: {str(e)}")


async def _persist_scan_results(scan_id: str, findings: list, status: str):
    """Persist completed scan results and findings to DB."""
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = res.scalar_one_or_none()
        if not scan:
            return
        scan.status = status
        scan.progress = 100.0
        scan.completed_at = datetime.now(timezone.utc)
        for f in findings:
            db.add(Finding(
                id=str(uuid.uuid4()), scan_id=scan_id,
                module_id=f.get("module_id", ""),
                title=f.get("title", ""),
                severity=f.get("severity", "INFO"),
                description=f.get("description", ""),
                affected_resource=f.get("affected_resource", ""),
                remediation=f.get("remediation", ""),
                evidence=f.get("evidence", {}),
                cis_controls=f.get("cis_controls", []),
                references=f.get("references", []),
                cloud_provider=f.get("cloud_provider", ""),
                region=f.get("region", ""),
            ))
        await db.commit()


@router.get("")
async def list_scans(user: dict = Depends(get_current_user)):
    """List all scans for current user from DB — powers History and Dashboard pages."""
    owner_id = user.get("id", "unknown")
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(Scan).where(Scan.owner_id == owner_id)
                        .order_by(Scan.created_at.desc()).limit(50)
        )
        scans = res.scalars().all()
    return {"scans": [{
        "scan_id":      s.id,
        "name":         s.name,
        "status":       s.status,
        "provider":     s.provider,
        "progress":     s.progress,
        "created_at":   s.created_at.isoformat()  if s.created_at   else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
    } for s in scans]}


@router.get("/{scan_id}")
async def get_scan(scan_id: str, user: dict = Depends(get_current_user)):
    """Poll status — live in-memory state first, then DB for historical scans."""
    state = get_scan_state(scan_id)
    if state:
        if state.get("owner_id") and state["owner_id"] != user["id"]:
            raise HTTPException(403, detail="Access denied")
        return {k: v for k, v in state.items() if k not in ("credentials", "owner_id")}
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = res.scalar_one_or_none()
        if not scan:
            raise HTTPException(404, detail="Scan not found")
        if scan.owner_id != user["id"]:
            raise HTTPException(403, detail="Access denied")
        return {
            "scan_id": scan.id, "status": scan.status,
            "progress": scan.progress, "provider": scan.provider,
            "regions": scan.regions, "module_ids": scan.module_ids,
            "created_at":   scan.created_at.isoformat()  if scan.created_at   else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        }


@router.get("/{scan_id}/findings")
async def get_findings(
    scan_id: str, severity: Optional[str] = None,
    module_id: Optional[str] = None, user: dict = Depends(get_current_user),
):
    """Get findings — live state if scan just ran, DB for historical scans."""
    # Check live in-memory state first (scan ran in this server process)
    state = get_scan_state(scan_id)
    if state:
        if state.get("owner_id") and state["owner_id"] != user["id"]:
            raise HTTPException(403, detail="Access denied")
        if state["status"] not in ("completed",):
            raise HTTPException(409, detail=f"Scan not completed (status: {state['status']})")
        findings = state.get("findings", [])
        if severity:  findings = [f for f in findings if f["severity"] == severity.upper()]
        if module_id: findings = [f for f in findings if f["module_id"] == module_id]
        return {"scan_id": scan_id, "total": len(findings),
                "severity_counts": _count_severity(findings), "findings": findings}

    # Load from DB for historical / cross-session scans
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = res.scalar_one_or_none()
        if not scan:
            raise HTTPException(404, detail="Scan not found")
        if scan.owner_id != user["id"]:
            raise HTTPException(403, detail="Access denied")
        if scan.status not in ("completed",):
            raise HTTPException(409, detail=f"Scan not completed (status: {scan.status})")

        q = select(Finding).where(Finding.scan_id == scan_id)
        if severity:  q = q.where(Finding.severity == severity.upper())
        if module_id: q = q.where(Finding.module_id == module_id)
        fres = await db.execute(q)
        db_findings = fres.scalars().all()

    findings = [{
        "id": f.id, "scan_id": f.scan_id, "module_id": f.module_id,
        "title": f.title, "severity": f.severity, "description": f.description,
        "affected_resource": f.affected_resource, "remediation": f.remediation,
        "evidence": f.evidence, "cis_controls": f.cis_controls,
        "references": f.references, "cloud_provider": f.cloud_provider, "region": f.region,
    } for f in db_findings]
    return {"scan_id": scan_id, "total": len(findings),
            "severity_counts": _count_severity(findings), "findings": findings}


@router.post("/run-sync")
async def run_sync(request: Request, _: dict = Depends(get_current_user)):
    """Synchronous scan — runs all modules inline and returns. Use for testing."""
    body = await request.json()
    provider    = body.get("provider", "aws")
    credentials = body.get("credentials", {})
    regions     = body.get("regions", [])
    module_ids  = body.get("module_ids") or all_ids()

    unknown = [m for m in module_ids if m not in MODULE_META]
    if unknown:
        raise HTTPException(400, detail=f"Unknown module_ids: {unknown}")

    all_findings, all_results = [], []
    for event in run_modules(module_ids, provider, credentials, regions):
        if event["result"]:
            all_results.append(event["result"])
            all_findings.extend(event["result"].get("findings", []))
    return {"status": "completed", "provider": provider,
            "severity_counts": _count_severity(all_findings),
            "total_findings": len(all_findings),
            "module_results": all_results, "findings": all_findings}


@router.websocket("/{scan_id}/stream")
async def stream_progress(ws: WebSocket, scan_id: str):
    """WebSocket: stream live scan progress after calling POST /scans."""
    await ws.accept()
    sent_count = 0  # how many findings already pushed to client
    try:
        while True:
            state = get_scan_state(scan_id)
            if not state:
                await ws.send_json({"error": "Scan not found"})
                break

            all_findings = state.get("findings", [])
            new_findings = all_findings[sent_count:]
            sent_count  += len(new_findings)

            await ws.send_json({
                "scan_id":        scan_id,
                "status":         state["status"],
                "progress":       state.get("progress", 0),
                "current_module": state.get("current_module"),
                "severity_counts": state.get("severity_counts", {}),
                "findings":       new_findings if new_findings else None,
            })
            if state["status"] in ("completed", "error"):
                break
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        await ws.close()


@router.post("/{scan_id}/report/pdf")
async def get_pdf_report(scan_id: str, user: dict = Depends(get_current_user)):
    """Generate and stream a professional PDF pentest report."""
    from fastapi.responses import StreamingResponse
    import io

    log.info("PDF report requested: scan=%s user=%s", scan_id, user.get("id"))

    findings = []
    scan_info: dict = {"scan_id": scan_id, "provider": "aws"}

    state = get_scan_state(scan_id)
    if state:
        if state.get("owner_id") and state["owner_id"] != user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")
        if state["status"] != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")
        findings  = state.get("findings", [])
        scan_info = {
            "scan_id":  scan_id,
            "provider": state.get("provider", "aws"),
            "name":     state.get("name", ""),
        }
        log.info("PDF: loaded %d findings from memory", len(findings))
    else:
        async with AsyncSessionLocal() as db:
            res = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = res.scalar_one_or_none()
            if not scan:
                log.warning("PDF: scan %s not found in DB", scan_id)
                raise HTTPException(status_code=404, detail="Scan not found")
            if scan.owner_id != user["id"]:
                log.warning("PDF: access denied scan=%s owner=%s user=%s", scan_id, scan.owner_id, user.get("id"))
                raise HTTPException(status_code=403, detail="Access denied")
            if scan.status != "completed":
                raise HTTPException(status_code=400, detail=f"Scan not completed (status: {scan.status})")
            scan_info = {
                "scan_id":  scan_id,
                "provider": scan.provider or "aws",
                "name":     scan.name or "",
            }
            fres = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
            findings = [{
                "title": f.title or "", "severity": f.severity or "INFO",
                "description": f.description or "", "remediation": f.remediation or "",
                "affected_resource": f.affected_resource or "", "module_id": f.module_id or "",
                "cis_controls": f.cis_controls or [], "region": f.region or "",
            } for f in fres.scalars().all()]
            log.info("PDF: loaded %d findings from DB", len(findings))

    # AI narrative — falls back to local summary if API unavailable
    try:
        from app.services.ai_report_service import generate_ai_report, get_anthropic_api_key
        api_key    = get_anthropic_api_key()
        scan_input = {"scan_id": scan_id, "findings": findings, "total": len(findings)}
        log.info("PDF: calling AI report API…")
        ai_report  = await generate_ai_report(scan_input, api_key)
        log.info("PDF: AI report received, risk_score=%s", ai_report.get("risk_score"))
    except Exception as e:
        log.warning("PDF: AI report failed (%s), using fallback", str(e))
        crit = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
        high = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
        risk = min(100, crit * 20 + high * 8 + len(findings) * 2)
        ai_report = {
            "risk_score": risk,
            "executive_summary": (
                f"The assessment identified {len(findings)} security findings, "
                f"including {crit} critical and {high} high severity issues. "
                "Immediate remediation is recommended for all critical findings."
            ),
            "findings": [],
            "remediation_plans": {},
            "cis_mapping": {},
        }

    try:
        from app.services.pdf_report_service import generate_pdf_report
        log.info("PDF: generating PDF for %d findings…", len(findings))
        pdf_bytes = generate_pdf_report(scan_info, findings, ai_report)
        log.info("PDF: generated %d bytes", len(pdf_bytes))
    except Exception as e:
        log.error("PDF: generation failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

    filename = f"pentest-report-{scan_id[:8]}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{scan_id}/report/ai")
async def get_ai_report(scan_id: str, user: dict = Depends(get_current_user)):
    """Generate AI report — checks in-memory state first, falls back to DB for historical scans."""
    findings = []

    # 1. Try live in-memory state first
    state = get_scan_state(scan_id)
    if state:
        if state.get("owner_id") and state["owner_id"] != user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")
        if state["status"] != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")
        findings = state.get("findings", [])
    else:
        # 2. Fall back to DB for historical / cross-session scans
        async with AsyncSessionLocal() as db:
            res = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = res.scalar_one_or_none()
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")
            if scan.owner_id != user["id"]:
                raise HTTPException(status_code=403, detail="Access denied")
            if scan.status != "completed":
                raise HTTPException(status_code=400, detail=f"Scan not completed (status: {scan.status})")

            fres = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
            db_findings = fres.scalars().all()
            findings = [{
                "title": f.title, "severity": f.severity,
                "description": f.description, "remediation": f.remediation,
                "affected_resource": f.affected_resource, "module_id": f.module_id,
                "cis_controls": f.cis_controls or [],
            } for f in db_findings]

    # 3. Try real AI report via Anthropic API
    try:
        from app.services.ai_report_service import generate_ai_report, get_anthropic_api_key
        api_key = get_anthropic_api_key()
        scan_result = {"scan_id": scan_id, "findings": findings, "total": len(findings)}
        ai_report = await generate_ai_report(scan_result, api_key)
        return {"scan_id": scan_id, "ai_report": ai_report}
    except Exception as e:
        log.warning("AI report (Anthropic API) failed, using fallback: %s", str(e))

    # 4. Fallback: synthesize report locally without AI
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get((f.get("severity") or "INFO").upper(), 5))
    crit = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
    high = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
    med  = sum(1 for f in findings if (f.get("severity") or "").upper() == "MEDIUM")
    low  = sum(1 for f in findings if (f.get("severity") or "").upper() == "LOW")
    risk_score = min(100, crit * 20 + high * 8 + len(findings) * 2)

    remediation_plans = {}
    if crit:
        remediation_plans["CRITICAL"] = {
            "summary": f"{crit} critical finding(s) require immediate attention to prevent active exploitation.",
            "steps": [
                "Identify all affected resources listed under critical findings.",
                "Apply emergency patches or configuration changes immediately.",
                "Validate fixes and re-run the scan to confirm remediation.",
            ],
            "estimated_effort": f"{crit * 2}-{crit * 4} hours",
        }
    if high:
        remediation_plans["HIGH"] = {
            "summary": f"{high} high-severity finding(s) that significantly increase your attack surface.",
            "steps": [
                "Prioritize and schedule remediation within 48 hours.",
                "Apply recommended configuration changes for each finding.",
                "Review IAM policies and network access controls.",
            ],
            "estimated_effort": f"{high}-{high * 2} hours",
        }
    if med:
        remediation_plans["MEDIUM"] = {
            "summary": f"{med} medium-severity finding(s) that should be addressed in the next sprint.",
            "steps": [
                "Review each finding and assess business impact.",
                "Apply security hardening according to CIS benchmarks.",
                "Enable relevant logging and monitoring controls.",
            ],
            "estimated_effort": f"{med // 2 + 1}-{med} hours",
        }
    if low:
        remediation_plans["LOW"] = {
            "summary": f"{low} low-severity finding(s) for ongoing hygiene improvements.",
            "steps": [
                "Address during routine maintenance windows.",
                "Enable best-practice settings where not already applied.",
                "Document accepted risks with business justification.",
            ],
            "estimated_effort": f"{max(1, low // 2)}-{low} hours",
        }

    # Build CIS mapping from actual finding data
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    cis_map: dict = {}
    for f in findings:
        for ctrl in (f.get("cis_controls") or []):
            if ctrl not in cis_map:
                cis_map[ctrl] = {"title": ctrl, "status": "FAIL",
                                 "findings_count": 0, "highest_severity": "INFO",
                                 "remediation_note": f.get("remediation", "Apply the recommended configuration change.")}
            cis_map[ctrl]["findings_count"] += 1
            fsev = (f.get("severity") or "INFO").upper()
            if sev_rank.get(fsev, 0) > sev_rank.get(cis_map[ctrl]["highest_severity"], 0):
                cis_map[ctrl]["highest_severity"] = fsev

    return {
        "scan_id": scan_id,
        "ai_report": {
            "risk_score": risk_score,
            "executive_summary": (
                f"The assessment identified {len(findings)} security issues across your cloud environment, "
                f"including {crit} critical and {high} high severity findings. "
                f"Immediate remediation is recommended for critical issues."
            ),
            "findings": [{
                "severity": (f.get("severity") or "medium").lower(),
                "title": f.get("title", "Security Issue"),
                "explanation": f.get("description", "Review this finding and apply appropriate remediation."),
                "remediation_guidance": f.get("remediation", "Follow cloud provider best-practice documentation for this control."),
                "fix_cli": "",
                "cis_controls": f.get("cis_controls") or [],
            } for f in sorted_findings[:10]],
            "remediation_plans": remediation_plans,
            "cis_mapping": cis_map,
        }
    }
