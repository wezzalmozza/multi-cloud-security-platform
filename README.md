# Multi-Cloud Pentest Platform (MCPP)

A production-ready platform for automated security assessments across AWS, Azure, and GCP.

## Project Structure

```
mcpp/
├── backend/                        # Python / FastAPI backend
│   ├── app/
│   │   ├── api/
│   │   │   ├── deps/               # Shared FastAPI dependencies (auth, db)
│   │   │   └── v1/
│   │   │       └── endpoints/      # One file per resource group
│   │   │           ├── auth.py
│   │   │           ├── scans.py
│   │   │           ├── findings.py
│   │   │           └── reports.py
│   │   ├── core/
│   │   │   ├── config.py           # Settings (pydantic-settings + .env)
│   │   │   ├── security.py         # JWT creation / verification
│   │   │   ├── base_module.py      # BaseModule, Finding, ModuleResult
│   │   │   └── providers/
│   │   │       ├── aws.py          # boto3 client factory
│   │   │       ├── azure.py        # azure-identity factory
│   │   │       └── gcp.py          # google-auth factory
│   │   ├── db/
│   │   │   ├── session.py          # SQLAlchemy async engine + session
│   │   │   └── models.py           # ORM models (User, Scan, Finding)
│   │   ├── modules/                # One sub-package per category
│   │   │   ├── registry.py         # Central module registry
│   │   │   ├── iam/
│   │   │   │   ├── overpermissive.py
│   │   │   │   ├── mfa.py
│   │   │   │   ├── unused.py
│   │   │   │   ├── privilege_escalation.py
│   │   │   │   └── root_usage.py
│   │   │   ├── network/
│   │   │   │   ├── public_exposure.py
│   │   │   │   ├── sg_audit.py
│   │   │   │   ├── nacl.py
│   │   │   │   └── flow_logs.py
│   │   │   ├── storage/
│   │   │   │   ├── public_buckets.py
│   │   │   │   ├── encryption.py
│   │   │   │   ├── logging.py
│   │   │   │   └── versioning.py
│   │   │   ├── compute/
│   │   │   │   ├── public_ip.py
│   │   │   │   ├── ssh_rdp.py
│   │   │   │   └── metadata.py
│   │   │   └── compliance/
│   │   │       ├── cis_benchmark.py
│   │   │       └── logging_monitoring.py
│   │   ├── schemas/
│   │   │   ├── auth.py             # LoginRequest, Token
│   │   │   ├── scan.py             # ScanCreate, ScanResponse
│   │   │   └── finding.py          # FindingSchema, FindingList
│   │   ├── services/
│   │   │   ├── scan_service.py     # Business logic: start, run, store scan
│   │   │   └── report_service.py   # Generate PDF / HTML / JSON reports
│   │   ├── workers/
│   │   │   └── celery_app.py       # Celery app + scan task
│   │   └── main.py                 # FastAPI app entry point
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_auth.py
│   │   ├── test_scans.py
│   │   └── modules/
│   │       └── test_iam.py
│   ├── scripts/
│   │   └── seed_db.py              # Create demo users
│   ├── .env.example
│   ├── requirements.txt
│   └── Dockerfile
│
└── frontend/                       # Vanilla HTML/CSS/JS (zero dependencies)
    ├── index.html                  # Login page
    ├── pages/                      # One file per view
    │   ├── dashboard.html
    │   ├── new-scan.html           # Wizard steps 1-3
    │   ├── execution.html          # Live scan progress (WebSocket)
    │   ├── findings.html           # Filterable findings table
    │   ├── report.html             # Report generation
    │   ├── history.html
    │   ├── compliance.html
    │   └── profile.html
    └── assets/
        ├── css/
        │   └── app.css             # Single stylesheet
        └── js/
            ├── api/
            │   └── client.js       # All fetch() calls in one place
            ├── components/
            │   ├── sidebar.js      # Shared sidebar component
            │   ├── modal.js        # Reusable modal
            │   └── toast.js        # Notifications
            ├── pages/
            │   ├── dashboard.js
            │   ├── new-scan.js
            │   ├── execution.js
            │   └── findings.js
            └── utils/
                ├── auth.js         # Token storage / guard
                └── helpers.js      # Format dates, severity badges, etc.

```

## Quick Start

```bash
# Backend
cd backend
cp .env.example .env          # fill in secrets
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend (no build step)
cd frontend
python -m http.server 3000
# open http://localhost:3000
```

## Tech Stack

| Layer       | Technology                              |
|-------------|------------------------------------------|
| API         | FastAPI + Uvicorn                        |
| Auth        | JWT (python-jose) + bcrypt               |
| Database    | PostgreSQL (SQLAlchemy async) + Alembic  |
| Cache/Queue | Redis + Celery                           |
| Scanning    | boto3 / azure-sdk / google-cloud         |
| Reports     | WeasyPrint (PDF) + Jinja2 (HTML)         |
| Frontend    | Vanilla HTML/CSS/JS — zero dependencies  |
