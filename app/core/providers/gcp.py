"""
app/core/providers/gcp.py
"""

import json

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def credentials(creds: dict):
    from google.oauth2 import service_account
    from google.auth import default as _default

    if creds.get("service_account_file"):
        return service_account.Credentials.from_service_account_file(
            creds["service_account_file"], scopes=SCOPES
        )
    if creds.get("service_account_info"):
        info = creds["service_account_info"]
        if isinstance(info, str):
            info = json.loads(info)
        return service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
    gcreds, _ = _default(scopes=SCOPES)
    return gcreds


def project(creds: dict) -> str:
    return creds.get("project_id", "")


def build(service: str, version: str, creds: dict):
    from googleapiclient import discovery
    return discovery.build(service, version, credentials=credentials(creds))
