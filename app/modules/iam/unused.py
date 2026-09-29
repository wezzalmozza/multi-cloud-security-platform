"""app/modules/iam/unused.py — Stale credentials (90+ days)."""
import time
import logging
from datetime import datetime, timezone, timedelta
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)

STALE_DAYS = 90


class IAMUnusedModule(BaseModule):
    MODULE_ID    = "iam-unused"
    MODULE_NAME  = "Unused Credentials Detection"
    CATEGORY     = "IAM"
    CIS_CONTROLS = ["CIS 1.12", "CIS 1.13"]

    def run(self) -> ModuleResult:
        t0 = time.time()
        try:
            if self.provider == CloudProvider.AWS:     self._aws()
            elif self.provider == CloudProvider.AZURE: self._azure()
            elif self.provider == CloudProvider.GCP:   self._gcp()
        except Exception as e:
            return self._error(str(e))
        return self._ok(time.time() - t0)

    def _aws(self):
        iam    = aws.get_client("iam", self.credentials)
        now    = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=STALE_DAYS)
        iam.generate_credential_report()
        import time as _t; _t.sleep(2)
        lines  = iam.get_credential_report()["Content"].decode().splitlines()
        header = lines[0].split(",")
        for line in lines[1:]:
            row  = dict(zip(header, line.split(",")))
            user = row["user"]
            if user == "<root_account>": continue
            self._resources_checked += 1
            # Stale password
            lu = _dt(row.get("password_last_used", ""))
            if row.get("password_enabled") == "true" and lu and lu < cutoff:
                age = (now - lu).days
                self._add(title=f"Stale Console Password ({age} days)", severity=Severity.MEDIUM,
                          description=f"User '{user}' password unused for {age} days.",
                          affected_resource=f"arn:aws:iam::user/{user}",
                          remediation="Disable or remove console access for inactive users.",
                          evidence={"last_used": row.get("password_last_used"), "days": age})
            # Stale access keys
            for n in ("1", "2"):
                if row.get(f"access_key_{n}_active") != "true": continue
                self._resources_checked += 1
                lu_key = _dt(row.get(f"access_key_{n}_last_used_date", ""))
                if not lu_key:
                    created = _dt(row.get(f"access_key_{n}_last_rotated", ""))
                    if created and created < cutoff:
                        age = (now - created).days
                        self._add(title=f"Access Key {n} Never Used ({age} days old)", severity=Severity.HIGH,
                                  description=f"User '{user}' has an active key that has never been used.",
                                  affected_resource=f"arn:aws:iam::user/{user}/access-key-{n}",
                                  remediation="Delete keys that have never been used.",
                                  evidence={"age_days": age})
                elif lu_key < cutoff:
                    age = (now - lu_key).days
                    self._add(title=f"Access Key {n} Unused for {age} Days", severity=Severity.HIGH,
                              description=f"User '{user}' key {n} not used in {age} days.",
                              affected_resource=f"arn:aws:iam::user/{user}/access-key-{n}",
                              remediation="Deactivate and delete keys unused for 90+ days. Use IAM roles instead.",
                              evidence={"last_used": str(lu_key), "days": age})

    def _azure(self):
        import requests
        from app.core.providers import azure
        token = azure.graph_token(self.credentials)
        now   = datetime.now(timezone.utc)
        resp  = requests.get(
            "https://graph.microsoft.com/v1.0/applications?$select=displayName,appId,passwordCredentials",
            headers={"Authorization": f"Bearer {token}"}, timeout=15)
        resp.raise_for_status()
        for app in resp.json().get("value", []):
            self._resources_checked += 1
            for cred in app.get("passwordCredentials", []):
                end = _dt(cred.get("endDateTime", ""))
                if end and end < now:
                    self._add(title=f"Expired Client Secret on App '{app['displayName']}'",
                              severity=Severity.MEDIUM,
                              description="An expired client secret has not been removed.",
                              affected_resource=f"app/{app['appId']}",
                              remediation="Remove expired secrets from app registrations.",
                              evidence={"expired_at": cred.get("endDateTime")},
                              cis_controls=["CIS Azure 1.3"])

    def _gcp(self):
        from app.core.providers import gcp
        service = gcp.build("iam", "v1", self.credentials)
        project = gcp.project(self.credentials)
        now     = datetime.now(timezone.utc)
        cutoff  = now - timedelta(days=STALE_DAYS)
        for sa in service.projects().serviceAccounts().list(
                name=f"projects/{project}").execute().get("accounts", []):
            self._resources_checked += 1
            for key in service.projects().serviceAccounts().keys().list(
                    name=sa["name"], keyTypes=["USER_MANAGED"]).execute().get("keys", []):
                created = _dt(key.get("validAfterTime", ""))
                if created and created < cutoff:
                    age = (now - created).days
                    self._add(title=f"Service Account Key {age} Days Old",
                              severity=Severity.HIGH,
                              description=f"SA '{sa['email']}' key is {age} days old.",
                              affected_resource=key["name"],
                              remediation="Rotate or delete service account keys older than 90 days. Use Workload Identity instead.",
                              evidence={"age_days": age},
                              cis_controls=["CIS GCP 1.4"])


def _dt(val: str):
    if not val or val in ("N/A", "no_information", "not_supported"): return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try: return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
        except ValueError: pass
    return None
