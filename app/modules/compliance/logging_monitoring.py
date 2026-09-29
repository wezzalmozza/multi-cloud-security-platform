"""app/modules/compliance/logging_monitoring.py — CloudTrail / Azure Activity Logs / GCP audit logs."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class LoggingMonitoringModule(BaseModule):
    MODULE_ID    = "compliance-logging"
    MODULE_NAME  = "Logging & Monitoring"
    CATEGORY     = "Compliance"
    CIS_CONTROLS = ["CIS 3.1", "CIS 3.2", "CIS 3.3"]

    def run(self) -> ModuleResult:
        t0 = time.time()
        try:
            if self.provider == CloudProvider.AWS:
                for r in self.regions: self._aws(r)
            elif self.provider == CloudProvider.AZURE: self._azure()
            elif self.provider == CloudProvider.GCP:   self._gcp()
        except Exception as e:
            return self._error(str(e))
        return self._ok(time.time() - t0)

    def _aws(self, region: str):
        ct = aws.get_client("cloudtrail", self.credentials, region)
        self._resources_checked += 1
        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        except Exception as exc:
            msg = str(exc)
            if "AccessDenied" in msg or "UnauthorizedOperation" in msg:
                log.warning("[%s] cannot verify CloudTrail in %s due to permission error: %s", self.MODULE_ID, region, msg)
                return
            raise
        if not trails:
            self._add(title="CloudTrail Not Enabled", severity=Severity.CRITICAL,
                      description=f"No CloudTrail trail in '{region}'. API activity is unlogged.",
                      affected_resource=f"arn:aws:cloudtrail:{region}",
                      region=region,
                      remediation="Create a multi-region CloudTrail trail sending events to S3 and CloudWatch Logs.",
                      cis_controls=["CIS 3.1"])
            return
        for trail in trails:
            self._resources_checked += 1
            arn = trail["TrailARN"]
            if not trail.get("IsMultiRegionTrail"):
                self._add(title="CloudTrail Not Multi-Region", severity=Severity.MEDIUM,
                          description=f"Trail '{trail['Name']}' is single-region. Activity in other regions is invisible.",
                          affected_resource=arn, region=region,
                          remediation="Convert to a multi-region trail.",
                          cis_controls=["CIS 3.1"])
            if not trail.get("LogFileValidationEnabled"):
                self._add(title="CloudTrail Log File Validation Disabled", severity=Severity.MEDIUM,
                          description=f"Trail '{trail['Name']}' has no log file validation. Logs can be tampered undetected.",
                          affected_resource=arn, region=region,
                          remediation="Enable log file validation on the trail.",
                          cis_controls=["CIS 3.2"])
            if not trail.get("CloudWatchLogsLogGroupArn"):
                self._add(title="CloudTrail Not Integrated with CloudWatch Logs", severity=Severity.MEDIUM,
                          description=f"Trail '{trail['Name']}' does not send to CloudWatch Logs. Real-time alerting is impossible.",
                          affected_resource=arn, region=region,
                          remediation="Configure CloudWatch Logs delivery for real-time alerting.",
                          cis_controls=["CIS 3.4"])
            try:
                status = ct.get_trail_status(Name=arn)
                if not status.get("IsLogging"):
                    self._add(title="CloudTrail Logging is Stopped", severity=Severity.CRITICAL,
                              description=f"Trail '{trail['Name']}' exists but logging is OFF.",
                              affected_resource=arn, region=region,
                              remediation="Re-enable logging on the trail immediately.",
                              cis_controls=["CIS 3.1"])
            except Exception:
                pass

    def _azure(self):
        import requests
        from app.core.providers import azure
        token = azure.mgmt_token(self.credentials)
        sub   = self.credentials.get("subscription_id", "")
        resp  = requests.get(
            f"https://management.azure.com/subscriptions/{sub}/providers/"
            "microsoft.insights/logprofiles?api-version=2016-03-01",
            headers={"Authorization": f"Bearer {token}"}, timeout=15)
        self._resources_checked += 1
        if not resp.ok: return
        profiles = resp.json().get("value", [])
        if not profiles:
            self._add(title="No Azure Activity Log Profile Configured", severity=Severity.HIGH,
                      description="No log profile for Azure Activity Logs. Control-plane operations not archived.",
                      affected_resource=f"subscriptions/{sub}",
                      remediation="Create a diagnostic setting exporting Activity Logs to Storage or Log Analytics.",
                      cis_controls=["CIS Azure 5.1.1"])
        else:
            for profile in profiles:
                days = profile.get("properties", {}).get("retentionPolicy", {}).get("days", 0)
                if days < 365:
                    self._add(title=f"Activity Log Retention < 365 Days ({days}d)", severity=Severity.MEDIUM,
                              description=f"Log profile '{profile['name']}' retains logs for only {days} days.",
                              affected_resource=profile["id"],
                              remediation="Set retention to ≥ 365 days.",
                              cis_controls=["CIS Azure 5.1.2"])

    def _gcp(self):
        from app.core.providers import gcp
        from googleapiclient import discovery
        creds   = gcp.credentials(self.credentials)
        project = gcp.project(self.credentials)
        logging = discovery.build("logging", "v2", credentials=creds)
        self._resources_checked += 1
        sinks = logging.projects().sinks().list(parent=f"projects/{project}").execute()
        if not sinks.get("sinks"):
            self._add(title="No GCP Log Sink Configured", severity=Severity.HIGH,
                      description=f"Project '{project}' has no log sinks. Audit logs are not exported.",
                      affected_resource=f"projects/{project}",
                      remediation="Create a log sink exporting audit logs to Cloud Storage or BigQuery.",
                      cis_controls=["CIS GCP 2.1"])
        # Check Data Access audit logs
        crm = discovery.build("cloudresourcemanager", "v1", credentials=creds)
        policy = crm.projects().getIamPolicy(resource=project, body={}).execute()
        self._resources_checked += 1
        has_all = any(c.get("service") == "allServices" for c in policy.get("auditConfigs", []))
        if not has_all:
            self._add(title="Data Access Audit Logs Not Enabled for All Services", severity=Severity.MEDIUM,
                      description=f"Project '{project}' does not enable Data Access audit logs for all services.",
                      affected_resource=f"projects/{project}",
                      remediation="Enable DATA_READ and DATA_WRITE audit log types for allServices in IAM audit config.",
                      cis_controls=["CIS GCP 2.1"])
