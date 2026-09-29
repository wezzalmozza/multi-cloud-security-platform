"""app/modules/storage/logging.py — Access logging for storage buckets."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class StorageLoggingModule(BaseModule):
    MODULE_ID    = "storage-logging"
    MODULE_NAME  = "Access Logging Status"
    CATEGORY     = "Storage"
    CIS_CONTROLS = ["CIS 2.1.3"]

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
        s3 = aws.get_client("s3", self.credentials)
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            self._resources_checked += 1
            try:
                log = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in log:
                    self._add(title="S3 Bucket Access Logging Disabled", severity=Severity.MEDIUM,
                              description=f"Bucket '{name}' has no server access logging. Data access cannot be audited.",
                              affected_resource=f"arn:aws:s3:::{name}",
                              remediation="Enable S3 server access logging to a dedicated logging bucket with restricted access.")
            except Exception:
                pass

    def _azure(self):
        from azure.mgmt.storage import StorageManagementClient
        from azure.mgmt.monitor import MonitorManagementClient
        from app.core.providers import azure
        storage = azure.get_client(StorageManagementClient, self.credentials)
        monitor = azure.get_client(MonitorManagementClient, self.credentials)
        for account in storage.storage_accounts.list():
            self._resources_checked += 1
            try:
                diag = list(monitor.diagnostic_settings.list(account.id))
                if not diag:
                    self._add(title="Azure Storage Account Has No Diagnostic Logging",
                              severity=Severity.MEDIUM,
                              description=f"Account '{account.name}' has no diagnostic settings configured.",
                              affected_resource=account.id,
                              remediation="Enable diagnostic settings to capture read/write/delete operations.",
                              cis_controls=["CIS Azure 3.10"])
            except Exception:
                pass

    def _gcp(self):
        from google.cloud import storage as gcs
        from app.core.providers import gcp
        client = gcs.Client(project=gcp.project(self.credentials),
                            credentials=gcp.credentials(self.credentials))
        for bucket in client.list_buckets():
            self._resources_checked += 1
            if not bucket.logging:
                self._add(title="GCS Bucket Access Logging Disabled", severity=Severity.MEDIUM,
                          description=f"Bucket '{bucket.name}' has no access logging.",
                          affected_resource=f"gs://{bucket.name}",
                          remediation="Enable access logs on the bucket and direct them to a dedicated logging bucket.",
                          cis_controls=["CIS GCP 5.3"])
