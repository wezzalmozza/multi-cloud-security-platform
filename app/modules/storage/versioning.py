"""app/modules/storage/versioning.py — Versioning and soft-delete checks."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class StorageVersioningModule(BaseModule):
    MODULE_ID    = "storage-versioning"
    MODULE_NAME  = "Versioning & Backup"
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
                v = s3.get_bucket_versioning(Bucket=name)
                status     = v.get("Status", "")
                mfa_delete = v.get("MFADelete", "Disabled")
                if status != "Enabled":
                    self._add(title="S3 Bucket Versioning Not Enabled", severity=Severity.MEDIUM,
                              description=f"Bucket '{name}' has no versioning. Deleted or overwritten objects cannot be recovered.",
                              affected_resource=f"arn:aws:s3:::{name}",
                              remediation="Enable versioning and MFA Delete on buckets containing important data.")
                elif mfa_delete != "Enabled":
                    self._add(title="S3 Bucket MFA Delete Not Enabled", severity=Severity.LOW,
                              description=f"Bucket '{name}' has versioning but no MFA Delete. An attacker could permanently delete all versions.",
                              affected_resource=f"arn:aws:s3:::{name}",
                              remediation="Enable MFA Delete to require MFA for permanent version deletion.")
            except Exception:
                pass

    def _azure(self):
        from azure.mgmt.storage import StorageManagementClient
        from app.core.providers import azure
        storage = azure.get_client(StorageManagementClient, self.credentials)
        for account in storage.storage_accounts.list():
            self._resources_checked += 1
            try:
                rg    = account.id.split("/")[4]
                props = storage.blob_services.get_service_properties(rg, account.name)
                dr    = props.delete_retention_policy
                if not dr or not dr.enabled:
                    self._add(title="Azure Blob Soft Delete Not Enabled", severity=Severity.MEDIUM,
                              description=f"Account '{account.name}' has no blob soft delete. Deleted blobs cannot be recovered.",
                              affected_resource=account.id,
                              remediation="Enable blob soft delete with ≥7 day retention period.",
                              cis_controls=["CIS Azure 3.8"])
            except Exception:
                pass

    def _gcp(self):
        from google.cloud import storage as gcs
        from app.core.providers import gcp
        client = gcs.Client(project=gcp.project(self.credentials),
                            credentials=gcp.credentials(self.credentials))
        for bucket in client.list_buckets():
            self._resources_checked += 1
            if not bucket.versioning_enabled:
                self._add(title="GCS Bucket Versioning Disabled", severity=Severity.MEDIUM,
                          description=f"Bucket '{bucket.name}' has no object versioning.",
                          affected_resource=f"gs://{bucket.name}",
                          remediation="Enable versioning: gsutil versioning set on gs://<bucket>",
                          cis_controls=["CIS GCP 5.3"])
