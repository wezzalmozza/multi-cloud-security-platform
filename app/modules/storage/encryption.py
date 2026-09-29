"""app/modules/storage/encryption.py — Encryption at rest for S3/EBS/Blob/GCS."""
import time
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws


class StorageEncryptionModule(BaseModule):
    MODULE_ID    = "storage-encryption"
    MODULE_NAME  = "Encryption at Rest Check"
    CATEGORY     = "Storage"
    CIS_CONTROLS = ["CIS 2.1.1"]

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
                s3.get_bucket_encryption(Bucket=name)
            except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                self._add(title="S3 Bucket Encryption Not Enabled", severity=Severity.HIGH,
                          description=f"Bucket '{name}' has no default encryption. Objects may be stored in plaintext.",
                          affected_resource=f"arn:aws:s3:::{name}",
                          remediation="Enable default encryption with SSE-KMS using a customer-managed key.")
            except Exception:
                pass
        # EBS volumes
        for region in self.regions:
            ec2 = aws.get_client("ec2", self.credentials, region)
            for page in ec2.get_paginator("describe_volumes").paginate():
                for vol in page["Volumes"]:
                    self._resources_checked += 1
                    if not vol.get("Encrypted", False):
                        self._add(title="EBS Volume Not Encrypted", severity=Severity.HIGH,
                                  description=f"EBS volume '{vol['VolumeId']}' in '{region}' is not encrypted.",
                                  affected_resource=f"arn:aws:ec2:{region}:volume/{vol['VolumeId']}",
                                  region=region,
                                  remediation="Enable EBS encryption by default in EC2 console. Re-create existing volumes via encrypted snapshot copy.",
                                  cis_controls=["CIS 2.2.1"])

    def _azure(self):
        from azure.mgmt.storage import StorageManagementClient
        from app.core.providers import azure
        storage = azure.get_client(StorageManagementClient, self.credentials)
        for account in storage.storage_accounts.list():
            self._resources_checked += 1
            enc = account.encryption
            if not enc or not enc.services:
                self._add(title="Azure Storage Account Encryption Not Configured",
                          severity=Severity.HIGH,
                          description=f"Account '{account.name}' has no encryption configured.",
                          affected_resource=account.id,
                          remediation="Enable encryption for Blob and File services.",
                          cis_controls=["CIS Azure 3.1"])

    def _gcp(self):
        from google.cloud import storage as gcs
        from app.core.providers import gcp
        client = gcs.Client(project=gcp.project(self.credentials),
                            credentials=gcp.credentials(self.credentials))
        for bucket in client.list_buckets():
            self._resources_checked += 1
            if not bucket.default_kms_key_name:
                self._add(title="GCS Bucket Not Using CMEK", severity=Severity.LOW,
                          description=f"Bucket '{bucket.name}' uses Google-managed keys. CMEK provides better key control.",
                          affected_resource=f"gs://{bucket.name}",
                          remediation="Set a default Cloud KMS key on the bucket.",
                          cis_controls=["CIS GCP 5.2"])
