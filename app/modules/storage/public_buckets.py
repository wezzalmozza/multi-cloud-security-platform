"""app/modules/storage/public_buckets.py — Public S3/Blob/GCS buckets."""
import time
import logging
from botocore.exceptions import ClientError
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class StoragePublicBucketsModule(BaseModule):
    MODULE_ID    = "storage-public-buckets"
    MODULE_NAME  = "Public Storage Buckets"
    CATEGORY     = "Storage"
    CIS_CONTROLS = ["CIS 2.1.5"]

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
        log.info("[%s] starting AWS scan", self.MODULE_ID)
        s3 = aws.get_client("s3", self.credentials)
        buckets_found = 0
        for bucket in s3.list_buckets().get("Buckets", []):
            buckets_found += 1
            name = bucket["Name"]
            self._resources_checked += 1
            # Block Public Access
            try:
                bpa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                missing = [k for k, v in bpa.items() if not v]
                if missing:
                    log.debug("[%s] S3 bucket %s missing public access blocks: %s", self.MODULE_ID, name, missing)
                    self._add(title="S3 Block Public Access Not Fully Enabled", severity=Severity.HIGH,
                              description=f"Bucket '{name}' missing: {', '.join(missing)}",
                              affected_resource=f"arn:aws:s3:::{name}",
                              remediation="Enable all four Block Public Access settings on the bucket and account.",
                              evidence={"missing": missing})
            except ClientError as e:
                code = (e.response.get("Error", {}) or {}).get("Code", "")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    self._add(title="S3 Block Public Access Not Configured", severity=Severity.HIGH,
                              description=f"Bucket '{name}' has no Block Public Access config.",
                              affected_resource=f"arn:aws:s3:::{name}",
                              remediation="Configure Block Public Access for the bucket and account.")
                else:
                    log.warning("[%s] cannot verify Public Access Block for %s: %s", self.MODULE_ID, name, str(e))
            # ACL
            try:
                for grant in s3.get_bucket_acl(Bucket=name).get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        perm = grant.get("Permission", "UNKNOWN")
                        log.debug("[%s] S3 bucket %s is publicly accessible via ACL", self.MODULE_ID, name)
                        self._add(title=f"S3 Bucket Publicly Accessible via ACL ({perm})",
                                  severity=Severity.CRITICAL,
                                  description=f"Bucket '{name}' grants {perm} to {'all internet users' if 'AllUsers' in uri else 'all AWS users'}.",
                                  affected_resource=f"arn:aws:s3:::{name}",
                                  remediation="Remove public ACL grants. Use bucket policies with specific principal ARNs.",
                                  evidence={"grantee": uri, "permission": perm})
            except Exception:
                pass
        log.info("[%s] checked %d S3 buckets", self.MODULE_ID, buckets_found)

    def _azure(self):
        log.info("[%s] starting Azure scan", self.MODULE_ID)
        from azure.mgmt.storage import StorageManagementClient
        from app.core.providers import azure
        storage = azure.get_client(StorageManagementClient, self.credentials)
        accounts_found = 0
        for account in storage.storage_accounts.list():
            accounts_found += 1
            self._resources_checked += 1
            if account.allow_blob_public_access:
                log.debug("[%s] Azure storage account %s allows blob public access", self.MODULE_ID, account.name)
                self._add(title="Azure Storage Account Allows Blob Public Access",
                          severity=Severity.HIGH,
                          description=f"Account '{account.name}' has 'Allow Blob Public Access' enabled.",
                          affected_resource=account.id,
                          remediation="Disable 'Allow Blob Public Access' unless required for static website hosting.",
                          cis_controls=["CIS Azure 3.5"])
        log.info("[%s] checked %d Azure storage accounts", self.MODULE_ID, accounts_found)

    def _gcp(self):
        log.info("[%s] starting GCP scan", self.MODULE_ID)
        from google.cloud import storage as gcs
        from app.core.providers import gcp
        client = gcs.Client(project=gcp.project(self.credentials),
                            credentials=gcp.credentials(self.credentials))
        buckets_found = 0
        for bucket in client.list_buckets():
            buckets_found += 1
            self._resources_checked += 1
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                    log.debug("[%s] GCS bucket %s is publicly accessible", self.MODULE_ID, bucket.name)
                    self._add(title="GCS Bucket Publicly Accessible",
                              severity=Severity.CRITICAL,
                              description=f"Bucket '{bucket.name}' grants '{binding['role']}' to public.",
                              affected_resource=f"gs://{bucket.name}",
                              remediation="Remove allUsers/allAuthenticatedUsers from IAM policy. Use Uniform bucket-level access.",
                              cis_controls=["CIS GCP 5.1"])
        log.info("[%s] checked %d GCS buckets", self.MODULE_ID, buckets_found)
