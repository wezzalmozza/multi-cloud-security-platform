"""app/modules/compute/metadata.py — IMDSv2 enforcement and metadata security."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class ComputeMetadataModule(BaseModule):
    MODULE_ID    = "compute-metadata"
    MODULE_NAME  = "Instance Metadata Security"
    CATEGORY     = "Compute"
    CIS_CONTROLS = ["CIS 5.6"]

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
        ec2 = aws.get_client("ec2", self.credentials, region)
        for page in ec2.get_paginator("describe_instances").paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    self._resources_checked += 1
                    imds      = inst.get("MetadataOptions", {})
                    tokens    = imds.get("HttpTokens", "optional")
                    hop_limit = imds.get("HttpPutResponseHopLimit", 1)
                    name      = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                                     inst["InstanceId"])
                    if tokens == "optional":
                        self._add(title=f"IMDSv2 Not Enforced on '{name}'",
                                  severity=Severity.HIGH,
                                  description=f"Instance '{inst['InstanceId']}' allows IMDSv1 (token-optional). Vulnerable to SSRF-based credential theft.",
                                  affected_resource=f"arn:aws:ec2:{region}:instance/{inst['InstanceId']}",
                                  region=region,
                                  remediation="Enforce IMDSv2: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required",
                                  evidence={"http_tokens": tokens},
                                  references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"])
                    if hop_limit > 1:
                        self._add(title=f"IMDS Hop Limit Too High on '{name}'",
                                  severity=Severity.MEDIUM,
                                  description=f"Hop limit is {hop_limit}. Containers inside the instance can reach the metadata service.",
                                  affected_resource=f"arn:aws:ec2:{region}:instance/{inst['InstanceId']}",
                                  region=region,
                                  remediation="Set HttpPutResponseHopLimit=1 to block containers from accessing IMDS.",
                                  evidence={"hop_limit": hop_limit})

    def _azure(self):
        from azure.mgmt.compute import ComputeManagementClient
        from app.core.providers import azure
        compute = azure.get_client(ComputeManagementClient, self.credentials)
        for vm in compute.virtual_machines.list_all():
            self._resources_checked += 1
            if not vm.identity:
                self._add(title=f"Azure VM '{vm.name}' Has No Managed Identity",
                          severity=Severity.LOW,
                          description="Without managed identity, credentials must be managed manually.",
                          affected_resource=vm.id,
                          remediation="Assign a system-assigned or user-assigned managed identity to the VM.",
                          cis_controls=["CIS Azure 9.1"])

    def _gcp(self):
        from app.core.providers import gcp
        service = gcp.build("compute", "v1", self.credentials)
        project = gcp.project(self.credentials)
        for zdata in service.instances().aggregatedList(project=project).execute().get("items", {}).values():
            for inst in zdata.get("instances", []):
                self._resources_checked += 1
                for sa in inst.get("serviceAccounts", []):
                    if (sa.get("email", "").endswith("-compute@developer.gserviceaccount.com") and
                            "https://www.googleapis.com/auth/cloud-platform" in sa.get("scopes", [])):
                        self._add(title=f"GCP Instance '{inst['name']}' Uses Default SA with Full Scope",
                                  severity=Severity.HIGH,
                                  description="Default compute SA with cloud-platform scope grants full API access to all GCP services.",
                                  affected_resource=inst["selfLink"],
                                  remediation="Create a dedicated SA with minimal permissions. Avoid cloud-platform scope.",
                                  cis_controls=["CIS GCP 4.1", "CIS GCP 4.2"])
