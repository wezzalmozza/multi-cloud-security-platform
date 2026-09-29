"""app/modules/network/flow_logs.py — VPC / VNet / VPC subnet flow logging."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class NetworkFlowLogsModule(BaseModule):
    MODULE_ID    = "network-vpc-flow"
    MODULE_NAME  = "VPC Flow Logs Status"
    CATEGORY     = "Network"
    CIS_CONTROLS = ["CIS 3.9"]

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
        for vpc in ec2.describe_vpcs()["Vpcs"]:
            self._resources_checked += 1
            vid  = vpc["VpcId"]
            fls  = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vid]}])["FlowLogs"]
            active = [f for f in fls if f.get("FlowLogStatus") == "ACTIVE"]
            if not active:
                self._add(title="VPC Flow Logs Not Enabled", severity=Severity.MEDIUM,
                          description=f"VPC '{vid}' in '{region}' has no active flow logs. Network traffic is not auditable.",
                          affected_resource=f"arn:aws:ec2:{region}:vpc/{vid}",
                          region=region,
                          remediation="Enable VPC flow logs and send to CloudWatch Logs or S3. Capture ALL traffic.",
                          references=["https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"])
            else:
                for fl in active:
                    if fl.get("TrafficType") == "REJECT":
                        self._add(title="VPC Flow Logs Capture REJECT Only", severity=Severity.LOW,
                                  description=f"Flow log for VPC '{vid}' only logs rejected traffic. Accepted connections are invisible.",
                                  affected_resource=f"arn:aws:ec2:{region}:vpc/{vid}",
                                  region=region,
                                  remediation="Change flow log TrafficType to 'ALL'.")

    def _azure(self):
        from azure.mgmt.network import NetworkManagementClient
        from app.core.providers import azure
        net = azure.get_client(NetworkManagementClient, self.credentials)
        for nsg in net.network_security_groups.list_all():
            self._resources_checked += 1
            try:
                rg   = nsg.id.split("/")[4]
                fls  = list(net.flow_logs.list(rg, f"NetworkWatcher_{nsg.location}"))
                logged = any(fl.target_resource_id == nsg.id and fl.enabled for fl in fls)
            except Exception as exc:
                log.warning("[%s] cannot verify NSG flow logs for %s: %s", self.MODULE_ID, nsg.id, str(exc))
                continue
            if not logged:
                self._add(title="NSG Flow Logs Not Enabled", severity=Severity.MEDIUM,
                          description=f"NSG '{nsg.name}' has no NSG flow logs. Traffic is not recorded.",
                          affected_resource=nsg.id,
                          remediation="Enable NSG flow logs via Network Watcher → Storage Account / Log Analytics.",
                          cis_controls=["CIS Azure 6.5"])

    def _gcp(self):
        from app.core.providers import gcp
        service = gcp.build("compute", "v1", self.credentials)
        project = gcp.project(self.credentials)
        for zdata in service.subnetworks().aggregatedList(project=project).execute().get("items", {}).values():
            for subnet in zdata.get("subnetworks", []):
                self._resources_checked += 1
                if not subnet.get("enableFlowLogs", False):
                    self._add(title="GCP Subnet Flow Logs Disabled", severity=Severity.MEDIUM,
                              description=f"Subnet '{subnet['name']}' has no flow logs.",
                              affected_resource=subnet["selfLink"],
                              remediation="Enable flow logs: gcloud compute networks subnets update <name> --enable-flow-logs",
                              cis_controls=["CIS GCP 3.8"])
