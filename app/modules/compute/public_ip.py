"""app/modules/compute/public_ip.py — Instances with direct public IPs."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class ComputePublicIPModule(BaseModule):
    MODULE_ID    = "compute-public-ip"
    MODULE_NAME  = "Public IP Exposure"
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
        log.info("[%s] scanning AWS region: %s", self.MODULE_ID, region)
        ec2 = aws.get_client("ec2", self.credentials, region)
        instances_checked = 0
        for page in ec2.get_paginator("describe_instances").paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    instances_checked += 1
                    self._resources_checked += 1
                    if not inst.get("PublicIpAddress"): continue
                    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                                inst["InstanceId"])
                    log.debug("[%s] EC2 instance %s has public IP", self.MODULE_ID, name)
                    self._add(title=f"EC2 Instance '{name}' Has Public IP",
                              severity=Severity.MEDIUM,
                              description=f"Instance '{inst['InstanceId']}' has public IP {inst['PublicIpAddress']}.",
                              affected_resource=f"arn:aws:ec2:{region}:instance/{inst['InstanceId']}",
                              region=region,
                              remediation="Place instances in private subnets. Use a load balancer for public traffic and VPN/bastion for admin access.",
                              evidence={"public_ip": inst["PublicIpAddress"], "type": inst.get("InstanceType")})
        log.info("[%s] checked %d running instances in region %s", self.MODULE_ID, instances_checked, region)

    def _azure(self):
        log.info("[%s] starting Azure scan", self.MODULE_ID)
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
        from app.core.providers import azure
        compute = azure.get_client(ComputeManagementClient, self.credentials)
        network = azure.get_client(NetworkManagementClient, self.credentials)
        vms_checked = 0
        for vm in compute.virtual_machines.list_all():
            vms_checked += 1
            self._resources_checked += 1
            vm_d = compute.virtual_machines.get(vm.id.split("/")[4], vm.name)
            for nic_ref in (vm_d.network_profile.network_interfaces or []):
                rg  = nic_ref.id.split("/")[4]
                nic = network.network_interfaces.get(rg, nic_ref.id.split("/")[-1])
                for ip_cfg in (nic.ip_configurations or []):
                    if ip_cfg.public_ip_address:
                        log.debug("[%s] Azure VM %s has public IP", self.MODULE_ID, vm.name)
                        self._add(title=f"Azure VM '{vm.name}' Has Public IP",
                                  severity=Severity.MEDIUM,
                                  description=f"VM '{vm.name}' is directly assigned a public IP.",
                                  affected_resource=vm.id,
                                  remediation="Remove the public IP. Use Azure Bastion for SSH/RDP.",
                                  cis_controls=["CIS Azure 6.2"])
        log.info("[%s] checked %d Azure VMs", self.MODULE_ID, vms_checked)

    def _gcp(self):
        log.info("[%s] starting GCP scan", self.MODULE_ID)
        from app.core.providers import gcp
        service = gcp.build("compute", "v1", self.credentials)
        project = gcp.project(self.credentials)
        instances_checked = 0
        for zdata in service.instances().aggregatedList(project=project).execute().get("items", {}).values():
            for inst in zdata.get("instances", []):
                instances_checked += 1
                self._resources_checked += 1
                for iface in inst.get("networkInterfaces", []):
                    for cfg in iface.get("accessConfigs", []):
                        if cfg.get("natIP"):
                            log.debug("[%s] GCP instance %s has external IP", self.MODULE_ID, inst["name"])
                            self._add(title=f"GCP Instance '{inst['name']}' Has External IP",
                                      severity=Severity.MEDIUM,
                                      description=f"Instance has external IP {cfg['natIP']}.",
                                      affected_resource=inst["selfLink"],
                                      remediation="Remove external IPs. Use Cloud IAP for SSH and Cloud NAT for outbound.",
                                      cis_controls=["CIS GCP 4.9"])
        log.info("[%s] checked %d GCP instances", self.MODULE_ID, instances_checked)
