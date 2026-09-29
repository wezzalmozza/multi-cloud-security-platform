"""app/modules/compute/ssh_rdp.py — SSH/RDP open to the internet."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)

ADMIN_PORTS = {"22": "SSH", "3389": "RDP"}


class ComputeSSHRDPModule(BaseModule):
    MODULE_ID    = "compute-ssh-rdp"
    MODULE_NAME  = "SSH/RDP Public Access"
    CATEGORY     = "Compute"
    CIS_CONTROLS = ["CIS 5.2"]

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
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                self._resources_checked += 1
                for rule in sg.get("IpPermissions", []):
                    if rule.get("IpProtocol") not in ("tcp", "-1"): continue
                    open4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                    open6 = any(r.get("CidrIpv6") == "::/0"    for r in rule.get("Ipv6Ranges", []))
                    if not (open4 or open6): continue
                    fp = rule.get("FromPort", 0)
                    tp = rule.get("ToPort", 65535)
                    for port, label in ADMIN_PORTS.items():
                        if fp <= int(port) <= tp:
                            self._add(title=f"{label} Open to Internet",
                                      severity=Severity.CRITICAL,
                                      description=f"SG '{sg['GroupName']}' allows {label} (port {port}) from 0.0.0.0/0.",
                                      affected_resource=f"arn:aws:ec2:{region}:sg/{sg['GroupId']}",
                                      region=region,
                                      remediation=f"Restrict {label} to known IPs. Use AWS SSM Session Manager to eliminate open {label} entirely.",
                                      evidence={"sg_id": sg["GroupId"], "port": port})

    def _azure(self):
        from azure.mgmt.network import NetworkManagementClient
        from app.core.providers import azure
        net = azure.get_client(NetworkManagementClient, self.credentials)
        for nsg in net.network_security_groups.list_all():
            self._resources_checked += 1
            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound" or rule.access != "Allow": continue
                if rule.source_address_prefix not in ("*", "Internet", "0.0.0.0/0"): continue
                dp = rule.destination_port_range or ""
                for port, label in ADMIN_PORTS.items():
                    in_range = dp in (port, "*") or (
                        "-" in dp and int(dp.split("-")[0]) <= int(port) <= int(dp.split("-")[1])
                    )
                    if in_range:
                        self._add(title=f"{label} Open to Internet via NSG",
                                  severity=Severity.CRITICAL,
                                  description=f"NSG '{nsg.name}' allows {label} from any source.",
                                  affected_resource=nsg.id,
                                  remediation=f"Restrict {label}. Use Azure Bastion for browser-based access.",
                                  cis_controls=["CIS Azure 6.1", "CIS Azure 6.2"])

    def _gcp(self):
        from app.core.providers import gcp
        service = gcp.build("compute", "v1", self.credentials)
        project = gcp.project(self.credentials)
        for rule in service.firewalls().list(project=project).execute().get("items", []):
            self._resources_checked += 1
            if rule.get("direction") != "INGRESS": continue
            if "0.0.0.0/0" not in rule.get("sourceRanges", []): continue
            for allowed in rule.get("allowed", []):
                for pspec in allowed.get("ports", []):
                    for port, label in ADMIN_PORTS.items():
                        in_range = str(pspec) == port or (
                            "-" in str(pspec) and int(pspec.split("-")[0]) <= int(port) <= int(pspec.split("-")[1])
                        )
                        if in_range:
                            self._add(title=f"{label} Open to Internet via Firewall Rule",
                                      severity=Severity.CRITICAL,
                                      description=f"Rule '{rule['name']}' allows {label} from 0.0.0.0/0.",
                                      affected_resource=rule["selfLink"],
                                      remediation=f"Remove the {label} rule. Use Cloud IAP for browser-based SSH/RDP.",
                                      cis_controls=["CIS GCP 3.6", "CIS GCP 3.7"])
