"""app/modules/network/sg_audit.py — Unused SGs and unrestricted egress."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class NetworkSGAuditModule(BaseModule):
    MODULE_ID    = "network-sg-audit"
    MODULE_NAME  = "Security Group Misconfiguration"
    CATEGORY     = "Network"
    CIS_CONTROLS = ["CIS 5.2", "CIS 5.4"]

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
        sg_to_instances = self._aws_map_sg_to_instances(ec2)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                self._resources_checked += 1
                attached_instances = sg_to_instances.get(sg["GroupId"], [])
                if attached_instances:
                    related_resources = ", ".join(
                        f"{item['name']} ({item['id']})" for item in attached_instances[:5]
                    )
                else:
                    related_resources = "No EC2 instances currently attached"
                # Unrestricted egress
                for rule in sg.get("IpPermissionsEgress", []):
                    if rule.get("IpProtocol") == "-1" and any(
                        r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
                    ):
                        self._add(title="Unrestricted Outbound Traffic", severity=Severity.LOW,
                                  description=(
                                      f"SG '{sg['GroupName']}' allows all outbound to any destination. "
                                      f"Related EC2 instances: {related_resources}."
                                  ),
                                  affected_resource=f"arn:aws:ec2:{region}:sg/{sg['GroupId']}",
                                  region=region,
                                  remediation="Restrict egress to required protocols and destinations only.",
                                  evidence={
                                      "sg_id": sg["GroupId"],
                                      "sg_name": sg["GroupName"],
                                      "related_ec2_instances": attached_instances,
                                  })

    def _aws_map_sg_to_instances(self, ec2) -> dict:
        """Map each SG to attached EC2 instances with instance name and ID."""
        sg_to_instances = {}
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    state = instance.get("State", {}).get("Name")
                    if state == "terminated":
                        continue
                    instance_id = instance.get("InstanceId")
                    if not instance_id:
                        continue
                    instance_name = next(
                        (tag.get("Value") for tag in instance.get("Tags", []) if tag.get("Key") == "Name"),
                        instance_id,
                    )
                    item = {"id": instance_id, "name": instance_name}
                    for sg in instance.get("SecurityGroups", []):
                        sg_id = sg.get("GroupId")
                        if not sg_id:
                            continue
                        sg_to_instances.setdefault(sg_id, []).append(item)
        return sg_to_instances

    def _azure(self):
        from azure.mgmt.network import NetworkManagementClient
        from app.core.providers import azure
        net = azure.get_client(NetworkManagementClient, self.credentials)
        for nsg in net.network_security_groups.list_all():
            self._resources_checked += 1
            for rule in (nsg.security_rules or []):
                if rule.direction == "Outbound" and rule.access == "Allow" and \
                   rule.destination_address_prefix in ("*", "Internet") and \
                   rule.destination_port_range == "*":
                    self._add(title="NSG Allows Unrestricted Outbound", severity=Severity.LOW,
                              description=f"NSG '{nsg.name}' allows all outbound via rule '{rule.name}'.",
                              affected_resource=nsg.id,
                              remediation="Restrict outbound rules to necessary destinations and ports.",
                              cis_controls=["CIS Azure 6.2"])

    def _gcp(self):
        from app.core.providers import gcp
        service = gcp.build("compute", "v1", self.credentials)
        project = gcp.project(self.credentials)
        for rule in service.firewalls().list(project=project).execute().get("items", []):
            self._resources_checked += 1
            if rule.get("direction") != "EGRESS": continue
            if "0.0.0.0/0" not in rule.get("destinationRanges", []): continue
            for a in rule.get("allowed", []):
                if not a.get("ports"):
                    self._add(title="GCP Firewall: Unrestricted Outbound", severity=Severity.LOW,
                              description=f"Rule '{rule['name']}' allows all egress traffic.",
                              affected_resource=rule["selfLink"],
                              remediation="Restrict egress firewall rules to necessary destinations.",
                              cis_controls=["CIS GCP 3.7"])
