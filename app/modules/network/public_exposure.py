"""
app/modules/network/public_exposure.py
Public Exposure Detection (0.0.0.0/0) — AWS / Azure / GCP

Fallback strategy per provider:
  AWS   : describe_security_groups (primary) -> EC2 describe_instances network check (fallback)
  Azure : NetworkManagementClient (primary)  -> REST API direct call (fallback)
  GCP   : Compute Engine API (primary)       -> Cloud Asset Inventory API (fallback)
"""

import logging
import time

from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)

RISKY_PORTS = {
    22:    ("SSH",           Severity.CRITICAL),
    3389:  ("RDP",           Severity.CRITICAL),
    1433:  ("MSSQL",         Severity.CRITICAL),
    3306:  ("MySQL",         Severity.CRITICAL),
    5432:  ("PostgreSQL",    Severity.CRITICAL),
    27017: ("MongoDB",       Severity.CRITICAL),
    6379:  ("Redis",         Severity.CRITICAL),
    9200:  ("Elasticsearch", Severity.CRITICAL),
    5900:  ("VNC",           Severity.CRITICAL),
    445:   ("SMB",           Severity.CRITICAL),
    23:    ("Telnet",        Severity.CRITICAL),
    21:    ("FTP",           Severity.HIGH),
    5601:  ("Kibana",        Severity.HIGH),
    2049:  ("NFS",           Severity.HIGH),
    11211: ("Memcached",     Severity.HIGH),
    8080:  ("HTTP-alt",      Severity.MEDIUM),
}


class NetworkPublicExposureModule(BaseModule):
    MODULE_ID    = "network-public-exposure"
    MODULE_NAME  = "Public Exposure Detection (0.0.0.0/0)"
    CATEGORY     = "Network"
    CIS_CONTROLS = ["CIS 5.2", "CIS 5.3"]

    def run(self) -> ModuleResult:
        t0 = time.time()
        try:
            if self.provider == CloudProvider.AWS:
                for region in self.regions:
                    self._aws(region)
            elif self.provider == CloudProvider.AZURE:
                self._azure()
            elif self.provider == CloudProvider.GCP:
                self._gcp()
        except Exception as exc:
            return self._error(str(exc))
        return self._ok(time.time() - t0)

    # ══════════════════════════════════════════════════════════════════════════
    # AWS
    # Primary  : ec2:DescribeSecurityGroups  (reads all SG rules directly)
    # Fallback : ec2:DescribeInstances       (checks network interfaces — less detail
    #            but works with read-only EC2 perms when SG perms are missing)
    # ══════════════════════════════════════════════════════════════════════════

    def _aws(self, region: str):
        try:
            self._aws_security_groups(region)
        except Exception as exc:
            if _is_aws_access_denied(exc):
                log.warning(
                    "[network-public-exposure] describe_security_groups denied in %s "
                    "— falling back to describe_instances", region
                )
                self._aws_instance_network_fallback(region)
            else:
                raise

    def _aws_security_groups(self, region: str):
        """
        Primary: scan all security group inbound rules.
        Requires: ec2:DescribeSecurityGroups
        """
        ec2 = aws.get_client("ec2", self.credentials, region)
        sg_to_instances = self._aws_map_sg_to_instances(ec2)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                self._resources_checked += 1
                instance_ids = sg_to_instances.get(sg["GroupId"], [])
                instance_summary = (
                    ", ".join(instance_ids[:5]) if instance_ids else "No running instance attachment found"
                )
                for rule in sg.get("IpPermissions", []):
                    open4 = any(r.get("CidrIp") == "0.0.0.0/0"
                                for r in rule.get("IpRanges", []))
                    open6 = any(r.get("CidrIpv6") == "::/0"
                                for r in rule.get("Ipv6Ranges", []))
                    if not (open4 or open6):
                        continue

                    proto = rule.get("IpProtocol", "-1")
                    fp    = rule.get("FromPort", 0)
                    tp    = rule.get("ToPort", 65535)

                    if proto == "-1":
                        self._add(
                            title="All traffic open to internet",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Security group '{sg['GroupName']}' ({sg['GroupId']}) "
                                "allows ALL inbound traffic from 0.0.0.0/0. "
                                f"Attached EC2 instances: {instance_summary}."
                            ),
                            affected_resource=f"arn:aws:ec2:{region}:sg/{sg['GroupId']}",
                            region=region,
                            remediation="Remove the 0.0.0.0/0 inbound rule. Restrict to known CIDRs.",
                            evidence={"sg_id": sg["GroupId"], "sg_name": sg["GroupName"],
                                      "instance_ids": instance_ids,
                                      "method": "security_groups"},
                        )
                        continue

                    for port, (svc, sev) in RISKY_PORTS.items():
                        if fp <= port <= tp:
                            self._add(
                                title=f"{svc} (port {port}) open to internet",
                                severity=sev,
                                description=(
                                    f"SG '{sg['GroupName']}' exposes {svc} port {port} "
                                    "to 0.0.0.0/0. "
                                    f"Attached EC2 instances: {instance_summary}."
                                ),
                                affected_resource=f"arn:aws:ec2:{region}:sg/{sg['GroupId']}",
                                region=region,
                                remediation=(
                                    f"Restrict port {port} to trusted CIDRs. "
                                    "Use VPN or SSM Session Manager instead of open ports."
                                ),
                                evidence={"port": port, "service": svc,
                                          "sg_id": sg["GroupId"],
                                          "instance_ids": instance_ids,
                                          "method": "security_groups"},
                            )

    def _aws_map_sg_to_instances(self, ec2) -> dict:
        """Build a mapping from security group ID to attached running instance IDs."""
        sg_to_instances = {}
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    if not instance_id:
                        continue
                    for sg in instance.get("SecurityGroups", []):
                        sg_id = sg.get("GroupId")
                        if not sg_id:
                            continue
                        sg_to_instances.setdefault(sg_id, []).append(instance_id)
        return sg_to_instances

    def _aws_instance_network_fallback(self, region: str):
        """
        Fallback: detect publicly exposed instances via network interfaces.
        Requires: ec2:DescribeInstances  (weaker permission, widely available)
        Limitation: cannot see SG rules — only detects instances with public IPs,
                    which is a strong proxy for internet exposure.
        """
        ec2 = aws.get_client("ec2", self.credentials, region)
        for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    self._resources_checked += 1
                    public_ip  = instance.get("PublicIpAddress")
                    public_dns = instance.get("PublicDnsName")

                    if not public_ip:
                        continue

                    name = next(
                        (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                        instance["InstanceId"],
                    )
                    # List SG IDs attached (we can't read their rules in fallback)
                    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

                    self._add(
                        title=f"Instance '{name}' has public IP — SG rules unverified",
                        severity=Severity.HIGH,
                        description=(
                            f"Instance '{instance['InstanceId']}' has public IP {public_ip}. "
                            "Security group rules could not be read (insufficient permissions). "
                            "The instance may be exposing risky ports to the internet."
                        ),
                        affected_resource=(
                            f"arn:aws:ec2:{region}:instance/{instance['InstanceId']}"
                        ),
                        region=region,
                        remediation=(
                            "Verify security group rules manually. Grant ec2:DescribeSecurityGroups "
                            "to the scanner for full analysis. Consider placing instances in "
                            "private subnets behind a load balancer."
                        ),
                        evidence={
                            "public_ip":  public_ip,
                            "public_dns": public_dns,
                            "sg_ids":     sg_ids,
                            "method":     "fallback:describe_instances",
                        },
                    )

    # ══════════════════════════════════════════════════════════════════════════
    # Azure
    # Primary  : azure-mgmt-network SDK  (NetworkManagementClient)
    # Fallback : Azure REST API via requests (avoids SDK dependency issues)
    # ══════════════════════════════════════════════════════════════════════════

    def _azure(self):
        try:
            self._azure_mgmt_sdk()
        except Exception as exc:
            if _is_azure_access_denied(exc) or _is_azure_sdk_error(exc):
                log.warning(
                    "[network-public-exposure] Azure SDK failed (%s) "
                    "— falling back to REST API", type(exc).__name__
                )
                self._azure_rest_api()
            else:
                raise

    def _azure_mgmt_sdk(self):
        """Primary: azure-mgmt-network SDK — full NSG rule inspection."""
        from azure.mgmt.network import NetworkManagementClient
        from app.core.providers import azure

        net = azure.get_client(NetworkManagementClient, self.credentials)
        for nsg in net.network_security_groups.list_all():
            self._resources_checked += 1
            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                if rule.source_address_prefix not in ("*", "Internet", "0.0.0.0/0"):
                    continue

                dp  = rule.destination_port_range or "*"
                sev = Severity.CRITICAL if dp == "*" else Severity.HIGH

                self._add(
                    title=f"NSG allows inbound from internet: port {dp}",
                    severity=sev,
                    description=(
                        f"NSG '{nsg.name}' rule '{rule.name}' allows port {dp} "
                        "inbound from any source."
                    ),
                    affected_resource=nsg.id,
                    remediation=(
                        "Restrict source_address_prefix to known CIDRs. "
                        "Never use '*' or 'Internet' for sensitive ports."
                    ),
                    evidence={"rule": rule.name, "port": dp,
                              "priority": rule.priority, "method": "mgmt_sdk"},
                    cis_controls=["CIS Azure 6.1"],
                )

    def _azure_rest_api(self):
        """
        Fallback: query NSGs directly via Azure REST API with raw requests.
        Works when the azure-mgmt-network SDK fails (version mismatch, import error)
        or when the SDK credential scope is different.
        Requires: Microsoft.Network/networkSecurityGroups/read
        """
        import requests
        from app.core.providers import azure

        token = azure.mgmt_token(self.credentials)
        sub   = self.credentials.get("subscription_id", "")
        hdrs  = {"Authorization": f"Bearer {token}"}

        resp = requests.get(
            f"https://management.azure.com/subscriptions/{sub}"
            "/providers/Microsoft.Network/networkSecurityGroups"
            "?api-version=2023-05-01",
            headers=hdrs, timeout=20,
        )
        resp.raise_for_status()

        for nsg in resp.json().get("value", []):
            self._resources_checked += 1
            nsg_name = nsg.get("name", "unknown")
            nsg_id   = nsg.get("id", "")
            props    = nsg.get("properties", {})

            for rule in props.get("securityRules", []):
                rp = rule.get("properties", {})
                if rp.get("direction") != "Inbound" or rp.get("access") != "Allow":
                    continue
                if rp.get("sourceAddressPrefix") not in ("*", "Internet", "0.0.0.0/0"):
                    continue

                dp  = rp.get("destinationPortRange", "*")
                sev = Severity.CRITICAL if dp == "*" else Severity.HIGH

                self._add(
                    title=f"NSG allows inbound from internet: port {dp}",
                    severity=sev,
                    description=(
                        f"NSG '{nsg_name}' rule '{rule.get('name')}' allows "
                        f"port {dp} inbound from any source."
                    ),
                    affected_resource=nsg_id,
                    remediation=(
                        "Restrict sourceAddressPrefix to known CIDRs. "
                        "Never use '*' or 'Internet' for sensitive ports."
                    ),
                    evidence={"rule": rule.get("name"), "port": dp,
                              "method": "fallback:rest_api"},
                    cis_controls=["CIS Azure 6.1"],
                )

    # ══════════════════════════════════════════════════════════════════════════
    # GCP
    # Primary  : compute.firewalls.list  (requires compute.firewalls.list perm)
    # Fallback : Cloud Asset Inventory   (requires cloudasset.assets.searchAllResources)
    # ══════════════════════════════════════════════════════════════════════════

    def _gcp(self):
        try:
            self._gcp_compute_firewalls()
        except Exception as exc:
            if _is_gcp_access_denied(exc):
                log.warning(
                    "[network-public-exposure] compute.firewalls.list denied "
                    "— falling back to Cloud Asset Inventory"
                )
                self._gcp_asset_inventory()
            else:
                raise

    def _gcp_compute_firewalls(self):
        """Primary: list all VPC firewall rules directly."""
        from app.core.providers import gcp

        service = gcp.build("compute", "v1", self.credentials)
        project = gcp.project(self.credentials)

        for rule in service.firewalls().list(project=project).execute().get("items", []):
            self._resources_checked += 1
            if rule.get("direction", "INGRESS") != "INGRESS":
                continue
            if "0.0.0.0/0" not in rule.get("sourceRanges", []):
                continue

            for allowed in rule.get("allowed", []):
                ports = allowed.get("ports", [])
                proto = allowed.get("IPProtocol", "all")

                if not ports:
                    # All ports open
                    self._add(
                        title="GCP firewall: all ports open to internet",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Rule '{rule['name']}' allows all {proto} traffic from 0.0.0.0/0."
                        ),
                        affected_resource=rule["selfLink"],
                        remediation=(
                            "Replace 0.0.0.0/0 with specific CIDRs. "
                            "Use Cloud IAP for SSH/RDP access."
                        ),
                        evidence={"rule": rule["name"], "protocol": proto,
                                  "method": "compute_firewalls"},
                        cis_controls=["CIS GCP 3.6"],
                    )
                else:
                    for port_spec in ports:
                        for port, (svc, sev) in RISKY_PORTS.items():
                            if _gcp_port_in_range(str(port_spec), port):
                                self._add(
                                    title=f"GCP firewall: {svc} (port {port}) open to internet",
                                    severity=sev,
                                    description=(
                                        f"Rule '{rule['name']}' allows {svc} port {port} "
                                        "from 0.0.0.0/0."
                                    ),
                                    affected_resource=rule["selfLink"],
                                    remediation=(
                                        f"Restrict port {port}. Use Cloud IAP instead of "
                                        "open firewall rules for admin access."
                                    ),
                                    evidence={"rule": rule["name"], "port": port,
                                              "method": "compute_firewalls"},
                                    cis_controls=["CIS GCP 3.6"],
                                )

    def _gcp_asset_inventory(self):
        """
        Fallback: search firewall resources via Cloud Asset Inventory API.
        Requires: cloudasset.assets.searchAllResources (broader but lower-privilege path)
        """
        from app.core.providers import gcp

        service = gcp.build("cloudasset", "v1", self.credentials)
        project = gcp.project(self.credentials)
        scope   = f"projects/{project}"

        try:
            response = service.assets().list(
                parent=scope,
                assetTypes=["compute.googleapis.com/Firewall"],
                contentType="RESOURCE",
            ).execute()
        except Exception as exc:
            # If even the asset inventory is denied, report it clearly
            self._add(
                title="GCP firewall rules could not be read — insufficient permissions",
                severity=Severity.INFO,
                description=(
                    "Both compute.firewalls.list and Cloud Asset Inventory returned "
                    "permission denied. Firewall rules could not be assessed."
                ),
                affected_resource=f"projects/{project}",
                remediation=(
                    "Grant roles/compute.networkViewer or roles/cloudasset.viewer "
                    "to the scanning service account."
                ),
                evidence={"method": "fallback:asset_inventory",
                          "error": str(exc)},
            )
            return

        for asset in response.get("assets", []):
            self._resources_checked += 1
            resource = asset.get("resource", {}).get("data", {})
            name     = resource.get("name", "unknown")
            source_ranges = resource.get("sourceRanges", [])
            direction     = resource.get("direction", "INGRESS")

            if direction != "INGRESS" or "0.0.0.0/0" not in source_ranges:
                continue

            self._add(
                title=f"GCP firewall '{name}' may expose ports to internet",
                severity=Severity.HIGH,
                description=(
                    f"Firewall rule '{name}' has sourceRange 0.0.0.0/0. "
                    "Full port-level analysis unavailable (fallback mode)."
                ),
                affected_resource=asset.get("name", name),
                remediation=(
                    "Review and restrict the firewall rule. Grant compute.networkViewer "
                    "for full analysis in future scans."
                ),
                evidence={"rule": name, "source_ranges": source_ranges,
                          "method": "fallback:asset_inventory"},
                cis_controls=["CIS GCP 3.6"],
            )


# ── helpers ───────────────────────────────────────────────────────────────────

def _gcp_port_in_range(port_spec: str, port: int) -> bool:
    """Check if port is within a GCP port spec ('22', '8080-8090')."""
    if "-" in port_spec:
        parts = port_spec.split("-")
        try:
            return int(parts[0]) <= port <= int(parts[1])
        except ValueError:
            return False
    try:
        return int(port_spec) == port
    except ValueError:
        return False

def _is_aws_access_denied(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"} \
        or "AccessDenied" in str(exc) or "UnauthorizedOperation" in str(exc)

def _is_azure_access_denied(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "403" in msg or "401" in msg or "authorization" in msg or "permission" in msg

def _is_azure_sdk_error(exc: Exception) -> bool:
    return "ImportError" in type(exc).__name__ or "ModuleNotFoundError" in type(exc).__name__

def _is_gcp_access_denied(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "403" in msg or "permission" in msg or "forbidden" in msg or "access denied" in msg