"""app/modules/network/nacl.py — Network ACL analysis (AWS-only)."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class NetworkNACLModule(BaseModule):
    MODULE_ID    = "network-nacl"
    MODULE_NAME  = "Network ACL Analysis"
    CATEGORY     = "Network"
    CIS_CONTROLS = ["CIS 5.1"]

    def run(self) -> ModuleResult:
        t0 = time.time()
        if self.provider != CloudProvider.AWS:
            return self._skip("NACL analysis is AWS-specific. Azure/GCP use NSG rules.")
        try:
            for r in self.regions: self._aws(r)
        except Exception as e:
            return self._error(str(e))
        return self._ok(time.time() - t0)

    def _aws(self, region: str):
        ec2 = aws.get_client("ec2", self.credentials, region)
        for page in ec2.get_paginator("describe_network_acls").paginate():
            for nacl in page["NetworkAcls"]:
                self._resources_checked += 1
                entries  = nacl.get("Entries", [])
                inbound  = [e for e in entries if not e["Egress"]]
                outbound = [e for e in entries if e["Egress"]]
                for direction, rules in [("Inbound", inbound), ("Outbound", outbound)]:
                    allows_all = any(e.get("RuleAction") == "allow" and
                                     e.get("CidrBlock") in ("0.0.0.0/0",) and
                                     e.get("Protocol") == "-1" for e in rules)
                    has_deny   = any(e.get("RuleAction") == "deny" and
                                     e.get("RuleNumber") != 32767 for e in rules)
                    if allows_all and not has_deny:
                        self._add(
                            title=f"NACL Missing {direction} Deny Rules",
                            severity=Severity.LOW,
                            description=f"NACL '{nacl['NetworkAclId']}' has catch-all {direction.lower()} ALLOW but no explicit DENY rules.",
                            affected_resource=f"arn:aws:ec2:{region}:network-acl/{nacl['NetworkAclId']}",
                            region=region,
                            remediation="Add explicit DENY rules before the allow rules for high-risk ports. NACLs are stateless — add rules for both directions.",
                        )
                if nacl.get("IsDefault"):
                    all_allow = any(e.get("RuleNumber") == 100 and
                                    e.get("CidrBlock") == "0.0.0.0/0" and
                                    e.get("RuleAction") == "allow" for e in inbound)
                    if all_allow:
                        self._add(
                            title="Default NACL Allows All Inbound Traffic",
                            severity=Severity.MEDIUM,
                            description=f"Default NACL '{nacl['NetworkAclId']}' for VPC '{nacl['VpcId']}' allows all inbound traffic.",
                            affected_resource=f"arn:aws:ec2:{region}:network-acl/{nacl['NetworkAclId']}",
                            region=region,
                            remediation="Create custom NACLs for each subnet. Do not rely on the default NACL for security.",
                        )
