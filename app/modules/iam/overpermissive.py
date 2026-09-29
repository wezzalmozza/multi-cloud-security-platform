"""
app/modules/iam/overpermissive.py
Detects IAM policies with wildcard actions (*) or wildcard resources (*).
"""

import json
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class IAMOverpermissiveModule(BaseModule):
    MODULE_ID    = "iam-overpermissive"
    MODULE_NAME  = "Overly Permissive Policies"
    CATEGORY     = "IAM"
    CIS_CONTROLS = ["CIS 1.16", "CIS 1.17"]

    def run(self) -> ModuleResult:
        t0 = time.time()
        try:
            if self.provider == CloudProvider.AWS:   self._aws()
            elif self.provider == CloudProvider.AZURE: self._azure()
            elif self.provider == CloudProvider.GCP:   self._gcp()
        except Exception as e:
            return self._error(str(e))
        return self._ok(time.time() - t0)

    def _aws(self):
        log.info("[%s] starting AWS scan", self.MODULE_ID)
        iam = aws.get_client("iam", self.credentials)
        # Attached managed policies (customer + AWS managed)
        policies_found = 0
        for page in iam.get_paginator("list_policies").paginate(Scope="All", OnlyAttached=True):
            for policy in page["Policies"]:
                policies_found += 1
                self._resources_checked += 1
                ver = iam.get_policy_version(PolicyArn=policy["Arn"],
                                              VersionId=policy["DefaultVersionId"])
                doc    = ver["PolicyVersion"]["Document"]
                issues = _wildcard_issues(doc)
                if issues:
                    log.debug("[%s] found overpermissive policy: %s", self.MODULE_ID, policy["PolicyName"])
                    ptype = "AWS managed" if policy.get("Arn", "").startswith("arn:aws:iam::aws:policy/") else "Customer managed"
                    self._add(
                        title="Overly Permissive IAM Policy",
                        severity=Severity.CRITICAL,
                        description=f"{ptype} policy '{policy['PolicyName']}' grants: {', '.join(issues)}",
                        affected_resource=policy["Arn"],
                        remediation="Replace wildcard actions/resources with minimum required permissions. Use IAM Access Analyzer.",
                        evidence={"issues": issues},
                        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
                    )
        log.info("[%s] checked %d attached managed policies", self.MODULE_ID, policies_found)
        
        # Inline policies on users / groups / roles
        for entity, list_fn, get_fn, key in [
            ("user",  "list_users",  "list_user_policies",  "Users"),
            ("group", "list_groups", "list_group_policies", "Groups"),
            ("role",  "list_roles",  "list_role_policies",  "Roles"),
        ]:
            entity_count = 0
            for page in iam.get_paginator(list_fn).paginate():
                for item in page[key]:
                    entity_count += 1
                    name = item[entity.capitalize() + "Name"]
                    for ip in iam.get_paginator(get_fn).paginate(**{entity.capitalize()+"Name": name}):
                        for pname in ip["PolicyNames"]:
                            self._resources_checked += 1
                            if entity == "user":
                                doc = iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]
                            elif entity == "group":
                                doc = iam.get_group_policy(GroupName=name, PolicyName=pname)["PolicyDocument"]
                            else:
                                doc = iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
                            if isinstance(doc, str): doc = json.loads(doc)
                            issues = _wildcard_issues(doc)
                            if issues:
                                log.debug("[%s] found overpermissive inline policy on %s: %s", self.MODULE_ID, entity, name)
                                self._add(
                                    title=f"Overly Permissive Inline Policy on {entity} '{name}'",
                                    severity=Severity.CRITICAL,
                                    description=f"Inline policy '{pname}' grants: {', '.join(issues)}",
                                    affected_resource=f"iam:{entity}/{name}/inline/{pname}",
                                    remediation="Convert to managed policy and remove wildcards.",
                                    evidence={"issues": issues},
                                )
            log.info("[%s] checked %d %ss with inline policies", self.MODULE_ID, entity_count, entity)

    def _azure(self):
        log.info("[%s] starting Azure scan", self.MODULE_ID)
        from azure.mgmt.authorization import AuthorizationManagementClient
        from app.core.providers import azure
        auth = azure.get_client(AuthorizationManagementClient, self.credentials)
        sub  = self.credentials.get("subscription_id", "")
        roles_checked = 0
        for rd in auth.role_definitions.list(f"/subscriptions/{sub}"):
            roles_checked += 1
            self._resources_checked += 1
            if rd.role_type != "CustomRole": continue
            for perm in (rd.permissions or []):
                if any("*" in a for a in (perm.actions or [])):
                    log.debug("[%s] found wildcard role: %s", self.MODULE_ID, rd.role_name)
                    self._add(
                        title=f"Custom Role '{rd.role_name}' Has Wildcard Actions",
                        severity=Severity.CRITICAL,
                        description="Custom role grants wildcard (*) actions.",
                        affected_resource=rd.id,
                        remediation="Replace wildcard actions with specific required actions.",
                        evidence={"actions": perm.actions},
                        cis_controls=["CIS Azure 1.23"],
                    )
        log.info("[%s] checked %d Azure role definitions", self.MODULE_ID, roles_checked)

    def _gcp(self):
        log.info("[%s] starting GCP scan", self.MODULE_ID)
        from app.core.providers import gcp
        service = gcp.build("iam", "v1", self.credentials)
        project = gcp.project(self.credentials)
        resp = service.projects().roles().list(parent=f"projects/{project}").execute()
        roles_found = 0
        for role in resp.get("roles", []):
            roles_found += 1
            self._resources_checked += 1
            detail = service.projects().roles().get(name=role["name"]).execute()
            dangerous = [p for p in detail.get("includedPermissions", [])
                         if p.endswith(".setIamPolicy") or p.endswith(".*")]
            if dangerous:
                log.debug("[%s] found dangerous GCP role: %s", self.MODULE_ID, role["name"])
                self._add(
                    title=f"GCP Custom Role with Dangerous Permissions",
                    severity=Severity.HIGH,
                    description=f"Role '{role['name']}' has: {', '.join(dangerous)}",
                    affected_resource=role["name"],
                    remediation="Remove setIamPolicy and wildcard permissions.",
                    evidence={"dangerous": dangerous},
                    cis_controls=["CIS GCP 1.4"],
                )
        log.info("[%s] checked %d GCP custom roles", self.MODULE_ID, roles_found)


def _wildcard_issues(doc: dict) -> list[str]:
    issues = []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict): stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow": continue
        actions   = _as_list(s.get("Action", []))
        resources = _as_list(s.get("Resource", []))
        if s.get("NotAction"):
            issues.append("Uses NotAction in Allow statement (potentially broad)")
            continue
        if s.get("NotResource"):
            issues.append("Uses NotResource in Allow statement (potentially broad)")
            continue
        if isinstance(actions, str):   actions   = [actions]
        if isinstance(resources, str): resources = [resources]
        action_wild = any(_is_wildcard_action(a) for a in actions)
        resource_wild = any(_is_wildcard_resource(r) for r in resources)
        if action_wild and resource_wild: issues.append("Full admin or broad admin scope (wildcard Action + wildcard Resource)")
        elif action_wild:   issues.append("Wildcard actions detected (e.g., * or service:*)")
        elif resource_wild: issues.append("Resource: * (all resources)")
    return list(set(issues))


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _is_wildcard_action(action: str) -> bool:
    a = action.strip().lower()
    return a == "*" or "*" in a


def _is_wildcard_resource(resource: str) -> bool:
    return resource.strip() == "*"
