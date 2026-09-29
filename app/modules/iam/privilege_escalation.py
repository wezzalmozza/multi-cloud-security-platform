"""app/modules/iam/privilege_escalation.py — Known AWS IAM privilege escalation paths."""
import json, time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)

ESCALATION_PATHS = [
    {"name": "CreatePolicyVersion",       "actions": ["iam:createpolicyversion"],
     "desc": "Can create a new policy version with admin permissions."},
    {"name": "SetDefaultPolicyVersion",   "actions": ["iam:setdefaultpolicyversion"],
     "desc": "Can switch active policy version to one granting more access."},
    {"name": "CreateAccessKey",           "actions": ["iam:createaccesskey"],
     "desc": "Can create access keys for other (privileged) users."},
    {"name": "UpdateLoginProfile",        "actions": ["iam:updateloginprofile"],
     "desc": "Can change another user's console password."},
    {"name": "AttachUserPolicy",          "actions": ["iam:attachuserpolicy"],
     "desc": "Can attach any managed policy (including AdministratorAccess) to a user."},
    {"name": "AttachGroupPolicy",         "actions": ["iam:attachgrouppolicy"],
     "desc": "Can attach admin policies to a group the attacker is in."},
    {"name": "AttachRolePolicy",          "actions": ["iam:attachrolepolicy"],
     "desc": "Can attach admin policies to assumable roles."},
    {"name": "PutUserPolicy",             "actions": ["iam:putuserpolicy"],
     "desc": "Can inject inline admin policies on any user."},
    {"name": "PutGroupPolicy",            "actions": ["iam:putgrouppolicy"],
     "desc": "Can inject inline admin policies on any group."},
    {"name": "PutRolePolicy",             "actions": ["iam:putrolepolicy"],
     "desc": "Can inject inline admin policies on any role."},
    {"name": "AddUserToGroup",            "actions": ["iam:addusertogroup"],
     "desc": "Can add self to a privileged group."},
    {"name": "UpdateAssumeRolePolicy",    "actions": ["iam:updateassumerolepolicy"],
     "desc": "Can modify a role's trust policy to allow self to assume it."},
    {"name": "PassRole+EC2",              "actions": ["iam:passrole", "ec2:runinstances"],
     "desc": "Can launch EC2 with a privileged role and read its credentials via IMDS."},
    {"name": "PassRole+Lambda",           "actions": ["iam:passrole", "lambda:createfunction", "lambda:invokefunction"],
     "desc": "Can deploy a Lambda with a privileged role and invoke it."},
    {"name": "PassRole+CloudFormation",   "actions": ["iam:passrole", "cloudformation:createstack"],
     "desc": "Can create a CloudFormation stack using a privileged role."},
]


class IAMPrivEscModule(BaseModule):
    MODULE_ID    = "iam-privilege-escalation"
    MODULE_NAME  = "Privilege Escalation Paths"
    CATEGORY     = "IAM"
    CIS_CONTROLS = ["CIS 1.16"]

    def run(self) -> ModuleResult:
        t0 = time.time()
        if self.provider != CloudProvider.AWS:
            return self._skip("Privilege escalation path analysis is AWS-only.")
        try:
            self._aws()
        except Exception as e:
            return self._error(str(e))
        return self._ok(time.time() - t0)

    def _aws(self):
        iam = aws.get_client("iam", self.credentials)
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                self._resources_checked += 1
                effective = _effective_actions(iam, user["UserName"])
                for path in ESCALATION_PATHS:
                    required = set(path["actions"])
                    if required.issubset(effective):
                        self._add(
                            title=f"Privilege Escalation Path: {path['name']}",
                            severity=Severity.CRITICAL,
                            description=f"User '{user['UserName']}' can escalate via: {path['desc']}",
                            affected_resource=user["Arn"],
                            remediation="Remove the listed actions or add a permission boundary to block escalation.",
                            evidence={"path": path["name"], "required_actions": path["actions"]},
                            references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
                        )


def _effective_actions(iam, username: str) -> set[str]:
    actions: set[str] = set()
    for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=username):
        for p in page["AttachedPolicies"]:
            actions |= _actions_from_arn(iam, p["PolicyArn"])
    for page in iam.get_paginator("list_user_policies").paginate(UserName=username):
        for pname in page["PolicyNames"]:
            doc = iam.get_user_policy(UserName=username, PolicyName=pname)["PolicyDocument"]
            if isinstance(doc, str): doc = json.loads(doc)
            actions |= _extract(doc)
    for page in iam.get_paginator("list_groups_for_user").paginate(UserName=username):
        for g in page["Groups"]:
            gn = g["GroupName"]
            for gp in iam.get_paginator("list_attached_group_policies").paginate(GroupName=gn):
                for p in gp["AttachedPolicies"]:
                    actions |= _actions_from_arn(iam, p["PolicyArn"])
            for ip in iam.get_paginator("list_group_policies").paginate(GroupName=gn):
                for pname in ip["PolicyNames"]:
                    doc = iam.get_group_policy(GroupName=gn, PolicyName=pname)["PolicyDocument"]
                    if isinstance(doc, str): doc = json.loads(doc)
                    actions |= _extract(doc)
    return actions


def _actions_from_arn(iam, arn: str) -> set[str]:
    p   = iam.get_policy(PolicyArn=arn)["Policy"]
    ver = iam.get_policy_version(PolicyArn=arn, VersionId=p["DefaultVersionId"])
    doc = ver["PolicyVersion"]["Document"]
    if isinstance(doc, str): doc = json.loads(doc)
    return _extract(doc)


def _extract(doc: dict) -> set[str]:
    actions: set[str] = set()
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict): stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow": continue
        raw = s.get("Action", [])
        if isinstance(raw, str): raw = [raw]
        actions |= {a.lower() for a in raw}
    return actions
