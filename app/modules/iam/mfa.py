"""
app/modules/iam/mfa.py
MFA Enforcement Check — AWS / Azure / GCP

Fallback strategy per provider:
  AWS   : credential report (primary) -> per-user ListMFADevices (fallback)
  Azure : Conditional Access policies (primary) -> per-user MS Graph authMethods (fallback)
  GCP   : Admin Directory API (primary) -> Cloud Identity API (fallback)
"""

import logging
import time

from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)

_AWS_FALLBACK_CODES   = {"AccessDenied", "AccessDeniedException", "NoSuchEntity"}
_AZURE_FALLBACK_CODES = {403, 401}


class IAMMFAModule(BaseModule):
    MODULE_ID    = "iam-mfa"
    MODULE_NAME  = "MFA Enforcement Check"
    CATEGORY     = "IAM"
    CIS_CONTROLS = ["CIS 1.10", "CIS 1.14"]
    _method_used: str = "primary"

    def run(self) -> ModuleResult:
        t0 = time.time()
        try:
            if self.provider == CloudProvider.AWS:
                self._aws()
            elif self.provider == CloudProvider.AZURE:
                self._azure()
            elif self.provider == CloudProvider.GCP:
                self._gcp()
        except Exception as exc:
            return self._error(str(exc))
        return self._ok(time.time() - t0)

    # === AWS ===

    def _aws(self):
        try:
            self._aws_credential_report()
            self._method_used = "primary:credential_report"
        except Exception as exc:
            if _is_aws_access_denied(exc):
                log.warning("[iam-mfa] credential report denied — falling back to ListMFADevices")
                self._aws_list_mfa_devices()
                self._method_used = "fallback:list_mfa_devices"
            else:
                raise

    def _aws_credential_report(self):
     """Primary: full credential report — requires iam:GenerateCredentialReport."""
     iam = aws.get_client("iam", self.credentials)

     iam.generate_credential_report()
     import time as _t
     _t.sleep(2)

     report = iam.get_credential_report()
     lines = report["Content"].decode().splitlines()

     if not lines:
         return

     header = lines[0].split(",")

     for line in lines[1:]:
         row = dict(zip(header, line.split(",")))

         user = row.get("user", "").strip()
         self._resources_checked += 1

         mfa_active = row.get("mfa_active", "").strip().lower()
         password_enabled = row.get("password_enabled", "").strip().lower()

         # ROOT ACCOUNT CHECK
         if user == "<root_account>":
             if mfa_active != "true":
                 self._add(
                     title="Root account MFA not enabled",
                     severity=Severity.CRITICAL,
                     description="The root account has no MFA device attached.",
                     affected_resource="arn:aws:iam::root",
                     remediation="Enable a hardware MFA on the root account immediately.",
                     cis_controls=["CIS 1.5"],
                 )
             continue

         # USER CHECK
         if password_enabled == "true" and mfa_active != "true":
             self._add(
                 title=f"IAM user '{user}' without MFA",
                 severity=Severity.HIGH,
                 description=f"User '{user}' has console access but MFA is disabled.",
                 affected_resource=f"arn:aws:iam::user/{user}",
                 remediation="Enable MFA. Enforce via SCP condition aws:MultiFactorAuthPresent.",
                 evidence={
                     "last_used": row.get("password_last_used", "N/A"),
                     "method": "credential_report"
                 },
             )

    def _aws_list_mfa_devices(self):
        """
        Fallback: iterate users + ListMFADevices per user.
        Requires: iam:ListUsers + iam:ListMFADevices (less privileged).
        Note: root account MFA cannot be checked via this path.
        """
        iam = aws.get_client("iam", self.credentials)
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                self._resources_checked += 1
                try:
                    devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
                    if not devices:
                        try:
                            iam.get_login_profile(UserName=uname)
                            has_console = True
                        except iam.exceptions.NoSuchEntityException:
                            has_console = False

                        if has_console:
                            self._add(
                                title=f"IAM user '{uname}' without MFA",
                                severity=Severity.HIGH,
                                description=(
                                    f"User '{uname}' has console access but no MFA device. "
                                    "(Fallback detection — credential report was unavailable.)"
                                ),
                                affected_resource=user["Arn"],
                                remediation="Enable MFA. Consider enforcing via SCP or permission boundary.",
                                evidence={"method": "fallback:list_mfa_devices"},
                            )
                except Exception as exc:
                    log.debug("[iam-mfa] skipping user %s: %s", uname, exc)

    # === Azure ===

    def _azure(self):
        try:
            self._azure_conditional_access()
            self._method_used = "primary:conditional_access"
        except Exception as exc:
            if _is_azure_access_denied(exc):
                log.warning("[iam-mfa] CA policies denied — falling back to per-user auth methods")
                self._azure_per_user_mfa()
                self._method_used = "fallback:per_user_auth_methods"
            else:
                raise

    def _azure_conditional_access(self):
        """Primary: check CA policies for MFA enforcement (Policy.Read.All)."""
        import requests
        from app.core.providers import azure

        token   = azure.graph_token(self.credentials)
        headers = {"Authorization": f"Bearer {token}"}
        resp    = requests.get(
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
            headers=headers, timeout=15,
        )
        if resp.status_code in _AZURE_FALLBACK_CODES:
            raise PermissionError(f"CA policies: HTTP {resp.status_code}")
        resp.raise_for_status()

        policies = resp.json().get("value", [])
        self._resources_checked += len(policies)

        mfa_enforced = any(
            "mfa" in str(p.get("grantControls", {})).lower()
            and p.get("state") == "enabled"
            for p in policies
        )
        if not mfa_enforced:
            self._add(
                title="No Conditional Access policy enforcing MFA",
                severity=Severity.CRITICAL,
                description="No enabled CA policy requires MFA. Users can authenticate with password only.",
                affected_resource=f"tenant/{self.credentials.get('tenant_id')}",
                remediation="Create a CA policy requiring MFA for all users.",
                cis_controls=["CIS Azure 1.2"],
                evidence={"policies_checked": len(policies), "method": "conditional_access"},
            )

    def _azure_per_user_mfa(self):
        """
        Fallback: check each user's registered auth methods.
        Requires: User.Read.All + UserAuthenticationMethod.Read.All
        """
        import requests
        from app.core.providers import azure

        token   = azure.graph_token(self.credentials)
        headers = {"Authorization": f"Bearer {token}"}
        MFA_TYPES = {
            "microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
            "microsoft.graph.phoneAuthenticationMethod",
            "microsoft.graph.fido2AuthenticationMethod",
            "microsoft.graph.softwareOathAuthenticationMethod",
        }

        url = "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName&$top=100"
        while url:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            for user in data.get("value", []):
                self._resources_checked += 1
                uid = user["id"]
                upn = user.get("userPrincipalName", uid)
                try:
                    mr = requests.get(
                        f"https://graph.microsoft.com/v1.0/users/{uid}/authentication/methods",
                        headers=headers, timeout=15,
                    )
                    mr.raise_for_status()
                    methods = mr.json().get("value", [])
                    has_mfa = any(m.get("@odata.type") in MFA_TYPES for m in methods)
                    if not has_mfa:
                        self._add(
                            title=f"Azure user '{upn}' has no MFA method registered",
                            severity=Severity.HIGH,
                            description=f"User '{upn}' has no strong authentication method registered.",
                            affected_resource=f"users/{uid}",
                            remediation="Register MFA at https://aka.ms/mfasetup or enforce via CA policy.",
                            evidence={"registered_methods": [m.get("@odata.type") for m in methods],
                                      "method": "fallback:per_user_auth_methods"},
                        )
                except Exception as exc:
                    log.debug("[iam-mfa] skipping user %s: %s", upn, exc)

            url = data.get("@odata.nextLink")

    # === GCP ===

    def _gcp(self):
        try:
            self._gcp_directory()
            self._method_used = "primary:directory_api"
        except Exception as exc:
            if _is_gcp_access_denied(exc):
                log.warning("[iam-mfa] Directory API denied — falling back to Cloud Identity")
                self._gcp_cloud_identity()
                self._method_used = "fallback:cloud_identity"
            else:
                raise

    def _gcp_directory(self):
        """Primary: Admin Directory API — isEnrolledIn2Sv per user."""
        from googleapiclient import discovery
        from app.core.providers import gcp

        creds   = gcp.credentials(self.credentials)
        service = discovery.build("admin", "directory_v1", credentials=creds)
        request = service.users().list(customer="my_customer", projection="full", maxResults=500)
        while request:
            response = request.execute()
            for user in response.get("users", []):
                self._resources_checked += 1
                if not user.get("isEnrolledIn2Sv", False):
                    self._add(
                        title=f"GCP user '{user['primaryEmail']}' without 2SV",
                        severity=Severity.HIGH,
                        description=f"User '{user['primaryEmail']}' is not enrolled in 2-Step Verification.",
                        affected_resource=user["primaryEmail"],
                        remediation="Enforce 2SV: Google Admin Console → Security → 2-step verification.",
                        cis_controls=["CIS GCP 1.1"],
                        evidence={"enrolled": False, "method": "directory_api"},
                    )
            request = service.users().list_next(request, response)

    def _gcp_cloud_identity(self):
        """
        Fallback: org-level check via Admin Customer API.
        Less granular — reports policy gap, not per-user status.
        """
        import requests
        from app.core.providers import gcp

        creds   = gcp.credentials(self.credentials)
        creds.refresh(requests.Request())
        token   = creds.token
        project = gcp.project(self.credentials)

        resp = requests.get(
            "https://admin.googleapis.com/admin/directory/v1/customer/my_customer",
            headers={"Authorization": f"Bearer {token}"}, timeout=15,
        )
        self._resources_checked += 1

        if resp.ok:
            domain = resp.json().get("customerDomain", "unknown")
            self._add(
                title="GCP 2SV enforcement could not be verified per-user",
                severity=Severity.MEDIUM,
                description=(
                    f"Domain '{domain}': the Admin Directory API was unavailable. "
                    "Per-user 2SV enrollment could not be checked. Verify manually."
                ),
                affected_resource=f"domain/{domain}",
                remediation="Grant Security Viewer role to the scanning service account.",
                evidence={"method": "fallback:cloud_identity", "domain": domain},
            )
        else:
            self._add(
                title="GCP MFA check skipped — insufficient permissions",
                severity=Severity.INFO,
                description="Both Directory API and Cloud Identity API returned permission denied.",
                affected_resource=f"project/{project}",
                remediation="Grant roles/iam.securityReviewer to the scanning service account.",
                evidence={"method": "fallback:cloud_identity", "status": "permission_denied"},
            )


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_aws_access_denied(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return code in _AWS_FALLBACK_CODES or "AccessDenied" in str(exc)

def _is_azure_access_denied(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "403" in msg or "401" in msg or "authorization" in msg or "permission" in msg

def _is_gcp_access_denied(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "403" in msg or "permission" in msg or "forbidden" in msg or "access denied" in msg
