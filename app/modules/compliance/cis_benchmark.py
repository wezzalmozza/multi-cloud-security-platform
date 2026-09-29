"""app/modules/compliance/cis_benchmark.py — CIS benchmark checks not covered by other modules."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class CISBenchmarkModule(BaseModule):
    MODULE_ID    = "compliance-cis"
    MODULE_NAME  = "CIS Benchmark Assessment"
    CATEGORY     = "Compliance"
    CIS_CONTROLS = ["CIS 1.x", "CIS 2.x", "CIS 3.x"]

    def run(self) -> ModuleResult:
        t0 = time.time()
        try:
            if self.provider == CloudProvider.AWS:     self._aws()
            elif self.provider == CloudProvider.AZURE: self._azure()
            elif self.provider == CloudProvider.GCP:   self._gcp()
        except Exception as e:
            return self._error(str(e))
        return self._ok(time.time() - t0)

    def _aws(self):
        iam = aws.get_client("iam", self.credentials)
        self._resources_checked += 1
        # Password policy
        try:
            pw = iam.get_account_password_policy()["PasswordPolicy"]
            for key, expected, label, ctrl in [
                ("MinimumPasswordLength",    14,   "Min length ≥ 14",          "CIS 1.8"),
                ("RequireUppercaseCharacters", True, "Require uppercase",       "CIS 1.9"),
                ("RequireLowercaseCharacters", True, "Require lowercase",       "CIS 1.9"),
                ("RequireNumbers",           True,  "Require numbers",          "CIS 1.9"),
                ("RequireSymbols",           True,  "Require symbols",          "CIS 1.9"),
                ("MaxPasswordAge",           90,    "Max password age ≤ 90",    "CIS 1.11"),
                ("PasswordReusePrevention",  24,    "Prevent last 24 reuse",    "CIS 1.10"),
            ]:
                self._resources_checked += 1
                actual = pw.get(key)
                if isinstance(expected, bool):
                    failed = actual is not True
                elif key == "MaxPasswordAge":
                    failed = actual is None or actual > expected
                else:
                    failed = actual is None or actual < expected
                if failed:
                    self._add(title=f"Password Policy: {label}", severity=Severity.MEDIUM,
                              description=f"Current: {actual}. Required: {expected}.",
                              affected_resource="arn:aws:iam::account/password-policy",
                              remediation=f"Update IAM password policy: {label}.",
                              cis_controls=[ctrl])
        except iam.exceptions.NoSuchEntityException:
            self._add(title="No IAM Password Policy Configured", severity=Severity.HIGH,
                      description="No password policy exists. Users can set any password.",
                      affected_resource="arn:aws:iam::account/password-policy",
                      remediation="Create an IAM password policy with all CIS-required settings.",
                      cis_controls=["CIS 1.8", "CIS 1.9"])
        # Support role
        try:
            iam.get_role(RoleName="AWSSupportAccess")
        except iam.exceptions.NoSuchEntityException:
            self._add(title="No AWS Support Role Defined", severity=Severity.LOW,
                      description="No AWSSupportAccess role for incident response.",
                      affected_resource="arn:aws:iam::account/roles",
                      remediation="Create a role with AWSSupportAccess managed policy.",
                      cis_controls=["CIS 1.20"])
        # CloudWatch alarm checks (CIS 3.1-3.12)
        for region in self.regions:
            self._check_cw_alarms(region)

    def _check_cw_alarms(self, region: str):
        required = [
            ("CIS 3.1",  "root",                         "Root account usage"),
            ("CIS 3.4",  "StopLogging",                  "CloudTrail config changes"),
            ("CIS 3.7",  "AuthorizeSecurityGroupIngress", "Security group changes"),
            ("CIS 3.8",  "CreateNetworkAcl",              "Network ACL changes"),
            ("CIS 3.3",  "AccessDenied",                  "Unauthorized API calls"),
        ]
        try:
            logs = aws.get_client("logs", self.credentials, region)
            existing = [f.get("filterPattern", "")
                        for f in logs.describe_metric_filters().get("metricFilters", [])]
        except Exception:
            return
        for ctrl, hint, label in required:
            self._resources_checked += 1
            found = any(hint.lower() in p.lower() for p in existing)
            if not found:
                self._add(title=f"Missing CloudWatch Alarm: {label}", severity=Severity.MEDIUM,
                          description=f"No metric filter+alarm found for: {label} ({ctrl}).",
                          affected_resource=f"arn:aws:logs:{region}:metric-filters",
                          region=region,
                          remediation=f"Create a CloudWatch Logs metric filter matching '{hint}' and an SNS alarm.",
                          cis_controls=[ctrl])

    def _azure(self):
        import requests
        from app.core.providers import azure
        token = azure.mgmt_token(self.credentials)
        sub   = self.credentials.get("subscription_id", "")
        resp  = requests.get(
            f"https://management.azure.com/subscriptions/{sub}/providers/"
            "Microsoft.Security/securityContacts?api-version=2017-08-01-preview",
            headers={"Authorization": f"Bearer {token}"}, timeout=15)
        self._resources_checked += 1
        if resp.ok and not resp.json().get("value"):
            self._add(title="No Security Contact Defined", severity=Severity.MEDIUM,
                      description="No security contact email/phone configured in Microsoft Defender.",
                      affected_resource=f"subscriptions/{sub}",
                      remediation="Configure a security contact in Defender for Cloud → Environment Settings.",
                      cis_controls=["CIS Azure 1.18"])

    def _gcp(self):
        from app.core.providers import gcp
        service = gcp.build("sqladmin", "v1beta4", self.credentials)
        project = gcp.project(self.credentials)
        for inst in service.instances().list(project=project).execute().get("items", []):
            self._resources_checked += 1
            settings = inst.get("settings", {})
            ip_cfg   = settings.get("ipConfiguration", {})
            if ip_cfg.get("ipv4Enabled", False):
                self._add(title=f"Cloud SQL '{inst['name']}' Has Public IP", severity=Severity.HIGH,
                          description="Cloud SQL instance is publicly reachable.",
                          affected_resource=f"projects/{project}/instances/{inst['name']}",
                          remediation="Disable public IP. Use Cloud SQL Auth Proxy with private IP.",
                          cis_controls=["CIS GCP 6.2"])
            if not settings.get("requireSsl", False):
                self._add(title=f"Cloud SQL '{inst['name']}' Does Not Require SSL", severity=Severity.HIGH,
                          description="Cloud SQL allows unencrypted connections.",
                          affected_resource=f"projects/{project}/instances/{inst['name']}",
                          remediation="Enable 'Require SSL' on the Cloud SQL instance.",
                          cis_controls=["CIS GCP 6.4"])
