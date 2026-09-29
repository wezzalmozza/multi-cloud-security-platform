"""app/modules/iam/root_usage.py — Root account key, MFA, and usage checks."""
import time
import logging
from app.core.base_module import BaseModule, CloudProvider, ModuleResult, Severity
from app.core.providers import aws

log = logging.getLogger(__name__)


class IAMRootModule(BaseModule):
    MODULE_ID    = "iam-root"
    MODULE_NAME  = "Root Account Usage"
    CATEGORY     = "IAM"
    CIS_CONTROLS = ["CIS 1.1", "CIS 1.5"]

    def run(self) -> ModuleResult:
        t0 = time.time()
        if self.provider != CloudProvider.AWS:
            return self._skip("Root account checks are AWS-specific.")
        try:
            self._aws()
        except Exception as e:
            return self._error(str(e))
        return self._ok(time.time() - t0)

    def _aws(self):
        iam = aws.get_client("iam", self.credentials)
        self._resources_checked += 1
        summary = iam.get_account_summary()["SummaryMap"]

        if summary.get("AccountAccessKeysPresent", 0) > 0:
            self._add(title="Root Account Has Active Access Keys", severity=Severity.CRITICAL,
                      description="Root access keys provide unrestricted API access and cannot be restricted by IAM.",
                      affected_resource="arn:aws:iam::root/access-keys",
                      remediation="Delete root access keys immediately. Use IAM roles or users instead.",
                      cis_controls=["CIS 1.4"])

        if summary.get("AccountMFAEnabled", 0) == 0:
            self._add(title="Root Account MFA Not Enabled", severity=Severity.CRITICAL,
                      description="Root account has no MFA. If the password is compromised, attacker has full control.",
                      affected_resource="arn:aws:iam::root",
                      remediation="Enable a hardware MFA device on the root account. Store recovery codes securely offline.",
                      cis_controls=["CIS 1.5"])

        # Check CloudTrail for recent root usage
        for region in self.regions:
            try:
                ct = aws.get_client("cloudtrail", self.credentials, region)
                events = ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": "root"}],
                    MaxResults=10,
                )
                if events.get("Events"):
                    latest = events["Events"][0]["EventTime"].isoformat()
                    self._add(title="Root Account Used Recently", severity=Severity.HIGH,
                              description=f"Root account activity detected. Last event: {latest}. Root usage should be extremely rare.",
                              affected_resource="arn:aws:iam::root",
                              region=region,
                              remediation="Review root usage in CloudTrail. Delegate tasks to IAM users/roles.",
                              evidence={"last_event": latest,
                                        "events": [e["EventName"] for e in events["Events"][:5]]},
                              cis_controls=["CIS 1.1"])
            except Exception:
                pass
