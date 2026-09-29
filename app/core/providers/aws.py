"""
app/core/providers/aws.py
boto3 session factory supporting keys, role assumption, and named profiles.
"""

import boto3
import logging
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

log = logging.getLogger(__name__)
_RETRY = Config(retries={"max_attempts": 3, "mode": "standard"})


def get_client(service: str, credentials: dict, region: str = "us-east-1"):
    return _session(credentials, region).client(service, region_name=region, config=_RETRY)


def get_resource(name: str, credentials: dict, region: str = "us-east-1"):
    return _session(credentials, region).resource(name, region_name=region, config=_RETRY)


def enabled_regions(credentials: dict) -> list[str]:
    ec2 = get_client("ec2", credentials)
    resp = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    return [r["RegionName"] for r in resp["Regions"]]


def _session(credentials: dict, region: str) -> boto3.Session:
    creds = _clean_credentials(credentials)

    # Validate credentials not completely empty
    if not creds:
        log.warning("Empty credentials dict — attempting to use environment credentials")
        # Fall through to environment-based auth
        return boto3.Session(region_name=region)

    if creds.get("role_arn"):
        return _assume_role(creds, region)
    if creds.get("profile"):
        return boto3.Session(profile_name=creds["profile"], region_name=region)
    
    # Direct keys auth
    access_key = creds.get("access_key_id")
    secret_key = creds.get("secret_access_key")
    if bool(access_key) ^ bool(secret_key):
        raise RuntimeError("Incomplete AWS key credentials: provide both access_key_id and secret_access_key")
    if not access_key and not secret_key:
        log.warning("Missing access_key_id or secret_access_key — using environment credentials")
        return boto3.Session(region_name=region)

    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=creds.get("session_token"),
        region_name=region,
    )


def _assume_role(credentials: dict, region: str) -> boto3.Session:
    role_arn = str(credentials.get("role_arn", "")).strip()
    if not role_arn:
        raise RuntimeError("Role assumption failed: role_arn is empty")

    # Source credentials can come from explicit keys, named profile, or environment.
    if credentials.get("profile"):
        base = boto3.Session(profile_name=credentials["profile"], region_name=region)
    elif credentials.get("access_key_id") and credentials.get("secret_access_key"):
        base = boto3.Session(
            aws_access_key_id=credentials.get("access_key_id"),
            aws_secret_access_key=credentials.get("secret_access_key"),
            aws_session_token=credentials.get("session_token"),
            region_name=region,
        )
    else:
        base = boto3.Session(region_name=region)

    sts = base.client("sts", config=_RETRY)
    kw: dict = {
        "RoleArn": role_arn,
        "RoleSessionName": "MCPP-Scan",
        "DurationSeconds": 3600,
    }
    if credentials.get("external_id"):
        kw["ExternalId"] = credentials["external_id"]
    try:
        creds = sts.assume_role(**kw)["Credentials"]
    except NoCredentialsError as exc:
        raise RuntimeError(
            "Role assumption failed: no source AWS credentials found. "
            "Provide access_key_id/secret_access_key, set a profile, or configure environment credentials on the API server."
        ) from exc
    except ClientError as exc:
        code = (exc.response.get("Error", {}) or {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            raise RuntimeError(
                "Role assumption failed: access denied. Ensure source credentials are valid and trusted to assume this role."
            ) from exc
        raise RuntimeError(f"Role assumption failed: {exc}") from exc
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def _clean_credentials(credentials: dict | None) -> dict:
    if not credentials:
        return {}
    cleaned = {}
    for k, v in credentials.items():
        if isinstance(v, str):
            v = v.strip()
        if v not in (None, ""):
            cleaned[k] = v
    return cleaned
