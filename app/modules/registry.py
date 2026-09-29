"""
app/modules/registry.py
Central registry mapping module_id → (import path, class name).
This is the single place to add, remove, or rename modules.
"""

from __future__ import annotations
import importlib
from app.core.base_module import BaseModule

# module_id → (dotted import path, ClassName)
REGISTRY: dict[str, tuple[str, str]] = {
    # IAM
    "iam-overpermissive":       ("app.modules.iam.overpermissive",       "IAMOverpermissiveModule"),
    "iam-mfa":                  ("app.modules.iam.mfa",                  "IAMMFAModule"),
    "iam-unused":               ("app.modules.iam.unused",               "IAMUnusedModule"),
    "iam-privilege-escalation": ("app.modules.iam.privilege_escalation", "IAMPrivEscModule"),
    "iam-root":                 ("app.modules.iam.root_usage",           "IAMRootModule"),

    # Network
    "network-public-exposure":  ("app.modules.network.public_exposure",  "NetworkPublicExposureModule"),
    "network-sg-audit":         ("app.modules.network.sg_audit",         "NetworkSGAuditModule"),
    "network-nacl":             ("app.modules.network.nacl",             "NetworkNACLModule"),
    "network-vpc-flow":         ("app.modules.network.flow_logs",        "NetworkFlowLogsModule"),

    # Storage
    "storage-public-buckets":   ("app.modules.storage.public_buckets",   "StoragePublicBucketsModule"),
    "storage-encryption":       ("app.modules.storage.encryption",       "StorageEncryptionModule"),
    "storage-logging":          ("app.modules.storage.logging",          "StorageLoggingModule"),
    "storage-versioning":       ("app.modules.storage.versioning",       "StorageVersioningModule"),

    # Compute
    "compute-public-ip":        ("app.modules.compute.public_ip",        "ComputePublicIPModule"),
    "compute-ssh-rdp":          ("app.modules.compute.ssh_rdp",          "ComputeSSHRDPModule"),
    "compute-metadata":         ("app.modules.compute.metadata",         "ComputeMetadataModule"),

    # Compliance
    "compliance-cis":           ("app.modules.compliance.cis_benchmark", "CISBenchmarkModule"),
    "compliance-logging":       ("app.modules.compliance.logging_monitoring", "LoggingMonitoringModule"),
}

# Human-readable metadata (used by GET /api/v1/modules)
MODULE_META: dict[str, dict] = {
    "iam-overpermissive":       {"name": "Overly Permissive Policies",         "category": "IAM",        "severity": "CRITICAL", "providers": ["aws","azure","gcp"]},
    "iam-mfa":                  {"name": "MFA Enforcement Check",              "category": "IAM",        "severity": "HIGH",     "providers": ["aws","azure","gcp"]},
    "iam-unused":               {"name": "Unused Credentials Detection",       "category": "IAM",        "severity": "HIGH",     "providers": ["aws","azure","gcp"]},
    "iam-privilege-escalation": {"name": "Privilege Escalation Paths",         "category": "IAM",        "severity": "CRITICAL", "providers": ["aws"]},
    "iam-root":                 {"name": "Root Account Usage",                 "category": "IAM",        "severity": "CRITICAL", "providers": ["aws"]},
    "network-public-exposure":  {"name": "Public Exposure Detection (0.0.0.0/0)","category": "Network",  "severity": "CRITICAL", "providers": ["aws","azure","gcp"]},
    "network-sg-audit":         {"name": "Security Group Misconfiguration",    "category": "Network",    "severity": "HIGH",     "providers": ["aws","azure","gcp"]},
    "network-nacl":             {"name": "Network ACL Analysis",               "category": "Network",    "severity": "MEDIUM",   "providers": ["aws"]},
    "network-vpc-flow":         {"name": "VPC Flow Logs Status",               "category": "Network",    "severity": "MEDIUM",   "providers": ["aws","azure","gcp"]},
    "storage-public-buckets":   {"name": "Public Storage Buckets",             "category": "Storage",    "severity": "CRITICAL", "providers": ["aws","azure","gcp"]},
    "storage-encryption":       {"name": "Encryption at Rest Check",           "category": "Storage",    "severity": "HIGH",     "providers": ["aws","azure","gcp"]},
    "storage-logging":          {"name": "Access Logging Status",              "category": "Storage",    "severity": "MEDIUM",   "providers": ["aws","azure","gcp"]},
    "storage-versioning":       {"name": "Versioning & Backup",                "category": "Storage",    "severity": "MEDIUM",   "providers": ["aws","azure","gcp"]},
    "compute-public-ip":        {"name": "Public IP Exposure",                 "category": "Compute",    "severity": "MEDIUM",   "providers": ["aws","azure","gcp"]},
    "compute-ssh-rdp":          {"name": "SSH/RDP Public Access",              "category": "Compute",    "severity": "CRITICAL", "providers": ["aws","azure","gcp"]},
    "compute-metadata":         {"name": "Instance Metadata Security",         "category": "Compute",    "severity": "HIGH",     "providers": ["aws","azure","gcp"]},
    "compliance-cis":           {"name": "CIS Benchmark Assessment",           "category": "Compliance", "severity": "MEDIUM",   "providers": ["aws","azure","gcp"]},
    "compliance-logging":       {"name": "Logging & Monitoring",               "category": "Compliance", "severity": "MEDIUM",   "providers": ["aws","azure","gcp"]},
}


def load(module_id: str) -> type[BaseModule]:
    if module_id not in REGISTRY:
        raise ValueError(f"Unknown module_id: '{module_id}'")
    path, cls_name = REGISTRY[module_id]
    mod = importlib.import_module(path)
    return getattr(mod, cls_name)


def all_ids() -> list[str]:
    return list(REGISTRY.keys())


def meta(module_id: str) -> dict:
    return MODULE_META.get(module_id, {})
