#!/usr/bin/env python3
"""
Quick test script to debug module execution with full logging.
Run: python test_modules_debug.py
"""
import sys
import json
import logging

# Configure logging to see all debug/info messages from modules
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from app.core.base_module import CloudProvider, Severity
from app.modules.registry import all_ids, load

print("=" * 80)
print("MODULE EXECUTION TEST WITH DETAILED LOGGING")
print("=" * 80)
print()

# Test with empty/invalid credentials to see what happens
print("TEST 1: Running all modules with EMPTY credentials")
print("-" * 80)
try:
    for module_id in all_ids()[:5]:  # Just test first 5
        print(f"\nTesting: {module_id}")
        try:
            cls = load(module_id)
            mod = cls(CloudProvider.AWS, {}, ["us-east-1"])
            result = mod.run()
            print(f"  Status: {result.status}")
            print(f"  Resources checked: {result.resources_checked}")
            print(f"  Findings: {len(result.findings)}")
            if result.error_message:
                print(f"  Error: {result.error_message[:100]}...")
        except Exception as e:
            print(f"  Exception during load/run: {str(e)[:100]}...")
except Exception as e:
    print(f"Failed: {e}")

print()
print("=" * 80)
print("TEST 2: Environment AWS credentials (if available)")
print("-" * 80)
try:
    import boto3
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print(f"✓ AWS credentials available (Account: {identity.get('Account')})")
    
    # Test a few key modules with environment credentials
    test_modules = ["iam-overpermissive", "storage-public-buckets", "compute-public-ip"]
    for module_id in test_modules:
        print(f"\nTesting: {module_id} with environment creds")
        try:
            cls = load(module_id)
            mod = cls(CloudProvider.AWS, {}, ["us-east-1"])
            result = mod.run()
            print(f"  Status: {result.status}")
            print(f"  Resources checked: {result.resources_checked}")
            print(f"  Findings: {len(result.findings)}")
            if result.findings:
                print(f"  First finding: {result.findings[0].title}")
            if result.error_message:
                print(f"  Error: {result.error_message[:100]}...")
        except Exception as e:
            print(f"  Exception: {str(e)[:100]}...")
            
except Exception as e:
    print(f"✗ No environment AWS credentials: {e}")

print()
print("=" * 80)
print("NEXT STEP: Check logs above for ERROR messages")
print("If modules show errors, they need proper credentials")
print("If modules show 0 findings but no errors, environment is likely secure")
print("=" * 80)

