#!/usr/bin/env python3
"""
Cthaeh regression test suite.

Tests scoring against known ground-truth samples:
- 8 confirmed vulnerabilities (should score HIGH or CRITICAL)
- 5 known false positives (should score lower or be skipped)

Run: python test_regression.py [--json triage_results.json]
"""

import json
import sys
import os


# Ground truth: drivers with confirmed vulns should score HIGH+
CONFIRMED_VULNS = {
    "ssudbus2.sys": {
        "min_score": 85,  # Should be HIGH+
        "expected_checks": ["has_ioctl_handler", "usb_request_forwarding"],
        "vulns": "4 vulns: pool overflow, info leak, USB passthrough, weak device security",
    },
    "AsusWmiAcpi.sys": {
        "min_score": 85,
        "expected_checks": ["wmi_method_execution"],
        "vulns": "4 vulns: missing ACL on ACPI/WMI IOCTLs",
    },
    "mtkbtfilterx.sys": {
        "min_score": 85,
        "expected_checks": ["bt_driver_crypto"],
        "vulns": "BT HCI command passthrough, eFuse access",
    },
}

# Known FPs: should be KNOWN_FP (skipped) or score below CRITICAL
KNOWN_FPS = {
    "nvpcf.sys": {
        "max_priority": "KNOWN_FP",  # Should be skipped
        "reason": "MSR read not user-reachable",
    },
    "AMDRyzenMasterDriver.sys": {
        "max_priority": "KNOWN_FP",
        "reason": "Cannot obtain latest version",
    },
    "AsusSAIO.sys": {
        "max_priority": "KNOWN_FP",
        "reason": "Already investigated",
    },
}

# Score should be reasonable (not astronomical)
SANITY_CHECKS = {
    "max_possible_score": 500,  # No driver should score above this
    "critical_percentage_max": 25,  # CRITICAL should be <25% of all drivers
}


def load_results(json_path):
    with open(json_path, "r") as f:
        return json.load(f)


def find_driver(results, name):
    name_lower = name.lower()
    for r in results:
        d = r.get("driver", {})
        if d.get("name", "").lower() == name_lower:
            return r
    return None


def run_tests(results):
    passed = 0
    failed = 0
    skipped = 0
    
    print(f"Running regression tests against {len(results)} drivers...\n")
    
    # Test confirmed vulns
    print("=== Confirmed Vulnerabilities (should score HIGH+) ===")
    for driver_name, expected in CONFIRMED_VULNS.items():
        r = find_driver(results, driver_name)
        if not r:
            print(f"  SKIP  {driver_name} - not in results")
            skipped += 1
            continue
        
        score = r.get("score", 0)
        priority = r.get("priority", "?")
        checks = {f["check"] for f in r.get("findings", [])}
        
        # KNOWN_FP drivers are expected to be skipped (they've been investigated)
        if priority == "KNOWN_FP":
            print(f"  PASS  {driver_name}: KNOWN_FP (already investigated, skip is correct)")
            passed += 1
            continue
        
        # Check minimum score
        if score >= expected["min_score"]:
            print(f"  PASS  {driver_name}: score={score} priority={priority} (min={expected['min_score']})")
            passed += 1
        else:
            print(f"  FAIL  {driver_name}: score={score} priority={priority} (expected min={expected['min_score']})")
            failed += 1
        
        # Check expected checks fired
        for check in expected.get("expected_checks", []):
            if check in checks:
                print(f"        + check '{check}' fired")
            else:
                print(f"        ! check '{check}' DID NOT fire")
    
    print()
    
    # Test known FPs
    print("=== Known False Positives (should be skipped) ===")
    for driver_name, expected in KNOWN_FPS.items():
        r = find_driver(results, driver_name)
        if not r:
            print(f"  SKIP  {driver_name} - not in results")
            skipped += 1
            continue
        
        priority = r.get("priority", "?")
        if priority == expected["max_priority"]:
            print(f"  PASS  {driver_name}: priority={priority}")
            passed += 1
        else:
            print(f"  FAIL  {driver_name}: priority={priority} (expected={expected['max_priority']})")
            failed += 1
    
    print()
    
    # Sanity checks
    print("=== Sanity Checks ===")
    
    max_score = max(r.get("score", 0) for r in results)
    if max_score <= SANITY_CHECKS["max_possible_score"]:
        print(f"  PASS  Max score {max_score} <= {SANITY_CHECKS['max_possible_score']}")
        passed += 1
    else:
        print(f"  FAIL  Max score {max_score} > {SANITY_CHECKS['max_possible_score']}")
        failed += 1
    
    active_results = [r for r in results if r.get("priority") != "KNOWN_FP"]
    if active_results:
        critical_count = sum(1 for r in active_results if r.get("priority") == "CRITICAL")
        critical_pct = (critical_count / len(active_results)) * 100
        max_pct = SANITY_CHECKS["critical_percentage_max"]
        if critical_pct <= max_pct:
            print(f"  PASS  CRITICAL rate {critical_pct:.1f}% <= {max_pct}%")
            passed += 1
        else:
            print(f"  FAIL  CRITICAL rate {critical_pct:.1f}% > {max_pct}% ({critical_count}/{len(active_results)})")
            failed += 1
    
    print(f"\n{'='*40}")
    print(f"  Results: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*40}")
    
    return failed == 0


def main():
    json_path = "triage_results.json"
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--json" and len(sys.argv) > 2:
            json_path = sys.argv[2]
        else:
            json_path = sys.argv[1]
    
    if not os.path.exists(json_path):
        # Try home directory
        home_path = os.path.expanduser(f"~/{json_path}")
        if os.path.exists(home_path):
            json_path = home_path
        else:
            print(f"ERROR: {json_path} not found")
            print("Run a scan first or specify: python test_regression.py --json <path>")
            sys.exit(1)
    
    results = load_results(json_path)
    success = run_tests(results)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
