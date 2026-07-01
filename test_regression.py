#!/usr/bin/env python3
"""Cthaeh regression test suite.

Tests scoring against known ground-truth samples and investigated drivers.
The integration path needs a triage_results.json from a real scan. The unit
path checks pure orchestrator scoring behavior without Ghidra.

Run:
    python test_regression.py --unit
    python test_regression.py --json triage_results.json

## Canary Test Concept (TODO)
When we have a collection of known-vulnerable driver binaries (.sys files),
we should inject them into every scan as calibration checks:
1. Maintain a canary/ directory with 5-10 drivers that have confirmed CVEs
2. Before each scan, copy canaries into the scan directory
3. After scoring, verify all canaries score CRITICAL or HIGH
4. If any canary drifts below expected tier, scoring weights have regressed
This catches silent regressions from weight tuning or threshold changes.
Requires: actual .sys binaries we have rights to redistribute (or download scripts).
"""

import json
import sys
import os
import argparse


# Ground truth: drivers with confirmed vulns should score HIGH+
CONFIRMED_VULNS = {
    "ssudbus2.sys": {
        "min_score": 150,
        "expected_checks": ["has_ioctl_handler", "usb_request_forwarding"],
        "vulns": "4 vulns: pool overflow, info leak, USB passthrough, weak device security",
    },
    "AsusWmiAcpi.sys": {
        "min_score": 150,
        "expected_checks": ["wmi_method_execution"],
        "vulns": "4 vulns: missing ACL on ACPI/WMI IOCTLs",
    },
    "mtkbtfilterx.sys": {
        "min_score": 150,
        "expected_checks": ["bt_driver_crypto"],
        "vulns": "BT HCI command passthrough, eFuse access",
    },
}

# Score should be reasonable (not astronomical)
SANITY_CHECKS = {
    "max_possible_score": 500,  # No driver should score above this
    "critical_percentage_max": 5,  # CRITICAL should be <5% of all drivers
}


def load_investigated_expectations(path="investigated.json"):
    """Load investigated driver expectations from the repo source of truth."""
    if not os.path.exists(path):
        return {}

    with open(path, "r") as f:
        data = json.load(f)

    entries = data.get("investigated", data.get("skip_drivers", {}))
    expectations = {}
    for driver_name, entry in entries.items():
        reason = entry.get("reason", "investigated") if isinstance(entry, dict) else str(entry)
        expectations[driver_name] = {
            "max_priority": "INVESTIGATED",
            "reason": reason,
        }
    return expectations


INVESTIGATEDS = load_investigated_expectations()


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


def run_unit_tests():
    """Run tests that do not require Ghidra output."""
    from run_triage import SCORE_TIERS, get_score_tier

    passed = 0
    failed = 0

    checks = [
        (SCORE_TIERS["LOW"] - 1, "SKIP"),
        (SCORE_TIERS["LOW"], "LOW"),
        (SCORE_TIERS["MEDIUM"] - 1, "LOW"),
        (SCORE_TIERS["MEDIUM"], "MEDIUM"),
        (SCORE_TIERS["HIGH"] - 1, "MEDIUM"),
        (SCORE_TIERS["HIGH"], "HIGH"),
        (SCORE_TIERS["CRITICAL"] - 1, "HIGH"),
        (SCORE_TIERS["CRITICAL"], "CRITICAL"),
    ]

    print("=== Unit Scoring Checks ===")
    for score, expected in checks:
        actual = get_score_tier(score)
        if actual == expected:
            print(f"  PASS  score {score} -> {actual}")
            passed += 1
        else:
            print(f"  FAIL  score {score} -> {actual} (expected {expected})")
            failed += 1

    print("\n=== Investigated Source of Truth ===")
    if INVESTIGATEDS:
        print(f"  PASS  loaded {len(INVESTIGATEDS)} investigated drivers from investigated.json")
        passed += 1
    else:
        print("  FAIL  no investigated drivers loaded from investigated.json")
        failed += 1

    print(f"\nUnit results: {passed} passed, {failed} failed")
    return failed == 0


def run_tests(results, strict_missing=False):
    passed = 0
    failed = 0
    missing = 0
    
    print(f"Running regression tests against {len(results)} drivers...\n")
    
    # Test confirmed vulns
    print("=== Confirmed Vulnerabilities (should score HIGH+) ===")
    for driver_name, expected in CONFIRMED_VULNS.items():
        r = find_driver(results, driver_name)
        if not r:
            print(f"  WARN  {driver_name} - expected sample not in results")
            missing += 1
            continue
        
        score = r.get("score", 0)
        priority = r.get("priority", "?")
        checks = {f["check"] for f in r.get("findings", [])}
        
        # INVESTIGATED drivers are expected to be skipped (they've been investigated)
        if priority in ("INVESTIGATED", "KNOWN_FP"):
            print(f"  PASS  {driver_name}: {priority} (already investigated, skip is correct)")
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
    for driver_name, expected in INVESTIGATEDS.items():
        r = find_driver(results, driver_name)
        if not r:
            print(f"  WARN  {driver_name} - investigated driver not in results")
            missing += 1
            continue
        
        priority = r.get("priority", "?")
        accepted = {expected["max_priority"], "KNOWN_FP"}  # Accept legacy label too
        if priority in accepted:
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
    
    active_results = [r for r in results if r.get("priority") not in ("INVESTIGATED", "KNOWN_FP")]
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
    print(f"  Results: {passed} passed, {failed} failed, {missing} missing")
    print(f"{'='*40}")
    
    if strict_missing and missing:
        return False
    return failed == 0


def main():
    parser = argparse.ArgumentParser(description="Run Cthaeh scoring regression checks")
    parser.add_argument("json_path", nargs="?", default="triage_results.json",
                        help="Path to triage_results.json")
    parser.add_argument("--json", dest="json_flag",
                        help="Path to triage_results.json")
    parser.add_argument("--unit", action="store_true",
                        help="Run unit checks only, without triage_results.json")
    parser.add_argument("--strict-missing", action="store_true",
                        help="Fail when expected drivers are missing from scan results")
    args = parser.parse_args()

    if args.unit:
        sys.exit(0 if run_unit_tests() else 1)

    json_path = args.json_flag or args.json_path
    
    if not os.path.exists(json_path):
        # Try home directory
        home_path = os.path.expanduser(f"~/{json_path}")
        if os.path.exists(home_path):
            json_path = home_path
        else:
            print(f"ERROR: {json_path} not found")
            print("Run a scan first or specify: python test_regression.py --json <path>")
            print("For local checks without Ghidra output, run: python test_regression.py --unit")
            sys.exit(1)
    
    results = load_results(json_path)
    success = run_unit_tests()
    print()
    success = run_tests(results, strict_missing=args.strict_missing) and success
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
