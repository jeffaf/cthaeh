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

try:
    import yaml
except ImportError:
    yaml = None


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


# Synthetic finding sets used by --unit scoring tests. Each set is a list of
# check names from scoring_rules.yaml `weights:`; the test sums their weights
# and asserts the tier boundary. This catches weight edits that silently
# move a canonical driver profile across a tier boundary. When a wave
# intentionally shifts a boundary, update `expected_tier` here as the
# calibration event.
SYNTHETIC_PROFILES = {
    # Tier expectations derived from the current YAML weights on 2026-07-01
    # against real CRITICAL/HIGH drivers observed in a 340-driver scan
    # (athw8x.sys, mtkbtfilterx.sys, vhdmp.sys) plus reducer-driven FP
    # profiles (nvpcf, amdfendr). Recalibrate these tiers whenever a
    # heuristic wave shifts weights or thresholds.
    "wifi_god_mode_realistic": {
        # Modelled on athw8x.sys / athwnx.sys signature (score=285, CRITICAL)
        "checks": [
            "insecure_device_creation", "has_ioctl_handler", "method_neither_heavy",
            "file_any_access_heavy", "no_probe_functions", "maps_locked_pages_cache",
            "maps_physical_memory", "physical_memory_rw", "named_device",
            "likely_hvci_incompatible", "vendor_cna_bounty", "wifi_driver",
            "massive_ioctl_surface", "no_auth_imports", "wmi_method_execution",
            "port_io_rw", "uefi_variable_access", "compound_easy_target",
            "vuln_pattern_composite",
        ],
        "expected_tier": "CRITICAL",
        "why": "Regression anchor for the CRITICAL tier — models the Atheros wifi driver signature seen at score=285",
    },
    "bt_usb_passthrough_realistic": {
        # Modelled on the weighted subset of mtkbtfilterx.sys (real score=285
        # CRITICAL). Several signals on the real driver are informational-only
        # in scoring_rules.yaml (method_buffered, file_read/write, wmi_provider,
        # irp_forwarding) so the weighted-only subset lands HIGH, not CRITICAL.
        # HIGH is the honest anchor: a bt-passthrough signature must clear HIGH.
        "checks": [
            "insecure_device_creation", "has_ioctl_handler", "method_neither_heavy",
            "no_probe_functions", "named_device", "kernel_registry_write",
            "vendor_cna_bounty", "large_ioctl_surface", "symlink_no_acl",
            "no_auth_imports", "usb_request_forwarding", "bt_driver_crypto",
            "efuse_access", "wdm_direct_device", "hardcoded_crypto_key",
            "hci_command_passthrough", "compound_easy_target",
        ],
        "expected_tier": "HIGH",
        "why": "Regression anchor for the HIGH tier — BT/USB passthrough signature (real driver reaches CRITICAL only with additional file-op stacking)",
    },
    "moderate_ioctl_driver": {
        # A realistic mid-tier candidate: open device, IOCTLs, some auth gaps
        "checks": [
            "insecure_device_creation", "has_ioctl_handler", "named_device",
            "no_probe_functions", "moderate_ioctl_surface", "vendor_cna",
            "kernel_registry_write",
        ],
        "expected_tier": "MEDIUM",
        "why": "Sanity anchor for the MEDIUM tier — modest IOCTL surface without hard primitives",
    },
    "clean_wdf_inbox_driver": {
        # Canonical FP profile: WDF + WHQL-inbox + validation should suppress
        "checks": [
            "has_ioctl_handler", "wdf_device_interface", "whql_signed_inbox",
            "has_internal_validation",
        ],
        "expected_tier": "SKIP",
        "why": "Canonical FP profile — WDF + WHQL-inbox + validation must land below LOW so reducers cannot silently be neutralized",
    },
    "lol_driver_suppressed": {
        # LOLDrivers already exploited: primitives present but -30 reducer must
        # drop the tier so triage focuses on novel targets, not rehashes.
        # Without the reducer this profile scores 85 (MEDIUM); with it, 55 (LOW).
        "checks": [
            "msr_write", "physical_memory_rw", "control_register_access",
            "insecure_device_creation", "has_ioctl_handler",
            "loldrivers_known",  # -30 reducer
        ],
        "expected_tier": "LOW",
        "why": "LOLDrivers -30 reducer must drop a primitives-bearing known-bad driver from MEDIUM (85) to LOW (55). If this drifts, the 'novel targets first' contract is broken.",
    },
    "borderline_low": {
        # Anchor for the LOW/MEDIUM boundary. Detects threshold drift.
        "checks": [
            "has_ioctl_handler", "named_device", "no_probe_functions",
            "moderate_ioctl_surface",
        ],
        "expected_tier": "LOW",
        "why": "LOW/MEDIUM boundary anchor — if this drifts up or down, threshold recalibration is due",
    },
}


def _score_yaml_path():
    """Locate scoring_rules.yaml next to this file, then in cwd."""
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "scoring_rules.yaml"),
              os.path.join(os.getcwd(), "scoring_rules.yaml")):
        if os.path.exists(p):
            return p
    return None


def _load_weights():
    """Load {check_name: weight} from scoring_rules.yaml, or None if yaml unavailable."""
    path = _score_yaml_path()
    if not path or yaml is None:
        return None
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("weights", {}) if data else {}


def load_investigated_expectations(path="investigated.json"):
    """Load investigated driver expectations from the repo source of truth."""
    if not os.path.exists(path):
        return {}

    with open(path, "r") as f:
        data = json.load(f)

    entries = data.get("investigated", data.get("skip_drivers", {}))
    expectations = {}
    for driver_name, entry in entries.items():
        if isinstance(entry, dict):
            reason = entry.get("reason", "investigated")
            disposition = entry.get("disposition", "investigated")
        else:
            reason = str(entry)
            disposition = "investigated"
        expectations[driver_name] = {
            "max_priority": "INVESTIGATED",
            "reason": reason,
            "disposition": disposition,
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

    print("\n=== Investigated Disposition Split ===")
    dispositions = {e.get("disposition") for e in INVESTIGATEDS.values()}
    if {"confirmed_vuln", "false_positive"} <= dispositions:
        print(f"  PASS  disposition split present: {sorted(d for d in dispositions if d)}")
        passed += 1
    else:
        print(f"  FAIL  disposition split incomplete (found {sorted(d for d in dispositions if d)})")
        failed += 1

    print("\n=== Synthetic Scoring Profiles ===")
    weights = _load_weights()
    if weights is None:
        print("  WARN  pyyaml not installed or scoring_rules.yaml missing; skipping synthetic scoring")
    else:
        for profile_name, profile in SYNTHETIC_PROFILES.items():
            missing = [c for c in profile["checks"] if c not in weights]
            if missing:
                print(f"  FAIL  {profile_name}: missing weights for {missing} (edit synthetic profile or yaml)")
                failed += 1
                continue
            score = sum(weights[c] for c in profile["checks"])
            tier = get_score_tier(score)
            if tier == profile["expected_tier"]:
                print(f"  PASS  {profile_name}: score={score} tier={tier}")
                passed += 1
            else:
                print(f"  FAIL  {profile_name}: score={score} tier={tier} (expected {profile['expected_tier']})")
                print(f"        why: {profile['why']}")
                failed += 1

    print(f"\nUnit results: {passed} passed, {failed} failed")
    return failed == 0


def run_tests(results, strict_missing=False):
    passed = 0
    failed = 0
    missing = 0
    
    print(f"Running regression tests against {len(results)} drivers...\n")
    
    # Test confirmed vulns. A confirmed vuln overridden to INVESTIGATED does
    # NOT auto-PASS: that would make the test tautological once the driver is
    # added to investigated.json. Instead we WARN that scoring cannot be
    # evaluated on this scan; re-run with the driver temporarily removed from
    # investigated.json to verify raw scoring.
    print("=== Confirmed Vulnerabilities (should score HIGH+ on merit) ===")
    for driver_name, expected in CONFIRMED_VULNS.items():
        r = find_driver(results, driver_name)
        if not r:
            print(f"  WARN  {driver_name} - expected sample not in results")
            missing += 1
            continue

        score = r.get("score", 0)
        priority = r.get("priority", "?")
        checks = {f["check"] for f in r.get("findings", [])}

        if priority in ("INVESTIGATED", "KNOWN_FP"):
            print(f"  WARN  {driver_name}: {priority} — score unrecoverable, cannot evaluate")
            print(f"        re-run scan with this entry removed from investigated.json to verify")
            missing += 1
            continue

        if score >= expected["min_score"]:
            print(f"  PASS  {driver_name}: score={score} priority={priority} (min={expected['min_score']})")
            passed += 1
        else:
            print(f"  FAIL  {driver_name}: score={score} priority={priority} (expected min={expected['min_score']})")
            failed += 1

        for check in expected.get("expected_checks", []):
            if check in checks:
                print(f"        + check '{check}' fired")
            else:
                print(f"        ! check '{check}' DID NOT fire")

    print()

    # Test dispositions with real assertions per class.
    #   confirmed_vuln  : if scored on merit, must be HIGH+
    #   false_positive  : if scored on merit, must be below HIGH (raw-signal
    #                     FP suppression, independent of the override)
    #   investigated    : neutral — must be either INVESTIGATED-overridden or
    #                     just present (no scoring assertion)
    print("=== Investigated Drivers by Disposition ===")
    from run_triage import SCORE_TIERS
    high_thresh = SCORE_TIERS["HIGH"]
    for driver_name, expected in INVESTIGATEDS.items():
        r = find_driver(results, driver_name)
        if not r:
            print(f"  WARN  {driver_name} - investigated driver not in results")
            missing += 1
            continue

        priority = r.get("priority", "?")
        score = r.get("score", 0)
        disp = expected.get("disposition", "investigated")
        overridden = priority in ("INVESTIGATED", "KNOWN_FP")

        if disp == "confirmed_vuln":
            if overridden:
                print(f"  PASS  {driver_name}: {priority} [confirmed_vuln, override applied]")
                passed += 1
            elif score >= high_thresh:
                print(f"  PASS  {driver_name}: score={score} priority={priority} [confirmed_vuln, HIGH+ on merit]")
                passed += 1
            else:
                print(f"  FAIL  {driver_name}: score={score} priority={priority} [confirmed_vuln, expected HIGH+]")
                failed += 1
        elif disp == "false_positive":
            if overridden:
                print(f"  WARN  {driver_name}: {priority} [false_positive, override applied — raw score not evaluable]")
                missing += 1
            elif score < high_thresh:
                print(f"  PASS  {driver_name}: score={score} priority={priority} [false_positive, below HIGH on merit]")
                passed += 1
            else:
                print(f"  FAIL  {driver_name}: score={score} priority={priority} [false_positive, expected below HIGH — reducers failed]")
                failed += 1
        else:
            # "investigated" / "ambiguous" — no correctness claim
            print(f"  PASS  {driver_name}: priority={priority} [{disp}, no assertion]")
            passed += 1
    
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
