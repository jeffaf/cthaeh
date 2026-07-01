#!/usr/bin/env python3
"""Report score distribution and calibration guardrails for Cthaeh results."""

import argparse
import json
import os
import statistics
import sys

from run_triage import SCORE_TIERS


TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SKIP", "INVESTIGATED", "KNOWN_FP"]


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def load_results(path):
    data = load_json(path)
    if isinstance(data, dict):
        return data.get("results", data.get("drivers", []))
    return data


def load_investigated(path):
    if not path or not os.path.exists(path):
        return {}
    data = load_json(path)
    return data.get("investigated", data.get("skip_drivers", {}))


def driver_name(result):
    return result.get("driver", {}).get("name", "").lower()


def percentile(values, pct):
    if not values:
        return 0
    ordered = sorted(values)
    idx = int(round((pct / 100.0) * (len(ordered) - 1)))
    return ordered[idx]


def main():
    parser = argparse.ArgumentParser(description="Generate a Cthaeh scoring calibration report")
    parser.add_argument("--json", default="triage_results.json",
                        help="Path to triage_results.json")
    parser.add_argument("--investigated", default="investigated.json",
                        help="Path to investigated.json")
    parser.add_argument("--critical-max-pct", type=float, default=5.0,
                        help="Maximum acceptable active CRITICAL rate")
    args = parser.parse_args()

    if not os.path.exists(args.json):
        print("ERROR: %s not found" % args.json)
        return 1

    results = load_results(args.json)
    if not results:
        print("ERROR: no results found in %s" % args.json)
        return 1

    investigated = load_investigated(args.investigated)
    investigated_names = {name.lower() for name in investigated}

    active = [r for r in results if r.get("priority") not in ("INVESTIGATED", "KNOWN_FP")]
    active_scores = [r.get("score", 0) for r in active]

    counts = {}
    for tier in TIERS:
        counts[tier] = sum(1 for r in results if r.get("priority") == tier)

    active_critical = sum(1 for r in active if r.get("priority") == "CRITICAL")
    active_critical_pct = (active_critical / float(len(active))) * 100.0 if active else 0.0

    investigated_high = []
    for r in results:
        name = driver_name(r)
        if name in investigated_names and r.get("priority") not in ("INVESTIGATED", "KNOWN_FP"):
            if r.get("score", 0) >= SCORE_TIERS["HIGH"]:
                investigated_high.append(r)

    print("Cthaeh Calibration Report")
    print("=========================")
    print("Results: %s" % args.json)
    print("Drivers: %d total, %d active" % (len(results), len(active)))
    print("")
    print("Tier distribution:")
    for tier in TIERS:
        if counts[tier]:
            print("  %-12s %4d" % (tier + ":", counts[tier]))
    print("")
    print("Score distribution, active drivers:")
    print("  max:     %d" % (max(active_scores) if active_scores else 0))
    print("  median:  %.1f" % (statistics.median(active_scores) if active_scores else 0))
    print("  p90:     %d" % percentile(active_scores, 90))
    print("  p95:     %d" % percentile(active_scores, 95))
    print("  p99:     %d" % percentile(active_scores, 99))
    print("")
    print("Guardrails:")
    print("  CRITICAL rate: %.1f%% (%d/%d), max %.1f%%" % (
        active_critical_pct, active_critical, len(active), args.critical_max_pct))
    if active_critical_pct > args.critical_max_pct:
        print("  FAIL: CRITICAL rate exceeds guardrail")
    else:
        print("  PASS: CRITICAL rate within guardrail")

    if investigated_high:
        print("  FAIL: investigated drivers still rank HIGH+")
        for r in investigated_high:
            print("    %-32s score=%d priority=%s" % (
                r.get("driver", {}).get("name", "?"),
                r.get("score", 0),
                r.get("priority", "?"),
            ))
    else:
        print("  PASS: no investigated drivers rank HIGH+")

    return 1 if active_critical_pct > args.critical_max_pct or investigated_high else 0


if __name__ == "__main__":
    sys.exit(main())
