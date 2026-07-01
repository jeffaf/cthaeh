#!/usr/bin/env python3
"""Report score distribution and calibration guardrails for Cthaeh results.

Outcome metrics ("did the ranking do its job?"):
  precision@K  - fraction of the top K active drivers that are NOT confirmed FPs
  recall@HIGH  - fraction of confirmed-vuln drivers scored on merit (i.e. not
                 investigated-overridden) that landed >= HIGH
  fp_leakage   - count of confirmed-FP drivers that landed >= HIGH on raw signals

Proxy metrics (kept for shape, distrusted for correctness):
  CRITICAL rate, max score, score percentiles.

Drift detection:
  --write-baseline PATH  save current outcome metrics
  --baseline PATH        compare against saved metrics, fail on regression
"""

import argparse
import json
import os
import statistics
import sys

from run_triage import SCORE_TIERS


TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SKIP", "INVESTIGATED", "KNOWN_FP"]

# Regression tolerances for baseline drift. Tuned to catch real regressions
# while tolerating churn from adding one heuristic wave.
DRIFT_TOLERANCE = {
    "critical_rate_pct_abs": 1.5,   # absolute pct-point delta on CRITICAL rate
    "median_score_abs": 15,         # absolute score delta on active-median
    "p90_score_abs": 25,            # absolute score delta on p90
    "precision_at_10_abs": 0.10,    # absolute precision@10 drop
    "recall_high_abs": 0.10,        # absolute recall@HIGH drop
}


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
    parser.add_argument("--write-baseline", metavar="PATH",
                        help="Write outcome-metric snapshot to PATH for future drift checks")
    parser.add_argument("--baseline", metavar="PATH",
                        help="Compare current metrics against saved baseline PATH; fail on drift")
    args = parser.parse_args()

    if not os.path.exists(args.json):
        print("ERROR: %s not found" % args.json)
        return 1

    results = load_results(args.json)
    if not results:
        print("ERROR: no results found in %s" % args.json)
        return 1

    investigated = load_investigated(args.investigated)
    # Only false-positive dispositions must rank below HIGH. Confirmed vulns in
    # the investigated set are expected to score HIGH+ and must not be flagged.
    false_positive_names = {
        name.lower() for name, entry in investigated.items()
        if isinstance(entry, dict) and entry.get("disposition") == "false_positive"
    }
    confirmed_vuln_names = {
        name.lower() for name, entry in investigated.items()
        if isinstance(entry, dict) and entry.get("disposition") == "confirmed_vuln"
    }

    active = [r for r in results if r.get("priority") not in ("INVESTIGATED", "KNOWN_FP")]
    active_scores = [r.get("score", 0) for r in active]
    ranked = sorted(active, key=lambda r: r.get("score", 0), reverse=True)

    counts = {}
    for tier in TIERS:
        counts[tier] = sum(1 for r in results if r.get("priority") == tier)

    active_critical = sum(1 for r in active if r.get("priority") == "CRITICAL")
    active_critical_pct = (active_critical / float(len(active))) * 100.0 if active else 0.0

    fp_high = []
    for r in results:
        name = driver_name(r)
        if name in false_positive_names and r.get("priority") not in ("INVESTIGATED", "KNOWN_FP"):
            if r.get("score", 0) >= SCORE_TIERS["HIGH"]:
                fp_high.append(r)

    # Outcome metrics.
    # precision@K: top-K by score minus confirmed-FP contaminants, divided by K.
    # Unlabeled and confirmed-vuln drivers both count as legitimate top-of-list hits.
    precision_at = {}
    for k in (10, 25, 50):
        top_k = ranked[:k]
        if not top_k:
            precision_at[k] = None
            continue
        contaminants = sum(1 for r in top_k if driver_name(r) in false_positive_names)
        precision_at[k] = (len(top_k) - contaminants) / float(len(top_k))

    # recall@HIGH: of confirmed-vuln drivers actually scored on merit (i.e. the
    # investigated-override did NOT zero them), what fraction reached HIGH+?
    # Drivers where the override fired are excluded because their raw score is
    # unrecoverable from the stored results, not because they were wrong.
    confirmed_scored = [
        r for r in results
        if driver_name(r) in confirmed_vuln_names
        and r.get("priority") not in ("INVESTIGATED", "KNOWN_FP")
    ]
    recall_high_hits = sum(1 for r in confirmed_scored if r.get("score", 0) >= SCORE_TIERS["HIGH"])
    recall_high = (recall_high_hits / float(len(confirmed_scored))) if confirmed_scored else None

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
    print("Score distribution, active drivers (proxy metrics — distrust for correctness):")
    print("  max:     %d" % (max(active_scores) if active_scores else 0))
    print("  median:  %.1f" % (statistics.median(active_scores) if active_scores else 0))
    print("  p90:     %d" % percentile(active_scores, 90))
    print("  p95:     %d" % percentile(active_scores, 95))
    print("  p99:     %d" % percentile(active_scores, 99))
    print("")

    def _fmt(v):
        return "n/a" if v is None else "%.2f" % v

    print("Outcome metrics:")
    print("  precision@10:  %s  (top 10 minus confirmed-FP contaminants)" % _fmt(precision_at.get(10)))
    print("  precision@25:  %s" % _fmt(precision_at.get(25)))
    print("  precision@50:  %s" % _fmt(precision_at.get(50)))
    if recall_high is None:
        print("  recall@HIGH:   n/a  (no confirmed-vuln drivers scored on merit in this scan)")
    else:
        print("  recall@HIGH:   %s  (confirmed vulns >= HIGH, %d/%d)" % (
            _fmt(recall_high), recall_high_hits, len(confirmed_scored)))
    print("  fp_leakage:    %d confirmed-FP driver(s) ranked HIGH+" % len(fp_high))
    print("")
    print("Guardrails:")
    print("  CRITICAL rate: %.1f%% (%d/%d), max %.1f%%" % (
        active_critical_pct, active_critical, len(active), args.critical_max_pct))
    if active_critical_pct > args.critical_max_pct:
        print("  FAIL: CRITICAL rate exceeds guardrail")
    else:
        print("  PASS: CRITICAL rate within guardrail")

    if fp_high:
        print("  FAIL: known false-positive drivers still rank HIGH+")
        for r in fp_high:
            print("    %-32s score=%d priority=%s" % (
                r.get("driver", {}).get("name", "?"),
                r.get("score", 0),
                r.get("priority", "?"),
            ))
    else:
        print("  PASS: no known false-positive drivers rank HIGH+")

    snapshot = {
        "critical_rate_pct": active_critical_pct,
        "score_median": float(statistics.median(active_scores)) if active_scores else 0.0,
        "score_p90": percentile(active_scores, 90),
        "precision_at_10": precision_at.get(10),
        "recall_high": recall_high,
        "fp_leakage_count": len(fp_high),
    }

    if args.write_baseline:
        with open(args.write_baseline, "w") as f:
            json.dump(snapshot, f, indent=2, sort_keys=True)
        print("")
        print("Wrote baseline snapshot: %s" % args.write_baseline)

    exit_code = 0
    if active_critical_pct > args.critical_max_pct:
        exit_code = 1
    if fp_high:
        exit_code = 1  # confirmed-FP contamination in the ranked list is a real regression

    if args.baseline:
        if not os.path.exists(args.baseline):
            print("")
            print("ERROR: baseline %s not found" % args.baseline)
            return 1
        with open(args.baseline, "r") as f:
            base = json.load(f)
        violations = _compare_baseline(snapshot, base)
        print("")
        print("Baseline drift vs %s:" % args.baseline)
        if violations:
            for v in violations:
                print("  FAIL: %s" % v)
            exit_code = 1
        else:
            print("  PASS: within DRIFT_TOLERANCE")

    return exit_code


def _compare_baseline(current, baseline):
    """Return a list of drift violations vs. the saved baseline snapshot."""
    violations = []
    tol = DRIFT_TOLERANCE

    def _delta(k):
        c, b = current.get(k), baseline.get(k)
        if c is None or b is None:
            return None
        return c - b

    d = _delta("critical_rate_pct")
    if d is not None and abs(d) > tol["critical_rate_pct_abs"]:
        violations.append("critical_rate_pct drift %+.2f exceeds +/- %.2f" % (d, tol["critical_rate_pct_abs"]))

    d = _delta("score_median")
    if d is not None and abs(d) > tol["median_score_abs"]:
        violations.append("score_median drift %+.1f exceeds +/- %.1f" % (d, tol["median_score_abs"]))

    d = _delta("score_p90")
    if d is not None and abs(d) > tol["p90_score_abs"]:
        violations.append("score_p90 drift %+d exceeds +/- %d" % (d, tol["p90_score_abs"]))

    d = _delta("precision_at_10")
    if d is not None and d < -tol["precision_at_10_abs"]:
        violations.append("precision@10 dropped %+.2f, exceeds -%.2f" % (d, tol["precision_at_10_abs"]))

    d = _delta("recall_high")
    if d is not None and d < -tol["recall_high_abs"]:
        violations.append("recall@HIGH dropped %+.2f, exceeds -%.2f" % (d, tol["recall_high_abs"]))

    cur_fp, old_fp = current.get("fp_leakage_count", 0), baseline.get("fp_leakage_count", 0)
    if cur_fp > old_fp:
        violations.append("fp_leakage_count grew from %d to %d" % (old_fp, cur_fp))

    return violations


if __name__ == "__main__":
    sys.exit(main())
