#!/usr/bin/env python3
"""
Cthaeh - Batch driver triage orchestrator

Feeds .sys files through Ghidra headless analysis with driver_triage.py,
collects scores, and outputs a ranked CSV.

Usage:
    # Basic scan
    python run_triage.py --drivers-dir C:\\drivers --ghidra C:\\ghidra_11.3

    # With pre-filter (fast, skips uninteresting drivers)
    python run_triage.py --drivers-dir C:\\drivers --ghidra C:\\ghidra_11.3 --prefilter

    # Parallel (4 workers)
    python run_triage.py --drivers-dir C:\\drivers --ghidra C:\\ghidra_11.3 --prefilter --workers 4

    # Single driver
    python run_triage.py --single C:\\path\\to\\driver.sys --ghidra C:\\ghidra_11.3
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


def find_sys_files(directory):
    """Recursively find all .sys files in a directory."""
    sys_files = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            if f.lower().endswith(".sys"):
                sys_files.append(os.path.join(root, f))
    return sys_files


def run_ghidra_analysis(args_tuple):
    """Run Ghidra headless analysis on a single driver.
    
    Takes a tuple for ProcessPoolExecutor compatibility:
    (ghidra_path, driver_path, script_path, project_dir, worker_id)
    """
    ghidra_path, driver_path, script_path, project_base, worker_id = args_tuple
    
    # Each worker gets its own project directory to avoid conflicts
    project_dir = os.path.join(project_base, f"worker_{worker_id}")
    os.makedirs(project_dir, exist_ok=True)
    
    if sys.platform == "win32":
        headless = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
    else:
        headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
    
    if not os.path.exists(headless):
        return None, f"Ghidra headless not found at {headless}"
    
    driver_name = Path(driver_path).stem
    
    cmd = [
        headless,
        project_dir,
        f"triage_{driver_name}",
        "-import", driver_path,
        "-postScript", os.path.basename(script_path),
        "-deleteProject",
        "-scriptPath", os.path.dirname(script_path),
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout per driver
        )
        
        # Extract JSON from output (check both stdout and stderr)
        for output in [result.stdout, result.stderr]:
            if "===TRIAGE_START===" in output and "===TRIAGE_END===" in output:
                json_str = output.split("===TRIAGE_START===")[1].split("===TRIAGE_END===")[0].strip()
                return json.loads(json_str), None
        
        return None, "no triage output"
            
    except subprocess.TimeoutExpired:
        return None, "timeout (>5min)"
    except json.JSONDecodeError as e:
        return None, f"bad JSON: {e}"
    except Exception as e:
        return None, str(e)


def run_prefilter(drivers_dir, max_size_mb=5):
    """Run the pefile pre-filter to eliminate uninteresting drivers."""
    try:
        from prefilter import prefilter_directory
        max_bytes = max_size_mb * 1024 * 1024
        results = prefilter_directory(drivers_dir, max_bytes, check_loldrivers=True)
        return [d["path"] for d in results["analyze"]]
    except ImportError:
        print("WARNING: prefilter.py not found or pefile not installed.")
        print("  Install: pip install pefile")
        print("  Falling back to full scan.\n")
        return None


def write_json(results, output_path):
    """Write full results with all findings to JSON."""
    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Full results (JSON) written to: {output_path}")


def write_csv(results, output_path):
    """Write results to CSV, sorted by score descending."""
    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Priority", "Score", "Driver", "Class", "Path", "Size",
            "Functions", "Findings", "Top Checks"
        ])
        
        for r in results:
            driver = r.get("driver", {})
            findings = r.get("findings", [])
            top_checks = ", ".join(
                f["check"] for f in sorted(findings, key=lambda x: x["score"], reverse=True)[:5]
            )
            
            dc = r.get("driver_class", {})
            driver_cls = dc.get("class", "?") if dc else "?"

            writer.writerow([
                r.get("priority", "?"),
                r.get("score", 0),
                driver.get("name", "?"),
                driver_cls,
                driver.get("path", "?"),
                driver.get("size", 0),
                driver.get("function_count", 0),
                r.get("findings_count", 0),
                top_checks,
            ])
    
    print(f"\nResults written to: {output_path}")


def print_summary(results):
    """Print a quick summary to terminal."""
    total = len(results)
    critical = sum(1 for r in results if r.get("priority") == "CRITICAL")
    high = sum(1 for r in results if r.get("priority") == "HIGH")
    medium = sum(1 for r in results if r.get("priority") == "MEDIUM")
    low = sum(1 for r in results if r.get("priority") == "LOW")
    skip = sum(1 for r in results if r.get("priority") == "SKIP")
    
    print(f"\n{'='*60}")
    print(f"  🌳 CTHAEH TRIAGE COMPLETE: {total} drivers analyzed")
    print(f"{'='*60}")
    print(f"  💀 CRITICAL:        {critical}")
    print(f"  🔴 HIGH priority:   {high}")
    print(f"  🟡 MEDIUM priority: {medium}")
    print(f"  🟢 LOW priority:    {low}")
    print(f"  ⚪ SKIP:            {skip}")
    print()
    
    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    if results:
        print("Top targets:")
        for i, r in enumerate(results[:20], 1):
            driver = r.get("driver", {})
            dc = r.get("driver_class", {})
            cls_tag = f" [{dc['class']}]" if dc and dc.get("class", "UNKNOWN") != "UNKNOWN" else ""
            print(f"  {i:2d}. [{r.get('priority', '?'):6s}] {r.get('score', 0):3d} pts  {driver.get('name', '?')}{cls_tag}")


def run_analysis(drivers, ghidra_path, script_path, project_dir, workers=1, json_output=None):
    """Run analysis with 1+ workers. Streams results to JSON as they complete."""
    results = []
    failed = 0
    completed = 0
    total = len(drivers)

    # Build args tuples with worker IDs (round-robin assignment)
    args_list = [
        (ghidra_path, driver_path, script_path, project_dir, i % max(workers, 1))
        for i, driver_path in enumerate(drivers)
    ]

    if workers > 1:
        print(f"Running with {workers} parallel workers...\n")

    with ProcessPoolExecutor(max_workers=workers) as executor:
        future_to_driver = {
            executor.submit(run_ghidra_analysis, args): args[1]
            for args in args_list
        }

        for future in as_completed(future_to_driver):
            driver_path = future_to_driver[future]
            driver_name = os.path.basename(driver_path)
            completed += 1

            try:
                result, error = future.result()
                if result:
                    results.append(result)
                    score = result.get("score", 0)
                    priority = result.get("priority", "?")
                    print(f"[{completed}/{total}] {driver_name}... {priority} ({score} pts)")
                    # Stream results to JSON as they complete
                    if json_output:
                        _stream_json(results, json_output)
                else:
                    failed += 1
                    print(f"[{completed}/{total}] {driver_name}... FAILED ({error})")
            except Exception as e:
                failed += 1
                print(f"[{completed}/{total}] {driver_name}... ERROR ({e})")

    if failed:
        print(f"\n{failed} driver(s) failed analysis")

    return results


def _stream_json(results, output_path):
    """Write current results to JSON (called after each completion for crash recovery)."""
    try:
        sorted_results = sorted(results, key=lambda x: x.get("score", 0), reverse=True)
        with open(output_path, "w") as f:
            json.dump(sorted_results, f, indent=2)
    except Exception:
        pass  # Don't fail the scan over a write error


def write_report(results, output_path, top_n=20):
    """Generate a markdown triage report for top candidates."""
    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    
    total = len(results)
    critical = sum(1 for r in results if r.get("priority") == "CRITICAL")
    high = sum(1 for r in results if r.get("priority") == "HIGH")
    medium = sum(1 for r in results if r.get("priority") == "MEDIUM")
    low = sum(1 for r in results if r.get("priority") == "LOW")
    skip = sum(1 for r in results if r.get("priority") == "SKIP")
    investigated_count = sum(1 for r in results if r.get("priority") == "INVESTIGATED")
    
    PRIORITY_EMOJI = {
        "CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡",
        "LOW": "🟢", "SKIP": "⚪", "INVESTIGATED": "🚫"
    }
    
    lines = []
    lines.append("# Cthaeh Triage Report")
    lines.append("")
    lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"**Drivers analyzed:** {total}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- 💀 CRITICAL: {critical}")
    lines.append(f"- 🔴 HIGH: {high}")
    lines.append(f"- 🟡 MEDIUM: {medium}")
    lines.append(f"- 🟢 LOW: {low}")
    lines.append(f"- ⚪ SKIP: {skip}")
    if investigated_count:
        lines.append(f"- 🚫 Investigated: {investigated_count}")
    lines.append("")
    lines.append(f"## Top {top_n} Candidates")
    lines.append("")
    
    for i, r in enumerate(results[:top_n], 1):
        driver = r.get("driver", {})
        name = driver.get("name", "unknown")
        score = r.get("score", 0)
        priority = r.get("priority", "?")
        emoji = PRIORITY_EMOJI.get(priority, "❓")
        version_summary = driver.get("version_summary", "")
        skip_reason = r.get("skip_reason", "")
        
        lines.append(f"### {i}. {emoji} {name} (Score: {score}, {priority})")
        lines.append("")
        
        if skip_reason:
            lines.append(f"> **Skipped:** {skip_reason}")
            lines.append("")
            continue
        
        if version_summary:
            lines.append(f"**Vendor/Product:** {version_summary}")
        vi = r.get("vendor_info", {})
        if vi:
            cna_str = "✅ CNA" if vi.get("is_cna") else "❌ Not CNA"
            bounty_str = f" | 💰 Bounty: [{vi['bounty_url']}]({vi['bounty_url']})" if vi.get("bounty_url") else ""
            lines.append(f"**CNA Status:** {cna_str} ({vi.get('vendor_name', '?')}){bounty_str}")
        dc = r.get("driver_class", {})
        if dc and dc.get("class", "UNKNOWN") != "UNKNOWN":
            lines.append(f"**Driver Class:** {dc['class']} ({dc.get('category', '')})")
        lines.append(f"**Size:** {driver.get('size', 0):,} bytes | **Functions:** {driver.get('function_count', 0)}")
        lines.append("")
        
        # Group findings by score (high to low), skip zero-score
        findings = sorted(r.get("findings", []), key=lambda x: x["score"], reverse=True)
        scored_findings = [f for f in findings if f["score"] != 0]
        
        if scored_findings:
            lines.append("**Key findings:**")
            for f in scored_findings:
                score_str = f"+{f['score']}" if f["score"] > 0 else str(f["score"])
                lines.append(f"- [{score_str}] {f['detail']}")
            lines.append("")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    print(f"Markdown report written to: {output_path}")


def explain_driver(results, driver_name):
    """Show detailed scoring breakdown for a specific driver."""
    driver_name_lower = driver_name.lower()
    
    match = None
    for r in results:
        d = r.get("driver", {})
        name = d.get("name", "")
        if name.lower() == driver_name_lower or name.lower().replace(".sys", "") == driver_name_lower.replace(".sys", ""):
            match = r
            break
    
    if not match:
        print(f"Driver '{driver_name}' not found in results.")
        print("Available drivers:")
        for r in sorted(results, key=lambda x: x.get("score", 0), reverse=True)[:20]:
            d = r.get("driver", {})
            print(f"  {d.get('name', '?')} ({r.get('score', 0)} pts)")
        return
    
    d = match.get("driver", {})
    print(f"\n{'='*60}")
    print(f"  EXPLAIN: {d.get('name', '?')}")
    print(f"{'='*60}")
    print(f"  Score: {match.get('score', 0)} | Priority: {match.get('priority', '?')}")
    print(f"  Size: {d.get('size', 0):,} bytes | Functions: {d.get('function_count', 0)}")
    if d.get("version_summary"):
        print(f"  Vendor: {d['version_summary']}")
    vi = match.get("vendor_info", {})
    if vi:
        cna_str = "✅ CNA" if vi.get("is_cna") else "❌ Not CNA"
        bounty_str = f" | 💰 Bounty: {vi['bounty_url']}" if vi.get("bounty_url") else ""
        print(f"  CNA Status: {cna_str} ({vi.get('vendor_name', '?')}){bounty_str}")
    dc = match.get("driver_class", {})
    if dc and dc.get("class", "UNKNOWN") != "UNKNOWN":
        print(f"  Driver Class: {dc['class']} ({dc.get('category', '')})")
    print()
    
    findings = match.get("findings", [])
    scored = sorted([f for f in findings if f["score"] != 0], key=lambda x: x["score"], reverse=True)
    zero = [f for f in findings if f["score"] == 0]
    
    if scored:
        print("  Scored checks:")
        total_pos = 0
        total_neg = 0
        for f in scored:
            sign = "+" if f["score"] > 0 else ""
            print(f"    {sign}{f['score']:>4}  [{f['check']}] {f['detail']}")
            if f["score"] > 0:
                total_pos += f["score"]
            else:
                total_neg += f["score"]
        print(f"\n    Positive: +{total_pos} | Negative: {total_neg} | Net: {total_pos + total_neg}")
    
    if zero:
        print(f"\n  Informational ({len(zero)} checks, 0 pts each):")
        for f in zero:
            print(f"    [0]  [{f['check']}] {f['detail']}")
    
    print()


def detect_ghidra():
    """Auto-detect Ghidra installation from env var or common paths."""
    # 1. Environment variable
    env = os.environ.get("GHIDRA_HOME")
    if env and os.path.isdir(env):
        return env
    
    # 2. Common install paths
    candidates = []
    if sys.platform == "win32":
        # Windows: check C:\ghidra*, C:\Program Files\ghidra*, user home
        for base in ["C:\\", os.path.expanduser("~"), "C:\\Program Files"]:
            if os.path.isdir(base):
                for d in os.listdir(base):
                    if d.lower().startswith("ghidra"):
                        full = os.path.join(base, d)
                        if os.path.isdir(full):
                            candidates.append(full)
    else:
        # macOS/Linux
        for base in [os.path.expanduser("~"), "/opt", "/usr/local"]:
            if os.path.isdir(base):
                try:
                    for d in os.listdir(base):
                        if d.lower().startswith("ghidra"):
                            full = os.path.join(base, d)
                            if os.path.isdir(full):
                                candidates.append(full)
                except PermissionError:
                    pass
    
    # Pick the most recent version (sort descending)
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0]
    
    return None


def detect_cpu_count():
    """Get a reasonable worker count (half of CPUs, min 1, max 8)."""
    try:
        cpus = os.cpu_count() or 2
        return max(1, min(cpus // 2, 8))
    except:
        return 2


def main():
    parser = argparse.ArgumentParser(
        description="🌳 Cthaeh - Driver vulnerability triage scanner",
        epilog="""Examples:
  python run_triage.py C:\\drivers                    # Scan with smart defaults
  python run_triage.py C:\\drivers --no-prefilter     # Skip pre-filter
  python run_triage.py --single C:\\path\\to\\driver.sys
  python run_triage.py --explain amdfendr.sys        # Explain existing results
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("drivers_dir", nargs="?", default=None,
                        help="Directory containing .sys files (positional)")
    parser.add_argument("--drivers-dir", dest="drivers_dir_flag",
                        help="Directory containing .sys files (flag, same as positional)")
    parser.add_argument("--single", help="Single .sys file to analyze")
    parser.add_argument("--ghidra", help="Path to Ghidra install (auto-detects from GHIDRA_HOME or common paths)")
    parser.add_argument("--output", default="triage_results.csv", help="Output CSV path (default: triage_results.csv)")
    parser.add_argument("--max", type=int, default=0, help="Max drivers to analyze (0=all)")
    parser.add_argument("--workers", type=int, default=0,
                        help="Parallel Ghidra instances (default: auto = half CPUs)")
    parser.add_argument("--no-prefilter", action="store_true",
                        help="Disable pefile pre-filter (on by default)")
    parser.add_argument("--max-size", type=int, default=5,
                        help="Max driver size in MB for pre-filter (default: 5)")
    parser.add_argument("--no-json", action="store_true",
                        help="Disable JSON output (on by default as triage_results.json)")
    parser.add_argument("--json-output", help="JSON output path (default: triage_results.json)")
    parser.add_argument("--no-report", action="store_true",
                        help="Disable markdown report (on by default as triage_report.md)")
    parser.add_argument("--report", help="Markdown report path (default: triage_report.md)")
    parser.add_argument("--report-top", type=int, default=20,
                        help="Number of top drivers to include in report (default: 20)")
    parser.add_argument("--explain", help="Show detailed scoring breakdown for a specific driver (by name)")
    
    args = parser.parse_args()
    
    # Merge positional and flag versions of drivers_dir
    drivers_dir = args.drivers_dir or args.drivers_dir_flag
    
    # Smart defaults for outputs
    json_output = args.json_output or ("" if args.no_json else "triage_results.json")
    report_output = args.report or ("" if args.no_report else "triage_report.md")
    
    # --explain can work with existing JSON results (no scan needed)
    if args.explain and not drivers_dir and not args.single:
        json_candidates = [
            json_output,
            "triage_results.json",
            os.path.expanduser("~/triage_results.json"),
        ]
        for candidate in json_candidates:
            if candidate and os.path.exists(candidate):
                with open(candidate, "r") as f:
                    results = json.load(f)
                explain_driver(results, args.explain)
                return
        print("ERROR: No triage_results.json found. Run a scan first or specify --json-output.")
        return
    
    if not drivers_dir and not args.single:
        parser.error("Must specify a drivers directory or --single")
    
    # Auto-detect Ghidra
    ghidra_path = args.ghidra or detect_ghidra()
    if not ghidra_path:
        parser.error("Could not find Ghidra. Set GHIDRA_HOME env var or use --ghidra")
    
    # Validate Ghidra path
    if sys.platform == "win32":
        headless = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
    else:
        headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
    
    if not os.path.exists(headless):
        parser.error(f"Invalid Ghidra path: {ghidra_path} (no analyzeHeadless found in support/)")
    
    # Auto-detect worker count
    workers = args.workers if args.workers > 0 else detect_cpu_count()
    
    # Prefilter is ON by default now
    use_prefilter = not args.no_prefilter
    
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "driver_triage.py")
    
    if not os.path.exists(script_path):
        print(f"ERROR: Triage script not found at {script_path}")
        sys.exit(1)
    
    print(f"Ghidra: {ghidra_path}")
    print(f"Workers: {workers}")
    print(f"Pre-filter: {'on' if use_prefilter else 'off'}")
    print()
    
    # Find drivers
    if args.single:
        drivers = [args.single]
    else:
        if use_prefilter:
            print(f"Running pre-filter on {drivers_dir}...")
            filtered = run_prefilter(drivers_dir, args.max_size)
            if filtered is not None:
                drivers = filtered
            else:
                print(f"Scanning {drivers_dir} for .sys files...")
                drivers = find_sys_files(drivers_dir)
        else:
            print(f"Scanning {drivers_dir} for .sys files...")
            drivers = find_sys_files(drivers_dir)
    
    if not drivers:
        print("No .sys files found!")
        sys.exit(1)
    
    if args.max > 0:
        drivers = drivers[:args.max]
    
    print(f"🌳 Cthaeh sees {len(drivers)} driver(s)\n")
    
    # Create temp project directory for Ghidra
    project_dir = tempfile.mkdtemp(prefix="cthaeh_")
    
    start_time = time.time()
    
    # Run analysis
    results = run_analysis(drivers, ghidra_path, script_path, project_dir, workers, json_output)
    
    elapsed = time.time() - start_time
    
    if results:
        write_csv(results, args.output)
        if json_output:
            write_json(results, json_output)
        if report_output:
            write_report(results, report_output, args.report_top)
        print_summary(results)
    
    if results:
        if args.explain:
            explain_driver(results, args.explain)
        else:
            # Always explain the top scorer
            top = sorted(results, key=lambda x: x.get("score", 0), reverse=True)
            # Skip INVESTIGATED for auto-explain
            top = [r for r in top if r.get("priority") != "INVESTIGATED"]
            if top:
                print(f"\n--- Auto-explain: top scorer ---")
                explain_driver(results, top[0].get("driver", {}).get("name", ""))
    
    print(f"\nCompleted in {elapsed:.1f}s ({elapsed/max(len(drivers),1):.1f}s per driver)")
    
    # Cleanup
    try:
        import shutil
        shutil.rmtree(project_dir, ignore_errors=True)
    except:
        pass


if __name__ == "__main__":
    main()
