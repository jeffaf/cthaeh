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
        results = prefilter_directory(drivers_dir, max_bytes)
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
            "Priority", "Score", "Driver", "Path", "Size",
            "Functions", "Findings", "Top Checks"
        ])
        
        for r in results:
            driver = r.get("driver", {})
            findings = r.get("findings", [])
            top_checks = ", ".join(
                f["check"] for f in sorted(findings, key=lambda x: x["score"], reverse=True)[:5]
            )
            
            writer.writerow([
                r.get("priority", "?"),
                r.get("score", 0),
                driver.get("name", "?"),
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
            print(f"  {i:2d}. [{r.get('priority', '?'):6s}] {r.get('score', 0):3d} pts  {driver.get('name', '?')}")


def run_sequential(drivers, ghidra_path, script_path, project_dir):
    """Run analysis sequentially (original behavior)."""
    results = []
    
    for i, driver_path in enumerate(drivers, 1):
        driver_name = os.path.basename(driver_path)
        print(f"[{i}/{len(drivers)}] {driver_name}...", end="", flush=True)
        
        args_tuple = (ghidra_path, driver_path, script_path, project_dir, 0)
        result, error = run_ghidra_analysis(args_tuple)
        
        if result:
            results.append(result)
            score = result.get("score", 0)
            priority = result.get("priority", "?")
            print(f" {priority} ({score} pts)")
        else:
            print(f" FAILED ({error})")
    
    return results


def run_parallel(drivers, ghidra_path, script_path, project_dir, workers):
    """Run analysis in parallel with multiple Ghidra instances."""
    results = []
    failed = 0
    completed = 0
    total = len(drivers)
    
    # Build args tuples with worker IDs (round-robin assignment)
    args_list = [
        (ghidra_path, driver_path, script_path, project_dir, i % workers)
        for i, driver_path in enumerate(drivers)
    ]
    
    print(f"Running with {workers} parallel workers...\n")
    
    with ProcessPoolExecutor(max_workers=workers) as executor:
        # Submit all jobs
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
                else:
                    failed += 1
                    print(f"[{completed}/{total}] {driver_name}... FAILED ({error})")
            except Exception as e:
                failed += 1
                print(f"[{completed}/{total}] {driver_name}... ERROR ({e})")
    
    if failed:
        print(f"\n{failed} driver(s) failed analysis")
    
    return results


def write_report(results, output_path, top_n=20):
    """Generate a markdown triage report for top candidates."""
    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    
    total = len(results)
    critical = sum(1 for r in results if r.get("priority") == "CRITICAL")
    high = sum(1 for r in results if r.get("priority") == "HIGH")
    medium = sum(1 for r in results if r.get("priority") == "MEDIUM")
    low = sum(1 for r in results if r.get("priority") == "LOW")
    skip = sum(1 for r in results if r.get("priority") == "SKIP")
    known_fp = sum(1 for r in results if r.get("priority") == "KNOWN_FP")
    
    PRIORITY_EMOJI = {
        "CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡",
        "LOW": "🟢", "SKIP": "⚪", "KNOWN_FP": "🚫"
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
    if known_fp:
        lines.append(f"- 🚫 Known FP/Investigated: {known_fp}")
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


def main():
    parser = argparse.ArgumentParser(
        description="🌳 Cthaeh - Driver vulnerability triage scanner"
    )
    parser.add_argument("--drivers-dir", help="Directory containing .sys files")
    parser.add_argument("--single", help="Single .sys file to analyze")
    parser.add_argument("--ghidra", help="Path to Ghidra installation (required for scanning)")
    parser.add_argument("--output", default="triage_results.csv", help="Output CSV path")
    parser.add_argument("--max", type=int, default=0, help="Max drivers to analyze (0=all)")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel Ghidra instances (default: 1)")
    parser.add_argument("--prefilter", action="store_true",
                        help="Run pefile pre-filter to skip uninteresting drivers")
    parser.add_argument("--max-size", type=int, default=5,
                        help="Max driver size in MB for pre-filter (default: 5)")
    parser.add_argument("--json-output", help="Write full results with all findings to JSON file")
    parser.add_argument("--report", help="Generate markdown report (specify output .md path)")
    parser.add_argument("--report-top", type=int, default=20,
                        help="Number of top drivers to include in report (default: 20)")
    parser.add_argument("--explain", help="Show detailed scoring breakdown for a specific driver (by name)")
    
    args = parser.parse_args()
    
    # --explain can work with existing JSON results (no scan needed)
    if args.explain and not args.drivers_dir and not args.single:
        json_candidates = [
            args.json_output,
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
    
    if not args.drivers_dir and not args.single:
        parser.error("Must specify --drivers-dir or --single")
    
    if not args.ghidra:
        parser.error("--ghidra is required for scanning")
    
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "driver_triage.py")
    
    if not os.path.exists(script_path):
        print(f"ERROR: Triage script not found at {script_path}")
        sys.exit(1)
    
    # Find drivers
    if args.single:
        drivers = [args.single]
    else:
        # Pre-filter if requested
        if args.prefilter:
            print(f"Running pre-filter on {args.drivers_dir}...")
            filtered = run_prefilter(args.drivers_dir, args.max_size)
            if filtered is not None:
                drivers = filtered
            else:
                print(f"Scanning {args.drivers_dir} for .sys files...")
                drivers = find_sys_files(args.drivers_dir)
        else:
            print(f"Scanning {args.drivers_dir} for .sys files...")
            drivers = find_sys_files(args.drivers_dir)
    
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
    if args.workers > 1 and len(drivers) > 1:
        results = run_parallel(drivers, args.ghidra, script_path, project_dir, args.workers)
    else:
        results = run_sequential(drivers, args.ghidra, script_path, project_dir)
    
    elapsed = time.time() - start_time
    
    if results:
        write_csv(results, args.output)
        if args.json_output:
            write_json(results, args.json_output)
        if args.report:
            write_report(results, args.report, args.report_top)
        print_summary(results)
    
    if args.explain and results:
        explain_driver(results, args.explain)
    
    print(f"\nCompleted in {elapsed:.1f}s ({elapsed/max(len(drivers),1):.1f}s per driver)")
    
    # Cleanup
    try:
        import shutil
        shutil.rmtree(project_dir, ignore_errors=True)
    except:
        pass


if __name__ == "__main__":
    main()
