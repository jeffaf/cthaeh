#!/usr/bin/env python3
"""
Cthaeh Boot Analyzer - Find drivers blindly accessing HKLM\\SOFTWARE during Phase 0/1 boot

During Windows boot Phase 0/1, only the SYSTEM hive is loaded. Drivers that attempt
to access HKLM\\SOFTWARE at this stage get NAME NOT FOUND — revealing they operate in
an "EDR blind spot" where monitoring is not yet active.

Reference: Jiří Vinopal's research on EDR Phase 0 blind spots — boot-start drivers
load before any EDR can hook, making them prime targets for BYOVD/persistence.

Usage:
    python boot_analyzer.py --csv bootlog.csv
    python boot_analyzer.py --pml bootlog.pml --output report.json
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict


# Driver start types from HKLM\SYSTEM\CurrentControlSet\Services\{name}\Start
START_TYPE_NAMES = {
    0: "BOOT_START",
    1: "SYSTEM_START",
    2: "AUTO_START",
    3: "MANUAL",
    4: "DISABLED",
}

# Threshold for "high" NAME NOT FOUND count to flag as blind spot candidate
HIGH_HIT_THRESHOLD = 5


def parse_csv(filepath):
    """Parse Procmon CSV export. Columns: Time of Day, Process Name, PID, Operation, Path, Result, Detail"""
    entries = []
    with open(filepath, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            op = row.get("Operation", "").strip()
            result = row.get("Result", "").strip()
            path = row.get("Path", "").strip()

            if op == "RegOpenKey" and result == "NAME NOT FOUND" and "\\SOFTWARE\\" in path.upper():
                entries.append({
                    "time": row.get("Time of Day", "").strip(),
                    "process": row.get("Process Name", "").strip(),
                    "pid": row.get("PID", "").strip(),
                    "path": path,
                })
    return entries


def parse_pml(filepath):
    """Parse Procmon PML file using procmon-parser library."""
    try:
        from procmon_parser import ProcmonLogsReader
    except ImportError:
        print("ERROR: procmon-parser not installed. Run: pip install procmon-parser", file=sys.stderr)
        print("Falling back: export CSV from Procmon and use --csv instead.", file=sys.stderr)
        sys.exit(1)

    entries = []
    with open(filepath, "rb") as f:
        try:
            reader = ProcmonLogsReader(f)
        except Exception as e:
            # Handle corrupt/unclean PML files (common with boot logs)
            print(f"WARNING: PML file may be corrupt: {e}", file=sys.stderr)
            print("Attempting to read with should_get_details=False...", file=sys.stderr)
            f.seek(0)
            try:
                reader = ProcmonLogsReader(f, should_get_details=False)
            except Exception as e2:
                print(f"ERROR: Cannot parse PML file: {e2}", file=sys.stderr)
                print("Export as CSV from Procmon and use --csv instead.", file=sys.stderr)
                sys.exit(1)
        for event in reader:
            op = event.operation or ""
            result = event.result or ""
            path = event.path or ""

            if op == "RegOpenKey" and result == "NAME NOT FOUND" and "\\SOFTWARE\\" in path.upper():
                entries.append({
                    "time": str(event.date_filetime) if hasattr(event, "date_filetime") else str(getattr(event, "time_of_day", "")),
                    "process": event.process_name or "",
                    "pid": str(event.pid) if hasattr(event, "pid") else "",
                    "path": path,
                })
    return entries


def get_driver_start_type_from_name(driver_name):
    """Try to look up driver start type from Windows registry. Returns (start_type, start_name) or (None, 'UNKNOWN')."""
    # Strip .exe/.sys extension to get service name
    svc_name = os.path.splitext(driver_name)[0]

    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}"
        )
        start_val, _ = winreg.QueryValueEx(key, "Start")
        winreg.CloseKey(key)
        return start_val, START_TYPE_NAMES.get(start_val, f"UNKNOWN({start_val})")
    except Exception:
        return None, "UNKNOWN"


def analyze(entries):
    """Group entries by process and build ranked report."""
    by_process = defaultdict(lambda: {"paths": set(), "times": [], "count": 0})

    for e in entries:
        proc = e["process"]
        by_process[proc]["paths"].add(e["path"])
        by_process[proc]["times"].append(e["time"])
        by_process[proc]["count"] += 1

    results = []
    for proc_name, data in by_process.items():
        start_type, start_name = get_driver_start_type_from_name(proc_name)

        times_sorted = sorted(data["times"])
        is_blind_spot = (
            # Boot/system start drivers hitting missing keys = classic blind spot
            (start_type in (0, 1) and data["count"] >= 1)
            # Any driver with high hit count is suspicious regardless of start type
            or data["count"] >= HIGH_HIT_THRESHOLD
        )

        results.append({
            "driver": proc_name,
            "start_type": start_type if start_type is not None else -1,
            "boot_phase": start_name,
            "name_not_found_count": data["count"],
            "registry_paths": sorted(data["paths"]),
            "first_seen": times_sorted[0] if times_sorted else None,
            "last_seen": times_sorted[-1] if times_sorted else None,
            "boot_blind_spot_candidate": is_blind_spot,
        })

    # Sort: start_type ASC (earlier = more interesting), then hit count DESC
    # Unknown (-1) sorts last
    results.sort(key=lambda x: (x["start_type"] if x["start_type"] >= 0 else 999, -x["name_not_found_count"]))

    return results


def main():
    parser = argparse.ArgumentParser(
        description="🌳 Cthaeh Boot Analyzer - Find EDR Phase 0 blind spot drivers"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pml", help="Procmon PML boot log file")
    group.add_argument("--csv", help="Procmon CSV export file")
    parser.add_argument("--output", help="Output JSON file (default: stdout)")

    args = parser.parse_args()

    if args.pml:
        print(f"Parsing PML: {args.pml}", file=sys.stderr)
        entries = parse_pml(args.pml)
    else:
        print(f"Parsing CSV: {args.csv}", file=sys.stderr)
        entries = parse_csv(args.csv)

    print(f"Found {len(entries)} RegOpenKey NAME NOT FOUND entries targeting \\SOFTWARE\\", file=sys.stderr)

    report = {
        "source": args.pml or args.csv,
        "total_hits": len(entries),
        "drivers": analyze(entries),
        "summary": {},
    }

    # Summary stats
    blind_spots = [d for d in report["drivers"] if d["boot_blind_spot_candidate"]]
    report["summary"] = {
        "total_drivers": len(report["drivers"]),
        "blind_spot_candidates": len(blind_spots),
        "boot_start_drivers": len([d for d in report["drivers"] if d["start_type"] == 0]),
        "system_start_drivers": len([d for d in report["drivers"] if d["start_type"] == 1]),
    }

    output = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to: {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
