#!/usr/bin/env python3
"""
Cthaeh Pre-filter - Fast PE import check before Ghidra analysis

Uses pefile to quickly check driver imports. Skips drivers that lack
interesting attack surface (no IOCTL handling, no device creation).
Runs in milliseconds per driver vs minutes for Ghidra.

Requires: pip install pefile
"""

import os
import sys
import json
import time

try:
    import pefile
except ImportError:
    print("ERROR: pefile not installed. Run: pip install pefile")
    sys.exit(1)


# Imports that indicate interesting attack surface
INTERESTING_IMPORTS = {
    # Device creation (required for user-accessible attack surface)
    "IoCreateDevice",
    "IoCreateDeviceSecure",
    "WdfDeviceCreate",
    # IRP handling (IOCTL attack surface)
    "IofCompleteRequest",
    "IoCompleteRequest",
    # WMI (additional attack surface)
    "IoWMIRegistrationControl",
}

# Imports that indicate higher risk
HIGH_RISK_IMPORTS = {
    "MmMapIoSpace",
    "MmMapLockedPagesSpecifyCache",
    "MmMapLockedPagesWithReservedMapping",
    "ZwMapViewOfSection",
    "ExAllocatePool",
    "ExAllocatePoolWithTag",
    "ExAllocatePool2",
}

# Skip drivers larger than this (huge drivers = slow Ghidra analysis)
MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5MB default


def check_driver(driver_path, max_size=MAX_SIZE_BYTES):
    """
    Quick PE import check on a driver.
    Returns: (should_analyze, reason, risk_hint)
    """
    name = os.path.basename(driver_path)
    size = os.path.getsize(driver_path)
    
    # Size check
    if max_size and size > max_size:
        return False, f"too large ({size // 1024}KB)", 0
    
    try:
        pe = pefile.PE(driver_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception as e:
        return False, f"PE parse error: {e}", 0
    
    # Extract import names
    imports = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.add(imp.name.decode("utf-8", errors="ignore"))
    
    pe.close()
    
    # Must have at least one interesting import
    has_interesting = bool(imports & INTERESTING_IMPORTS)
    if not has_interesting:
        return False, "no device/IOCTL imports", 0
    
    # Count high-risk imports as a hint
    high_risk_count = len(imports & HIGH_RISK_IMPORTS)
    
    return True, "has attack surface", high_risk_count


def prefilter_directory(drivers_dir, max_size=MAX_SIZE_BYTES):
    """
    Pre-filter all .sys files in a directory.
    Returns list of drivers worth sending to Ghidra.
    """
    results = {"analyze": [], "skip": []}
    
    sys_files = []
    for root, dirs, files in os.walk(drivers_dir):
        for f in files:
            if f.lower().endswith(".sys"):
                sys_files.append(os.path.join(root, f))
    
    start = time.time()
    
    for path in sys_files:
        name = os.path.basename(path)
        should_analyze, reason, risk_hint = check_driver(path, max_size)
        
        entry = {
            "name": name,
            "path": path,
            "size": os.path.getsize(path),
            "risk_hint": risk_hint,
        }
        
        if should_analyze:
            results["analyze"].append(entry)
        else:
            entry["skip_reason"] = reason
            results["skip"].append(entry)
    
    elapsed = time.time() - start
    
    # Sort analyzable drivers by risk hint (highest first)
    results["analyze"].sort(key=lambda x: x["risk_hint"], reverse=True)
    
    total = len(sys_files)
    kept = len(results["analyze"])
    skipped = len(results["skip"])
    
    print(f"\n🌳 Cthaeh Pre-filter ({elapsed:.1f}s for {total} drivers)")
    print(f"  ✅ Analyze: {kept} drivers ({kept*100//max(total,1)}%)")
    print(f"  ⏭️  Skip:    {skipped} drivers")
    
    # Show skip breakdown
    skip_reasons = {}
    for s in results["skip"]:
        r = s.get("skip_reason", "unknown")
        skip_reasons[r] = skip_reasons.get(r, 0) + 1
    for reason, count in sorted(skip_reasons.items(), key=lambda x: -x[1]):
        print(f"      {reason}: {count}")
    
    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="🌳 Cthaeh Pre-filter - Fast PE import check"
    )
    parser.add_argument("drivers_dir", help="Directory containing .sys files")
    parser.add_argument("--max-size", type=int, default=5,
                        help="Max driver size in MB (default: 5)")
    parser.add_argument("--output", help="Write filtered list to JSON file")
    parser.add_argument("--list", action="store_true",
                        help="Print list of drivers to analyze")
    
    args = parser.parse_args()
    
    max_bytes = args.max_size * 1024 * 1024
    results = prefilter_directory(args.drivers_dir, max_bytes)
    
    if args.list:
        print("\nDrivers to analyze:")
        for d in results["analyze"]:
            hint = f" (risk:{d['risk_hint']})" if d["risk_hint"] else ""
            print(f"  {d['name']}{hint}")
    
    if args.output:
        # Write just the paths for piping to run_triage
        paths = [d["path"] for d in results["analyze"]]
        with open(args.output, "w") as f:
            json.dump(paths, f, indent=2)
        print(f"\nFiltered list written to: {args.output}")


if __name__ == "__main__":
    main()
