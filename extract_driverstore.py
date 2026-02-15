#!/usr/bin/env python3
"""
Cthaeh - Extract third-party .sys files from DriverStore

Copies non-Microsoft drivers from Windows DriverStore to a working directory
for batch triage. Filters out known Microsoft/Windows inbox drivers.

Usage:
    python extract_driverstore.py --output C:\\drivers\\extracted             # loaded drivers only (default)
    python extract_driverstore.py --output C:\\drivers\\extracted --all       # all drivers in store
    python extract_driverstore.py --output C:\\drivers\\extracted --include-microsoft
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


# Microsoft/Windows inbox driver indicators (skip these - well audited already)
MICROSOFT_INDICATORS = [
    "microsoft",
    "windows",
    "© microsoft",
    "msft",
]

# Known Microsoft driver prefixes (common inbox drivers)
MS_DRIVER_PREFIXES = [
    "acpi", "ahci", "ata", "bthhf", "bthport", "clfs", "cng", "disk",
    "dxgkrnl", "dxgmms", "fltmgr", "http", "ksecdd", "luafv", "mouclass",
    "mountmgr", "msfs", "mup", "ndis", "netbt", "npfs", "ntfs", "null",
    "partmgr", "pci", "pcw", "rdbss", "rdyboost", "storport", "tcpip",
    "tm", "vdrvroot", "volmgr", "volsnap", "wdf", "wdfilter", "wfplwfs",
    "wmilib",
]


def is_likely_microsoft(driver_path, include_microsoft=False):
    """Heuristic check if a driver is from Microsoft."""
    if include_microsoft:
        return False
    
    name = os.path.basename(driver_path).lower()
    
    for prefix in MS_DRIVER_PREFIXES:
        if name.startswith(prefix):
            return True
    
    parent = os.path.basename(os.path.dirname(driver_path)).lower()
    for indicator in MICROSOFT_INDICATORS:
        if indicator in parent:
            return True
    
    return False


def get_loaded_drivers():
    """Get set of currently loaded driver filenames.
    
    Uses PowerShell Get-WmiObject to get actual .sys paths of running drivers.
    Falls back to sc query if PowerShell fails.
    """
    loaded = set()
    
    # Method 1: PowerShell - most reliable, gets actual file paths
    try:
        ps_cmd = (
            "Get-WmiObject Win32_SystemDriver | "
            "Where-Object { $_.State -eq 'Running' } | "
            "ForEach-Object { $_.PathName } "
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Paths come as \SystemRoot\system32\DRIVERS\foo.sys or C:\Windows\...
            name = line.split('\\')[-1].lower()
            if name.endswith('.sys'):
                loaded.add(name)
        
        if loaded:
            return loaded
    except Exception as e:
        print(f"WARNING: PowerShell driver enum failed: {e}")
    
    # Method 2: sc query
    try:
        print("  Falling back to sc query...")
        result = subprocess.run(
            ["sc", "query", "type=", "driver", "state=", "active"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                svc = line.split(":", 1)[1].strip().lower()
                loaded.add(svc + ".sys")
    except Exception as e2:
        print(f"WARNING: sc query also failed: {e2}")
    
    return loaded


def extract_drivers(driverstore_path, output_dir, include_microsoft=False, loaded_only=False):
    """Extract third-party drivers from DriverStore."""
    
    if not os.path.exists(driverstore_path):
        print(f"ERROR: DriverStore not found at {driverstore_path}")
        return []
    
    os.makedirs(output_dir, exist_ok=True)
    
    loaded_set = None
    if loaded_only:
        loaded_set = get_loaded_drivers()
        if loaded_set:
            print(f"  Loaded drivers detected: {len(loaded_set)}")
            # Show a few examples for sanity check
            sample = sorted(loaded_set)[:5]
            print(f"  Sample: {', '.join(sample)}")
        else:
            print("WARNING: No loaded drivers detected, scanning all drivers.")
            loaded_set = None
    
    extracted = []
    skipped_ms = 0
    skipped_dup = 0
    skipped_not_loaded = 0
    seen_names = set()
    
    for root, dirs, files in os.walk(driverstore_path):
        for f in files:
            if not f.lower().endswith(".sys"):
                continue
            
            full_path = os.path.join(root, f)
            base_name = f.lower()
            
            # Check loaded filter FIRST (narrows the set before MS filter)
            if loaded_set is not None and base_name not in loaded_set:
                skipped_not_loaded += 1
                continue
            
            if is_likely_microsoft(full_path, include_microsoft):
                skipped_ms += 1
                continue
            if base_name in seen_names:
                skipped_dup += 1
                continue
            seen_names.add(base_name)
            
            dest = os.path.join(output_dir, f)
            try:
                shutil.copy2(full_path, dest)
                size = os.path.getsize(full_path)
                extracted.append({
                    "name": f,
                    "source": full_path,
                    "size": size,
                })
            except PermissionError:
                print(f"  SKIP (permission denied): {f}")
            except Exception as e:
                print(f"  SKIP ({e}): {f}")
    
    print(f"\n🌳 Extraction complete:")
    print(f"  Extracted:    {len(extracted)} third-party drivers")
    print(f"  Skipped (MS): {skipped_ms}")
    print(f"  Skipped (dup):{skipped_dup}")
    if loaded_only:
        print(f"  Skipped (not loaded): {skipped_not_loaded}")
    print(f"  Output:       {output_dir}")
    
    return extracted


def main():
    parser = argparse.ArgumentParser(
        description="🌳 Cthaeh - Extract third-party drivers from DriverStore"
    )
    parser.add_argument(
        "--driverstore",
        default=r"C:\Windows\System32\DriverStore\FileRepository",
        help="Path to DriverStore FileRepository"
    )
    parser.add_argument("--output", required=True, help="Output directory for extracted drivers")
    parser.add_argument("--include-microsoft", action="store_true", help="Include Microsoft drivers")
    parser.add_argument("--loaded-only", action="store_true", default=True,
                        help="Only extract drivers currently loaded in kernel (default: on)")
    parser.add_argument("--all", action="store_true",
                        help="Extract all drivers from store (override --loaded-only)")
    
    args = parser.parse_args()
    loaded_only = args.loaded_only and not args.all
    extract_drivers(args.driverstore, args.output, args.include_microsoft, loaded_only=loaded_only)


if __name__ == "__main__":
    main()
