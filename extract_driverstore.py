#!/usr/bin/env python3
"""
Cthaeh - Extract third-party .sys files from DriverStore

Copies non-Microsoft drivers from Windows DriverStore to a working directory
for batch triage. Filters out known Microsoft/Windows inbox drivers.

Usage:
    python extract_driverstore.py --output C:\\drivers\\extracted
    python extract_driverstore.py --output C:\\drivers\\extracted --include-microsoft
"""

import argparse
import os
import shutil
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


def extract_drivers(driverstore_path, output_dir, include_microsoft=False):
    """Extract third-party drivers from DriverStore."""
    
    if not os.path.exists(driverstore_path):
        print(f"ERROR: DriverStore not found at {driverstore_path}")
        return []
    
    os.makedirs(output_dir, exist_ok=True)
    
    extracted = []
    skipped_ms = 0
    skipped_dup = 0
    seen_names = set()
    
    for root, dirs, files in os.walk(driverstore_path):
        for f in files:
            if not f.lower().endswith(".sys"):
                continue
            
            full_path = os.path.join(root, f)
            
            if is_likely_microsoft(full_path, include_microsoft):
                skipped_ms += 1
                continue
            
            base_name = f.lower()
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
    
    args = parser.parse_args()
    extract_drivers(args.driverstore, args.output, args.include_microsoft)


if __name__ == "__main__":
    main()
