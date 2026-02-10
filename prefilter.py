#!/usr/bin/env python3
"""
Cthaeh Pre-filter - Fast PE import check before Ghidra analysis

Uses pefile to quickly check driver imports. Skips drivers that lack
interesting attack surface (no IOCTL handling, no device creation).
Runs in milliseconds per driver vs minutes for Ghidra.

Requires: pip install pefile

Optional: pip install requests (for LOLDrivers cross-reference)
"""

import os
import sys
import json
import time
import hashlib

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

# BYOVD process killer pairs - if a driver imports BOTH an opener and terminator,
# it can be weaponized to kill AV/EDR processes
BYOVD_OPENERS = {
    "ZwOpenProcess",
    "NtOpenProcess",
    "ObOpenObjectByPointer",
    "PsLookupProcessByProcessId",
}

BYOVD_TERMINATORS = {
    "ZwTerminateProcess",
    "NtTerminateProcess",
}

# Physical memory R/W pairs - drivers with both mapping + view = potential phys mem access
PHYS_MEM_INDICATORS = {
    "MmMapIoSpace",
    "ZwMapViewOfSection",
    "MmMapLockedPagesSpecifyCache",
    "ZwOpenSection",
    "ZwOpenPhysicalMemory",  # rare but critical
}

# Token stealing / EPROCESS manipulation indicators
TOKEN_STEAL_IMPORTS = {
    "PsLookupProcessByProcessId",
    "PsReferencePrimaryToken",
    "SePrivilegeCheck",
    "ZwOpenProcessTokenEx",
    "NtOpenProcessToken",
}

# Registry manipulation from kernel (persistence vector)
REGISTRY_IMPORTS = {
    "ZwCreateKey",
    "ZwSetValueKey",
    "ZwOpenKey",
    "ZwDeleteKey",
}

# DSE bypass related strings (checked in string scan, not imports)
DSE_STRINGS = {
    "CI.dll",
    "g_CiOptions",
    "CiValidateImageHeader",
    "CiInitialize",
}

# WinIO/WinRing0 codebase indicators (strings)
WINIO_STRINGS = {
    "WinIo",
    "WinRing0",
    "\\Device\\WinIo",
    "\\DosDevices\\WinRing0",
    "\\Device\\WinRing0",
    "WINIO_MAPPHYSTOLIN",
}

# Firmware/SPI flash access indicators
FIRMWARE_IMPORTS = {
    "HalGetBusDataByOffset",
    "HalSetBusDataByOffset",
}

# Disk direct access strings
DISK_ACCESS_STRINGS = {
    "\\Device\\Harddisk",
    "PhysicalDrive",
    "RawDisk",
}

# Skip drivers larger than this (huge drivers = slow Ghidra analysis)
MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5MB default

# LOLDrivers cache file
LOLDRIVERS_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".loldrivers_cache.json")
LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"


def load_loldrivers_hashes(force_refresh=False):
    """Load known vulnerable driver hashes from LOLDrivers."""
    cache_valid = False

    if not force_refresh and os.path.exists(LOLDRIVERS_CACHE):
        try:
            with open(LOLDRIVERS_CACHE, "r") as f:
                cache = json.load(f)
            # Cache valid for 7 days
            if time.time() - cache.get("fetched", 0) < 7 * 86400:
                return set(cache.get("hashes", [])), cache.get("names", {})
        except:
            pass

    try:
        import requests
        print("  Fetching LOLDrivers database...", end="", flush=True)
        resp = requests.get(LOLDRIVERS_URL, timeout=15)
        resp.raise_for_status()
        drivers = resp.json()

        hashes = set()
        names = {}  # hash -> driver name

        for driver in drivers:
            driver_name = driver.get("Tags", ["unknown"])[0] if driver.get("Tags") else "unknown"
            for sample in driver.get("KnownVulnerableSamples", []):
                for hash_type in ["SHA256", "SHA1", "MD5"]:
                    h = sample.get(hash_type, "")
                    if h:
                        h_lower = h.lower()
                        hashes.add(h_lower)
                        names[h_lower] = driver_name

        # Cache it
        with open(LOLDRIVERS_CACHE, "w") as f:
            json.dump({"fetched": time.time(), "hashes": list(hashes), "names": names}, f)

        print(f" {len(hashes)} hashes loaded")
        return hashes, names

    except ImportError:
        print("  LOLDrivers check skipped (install requests: pip install requests)")
        return set(), {}
    except Exception as e:
        print(f"  LOLDrivers fetch failed: {e}")
        return set(), {}


def get_file_hashes(filepath):
    """Calculate SHA256, SHA1, MD5 of a file."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def check_driver(driver_path, max_size=MAX_SIZE_BYTES, lol_hashes=None, lol_names=None):
    """
    Quick PE import check on a driver.
    Returns: (should_analyze, reason, risk_hint, flags)
    """
    name = os.path.basename(driver_path)
    size = os.path.getsize(driver_path)
    flags = []

    # Size check
    if max_size and size > max_size:
        return False, f"too large ({size // 1024}KB)", 0, flags

    # LOLDrivers check
    if lol_hashes:
        file_hashes = get_file_hashes(driver_path)
        for h in file_hashes.values():
            if h in lol_hashes:
                lol_name = lol_names.get(h, "unknown") if lol_names else "unknown"
                flags.append(f"KNOWN_VULN:{lol_name}")
                break

    try:
        pe = pefile.PE(driver_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception as e:
        return False, f"PE parse error: {e}", 0, flags

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
        return False, "no device/IOCTL imports", 0, flags

    # Count high-risk imports as a hint
    high_risk_count = len(imports & HIGH_RISK_IMPORTS)

    # BYOVD process killer detection
    has_opener = bool(imports & BYOVD_OPENERS)
    has_terminator = bool(imports & BYOVD_TERMINATORS)
    if has_opener and has_terminator:
        flags.append("BYOVD_CANDIDATE")
        high_risk_count += 3  # Boost priority

    # Physical memory R/W detection
    phys_mem_count = len(imports & PHYS_MEM_INDICATORS)
    if phys_mem_count >= 2:
        flags.append("PHYS_MEM_RW")
        high_risk_count += 2

    # MmMapIoSpace alone is notable
    if "MmMapIoSpace" in imports:
        if "PHYS_MEM_RW" not in flags:
            flags.append("MMIO_MAP")

    # Token stealing / EPROCESS manipulation
    token_imports = imports & TOKEN_STEAL_IMPORTS
    if len(token_imports) >= 2:
        flags.append("TOKEN_STEAL")
        high_risk_count += 2
    elif "PsLookupProcessByProcessId" in imports:
        flags.append("PROCESS_LOOKUP")
        high_risk_count += 1

    # Registry manipulation from kernel
    reg_imports = imports & REGISTRY_IMPORTS
    if len(reg_imports) >= 2:
        flags.append("REGISTRY_RW")
        high_risk_count += 1

    # Firmware/SPI access
    fw_imports = imports & FIRMWARE_IMPORTS
    if fw_imports:
        flags.append("FIRMWARE_ACCESS")
        high_risk_count += 2

    return True, "has attack surface", high_risk_count, flags


def prefilter_directory(drivers_dir, max_size=MAX_SIZE_BYTES, check_loldrivers=False, byovd_only=False):
    """
    Pre-filter all .sys files in a directory.
    Returns list of drivers worth sending to Ghidra.
    """
    results = {"analyze": [], "skip": [], "known_vuln": [], "byovd_candidates": []}

    # Load LOLDrivers if requested
    lol_hashes = set()
    lol_names = {}
    if check_loldrivers:
        lol_hashes, lol_names = load_loldrivers_hashes()

    sys_files = []
    for root, dirs, files in os.walk(drivers_dir):
        for f in files:
            if f.lower().endswith(".sys"):
                sys_files.append(os.path.join(root, f))

    start = time.time()

    for path in sys_files:
        name = os.path.basename(path)
        should_analyze, reason, risk_hint, flags = check_driver(path, max_size, lol_hashes, lol_names)

        entry = {
            "name": name,
            "path": path,
            "size": os.path.getsize(path),
            "risk_hint": risk_hint,
            "flags": flags,
        }

        # Track special categories
        if any(f.startswith("KNOWN_VULN") for f in flags):
            results["known_vuln"].append(entry)
        if "BYOVD_CANDIDATE" in flags:
            results["byovd_candidates"].append(entry)

        if should_analyze:
            # In BYOVD-only mode, only keep BYOVD candidates
            if byovd_only and "BYOVD_CANDIDATE" not in flags:
                entry["skip_reason"] = "not a BYOVD candidate"
                results["skip"].append(entry)
            else:
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

    # Show special findings
    if results["known_vuln"]:
        print(f"\n  ⚠️  Known vulnerable (LOLDrivers): {len(results['known_vuln'])}")
        for d in results["known_vuln"]:
            vuln_tag = [f for f in d["flags"] if f.startswith("KNOWN_VULN")][0]
            print(f"      {d['name']} ({vuln_tag})")

    if results["byovd_candidates"]:
        print(f"\n  🎯 BYOVD candidates (process killer imports): {len(results['byovd_candidates'])}")
        for d in results["byovd_candidates"]:
            extra = [f for f in d["flags"] if f != "BYOVD_CANDIDATE"]
            extra_str = f" [{', '.join(extra)}]" if extra else ""
            print(f"      {d['name']}{extra_str}")

    phys_mem = [d for d in results["analyze"] if "PHYS_MEM_RW" in d.get("flags", [])]
    if phys_mem:
        print(f"\n  🔓 Physical memory R/W candidates: {len(phys_mem)}")
        for d in phys_mem:
            print(f"      {d['name']}")

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
    parser.add_argument("--loldrivers", action="store_true",
                        help="Cross-reference against LOLDrivers database")
    parser.add_argument("--byovd", action="store_true",
                        help="Only show BYOVD process killer candidates")
    parser.add_argument("--refresh-lol", action="store_true",
                        help="Force refresh LOLDrivers cache")

    args = parser.parse_args()

    if args.refresh_lol:
        load_loldrivers_hashes(force_refresh=True)

    max_bytes = args.max_size * 1024 * 1024
    results = prefilter_directory(
        args.drivers_dir, max_bytes,
        check_loldrivers=args.loldrivers,
        byovd_only=args.byovd,
    )

    if args.list:
        print("\nDrivers to analyze:")
        for d in results["analyze"]:
            flags_str = f" [{', '.join(d['flags'])}]" if d["flags"] else ""
            hint = f" (risk:{d['risk_hint']})" if d["risk_hint"] else ""
            print(f"  {d['name']}{hint}{flags_str}")

    if args.output:
        paths = [d["path"] for d in results["analyze"]]
        with open(args.output, "w") as f:
            json.dump(paths, f, indent=2)
        print(f"\nFiltered list written to: {args.output}")


if __name__ == "__main__":
    main()
