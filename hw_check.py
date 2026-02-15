#!/usr/bin/env python3
"""
Cthaeh - Hardware presence check

Queries actual PnP hardware on the Windows machine and cross-references
against drivers to determine if the hardware backing a driver is present.

Helps avoid wasting time on drivers for hardware that isn't installed
(e.g., athw8x.sys recommended as CRITICAL but no Atheros hardware exists).

Usage:
    # Check hardware presence for all drivers in results
    python hw_check.py --results triage_results.json

    # Check a specific driver
    python hw_check.py --driver athw8x.sys

    # Just enumerate present hardware
    python hw_check.py --list-hardware

Requires: Windows (uses PowerShell for PnP device enumeration)
Works from WSL via powershell.exe
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


# DriverStore FileRepository default path
DRIVERSTORE_PATH = r"C:\Windows\System32\DriverStore\FileRepository"


def _get_powershell():
    """Find the right PowerShell executable (works from WSL and native Windows)."""
    if sys.platform == "win32":
        return "powershell"
    # WSL: powershell.exe is on PATH if interop is enabled
    for ps in ["powershell.exe", "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"]:
        try:
            result = subprocess.run(
                [ps, "-NoProfile", "-Command", "echo ok"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and "ok" in result.stdout:
                return ps
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def enumerate_hardware(powershell_cmd=None):
    """Query PnP devices present on the system.

    Returns:
        dict with:
            - hardware_ids: set of all hardware IDs (e.g., 'PCI\\VEN_8086&DEV_2723')
            - devices: list of dicts with friendly_name, instance_id, hardware_ids, status
    """
    if powershell_cmd is None:
        powershell_cmd = _get_powershell()
    if powershell_cmd is None:
        print("WARNING: PowerShell not available. Hardware check requires Windows.")
        return None

    # Get PnP devices with their hardware IDs
    ps_script = (
        "Get-PnpDevice -Status OK -ErrorAction SilentlyContinue | "
        "Select-Object FriendlyName, InstanceId, Class | "
        "ConvertTo-Json -Depth 3"
    )

    try:
        result = subprocess.run(
            [powershell_cmd, "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            print(f"WARNING: PnP enumeration failed: {result.stderr.strip()}")
            return None

        devices_raw = json.loads(result.stdout)
        if isinstance(devices_raw, dict):
            devices_raw = [devices_raw]

    except subprocess.TimeoutExpired:
        print("WARNING: PnP enumeration timed out")
        return None
    except json.JSONDecodeError as e:
        print(f"WARNING: Failed to parse PnP output: {e}")
        return None

    # Now get hardware IDs for each device (separate query since Select doesn't include HardwareID)
    ps_hwid_script = (
        "Get-PnpDevice -Status OK -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "  $hwids = (Get-PnpDeviceProperty -InstanceId $_.InstanceId "
        "    -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue).Data; "
        "  [PSCustomObject]@{ "
        "    InstanceId = $_.InstanceId; "
        "    HardwareIds = if ($hwids) { $hwids -join '|' } else { '' } "
        "  } "
        "} | ConvertTo-Json -Depth 3"
    )

    hwid_map = {}
    try:
        result2 = subprocess.run(
            [powershell_cmd, "-NoProfile", "-Command", ps_hwid_script],
            capture_output=True, text=True, timeout=60
        )
        if result2.returncode == 0 and result2.stdout.strip():
            hwid_data = json.loads(result2.stdout)
            if isinstance(hwid_data, dict):
                hwid_data = [hwid_data]
            for item in hwid_data:
                iid = item.get("InstanceId", "")
                hwids = item.get("HardwareIds", "")
                if iid and hwids:
                    hwid_map[iid.upper()] = [h.strip() for h in hwids.split("|") if h.strip()]
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass  # Hardware IDs are optional enrichment

    devices = []
    all_hardware_ids = set()
    all_instance_ids = set()

    for dev in devices_raw:
        instance_id = dev.get("InstanceId", "")
        friendly_name = dev.get("FriendlyName", "")
        dev_class = dev.get("Class", "")
        hw_ids = hwid_map.get(instance_id.upper(), [])

        devices.append({
            "friendly_name": friendly_name,
            "instance_id": instance_id,
            "class": dev_class,
            "hardware_ids": hw_ids,
        })

        all_instance_ids.add(instance_id.upper())
        for hwid in hw_ids:
            all_hardware_ids.add(hwid.upper())

    return {
        "hardware_ids": all_hardware_ids,
        "instance_ids": all_instance_ids,
        "devices": devices,
        "device_count": len(devices),
    }


def parse_inf_hardware_ids(inf_path):
    """Extract hardware IDs from a .inf file.

    Looks for lines like:
        %DeviceName% = Install, PCI\\VEN_14C3&DEV_0616
        HKR,,HardwareID,,"USB\\VID_0B05&PID_1234"
    """
    hardware_ids = set()
    try:
        # INF files can be UTF-16 or UTF-8
        for encoding in ["utf-16", "utf-8", "latin-1"]:
            try:
                with open(inf_path, "r", encoding=encoding) as f:
                    content = f.read()
                break
            except (UnicodeDecodeError, UnicodeError):
                continue
        else:
            return hardware_ids

        # Match hardware ID patterns: PCI\VEN_XXXX&DEV_XXXX, USB\VID_XXXX&PID_XXXX, etc.
        patterns = [
            r'(?:PCI|USB|ACPI|HID|SWD|HDAUDIO|ROOT)\\[A-Z0-9_&]+',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                hardware_ids.add(match.group(0).upper())

    except Exception:
        pass

    return hardware_ids


def build_driver_to_inf_map(driverstore_path=DRIVERSTORE_PATH, powershell_cmd=None):
    """Map driver .sys filenames to their INF hardware IDs.

    Scans DriverStore FileRepository directories. Each subdirectory typically
    contains an INF + associated .sys files.
    """
    driver_hw_map = {}  # driver_name.lower() -> set of hardware IDs

    # Convert path for WSL if needed
    scan_path = driverstore_path
    if sys.platform != "win32":
        # WSL: convert Windows path to /mnt/c/... path
        if driverstore_path.startswith("C:"):
            scan_path = "/mnt/c" + driverstore_path[2:].replace("\\", "/")
        elif driverstore_path.startswith("\\"):
            scan_path = driverstore_path  # already a UNC or similar

    if not os.path.isdir(scan_path):
        print(f"WARNING: DriverStore not accessible at {scan_path}")
        return driver_hw_map

    for direntry in os.scandir(scan_path):
        if not direntry.is_dir():
            continue

        # Find INF files in this directory
        inf_files = []
        sys_files = []
        try:
            for f in os.scandir(direntry.path):
                name_lower = f.name.lower()
                if name_lower.endswith(".inf"):
                    inf_files.append(f.path)
                elif name_lower.endswith(".sys"):
                    sys_files.append(f.name.lower())
        except PermissionError:
            continue

        if not inf_files or not sys_files:
            continue

        # Parse hardware IDs from all INFs in this directory
        all_hw_ids = set()
        for inf in inf_files:
            all_hw_ids |= parse_inf_hardware_ids(inf)

        # Map each .sys file to these hardware IDs
        for sys_name in sys_files:
            if sys_name in driver_hw_map:
                driver_hw_map[sys_name] |= all_hw_ids
            else:
                driver_hw_map[sys_name] = set(all_hw_ids)

    return driver_hw_map


def check_hardware_presence(driver_names, hw_info=None, driver_hw_map=None, powershell_cmd=None):
    """Check if hardware is present for a list of drivers.

    Args:
        driver_names: list of driver filenames (e.g., ['athw8x.sys'])
        hw_info: pre-computed hardware info from enumerate_hardware()
        driver_hw_map: pre-computed driver->INF map from build_driver_to_inf_map()

    Returns:
        dict mapping driver_name -> {
            'status': 'HARDWARE_PRESENT' | 'HARDWARE_ABSENT' | 'UNKNOWN',
            'matched_device': friendly name if present,
            'inf_hardware_ids': list of HW IDs from INF,
            'score_adjustment': int
        }
    """
    if powershell_cmd is None:
        powershell_cmd = _get_powershell()

    if hw_info is None:
        hw_info = enumerate_hardware(powershell_cmd)
    if hw_info is None:
        return {name: {"status": "UNKNOWN", "reason": "hardware enumeration unavailable"}
                for name in driver_names}

    if driver_hw_map is None:
        driver_hw_map = build_driver_to_inf_map(powershell_cmd=powershell_cmd)

    present_hw_ids = hw_info["hardware_ids"]
    results = {}

    for driver_name in driver_names:
        name_lower = driver_name.lower()
        inf_hw_ids = driver_hw_map.get(name_lower, set())

        if not inf_hw_ids:
            results[driver_name] = {
                "status": "UNKNOWN",
                "reason": "no INF hardware IDs found for this driver",
                "inf_hardware_ids": [],
                "score_adjustment": 0,
            }
            continue

        # Check if any of the driver's hardware IDs match present hardware
        matched_ids = inf_hw_ids & present_hw_ids
        if matched_ids:
            # Find the friendly name of the matched device
            matched_device = None
            for dev in hw_info["devices"]:
                dev_hw_ids = {h.upper() for h in dev.get("hardware_ids", [])}
                if dev_hw_ids & matched_ids:
                    matched_device = dev["friendly_name"]
                    break

            results[driver_name] = {
                "status": "HARDWARE_PRESENT",
                "matched_device": matched_device,
                "matched_hardware_ids": list(matched_ids)[:3],  # top 3 for brevity
                "inf_hardware_ids": list(inf_hw_ids)[:5],
                "score_adjustment": 0,  # no penalty when hardware is present
            }
        else:
            results[driver_name] = {
                "status": "HARDWARE_ABSENT",
                "reason": "no matching PnP hardware found on this system",
                "inf_hardware_ids": list(inf_hw_ids)[:5],
                "score_adjustment": -20,  # penalty in audit mode
            }

    return results


def augment_triage_results(results_path, research_mode=False, output_path=None, driverstore_path=None):
    """Augment existing triage results with hardware presence info.

    Args:
        results_path: path to triage_results.json
        research_mode: if True, hardware_absent is informational only (no score penalty)
        output_path: where to write augmented results (default: overwrite input)
        driverstore_path: path to DriverStore FileRepository (default: standard Windows path)
    """
    with open(results_path, "r") as f:
        results = json.load(f)

    driver_names = []
    for r in results:
        d = r.get("driver", {})
        name = d.get("name", "")
        if name:
            driver_names.append(name)

    if not driver_names:
        print("No drivers found in results.")
        return results

    print(f"Checking hardware presence for {len(driver_names)} drivers...")

    # Get hardware info and driver map (one-time cost)
    powershell_cmd = _get_powershell()
    hw_info = enumerate_hardware(powershell_cmd)
    if hw_info is None:
        print("Cannot check hardware presence (not on Windows).")
        return results

    print(f"  Found {hw_info['device_count']} PnP devices")
    store_path = driverstore_path or DRIVERSTORE_PATH
    driver_hw_map = build_driver_to_inf_map(driverstore_path=store_path, powershell_cmd=powershell_cmd)
    print(f"  Mapped {len(driver_hw_map)} drivers to INF hardware IDs")

    hw_results = check_hardware_presence(driver_names, hw_info, driver_hw_map, powershell_cmd)

    # Augment results
    present_count = 0
    absent_count = 0
    unknown_count = 0

    for r in results:
        d = r.get("driver", {})
        name = d.get("name", "")
        if name not in hw_results:
            continue

        hw = hw_results[name]
        r["hardware_check"] = hw

        if hw["status"] == "HARDWARE_PRESENT":
            present_count += 1
        elif hw["status"] == "HARDWARE_ABSENT":
            absent_count += 1
            # Apply score adjustment in audit mode
            if not research_mode:
                adjustment = hw.get("score_adjustment", 0)
                if adjustment != 0:
                    r["score"] = r.get("score", 0) + adjustment
                    r.setdefault("findings", []).append({
                        "check": "hardware_presence",
                        "score": adjustment,
                        "detail": f"Hardware absent on this system ({hw.get('reason', '')})",
                    })
                    # Recalculate priority after adjustment
                    score = r["score"]
                    if score >= 250:
                        r["priority"] = "CRITICAL"
                    elif score >= 150:
                        r["priority"] = "HIGH"
                    elif score >= 75:
                        r["priority"] = "MEDIUM"
                    elif score >= 30:
                        r["priority"] = "LOW"
                    else:
                        r["priority"] = "SKIP"
            else:
                # Research mode: informational only
                r.setdefault("findings", []).append({
                    "check": "hardware_presence",
                    "score": 0,
                    "detail": f"Hardware absent on this system (informational - research mode)",
                })
        else:
            unknown_count += 1

    # Re-sort by score
    results.sort(key=lambda x: x.get("score", 0), reverse=True)

    # Write output
    out = output_path or results_path
    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nHardware presence results:")
    print(f"  PRESENT:  {present_count} drivers (hardware found)")
    print(f"  ABSENT:   {absent_count} drivers (no hardware)")
    print(f"  UNKNOWN:  {unknown_count} drivers (no INF mapping)")
    if not research_mode and absent_count:
        print(f"  Score adjustment: -{20} applied to {absent_count} absent drivers")
    elif research_mode and absent_count:
        print(f"  Research mode: no score adjustment applied")
    print(f"  Results written to: {out}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Cthaeh - Hardware presence check for driver triage"
    )
    parser.add_argument("--results", help="Path to triage_results.json to augment")
    parser.add_argument("--driver", help="Check a specific driver filename")
    parser.add_argument("--list-hardware", action="store_true",
                        help="Just list present PnP hardware")
    parser.add_argument("--research", action="store_true",
                        help="Research mode: hardware_absent is informational only (no score penalty)")
    parser.add_argument("--output", help="Output path (default: overwrite input)")
    parser.add_argument("--driverstore",
                        default=DRIVERSTORE_PATH,
                        help="DriverStore FileRepository path")

    args = parser.parse_args()

    if args.list_hardware:
        hw = enumerate_hardware()
        if hw is None:
            print("Hardware enumeration not available (requires Windows).")
            sys.exit(1)
        print(f"PnP devices ({hw['device_count']}):\n")
        for dev in sorted(hw["devices"], key=lambda d: d.get("class") or ""):
            hw_ids = dev.get("hardware_ids", [])
            hw_str = f" [{hw_ids[0]}]" if hw_ids else ""
            cls = dev.get("class") or "Unknown"
            name = dev.get("friendly_name") or "Unknown"
            print(f"  [{cls:>20s}] {name}{hw_str}")
        return

    if args.driver:
        hw_results = check_hardware_presence([args.driver])
        for name, info in hw_results.items():
            print(f"\n{name}: {info['status']}")
            for k, v in info.items():
                if k != "status":
                    print(f"  {k}: {v}")
        return

    if args.results:
        augment_triage_results(
            args.results, research_mode=args.research,
            output_path=args.output, driverstore_path=args.driverstore,
        )
        return

    parser.print_help()


if __name__ == "__main__":
    main()
