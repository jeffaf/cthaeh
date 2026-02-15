#!/usr/bin/env python3
"""
Cthaeh - Device object security descriptor check

Enumerates device objects created by drivers and checks their DACLs
to determine if they're accessible from unprivileged user context.

A driver may create a device object, but if the DACL restricts access
to administrators only, it's not exploitable from a standard user.

Usage:
    # Check all high-scoring drivers from triage results
    python device_check.py --results triage_results.json

    # Check a specific device path
    python device_check.py --device "\\\\.\\MyDevice"

    # Only check drivers scoring above threshold
    python device_check.py --results triage_results.json --min-score 75

Requires: Windows (uses PowerShell/ctypes for device access checks)
Works from WSL via powershell.exe
"""

import argparse
import json
import os
import re
import subprocess
import sys


def _get_powershell():
    """Find the right PowerShell executable (works from WSL and native Windows)."""
    if sys.platform == "win32":
        return "powershell"
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


def enumerate_driver_devices(driver_name, powershell_cmd=None):
    """Find device objects associated with a driver.

    Uses WMI to find device paths, then checks for symbolic links
    in the DOS device namespace that point to them.

    Args:
        driver_name: driver filename (e.g., 'mydriver.sys')

    Returns:
        list of device path strings (e.g., ['\\\\.\\MyDevice'])
    """
    if powershell_cmd is None:
        powershell_cmd = _get_powershell()
    if powershell_cmd is None:
        return []

    base_name = driver_name.lower().replace(".sys", "")

    # Strategy 1: Check common device naming conventions
    # Many drivers create devices named after themselves
    candidate_paths = [
        f"\\\\.\\{base_name}",
        f"\\\\.\\{base_name.upper()}",
    ]

    # Strategy 2: Query WMI for driver -> device association
    ps_script = f"""
$results = @()

# Try to find devices via driver service name
$services = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue |
    Where-Object {{ $_.PathName -like '*{base_name}*' }} |
    Select-Object -ExpandProperty Name

foreach ($svc in $services) {{
    # Get PnP devices using this driver
    $pnpDevs = Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object {{ $_.InstanceId -like "*$svc*" -or $_.FriendlyName -like "*$svc*" }}
    foreach ($dev in $pnpDevs) {{
        $results += $dev.InstanceId
    }}
}}

# Also check for symbolic links matching the driver name pattern
$dosDevices = @(
    "\\\\.\\" + "{base_name}",
    "\\\\.\\" + "{base_name.upper()}"
)

# Output device candidates
$output = @{{
    'service_matches' = @($services)
    'candidate_paths' = @($dosDevices)
    'pnp_instances' = @($results)
}}
$output | ConvertTo-Json -Depth 3
"""
    try:
        result = subprocess.run(
            [powershell_cmd, "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            extra_paths = data.get("candidate_paths", [])
            if isinstance(extra_paths, str):
                extra_paths = [extra_paths]
            for p in extra_paths:
                if p and p not in candidate_paths:
                    candidate_paths.append(p)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    return candidate_paths


def check_device_access(device_path, powershell_cmd=None):
    """Test if a device object is accessible and check its DACL.

    Attempts to open the device with different access levels, then reads
    the security descriptor to identify permissive DACLs.

    Returns:
        dict with:
            - accessible: bool (could open the device at all)
            - access_level: 'everyone' | 'users' | 'admin_only' | 'no_device'
            - dacl_info: parsed DACL details
            - score_adjustment: int
            - error: error message if any
    """
    if powershell_cmd is None:
        powershell_cmd = _get_powershell()
    if powershell_cmd is None:
        return {
            "accessible": False,
            "access_level": "unknown",
            "error": "PowerShell not available",
            "score_adjustment": 0,
        }

    # PowerShell script to test device access and read DACL
    # Runs as the current user to test real accessibility
    ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$devicePath = '{device_path}'
$result = @{{
    'path' = $devicePath
    'exists' = $false
    'accessible' = $false
    'access_level' = 'no_device'
    'dacl_sddl' = ''
    'dacl_aces' = @()
    'error' = ''
}}

try {{
    # Try to open the device with minimum access (just query)
    $handle = [System.IO.File]::Open($devicePath, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $result['exists'] = $true
    $result['accessible'] = $true
    $handle.Close()
}} catch [System.UnauthorizedAccessException] {{
    # Device exists but access denied (admin only or restricted)
    $result['exists'] = $true
    $result['accessible'] = $false
    $result['access_level'] = 'admin_only'
    $result['error'] = 'Access denied (likely admin-only DACL)'
}} catch [System.IO.FileNotFoundException] {{
    $result['exists'] = $false
    $result['access_level'] = 'no_device'
    $result['error'] = 'Device path not found'
}} catch [System.IO.IOException] {{
    # Device exists but busy or other I/O error - still means it exists
    $result['exists'] = $true
    $result['accessible'] = $true
    $result['error'] = $_.Exception.Message
}} catch {{
    $result['error'] = $_.Exception.Message
}}

# If device exists, try to get its security descriptor
if ($result['exists']) {{
    try {{
        # Use Get-Acl on the device path
        $acl = Get-Acl -Path $devicePath -ErrorAction Stop
        $result['dacl_sddl'] = $acl.Sddl

        foreach ($ace in $acl.Access) {{
            $aceInfo = @{{
                'identity' = $ace.IdentityReference.ToString()
                'rights' = $ace.FileSystemRights.ToString()
                'type' = $ace.AccessControlType.ToString()
            }}
            $result['dacl_aces'] += $aceInfo
        }}
    }} catch {{
        # Can't read DACL - infer from access test
    }}
}}

$result | ConvertTo-Json -Depth 3
"""

    try:
        proc_result = subprocess.run(
            [powershell_cmd, "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=15
        )
        if proc_result.returncode == 0 and proc_result.stdout.strip():
            data = json.loads(proc_result.stdout)
            return _classify_access(data)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return {
            "accessible": False,
            "access_level": "unknown",
            "error": str(e),
            "score_adjustment": 0,
        }

    return {
        "accessible": False,
        "access_level": "unknown",
        "error": "no output from access check",
        "score_adjustment": 0,
    }


def _classify_access(data):
    """Classify device access level from the raw check results.

    Scoring from issue #4:
        device_accessible_everyone: +20
        device_accessible_users:    +15
        device_admin_only:          -15
        no_named_device:            -10
    """
    result = {
        "path": data.get("path", ""),
        "exists": data.get("exists", False),
        "accessible": data.get("accessible", False),
        "dacl_sddl": data.get("dacl_sddl", ""),
        "dacl_aces": data.get("dacl_aces", []),
        "error": data.get("error", ""),
    }

    if not data.get("exists", False):
        result["access_level"] = "no_device"
        result["score_adjustment"] = -10
        result["detail"] = "No named device object found"
        return result

    # Analyze DACL ACEs
    sddl = data.get("dacl_sddl", "")
    aces = data.get("dacl_aces", [])

    # Check for overly permissive DACLs
    everyone_access = False
    users_access = False
    admin_only = True

    # SDDL-based detection
    if sddl:
        # D:(A;;GA;;;WD) = Everyone has GenericAll
        # D:(A;;GA;;;BU) = Builtin Users have GenericAll
        # WD = Everyone (World), BU = Builtin Users, BA = Builtin Administrators
        if "WD" in sddl and ("GA" in sddl or "GR" in sddl or "GW" in sddl or "GRGW" in sddl):
            everyone_access = True
        if "BU" in sddl and ("GA" in sddl or "GR" in sddl or "GW" in sddl):
            users_access = True

    # ACE-based detection (more precise)
    for ace in aces:
        identity = ace.get("identity", "").lower()
        rights = ace.get("rights", "").lower()
        ace_type = ace.get("type", "").lower()

        if ace_type != "allow":
            continue

        is_privileged = any(x in identity for x in [
            "administrators", "system", "trustedinstaller"
        ])

        if not is_privileged:
            admin_only = False
            if "everyone" in identity or "world" in identity:
                everyone_access = True
            elif "users" in identity or "authenticated" in identity:
                users_access = True

    if everyone_access:
        result["access_level"] = "everyone"
        result["score_adjustment"] = 20
        result["detail"] = "Device accessible to Everyone - high exploitability"
    elif users_access:
        result["access_level"] = "users"
        result["score_adjustment"] = 15
        result["detail"] = "Device accessible to Builtin Users - exploitable from standard account"
    elif data.get("accessible", False):
        # Could open it but couldn't read DACL - treat as user-accessible
        result["access_level"] = "users"
        result["score_adjustment"] = 15
        result["detail"] = "Device opened successfully from current user context"
    elif admin_only:
        result["access_level"] = "admin_only"
        result["score_adjustment"] = -15
        result["detail"] = "Device restricted to administrators only"
    else:
        result["access_level"] = "unknown"
        result["score_adjustment"] = 0
        result["detail"] = "Could not determine access level"

    return result


def check_driver_devices(driver_name, powershell_cmd=None):
    """Full device security check for a single driver.

    Enumerates device objects, tests each one, returns best (most permissive) result.
    """
    if powershell_cmd is None:
        powershell_cmd = _get_powershell()

    device_paths = enumerate_driver_devices(driver_name, powershell_cmd)

    if not device_paths:
        return {
            "driver": driver_name,
            "devices_checked": 0,
            "access_level": "no_device",
            "score_adjustment": -10,
            "detail": "No device objects found for this driver",
            "device_results": [],
        }

    device_results = []
    for path in device_paths:
        result = check_device_access(path, powershell_cmd)
        device_results.append(result)

    # Use the most permissive access level found (worst case for security)
    access_priority = {"everyone": 4, "users": 3, "admin_only": 1, "no_device": 0, "unknown": 0}
    best = max(device_results, key=lambda r: access_priority.get(r.get("access_level", "unknown"), 0))

    return {
        "driver": driver_name,
        "devices_checked": len(device_paths),
        "access_level": best.get("access_level", "unknown"),
        "score_adjustment": best.get("score_adjustment", 0),
        "detail": best.get("detail", ""),
        "device_results": device_results,
    }


def augment_triage_results(results_path, min_score=0, output_path=None):
    """Augment triage results with device security check findings.

    Args:
        results_path: path to triage_results.json
        min_score: only check drivers with score >= this threshold
        output_path: where to write augmented results (default: overwrite input)
    """
    with open(results_path, "r") as f:
        results = json.load(f)

    powershell_cmd = _get_powershell()
    if powershell_cmd is None:
        print("Device check requires Windows (PowerShell not available).")
        return results

    # Filter drivers by score threshold
    drivers_to_check = []
    for r in results:
        score = r.get("score", 0)
        name = r.get("driver", {}).get("name", "")
        priority = r.get("priority", "")
        if name and score >= min_score and priority not in ("INVESTIGATED", "SKIP"):
            drivers_to_check.append((name, r))

    if not drivers_to_check:
        print(f"No drivers above score threshold ({min_score}).")
        return results

    print(f"Checking device security for {len(drivers_to_check)} drivers (score >= {min_score})...\n")

    everyone_count = 0
    users_count = 0
    admin_count = 0
    no_device_count = 0

    for driver_name, r in drivers_to_check:
        device_info = check_driver_devices(driver_name, powershell_cmd)
        access = device_info["access_level"]
        adj = device_info["score_adjustment"]

        # Store device check results
        r["device_check"] = {
            "access_level": access,
            "devices_checked": device_info["devices_checked"],
            "score_adjustment": adj,
            "detail": device_info["detail"],
        }

        # Apply score adjustment
        if adj != 0:
            r["score"] = r.get("score", 0) + adj
            r.setdefault("findings", []).append({
                "check": "device_access",
                "score": adj,
                "detail": device_info["detail"],
            })
            # Recalculate priority
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

        status_icon = {
            "everyone": "!!",
            "users": "! ",
            "admin_only": "OK",
            "no_device": "--",
        }.get(access, "??")

        print(f"  [{status_icon}] {driver_name}: {access} (adj: {adj:+d})")

        if access == "everyone":
            everyone_count += 1
        elif access == "users":
            users_count += 1
        elif access == "admin_only":
            admin_count += 1
        else:
            no_device_count += 1

    # Re-sort by score
    results.sort(key=lambda x: x.get("score", 0), reverse=True)

    out = output_path or results_path
    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nDevice security check results:")
    print(f"  !! Everyone access:  {everyone_count} (score +20 each)")
    print(f"  !  User access:      {users_count} (score +15 each)")
    print(f"  OK Admin only:       {admin_count} (score -15 each)")
    print(f"  -- No device:        {no_device_count} (score -10 each)")
    print(f"  Results written to: {out}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Cthaeh - Device object security descriptor check"
    )
    parser.add_argument("--results", help="Path to triage_results.json to augment")
    parser.add_argument("--device", help="Check a specific device path (e.g., \\\\.\\MyDevice)")
    parser.add_argument("--driver", help="Check devices for a specific driver filename")
    parser.add_argument("--min-score", type=int, default=75,
                        help="Only check drivers scoring above this threshold (default: 75)")
    parser.add_argument("--output", help="Output path (default: overwrite input)")

    args = parser.parse_args()

    if args.device:
        result = check_device_access(args.device)
        print(f"\nDevice: {args.device}")
        for k, v in result.items():
            print(f"  {k}: {v}")
        return

    if args.driver:
        result = check_driver_devices(args.driver)
        print(f"\nDriver: {args.driver}")
        print(f"  Access level: {result['access_level']}")
        print(f"  Score adjustment: {result['score_adjustment']:+d}")
        print(f"  Detail: {result['detail']}")
        print(f"  Devices checked: {result['devices_checked']}")
        for dr in result["device_results"]:
            print(f"    {dr.get('path', '?')}: {dr.get('access_level', '?')} - {dr.get('detail', '')}")
        return

    if args.results:
        augment_triage_results(args.results, min_score=args.min_score, output_path=args.output)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
