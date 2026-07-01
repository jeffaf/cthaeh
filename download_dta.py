#!/usr/bin/env python3
"""Download the Cisco Talos Ghidra Data Type Archive for Windows drivers.

Source: https://github.com/Cisco-Talos/Windows-drivers-GDT-file
Blog:   https://blog.talosintelligence.com/ghidra-data-type-archive-for-windows-drivers/

Saves to data/windows_driver_types.gdt for use by apply_dta.py pre-script.
"""

import argparse
import hashlib
import os
import sys

try:
    from urllib.request import urlopen
except ImportError:
    from urllib import urlopen

GDT_URL = "https://raw.githubusercontent.com/Cisco-Talos/Windows-drivers-GDT-file/main/Windows_Driver_functons.gdt"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
OUTPUT_PATH = os.path.join(OUTPUT_DIR, "windows_driver_types.gdt")
ENV_SHA256 = "CTHAEH_DTA_SHA256"


def sha256_file(path):
    """Return SHA256 hex digest for a file."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def download(output_path=OUTPUT_PATH, expected_sha256=None, force=False, timeout=30):
    """Download the DTA file, optionally enforcing an expected SHA256."""
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    expected_sha256 = (expected_sha256 or os.environ.get(ENV_SHA256, "")).strip().lower()

    if os.path.exists(output_path) and not force:
        digest = sha256_file(output_path)
        print("Already exists: %s" % output_path)
        print("SHA256: %s" % digest)
        if expected_sha256 and digest != expected_sha256:
            print("ERROR: Existing file does not match expected SHA256.")
            print("Use --force to re-download after verifying the source hash.")
            return 1
        print("Use --force if you want to re-download.")
        return 0

    print("Downloading Talos Windows Driver DTA...")
    print("  From: %s" % GDT_URL)
    print("  To:   %s" % output_path)

    tmp_path = output_path + ".tmp"
    try:
        with urlopen(GDT_URL, timeout=timeout) as response:
            with open(tmp_path, "wb") as f:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        print("ERROR: Download failed: %s" % e)
        return 1

    digest = sha256_file(tmp_path)
    if expected_sha256 and digest != expected_sha256:
        os.remove(tmp_path)
        print("ERROR: SHA256 mismatch.")
        print("  Expected: %s" % expected_sha256)
        print("  Actual:   %s" % digest)
        return 1

    os.replace(tmp_path, output_path)

    size = os.path.getsize(output_path)
    print("Done. %d bytes written." % size)
    print("SHA256: %s" % digest)
    if not expected_sha256:
        print("Set %s or pass --sha256 to pin this dependency in repeatable builds." % ENV_SHA256)
    return 0


def main():
    parser = argparse.ArgumentParser(description="Download the Talos Windows driver GDT archive")
    parser.add_argument("--output", default=OUTPUT_PATH, help="Output .gdt path")
    parser.add_argument("--sha256", help="Expected SHA256 digest")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output file")
    parser.add_argument("--timeout", type=int, default=30, help="Download timeout in seconds")
    args = parser.parse_args()
    return download(args.output, args.sha256, args.force, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
