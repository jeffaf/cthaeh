#!/usr/bin/env python3
"""Single command-line entry point for Cthaeh.

Running this file without a subcommand performs the normal Windows workflow:
download the Talos DTA when needed, extract a driver corpus, and scan it.
Specialized operations remain available as subcommands so users never need to
invoke the implementation scripts directly.
"""

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
COMMANDS = {
    "setup": "download_dta.py",
    "extract": "extract_driverstore.py",
    "scan": "run_triage.py",
    "calibrate": "calibrate_scoring.py",
    "test": "test_regression.py",
}


def script_command(script_name, arguments):
    """Build a child command using the current Python interpreter."""
    return [sys.executable, str(ROOT / script_name), *arguments]


def print_command(command):
    """Print a readable command without requiring shell quoting semantics."""
    print("+ " + subprocess.list2cmdline(command))


def run_command(command, dry_run=False):
    """Run one implementation script and return its exit status."""
    print_command(command)
    if dry_run:
        return 0
    return subprocess.run(command).returncode


def has_driver_files(directory):
    """Return whether a directory contains at least one .sys file."""
    path = Path(directory)
    if not path.is_dir():
        return False
    try:
        return any(
            candidate.is_file() and candidate.suffix.lower() == ".sys"
            for candidate in path.rglob("*")
        )
    except OSError:
        return False


def default_drivers_dir():
    if sys.platform == "win32":
        return r"C:\drivers"
    return str(Path.cwd() / "drivers")


def build_pipeline_parser():
    parser = argparse.ArgumentParser(
        prog="cthaeh.py",
        description=(
            "Download Cthaeh's DTA dependency, extract Windows drivers, and "
            "run the triage scanner. Unknown scan options are passed through "
            "to the scanner."
        ),
        epilog=(
            "Other operations: cthaeh.py scan|setup|extract|calibrate|test --help"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--drivers-dir",
        help="Driver corpus directory (default: C:\\drivers on Windows)",
    )
    parser.add_argument(
        "--driverstore",
        default=r"C:\Windows\System32\DriverStore\FileRepository",
        help="Windows DriverStore FileRepository path",
    )
    parser.add_argument(
        "--include-microsoft",
        action="store_true",
        help="Include Microsoft drivers during extraction",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Extract and scan all drivers instead of loaded drivers only",
    )
    parser.add_argument(
        "--skip-dta",
        action="store_true",
        help="Do not check or download the Talos DTA",
    )
    parser.add_argument(
        "--skip-extract",
        action="store_true",
        help="Scan an existing corpus without extracting DriverStore",
    )
    parser.add_argument(
        "--dta-sha256",
        help="Expected SHA256 for the Talos DTA download",
    )
    parser.add_argument(
        "--dta-force",
        action="store_true",
        help="Re-download the Talos DTA even when it already exists",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the workflow commands without running them",
    )
    return parser


def run_pipeline(argv):
    parser = build_pipeline_parser()
    positional_drivers_dir = None
    if argv and not argv[0].startswith("-"):
        positional_drivers_dir = argv.pop(0)
    args, scan_args = parser.parse_known_args(argv)

    drivers_dir = args.drivers_dir or positional_drivers_dir or default_drivers_dir()
    single_scan = "--single" in scan_args
    explain_only = "--explain" in scan_args and not single_scan

    if not args.skip_dta and not explain_only:
        setup_args = []
        if args.dta_sha256:
            setup_args.extend(["--sha256", args.dta_sha256])
        if args.dta_force:
            setup_args.append("--force")
        status = run_command(
            script_command(COMMANDS["setup"], setup_args),
            dry_run=args.dry_run,
        )
        if status:
            return status

    should_extract = not args.skip_extract and not single_scan and not explain_only
    if should_extract and sys.platform != "win32" and not args.dry_run:
        if has_driver_files(drivers_dir):
            print("Non-Windows host: using the existing driver corpus; extraction skipped.")
            should_extract = False
        else:
            parser.error(
                "DriverStore extraction requires Windows. Supply an existing corpus "
                "with --drivers-dir and --skip-extract, or use the scan subcommand."
            )

    if should_extract:
        extract_args = [
            "--driverstore",
            args.driverstore,
            "--output",
            drivers_dir,
        ]
        if args.include_microsoft:
            extract_args.append("--include-microsoft")
        if args.all:
            extract_args.append("--all")
        status = run_command(
            script_command(COMMANDS["extract"], extract_args),
            dry_run=args.dry_run,
        )
        if status:
            return status

    if not args.dry_run and not single_scan and not explain_only and not has_driver_files(drivers_dir):
        print("ERROR: No .sys files found in %s" % drivers_dir, file=sys.stderr)
        return 1

    triage_args = list(scan_args)
    if not single_scan and not explain_only:
        triage_args.insert(0, drivers_dir)
    if args.all:
        triage_args.append("--all")
    return run_command(
        script_command(COMMANDS["scan"], triage_args),
        dry_run=args.dry_run,
    )


def print_top_level_help():
    build_pipeline_parser().print_help()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] in COMMANDS:
        command = argv.pop(0)
        return run_command(script_command(COMMANDS[command], argv))

    if argv and argv[0] in ("help", "-h", "--help"):
        print_top_level_help()
        return 0

    if argv and argv[0] == "pipeline":
        argv.pop(0)

    return run_pipeline(argv)


if __name__ == "__main__":
    sys.exit(main())
