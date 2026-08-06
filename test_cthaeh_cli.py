#!/usr/bin/env python3
"""Tests for the unified Cthaeh command-line entry point."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import Cthaeh


class CthaehCliTests(unittest.TestCase):
    def test_subcommand_dispatches_to_implementation_script(self):
        completed = mock.Mock(returncode=7)
        with mock.patch.object(Cthaeh.subprocess, "run", return_value=completed) as run:
            status = Cthaeh.main(["scan", "drivers", "--all"])

        self.assertEqual(status, 7)
        command = run.call_args.args[0]
        self.assertEqual(Path(command[1]).name, "run_triage.py")
        self.assertEqual(command[2:], ["drivers", "--all"])

    def test_pipeline_dry_run_builds_setup_extract_and_scan_commands(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = Cthaeh.main([
                "--dry-run",
                "--drivers-dir",
                r"C:\corpus",
                "--ghidra",
                r"C:\ghidra",
                "--all",
            ])

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("download_dta.py", rendered)
        self.assertIn("extract_driverstore.py", rendered)
        self.assertIn("run_triage.py", rendered)
        self.assertIn("--ghidra", rendered)
        self.assertIn("--all", rendered)

    def test_explain_is_scan_only(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = Cthaeh.main(["--dry-run", "--explain", "example.sys"])

        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertNotIn("download_dta.py", rendered)
        self.assertNotIn("extract_driverstore.py", rendered)
        self.assertIn("run_triage.py", rendered)
        self.assertIn("--explain", rendered)

    def test_driver_corpus_detection_is_recursive(self):
        with tempfile.TemporaryDirectory() as directory:
            nested = Path(directory) / "vendor"
            nested.mkdir()
            self.assertFalse(Cthaeh.has_driver_files(directory))
            (nested / "sample.sys").touch()
            self.assertTrue(Cthaeh.has_driver_files(directory))


if __name__ == "__main__":
    unittest.main()
