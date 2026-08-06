#!/usr/bin/env python3
"""Focused unit tests for the Ghidra orchestration layer."""

import json
import os
import subprocess
import unittest
from unittest import mock

import run_triage


class LauncherSelectionTests(unittest.TestCase):
    @mock.patch.object(run_triage.sys, "platform", "win32")
    @mock.patch.object(run_triage.os.path, "exists", return_value=True)
    @mock.patch.object(run_triage, "get_ghidra_version", return_value=(11, 3, 2))
    def test_ghidra_11_prefers_analyze_headless(self, _version_mock, _exists_mock):
        launcher, args, name = run_triage.get_ghidra_headless_launcher("C:\\ghidra")
        self.assertEqual("analyzeHeadless", name)
        self.assertEqual([], args)
        self.assertTrue(launcher.endswith("analyzeHeadless.bat"))

    @mock.patch.object(run_triage.sys, "platform", "win32")
    @mock.patch.object(run_triage.os.path, "exists", return_value=True)
    @mock.patch.object(run_triage, "get_ghidra_version", return_value=(12, 0, 1))
    def test_ghidra_12_prefers_pyghidra(self, _version_mock, _exists_mock):
        launcher, args, name = run_triage.get_ghidra_headless_launcher("C:\\ghidra")
        self.assertEqual("pyghidraRun", name)
        self.assertEqual(["--headless"], args)
        self.assertTrue(launcher.endswith("pyghidraRun.bat"))


class StartupCheckTests(unittest.TestCase):
    @mock.patch.object(run_triage, "get_ghidra_headless_launcher")
    @mock.patch.object(run_triage.subprocess, "run")
    def test_reports_interactive_pyghidra_setup(self, run_mock, launcher_mock):
        launcher_mock.return_value = ("pyghidraRun.bat", ["--headless"], "pyghidraRun")
        run_mock.return_value = subprocess.CompletedProcess(
            [], 1, "Do you wish to install PyGhidra (y/n)? ", "EOFError"
        )

        name, error = run_triage.check_ghidra_startup("C:\\ghidra")

        self.assertEqual("pyghidraRun", name)
        self.assertIn("PyGhidra is not initialized", error)
        self.assertIs(subprocess.DEVNULL, run_mock.call_args.kwargs["stdin"])


class AnalysisDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.args = (
            "C:\\ghidra",
            "C:\\drivers\\sample.sys",
            os.path.abspath("driver_triage.py"),
            os.getcwd(),
            0,
        )

    @mock.patch.object(run_triage, "get_ghidra_headless_launcher")
    @mock.patch.object(run_triage.subprocess, "run")
    def test_returns_ghidra_diagnostics_on_failure(self, run_mock, launcher_mock):
        launcher_mock.return_value = ("analyzeHeadless.bat", [], "analyzeHeadless")
        run_mock.return_value = subprocess.CompletedProcess(
            [], 1, "", "ERROR: Failed to find a supported JDK."
        )

        result, error = run_triage.run_ghidra_analysis(self.args)

        self.assertIsNone(result)
        self.assertIn("Ghidra exit 1", error)
        self.assertIn("supported JDK", error)
        self.assertIs(subprocess.DEVNULL, run_mock.call_args.kwargs["stdin"])

    @mock.patch.object(run_triage, "get_ghidra_headless_launcher")
    @mock.patch.object(run_triage.subprocess, "run")
    def test_parses_triage_json(self, run_mock, launcher_mock):
        launcher_mock.return_value = ("analyzeHeadless.bat", [], "analyzeHeadless")
        payload = {"driver": {"name": "sample.sys"}, "score": 42}
        output = "===TRIAGE_START===\n%s\n===TRIAGE_END===" % json.dumps(payload)
        run_mock.return_value = subprocess.CompletedProcess([], 0, output, "")

        result, error = run_triage.run_ghidra_analysis(self.args)

        self.assertEqual(payload, result)
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
