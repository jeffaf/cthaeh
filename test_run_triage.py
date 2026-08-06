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


class RunningDriverTests(unittest.TestCase):
    def test_driverquery_parser_excludes_stopped_drivers(self):
        output = ('"Module Name","Display Name","State"\n'
                  '"mtkwl6ex","MediaTek Wi-Fi","Running"\n'
                  '"athw8x","Atheros Wi-Fi","Stopped"\n')

        self.assertEqual(
            {"mtkwl6ex.sys"}, run_triage._parse_driverquery_running(output)
        )

    def test_sc_parser_uses_numeric_running_state(self):
        output = """
SERVICE_NAME: mtkwl6ex
        STATE              : 4  RUNNING
SERVICE_NAME: athw8x
        STATE              : 1  STOPPED
"""

        self.assertEqual({"mtkwl6ex.sys"}, run_triage._parse_sc_running(output))

    def test_registry_parser_maps_service_to_actual_filename(self):
        output = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mtkwlex
    ImagePath    REG_EXPAND_SZ    \SystemRoot\System32\DriverStore\FileRepository\mtkwl6ex.inf_amd64_x\mtkwl6ex.sys
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\athw8x
    ImagePath    REG_EXPAND_SZ    \SystemRoot\System32\drivers\athw8x.sys
"""

        files, mapped = run_triage._parse_service_image_paths(output, {"mtkwlex"})
        self.assertEqual({"mtkwl6ex.sys"}, files)
        self.assertEqual({"mtkwlex"}, mapped)


class ReportSemanticsTests(unittest.TestCase):
    def test_absent_hardware_overrides_critical_action(self):
        action = run_triage.get_tier_recommendation("CRITICAL", has_hardware=False)
        self.assertIn("not locally exposed", action)
        self.assertNotIn("PoC", action)

    def test_cleans_jython_unicode_prefixes(self):
        value = 'u"Qualcomm | u"Network Adapter | u"3.0.2.201'
        self.assertEqual(
            "Qualcomm | Network Adapter | 3.0.2.201",
            run_triage.clean_version_summary(value),
        )

    def test_report_separates_research_priority_from_local_exposure(self):
        results = [{
            "driver": {
                "name": "athw8x.sys",
                "size": 1,
                "function_count": 1,
                "version_summary": 'u"Qualcomm | u"Adapter | u"3.0.2.201',
            },
            "score": 445,
            "priority": "CRITICAL",
            "hardware_check": {"status": "HARDWARE_ABSENT"},
            "findings": [],
        }, {
            "driver": {
                "name": "mtkwl6ex.sys",
                "size": 1,
                "function_count": 1,
            },
            "score": 200,
            "priority": "HIGH",
            "hardware_check": {"status": "HARDWARE_PRESENT"},
            "findings": [],
        }]

        report_handle = mock.mock_open(read_data="{}")
        with mock.patch("builtins.open", report_handle):
            run_triage.write_report(results, "report.md", top_n=1)
        rendered = report_handle().write.call_args.args[0]

        self.assertIn("Top 1 Locally Applicable Candidates", rendered)
        self.assertIn("Not applicable on this host (hardware absent): 1", rendered)
        self.assertIn("mtkwl6ex.sys", rendered)
        self.assertNotIn("athw8x.sys", rendered)
        self.assertNotIn("build PoC exploit", rendered)


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
