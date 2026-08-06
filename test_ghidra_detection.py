#!/usr/bin/env python3
"""Tests for Ghidra installation discovery."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_triage


class GhidraDetectionTests(unittest.TestCase):
    def make_install(self, root, name):
        install = Path(root) / name
        support = install / "support"
        support.mkdir(parents=True)
        launcher = support / "analyzeHeadless.bat"
        launcher.touch()
        return install

    def test_resolves_exact_install_root(self):
        with tempfile.TemporaryDirectory() as directory:
            install = self.make_install(directory, "ghidra_12.0.3_PUBLIC")
            with mock.patch.object(run_triage.sys, "platform", "win32"):
                self.assertEqual(
                    run_triage.resolve_ghidra_install(str(install)),
                    str(install),
                )

    def test_resolves_versioned_install_below_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            install = self.make_install(directory, "ghidra_12.0.3_PUBLIC")
            with mock.patch.object(run_triage.sys, "platform", "win32"):
                self.assertEqual(
                    run_triage.resolve_ghidra_install(directory),
                    str(install),
                )

    def test_prefers_newest_versioned_install(self):
        with tempfile.TemporaryDirectory() as directory:
            self.make_install(directory, "ghidra_11.4_PUBLIC")
            newest = self.make_install(directory, "ghidra_12.0.3_PUBLIC")
            with mock.patch.object(run_triage.sys, "platform", "win32"):
                self.assertEqual(
                    run_triage.resolve_ghidra_install(directory),
                    str(newest),
                )

    def test_ghidra_home_may_point_at_parent_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            install = self.make_install(directory, "ghidra_12.0.3_PUBLIC")
            with mock.patch.object(run_triage.sys, "platform", "win32"), mock.patch.dict(
                run_triage.os.environ,
                {"GHIDRA_HOME": directory},
            ):
                self.assertEqual(run_triage.detect_ghidra(), str(install))


if __name__ == "__main__":
    unittest.main()
