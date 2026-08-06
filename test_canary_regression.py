#!/usr/bin/env python3
"""Tests for the metadata-driven canary regression harness."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import test_regression


class CanaryRegressionTests(unittest.TestCase):
    def run_canaries(self, canaries, results, *, strict_missing=False):
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(json.dumps({"canaries": canaries}), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                success = test_regression.run_canary_tests(
                    results,
                    manifest_path=str(manifest_path),
                    strict_missing=strict_missing,
                )
        return success, output.getvalue()

    def test_accepts_matching_canary_at_or_above_minimums(self):
        success, output = self.run_canaries(
            [
                {
                    "driver": "sample.sys",
                    "version": "1.2.3.4",
                    "min_priority": "HIGH",
                    "min_score": 150,
                    "expected_checks": ["has_ioctl_handler"],
                }
            ],
            [
                {
                    "driver": {"name": "SAMPLE.SYS", "version": "1.2.3.4"},
                    "priority": "CRITICAL",
                    "score": 250,
                    "findings": [{"check": "has_ioctl_handler"}],
                }
            ],
        )

        self.assertTrue(success)
        self.assertIn("PASS  sample.sys", output)

    def test_rejects_canary_below_expected_tier_or_missing_check(self):
        success, output = self.run_canaries(
            [
                {
                    "driver": "sample.sys",
                    "min_priority": "HIGH",
                    "min_score": 150,
                    "expected_checks": ["has_ioctl_handler"],
                }
            ],
            [{"driver": {"name": "sample.sys"}, "priority": "MEDIUM", "score": 100}],
        )

        self.assertFalse(success)
        self.assertIn("priority MEDIUM below HIGH", output)
        self.assertIn("missing checks: has_ioctl_handler", output)

    def test_pinned_canary_without_version_is_not_evaluable(self):
        success, output = self.run_canaries(
            [{"driver": "sample.sys", "version": "1.2.3.4"}],
            [{"driver": {"name": "sample.sys"}, "priority": "HIGH", "score": 150}],
            strict_missing=True,
        )

        self.assertFalse(success)
        self.assertIn("version mismatch '' != expected '1.2.3.4'", output)

    def test_missing_canary_only_fails_in_strict_mode(self):
        canaries = [{"driver": "missing.sys"}]

        non_strict, _ = self.run_canaries(canaries, [], strict_missing=False)
        strict, _ = self.run_canaries(canaries, [], strict_missing=True)

        self.assertTrue(non_strict)
        self.assertFalse(strict)


if __name__ == "__main__":
    unittest.main()
