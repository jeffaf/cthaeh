#!/usr/bin/env python3
"""Focused tests for host hardware-presence enrichment."""

import unittest

import hw_check


class PnpUtilParserTests(unittest.TestCase):
    SAMPLE = r"""
Instance ID:                PCI\VEN_14C3&DEV_0616&SUBSYS_E0DF105B&REV_00\4&ABC
Device Description:         MediaTek Wi-Fi 6E MT7922
Class Name:                 Net
Properties:
    DEVPKEY_Device_HardwareIds [String List]:
        PCI\VEN_14C3&DEV_0616&SUBSYS_E0DF105B&REV_00
        PCI\VEN_14C3&DEV_0616&SUBSYS_E0DF105B
    DEVPKEY_Device_Service [String]:
        mtkwlex
"""

    def test_extracts_device_and_hardware_ids(self):
        result = hw_check._parse_pnputil_devices(self.SAMPLE)

        self.assertEqual(1, result["device_count"])
        self.assertIn("PCI\\VEN_14C3&DEV_0616&SUBSYS_E0DF105B",
                      result["hardware_ids"])
        self.assertEqual("MediaTek Wi-Fi 6E MT7922",
                         result["devices"][0]["friendly_name"])

    def test_absent_hardware_does_not_change_intrinsic_score(self):
        hw_info = hw_check._parse_pnputil_devices(self.SAMPLE)
        result = hw_check.check_hardware_presence(
            ["athw8x.sys"],
            hw_info=hw_info,
            driver_hw_map={"athw8x.sys": {"PCI\\VEN_168C&DEV_0030"}},
        )["athw8x.sys"]

        self.assertEqual("HARDWARE_ABSENT", result["status"])
        self.assertEqual(0, result["score_adjustment"])
        self.assertEqual("NOT_APPLICABLE", result["local_applicability"])


if __name__ == "__main__":
    unittest.main()
