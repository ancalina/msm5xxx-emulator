"""Source-linked Sharp board-status recognition against the private corpus."""
from pathlib import Path
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from corpus import firmware_path
from msm5xxx_emulator.detection.sharp_board_status import (
    find_sharp_board_status_profile,
)
from msm5xxx_emulator.qemu.transport import qemu_sharp_board_status_property


RAM_BASE = 0x01000000
RAM_SIZE = 0x00800000


def images():
    return {
        "T030": firmware_path(
            "T030TEDT09_5.177_JTAG - Old Phone Preservation.bin"
        ).read_bytes(),
        "T050": firmware_path(
            "incoming-msm5xxx-all-manufacturers-20260726", "Audiovox",
            "CDM-8500", "T050VMDM01_3.191_JTAG",
            "T050VMDM01_3.191_JTAG.bin",
        ).read_bytes(),
        "T000": firmware_path(
            "incoming-msm5xxx-all-manufacturers-20260726", "Audiovox",
            "CDM-8500", "T050VMDT09_2.191_JTAG_1",
            "T000VEDW00_0.000_JTAG.bin",
        ).read_bytes(),
    }


def detect(image):
    return find_sharp_board_status_profile(
        image, len(image), RAM_BASE, RAM_SIZE
    )


class SharpBoardStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.images = images()

    def test_t030_admits_rf_ready_only(self):
        profile, reason = detect(self.images["T030"])
        self.assertEqual(reason, "accepted-sharp-cdm-board-status")
        self.assertEqual(profile["rf"]["address"], 0x03000730)
        self.assertEqual((profile["rf"]["mask"], profile["rf"]["default"]), (1, 1))
        self.assertIsNone(profile["lid"])

    def test_t050_and_t000_admit_lid_status_only(self):
        for image_name in ("T050", "T000"):
            with self.subTest(image=image_name):
                profile, reason = detect(self.images[image_name])
                self.assertEqual(reason, "accepted-sharp-cdm-board-status")
                self.assertIsNone(profile["rf"])
                self.assertEqual(profile["lid"]["address"], 0x03000728)
                self.assertEqual((profile["lid"]["mask"], profile["lid"]["default"]),
                                 (0x40, 0x40))
                self.assertEqual(
                    struct.unpack_from(
                        "<I", self.images[image_name],
                        profile["lid"]["descriptor_source"] + 0x24,
                    )[0],
                    0x03000728,
                )

    def test_changed_rf_literal_does_not_admit_the_rf_input(self):
        image = bytearray(self.images["T030"])
        profile, _ = detect(bytes(image))
        literal = profile["rf"]["status_literal"]
        struct.pack_into("<I", image, literal, 0x0300072C)
        changed, reason = detect(bytes(image))
        self.assertEqual(reason, "sharp-board-status-paths-not-matched")
        self.assertIsNone(changed)

    def test_changed_lid_descriptor_does_not_admit_the_lid_input(self):
        image = bytearray(self.images["T050"])
        profile, _ = detect(bytes(image))
        source = profile["lid"]["descriptor_source"]
        struct.pack_into("<I", image, source + 0x24, 0x0300072C)
        changed, reason = detect(bytes(image))
        self.assertEqual(reason, "sharp-board-status-paths-not-matched")
        self.assertIsNone(changed)

    def test_unrelated_image_is_not_admitted(self):
        profile, reason = detect(bytes(0x800000))
        self.assertIsNone(profile)
        self.assertTrue(reason.startswith("sharp-board-status-lcd-source-unverified"))

    def test_transport_rechecks_loaded_source_and_respects_existing_owner(self):
        config = SimpleNamespace(flash_size=8, ram_base=RAM_BASE, ram_size=RAM_SIZE)
        profile = {"rf": {"address": 0x03000730, "mask": 1, "default": 1}, "lid": None}
        target = "msm5xxx_emulator.detection.sharp_board_status.find_sharp_board_status_profile"
        with patch(target, return_value=(profile, "accepted")) as finder:
            self.assertEqual(qemu_sharp_board_status_property(b"source!!", b"loaded!!", config,
                                                               claimed=False),
                             ("board-status-input=3000730:1:1", None))
            self.assertEqual(finder.call_count, 2)
            self.assertEqual(qemu_sharp_board_status_property(b"source!!", b"loaded!!", config,
                                                               claimed=True),
                             (None, "input-owner-conflict"))
        with patch(target, side_effect=((profile, "accepted"), (None, "changed"))):
            self.assertEqual(qemu_sharp_board_status_property(b"source!!", b"loaded!!", config,
                                                               claimed=False),
                             (None, "loaded-source-mismatch"))


if __name__ == "__main__":
    unittest.main()
