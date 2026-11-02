"""SC GPIO23 route admission is tied to the linked MA3 image structures."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from corpus import firmware_path
from msm5xxx_emulator.detection.audio import find_ma3_indexed_candidate
from msm5xxx_emulator.detection.ma3_gpio_irq import find_ma3_gpio_irq_candidate
from msm5xxx_emulator.qemu.transport import qemu_ma3_gpio_irq_property


class MA3GPIOIRQDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = firmware_path("SC-7080 (57.01.00.17) 16MB Memory Dump.bin")
        cls.image = path.read_bytes()
        cls.audio = find_ma3_indexed_candidate(cls.image)
        cls.config = SimpleNamespace(
            chipset="MSM5100", flash_size=0x01000000,
            ram_base=0x01000000, ram_size=0x00800000,
        )

    def test_sc_gpio23_route_matches_linked_copy_and_registrations(self):
        candidate = find_ma3_gpio_irq_candidate(self.image)
        self.assertEqual(candidate["status"], "candidate")
        self.assertEqual(candidate["vector_copy"],
                         [0x0066AC3C, 0x01000000, 0x00029538])
        self.assertEqual(candidate["parent_descriptor_source"], 0x006764EC)
        self.assertEqual(candidate["gpio_table_source"], 0x00676550)
        self.assertEqual(candidate["gpio_mask"], 0x80)
        self.assertEqual(candidate["fields"], [
            0x17, 0x1D, 0x0100B914, 0x0129E278, 0x0100B584,
            0x00161F69, 0x00161BFC, 0x0009BB71, 0x2000,
            0x03000C84, 0x03000C98,
        ])

    def test_property_is_ma3_sc_only_and_serializes_exact_native_gate(self):
        value, reason = qemu_ma3_gpio_irq_property(
            self.image, self.config, self.audio)
        self.assertIsNone(reason)
        self.assertEqual(value,
                         "ma3-gpio-irq=17:1d:100b914:129e278:100b584:"
                         "161f69:161bfc:9bb71:2000:3000c84:3000c98")
        bad = SimpleNamespace(**vars(self.config))
        bad.ram_size = 0x01000000
        self.assertEqual(qemu_ma3_gpio_irq_property(
            self.image, bad, self.audio),
            (None, "ma3-ram-profile-unverified"))
        self.assertEqual(qemu_ma3_gpio_irq_property(
            self.image, self.config,
            {**self.audio, "grammar": "ma2-command-v1"}),
            (None, "ma3-audio-profile-unverified"))

    def test_route_rejects_mutated_parent_gpio_and_callback_links(self):
        mutations = (
            (0x006764EC + 8, 4),
            (0x00676550 + 0x18 + 16, 2),
            (0x001621AA, 2),
            (0x0009BB8A, 2),
            (0x001621C0 + 12, 4),
        )
        for offset, width in mutations:
            with self.subTest(offset=hex(offset)):
                image = bytearray(self.image)
                image[offset] ^= 1
                candidate = find_ma3_gpio_irq_candidate(bytes(image))
                self.assertEqual(candidate["status"], "rejected")
                self.assertIsNotNone(candidate["reject_reason"])


if __name__ == "__main__":
    unittest.main()
