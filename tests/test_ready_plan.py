"""Synthetic source-to-device planning without external firmware fixtures."""
from dataclasses import FrozenInstanceError
import struct
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.detection.devices.ready_poll import (
    find_ready_poll_profile, ready_poll_plan, runtime_ready_poll_property,
)
from msm5xxx_emulator.detection.facts import bind_facts, fact_scope
from msm5xxx_emulator.detection.image_view import ImageView


def poll_image(entry=0x20, status=0x030007B4, pulse=0x03000600):
    image = bytearray(entry + 32)
    delta = entry - 4
    struct.pack_into('<2H', image, 0, 0xF000 | (delta >> 12 & 0x7FF),
                     0xF800 | (delta >> 1 & 0x7FF))
    # Byte status bit 3; pulse 1/0 until the ready branch returns.
    struct.pack_into('<11H', image, entry, 0x4805, 0x7900, 0x0900,
                     0xD205, 0x2001, 0x4904, 0x7008, 0x2000,
                     0x7008, 0xE7F5, 0x4770)
    struct.pack_into('<2I', image, entry + 24, status - 4, pulse)
    return bytes(image)


def config(image, profile=None):
    return SimpleNamespace(load_address=0, flash_size=len(image), nand_enabled=False,
                           upper_flash_size=0, uart_console=None,
                           ready_poll=find_ready_poll_profile(image) if profile is None else profile)


class ReadyPlanTests(unittest.TestCase):
    def test_code_evidence_projects_existing_property(self):
        image = poll_image()
        cfg = config(image)
        self.assertIsNotNone(cfg.ready_poll)
        resolution = ready_poll_plan(image, cfg)
        self.assertEqual(resolution.plan.properties, (('ready-poll', '30007b4:8:3000600:20'),))
        self.assertEqual(runtime_ready_poll_property(image, cfg),
                         ('ready-poll=30007b4:8:3000600:20', None, None))
        self.assertEqual({(claim.start, claim.end) for claim in resolution.plan.claims},
                         {(0x030007B4, 0x030007B5), (0x03000600, 0x03000601)})
        self.assertTrue(all(fact.locations for fact in resolution.plan.evidence))
        with self.assertRaises(FrozenInstanceError):
            resolution.plan.properties = ()

    def test_forged_profile_cannot_authorize_device(self):
        image = poll_image()
        original = find_ready_poll_profile(image)
        cfg = config(image, {**original, 'pulse_address': 0x03001080})
        self.assertEqual(ready_poll_plan(image, cfg).plan.capabilities, ())
        changed = bytearray(image)
        struct.pack_into('<H', changed, 0x20 + 12, 0x7000)
        self.assertEqual(ready_poll_plan(bytes(changed), config(image)).plan.capabilities, ())

    def test_empty_profile_and_cached_mutation(self):
        self.assertEqual(runtime_ready_poll_property(b'', SimpleNamespace(ready_poll=None)),
                         (None, None, None))
        image = poll_image()
        first = find_ready_poll_profile(image)
        first['entries'].clear()
        self.assertEqual(find_ready_poll_profile(image)['entries'], [0x20])

    def test_cache_and_caller_proof_respect_supplied_coverage(self):
        image = poll_image()
        self.assertIsNotNone(find_ready_poll_profile(image))
        for begin, end in ((2, 4), (0x38, 0x3C)):
            with self.subTest(missing=(begin, end)), fact_scope():
                view = ImageView.sparse(((0, image[:begin]), (end, image[end:])))
                bind_facts(image, view)
                self.assertIsNone(find_ready_poll_profile(image))
        self.assertIsNotNone(find_ready_poll_profile(image))

    def test_runtime_primary_prefix_retains_source_holes(self):
        primary = poll_image()
        image = primary + bytes(64)
        cfg = config(primary)
        with fact_scope():
            view = ImageView.sparse(((0, image[:2]), (4, image[4:])))
            bind_facts(image, view)
            self.assertEqual(ready_poll_plan(image, cfg).plan.capabilities, ())


if __name__ == '__main__':
    unittest.main()
