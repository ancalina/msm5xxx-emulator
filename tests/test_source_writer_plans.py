"""Synthetic selection and loaded-source checks for writer plans."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from msm5xxx_emulator.detection.devices.display import source_writers
from msm5xxx_emulator.detection.devices.storage import descriptor_bank, descriptor_plan
from test_descriptor_bank import synthetic_image


class SourceWriterPlanTests(unittest.TestCase):
    def test_page_precedence_and_loaded_source_guard(self):
        image = bytes(0x80000)
        config = SimpleNamespace(image_kind='firmware', load_address=0, image_offset=0, entry=0,
            missing_overlays=[], ram_bootstrap_profile=None, display_geometry_source='auto-default')
        with patch.object(source_writers, 'has_paired_page_writer', return_value=True), \
             patch.object(source_writers, 'has_byte_paired_page_writer', return_value=True):
            plan = source_writers.machine_plan(image, image, config)
            self.assertEqual(dict(plan.capabilities[0].parameters)['page'], 'paired')
            self.assertEqual((plan.claims[0].start, plan.claims[0].end), (0x2000000, 0x2000004))
            self.assertFalse(source_writers.machine_plan(image, b'X' + image[1:], config).capabilities)

    def test_binary_writer_claims_its_separate_ports(self):
        image = bytes(0x80000)
        config = SimpleNamespace(image_kind='firmware', load_address=0, image_offset=0, entry=0,
            missing_overlays=[], ram_bootstrap_profile=None, display_geometry_source='auto-default')
        with patch.object(source_writers, 'has_binary_window_writer', return_value=True):
            plan = source_writers.machine_plan(image, image, config)
        self.assertEqual([(claim.start, claim.end) for claim in plan.claims],
                         [(0x02000004, 0x02000005), (0x02000006, 0x02000007)])

    def test_bank_plan_requires_matching_loaded_source_and_unclaimed_bus(self):
        image, identifier, _, _, _ = synthetic_image()
        image = bytes(image)
        config = SimpleNamespace(load_address=0, flash_id_address=identifier,
            flash_size=len(image), ram_base=0x1000000, ram_size=0x800000)
        with patch.object(descriptor_bank, 'PRIMARY_FSD_AMD_X16_ID_ROUTINE', b'\x00\xb5\x00\xbd'):
            plan = descriptor_plan.bank_plan(image, image, config, claimed=False)
            self.assertEqual(dict(plan.capabilities[0].parameters)['profile'],
                             (0x180000, 0x80000, 0x10000, 1, 0x1234))
            self.assertEqual((plan.claims[0].start, plan.claims[0].end), (0x180000, 0x200000))
            self.assertFalse(descriptor_plan.bank_plan(image, image, config, claimed=True).capabilities)
            self.assertFalse(descriptor_plan.bank_plan(image, b'X'+image[1:], config, claimed=False).capabilities)
