"""Synthetic plan ownership and loaded-source guards for direct NOR drivers."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.storage import secondary_protected_plan as domain


class SecondaryDirectPlanTests(unittest.TestCase):
    def setUp(self):
        self.image = bytes(0x1000)
        self.cfg = SimpleNamespace(image_kind='firmware', load_address=0,
            image_offset=0, entry=0, file_size=len(self.image),
            flash_size=len(self.image), ram_base=0x14000000, ram_size=0x800000)
        self.profile = {
            'signature': 'direct-secondary-protected-nor-x16-v1',
            'identity_queried': False, 'bank_base': 0x12000000,
            'bank_size': 0x800000, 'sector_size': 0x10000,
            'evidence_spans': ((0x100, 0x110), (0x200, 0x208)),
        }

    def plan(self, *, loaded=None, claimed=False):
        with patch.object(domain.secondary_protected_nor,
                          'find_secondary_protected_nor', return_value=None), \
             patch.object(domain, 'find_secondary_direct_nor', return_value=self.profile):
            return domain.machine_plan(self.image,
                self.image if loaded is None else loaded, self.cfg, claimed=claimed)

    def test_direct_protocol_projects_private_bank_without_an_identity_query(self):
        plan = self.plan()
        self.assertEqual(dict(plan.properties)['protected-nor-bank'], '12000000:0')
        binding = domain.project(plan)
        self.assertEqual(binding.raw_size, 0x800000)
        self.assertIsNone(binding.source_offset)
        self.assertIn('experimental-protected-nor=12000000:800000:10000:f4240',
                      binding.machine)

    def test_loaded_code_mutation_and_competing_storage_are_rejected(self):
        changed = bytearray(self.image)
        changed[0x101] = 1
        self.assertFalse(self.plan(loaded=bytes(changed)).capabilities)
        self.assertFalse(self.plan(claimed=True).capabilities)
        self.cfg.secondary_flash_address = 0x12000000
        self.assertFalse(self.plan().capabilities)

    def test_unqueried_identity_and_complete_source_spans_are_required(self):
        for field, value in (('identity_queried', True),
                             ('sector_size', 0x20000),
                             ('bank_size', True),
                             ('evidence_spans', ((0x100, 0x2000),))):
            with self.subTest(field=field):
                saved = self.profile[field]
                self.profile[field] = value
                self.assertFalse(self.plan().capabilities)
                self.profile[field] = saved

    def test_projection_rejects_identity_or_protocol_evidence_tampering(self):
        plan = self.plan()
        cap = plan.capabilities[0]
        parameters = dict(cap.parameters)
        parameters['packed_id'] = 1
        with self.assertRaises(ValueError):
            domain.project(replace(plan, capabilities=(replace(cap,
                parameters=tuple(parameters.items())),)))
        evidence = replace(cap.evidence[0], value=(0x12000000, 0x400000, 0x10000, 0))
        with self.assertRaises(ValueError):
            domain.project(replace(plan, capabilities=(replace(cap,
                evidence=(evidence,)),)))


if __name__ == '__main__':
    unittest.main()
