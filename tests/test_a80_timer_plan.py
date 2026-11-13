"""The A80 source proof is guarded before native controller projection."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.registry import device_domain


class A80TimerPlanTests(unittest.TestCase):
    def setUp(self):
        self.module = device_domain('rex.a80_plan')
        self.image = bytes(range(256)) * 4
        self.config = SimpleNamespace(file_size=len(self.image))
        self.profile = {'parameters': dict(self.module._PARAMETERS),
                        'evidence_spans': [[16, 8], [512, 32]]}

    def plan(self, loaded=None):
        with patch.object(self.module, 'find_a80_timer', return_value=self.profile):
            return self.module.machine_plan(self.image,
                self.image if loaded is None else loaded, self.config)

    def test_source_evidence_projects_exact_hardware_contract(self):
        plan = self.plan()
        self.assertEqual(self.module.machine_properties(plan),
                         ',legacy-a80-timer=on')
        self.assertEqual(len(plan.claims), 2)

    def test_changed_guarded_code_and_missing_evidence_decline(self):
        loaded = bytearray(self.image)
        loaded[20] ^= 1
        self.assertFalse(self.plan(bytes(loaded)).capabilities)
        self.profile['evidence_spans'] = []
        self.assertFalse(self.plan().capabilities)

    def test_explicit_controller_owner_and_bad_source_parameters_decline(self):
        self.config.rex_irq_mask = 0x200
        self.assertFalse(self.plan().capabilities)
        self.config.rex_irq_mask = 0
        self.profile['parameters']['mask'] = 0x400
        self.assertFalse(self.plan().capabilities)

    def test_projection_rejects_changed_native_property(self):
        plan = self.plan()
        capability = replace(plan.capabilities[0], properties=(('legacy-a80-timer', False),))
        plan = replace(plan, capabilities=(capability,), properties=capability.properties)
        self.assertEqual(self.module.machine_properties(plan), '')


if __name__ == '__main__':
    unittest.main()
