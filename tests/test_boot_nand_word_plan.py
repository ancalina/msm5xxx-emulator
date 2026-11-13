"""Synthetic geometry, source guards, and independent NAND peripherals."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.registry import device_domain
from msm5xxx_emulator.detection.devices.storage.boot_nand_projection import project

module = device_domain('storage.boot_nand_word_plan')


class WordNandCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = bytes(0x08400000)

    def setUp(self):
        self.profile = {
            'selection_kind': 'fixed-row', 'main_size': 0x08000000,
            'identity_status': 0x76198000, 'stage_source': 0x4000,
            'stage_size': 0x10000, 'evidence': [{'span': [0x100, 4]}],
            'control_windows': [{'base': 0x48000000, 'length': 0x1000}],
            'control_evidence': [{'span': [0x200, 4]}],
        }
        self.config = SimpleNamespace(file_size=len(self.original))

    def plan(self, *, loaded=None, panel=None, bridge=None):
        with patch.object(module, 'find_indexed20', return_value=panel), \
             patch.object(module, 'find_bridge20', return_value=bridge):
            return module.machine_plan(self.original,
                self.original if loaded is None else loaded, self.config, self.profile)

    def test_controller_does_not_require_or_claim_optional_lcd_or_input(self):
        plan = self.plan()
        self.assertEqual(len(plan.capabilities), 1)
        properties = dict(plan.properties)
        self.assertEqual(properties['bootstrap-nand-word-peripherals'], 0)
        self.assertEqual(properties['bootstrap-nand-id-status'], 0x76198000)
        self.assertEqual(properties['bootstrap-nand-control-windows'], '48000000:1000')
        self.assertNotIn(0x20000000, {claim.start for claim in plan.claims})
        self.assertEqual(project(plan).main_size, 0x08000000)

    def test_control_evidence_and_loaded_bytes_are_required(self):
        changed = bytearray(self.original)
        changed[0x200] = 1
        self.assertFalse(self.plan(loaded=bytes(changed)).capabilities)
        self.profile['control_evidence'] = []
        self.assertFalse(self.plan().capabilities)

    def test_panel_is_independent_of_optional_bridge_identity(self):
        panel = {'command_port': 0x20000000, 'data_port': 0x20080000,
                 'evidence': [{'span': [0x300, 4]}]}
        plan = self.plan(panel=panel)
        properties = dict(plan.properties)
        self.assertEqual(properties['bootstrap-nand-word-peripherals'], 1)
        self.assertEqual(properties['bootstrap-nand-lcd-data-port'], 0x20080000)
        self.assertNotIn('bootstrap-nand-lcd-id', properties)
        self.assertIsNotNone(project(plan))

        bridge = {'controller_id': 0x7068, 'evidence': [{'span': [0x400, 4]}]}
        self.profile.update(input_address=0x48000050, input_value=31,
                            uart_evidence=[{'span': [0x500, 4]}])
        self.profile['evidence'].append({'span': [0x500, 4]})
        plan = self.plan(panel=panel, bridge=bridge)
        properties = dict(plan.properties)
        self.assertEqual(properties['bootstrap-nand-word-peripherals'], 7)
        self.assertEqual(properties['bootstrap-nand-lcd-id'], 0x7068)
        self.assertIn((0x20080000, 0x20080020),
                      {(claim.start, claim.end) for claim in plan.claims})
        self.assertIsNotNone(project(plan))

    def test_bridge_identity_is_optional_but_source_value_is_bounded(self):
        panel = {'command_port': 0x20000000, 'data_port': 0x20040000,
                 'evidence': [{'span': [0x300, 4]}]}
        for controller_id in (0, 0x4b15, 0x7069, True):
            bridge = {'controller_id': controller_id,
                      'evidence': [{'span': [0x400, 4]}]}
            self.assertFalse(self.plan(panel=panel, bridge=bridge).capabilities)
        self.assertFalse(self.plan(panel=panel,
            bridge={'evidence': [{'span': [0x400, 4]}]}).capabilities)
        self.assertFalse(self.plan(panel=panel,
            bridge={'controller_id': 0x7068, 'evidence': []}).capabilities)

    def test_duplicate_proven_pages_are_mapped_once(self):
        self.profile['control_windows'] *= 2
        plan = self.plan()
        self.assertEqual(dict(plan.properties)['bootstrap-nand-control-windows'],
                         '48000000:1000')

    def test_lcd_fifo_address_comes_from_source_profile(self):
        panel = {'command_port': 0x20000000, 'data_port': 0x20040000,
                 'evidence': [{'span': [0x300, 4]}]}
        bridge = {'controller_id': 0x7068,
                  'evidence': [{'span': [0x400, 4]}]}
        plan = self.plan(panel=panel, bridge=bridge)
        self.assertEqual(dict(plan.properties)['bootstrap-nand-lcd-data-port'], 0x20040000)
        self.assertEqual(dict(plan.properties)['bootstrap-nand-lcd-id'], 0x7068)
        self.assertIn((0x20040000, 0x20040020),
                      {(claim.start, claim.end) for claim in plan.claims})
        self.assertIn('bootstrap-nand-lcd-data-port=537133056', project(plan).machine)
        panel['data_port'] = 0x20060000
        self.assertFalse(self.plan(panel=panel, bridge=bridge).capabilities)

    def test_unsupported_windows_are_rejected(self):
        for windows in (
            [{'base': 0x48000001, 'length': 0x1000}],
            [{'base': 0x64000000, 'length': 0x2000}],
            [{'base': 0x48000000, 'length': 0x101000}],
        ):
            self.profile['control_windows'] = windows
            self.assertFalse(self.plan().capabilities)


if __name__ == '__main__':
    unittest.main()
