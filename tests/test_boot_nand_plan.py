"""Isolated synthetic query and machine-plan checks for the NAND bootstrap."""
from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.registry import device_domain

indexed28_writer = device_domain('display.indexed28_writer')
boot_nand = device_domain('storage.boot_nand')
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.values import CodeAddress
from boot_nand_synthetic import constant_image, plan_image, put32
from test_boot_presence import _image as presence_image


class BootNandSyntheticQueryTests(unittest.TestCase):
    def test_uart_poll_requires_reset_linked_aliases_and_ready_bit(self):
        from msm5xxx_emulator.detection.fact_models import ReachabilityFacts
        from msm5xxx_emulator.detection.fact_context import FirmwareFacts
        from test_external_devices import put16

        target = CodeAddress(0x20, 'thumb')
        root = CodeAddress(0x80, 'thumb')

        def image_with(shift=28, alternate_subtract=0x80):
            image = bytearray(0x60)
            words = (0x4b0b, 0x2001, 0x7008, 0x791c, (shift << 6) | 0x24,
                     0xd5fb, 0x2800, 0xd100, 0xbd10, 0x3b00 | alternate_subtract,
                     0x7008, 0x791c, (shift << 6) | 0x24, 0xd5fb, 0xbd10)
            for offset, word in enumerate(words):
                put16(image, 0x20 + offset * 2, word)
            put32(image, 0x50, 0x80000f10)
            return bytes(image)

        def check(image, linked=True):
            facts = facts_for(image)
            body = facts.function(target, budget=256)
            caller = SimpleNamespace(calls=((CodeAddress(0x82, 'thumb'), target),))
            references = ReachabilityFacts((), (target,) if linked else (),
                (root, target), True)
            with patch.object(FirmwareFacts, 'reset_references', return_value=references), \
                 patch.object(FirmwareFacts, 'function', side_effect=lambda entry, **kw:
                    body if entry == target else caller):
                return boot_nand._uart_tx_poll(facts, len(image))

        self.assertIsNotNone(check(image_with()))
        self.assertIsNone(check(image_with(shift=27)))
        self.assertIsNone(check(image_with(alternate_subtract=0x70)))
        self.assertIsNone(check(image_with(), linked=False))

    def test_constant_result_requires_one_constant_return(self):
        image = constant_image(42)
        result = boot_nand._constant_result(facts_for(image), CodeAddress(0, 'arm'))
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 42)

        nonconstant = bytearray(constant_image(42))
        put32(nonconstant, 0, 0xE1A00001)  # MOV r0, r1
        self.assertIsNone(boot_nand._constant_result(
            facts_for(bytes(nonconstant)), CodeAddress(0, 'arm')))

    def test_released_input_follows_real_reset_link_and_exact_test(self):
        def stage_for(**changes):
            stage = bytearray(presence_image(read_width='byte',
                status_base=0x58000070, status_add=0, setup_width='word', **changes))
            put32(stage, 0x300, 0x58000010)
            return bytes(stage)

        stage = stage_for()
        found = boot_nand._released_input(stage, facts_for(stage))
        self.assertIsNotNone(found)
        self.assertIn([0, 4], found[2])
        self.assertIn([0x20, 20], found[2])

        mutations = (
            ('shift', stage_for(shift=26)),
            ('mask', stage_for(mask=0x0f)),
            ('absent result', stage_for(absent=1)),
            ('setup store nop', stage_for()),
            ('reset linkage', stage_for(reset_link=False)),
        )
        setup_nop = bytearray(mutations[3][1])
        # The word STR that initializes the controller must dominate the input read.
        setup_nop[0x106:0x108] = b'\x00\x00'
        mutations = (*mutations[:3], ('setup store nop', bytes(setup_nop)), *mutations[4:])
        for name, mutated in mutations:
            with self.subTest(mutation=name):
                self.assertIsNone(boot_nand._released_input(mutated, facts_for(mutated)))

    def test_high_address_completion_branch_and_bitfield_are_normalized(self):
        from msm5xxx_emulator.detection.fact_context import FirmwareFacts
        from test_external_devices import ldr_literal, put16
        for shift, compare, branch, accepted in ((30, 3, 0xd000, True),
                (29, 3, 0xd000, False), (30, 1, 0xd000, False),
                (30, 3, 0xd100, False)):
            image = bytearray(0x40)
            put16(image, 0, ldr_literal(1, 0, 0x20), 0x6808,
                  17 << 6, 0x0800 | shift << 6, 0x2800 | compare,
                  branch, 0xe7f9, 0x4770)
            put32(image, 0x20, 0x80000c84)
            facts = FirmwareFacts(bytes(image), base=0xffff0000)
            function = facts.function(CodeAddress(0xffff0000), budget=64)
            self.assertEqual(boot_nand._two_bit_completion(facts, function), accepted)

    def test_indexed28_rejects_unlinked_stage_even_with_bootstrap_metadata(self):
        image = bytearray(0x14000)
        bootstrap = {'stage_source': 0x10000, 'stage_size': 0x4000,
                     'evidence': [{'span': [0x100, 4]}]}
        self.assertIsNone(indexed28_writer.find_indexed28(bytes(image), bootstrap))


class BootNandMachinePlanTests(unittest.TestCase):
    def setUp(self):
        self.original = plan_image()
        self.loaded = self.original
        self.profile = {
            'blocks': 1,
            'stage_source': 0x4000,
            'stage_size': 0x1000,
            'high_code_size': 0x2000,
            'evidence': [{'span': [0x100, 8], 'extra_spans': [[0x108, 4]]}],
        }
        self.panel = {
            'width': 240,
            'height': 320,
            'evidence': [{'span': [0x200, 4]}],
        }
        self.config = SimpleNamespace(image_kind='firmware', load_address=0,
            image_offset=0, entry=0, ram_base=0x01000000, missing_overlays=[],
            file_size=len(self.original), ram_size=0x01000000, flash_size=0x01000000)

    def plan(self, original=None, loaded=None, config=None):
        with patch.object(boot_nand, 'find_boot_nand', return_value=self.profile), \
             patch.object(boot_nand, 'find_indexed28', return_value=self.panel):
            return boot_nand.machine_plan(
                self.original if original is None else original,
                self.loaded if loaded is None else loaded,
                self.config if config is None else config)

    def test_synthetic_evidence_closes_into_nand_and_panel_claims(self):
        plan = self.plan()
        self.assertEqual(len(plan.capabilities), 1)
        capability = plan.capabilities[0]
        self.assertIn(('bootstrap-nand-main-size', 16384), capability.properties)
        self.assertEqual(dict(capability.parameters)['cpu'], 'arm926,reset-hivecs=on')
        self.assertEqual(dict(capability.parameters)['main_size'], 16384)
        self.assertEqual(dict(capability.parameters)['raw_size'], len(self.original))
        self.assertIn((0, 0x02000000),
                      {(claim.start, claim.end) for claim in capability.claims})

    def test_labels_do_not_select_and_loaded_code_guard_rejects_changes(self):
        self.profile['evidence'][0]['label'] = 'changed-label'
        self.panel['evidence'][0]['label'] = 'another-label'
        self.assertEqual(len(self.plan().capabilities), 1)

        changed = bytearray(self.loaded)
        changed[0x100] ^= 1
        self.assertFalse(self.plan(loaded=bytes(changed)).capabilities)

    def test_unsupported_layouts_are_not_admitted(self):
        for config in (
            SimpleNamespace(**{**vars(self.config), 'ram_base': 0x02000000}),
            SimpleNamespace(**{**vars(self.config), 'missing_overlays': ['x']}),
            SimpleNamespace(**{**vars(self.config), 'file_size': len(self.original) - 1}),
        ):
            with self.subTest(config=config):
                self.assertFalse(self.plan(config=config).capabilities)


if __name__ == '__main__':
    unittest.main()
