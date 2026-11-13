"""Synthetic planning and projection checks for source-linked upload memory."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, MachinePlan, ResourceClaim, resolve_proposals,
)
from msm5xxx_emulator.detection.registry import device_domain

from msm5xxx_emulator.detection.devices.storage.boot_nand_projection import word_claims

plan_module = device_domain('external_bus.signal_memory_plan')


def _profile(ranges=None):
    return {
        'version': 1,
        'ranges': ranges or [
            {'base': 0x50000000, 'length': 0x8000},
            {'base': 0x52000000, 'length': 0x1000},
        ],
        'units': [2, 4],
        'evidence': [
            {'span': [0x20, 8], 'extra_spans': [[0x30, 4]]},
            {'span': [0x80, 16], 'extra_spans': [[0xA0, 4]]},
        ],
    }


def _reset_profile():
    return {'sites': [
        {'kind': 'literal-access', 'operation': 'write',
         'address': 0x0A0000A0, 'span': [0xC0, 8],
         'extra_spans': [[0xC8, 4]]},
        {'kind': 'literal-access', 'operation': 'write',
         'address': 0x0A0000B0, 'span': [0xD0, 8],
         'extra_spans': [[0xD8, 4]]},
    ]}


def _bootstrap_plan(claims=None):
    claims = claims or (
        ResourceClaim('address', 'high-linked-nand-bootstrap',
                      0x50000000, 0x50004000),
        ResourceClaim('address', 'high-linked-nand-bootstrap',
                      0x50200000, 0x50204000),
        ResourceClaim('address', 'high-linked-nand-bootstrap',
                      0x50400000, 0x50404000),
        ResourceClaim('address', 'high-linked-nand-bootstrap',
                      0x58000000, 0x58001000),
    )
    evidence = Evidence('high-linked-nand-bootstrap', (64,), (0x10,), 'linkage')
    capability = Capability('high-linked-nand-bootstrap',
        ('high-linked-nand-bootstrap',), (evidence,),
        properties=(('bootstrap-nand-main-size', 0x04000000),
                    ('bootstrap-nand-word-interface', 1),
                    ('bootstrap-nand-id-status', 0x4c3b0000),
                    ('bootstrap-nand-word-peripherals', 7),
                    ('bootstrap-nand-lcd-data-port', 0x20080000),
                    ('bootstrap-nand-control-windows', ':'.join(f'{v:x}' for claim in claims for v in (claim.start,claim.end-claim.start)))),
        claims=word_claims(tuple((claim.start, claim.end) for claim in claims), 7, 0x20080000),
        parameters=(('cpu', 'arm926,reset-hivecs=on'),
                    ('raw_size', 0x04200000), ('main_size', 0x04000000),
                    ('high_code_size', 0x2000), ('word_interface', True),
                    ('identity_status', 0x4c3b0000), ('peripherals', 7),
                    ('lcd_data_port', 0x20080000),
                    ('lcd_identity', 0),
                    ('control_windows', tuple((claim.start, claim.end) for claim in claims))))
    return resolve_proposals((Decision('accepted', capability=capability),)).plan


class SignalMemoryPlanTests(unittest.TestCase):
    def setUp(self):
        self.original = bytes(0x200)
        self.loaded = self.original
        self.config = SimpleNamespace(image_kind='firmware', load_address=0,
            image_offset=0, entry=0, ram_base=0x14000000,
            ram_size=0x00800000, flash_size=len(self.original))

    def make_plan(self, *, original=None, loaded=None, config=None,
                  bootstrap_plan=None, reset=True, profile=None):
        reset_result = (_reset_profile(), 'accepted') if reset else (None, 'absent')
        with patch.object(plan_module, 'detect_external_cs0a', return_value=reset_result), \
             patch.object(plan_module, 'find_signal_memory',
                          return_value=_profile() if profile is None else profile):
            return plan_module.machine_plan(
                self.original if original is None else original,
                self.loaded if loaded is None else loaded,
                self.config if config is None else config,
                bootstrap_plan=bootstrap_plan)

    def test_ordinary_requires_reset_chip_select_and_guards_payload_bytes(self):
        plan = self.make_plan()
        self.assertEqual(plan.properties[0][0], 'signal-memory')
        self.assertIn('50000000:8000', plan_module.project(plan))
        self.assertEqual(len(plan.claims), 2)

        changed = bytearray(self.loaded)
        changed[0xA0] ^= 1
        self.assertFalse(self.make_plan(loaded=bytes(changed)).capabilities)
        self.assertFalse(self.make_plan(reset=False).capabilities)

    def test_word_bootstrap_claims_are_subtracted_from_upload_pages(self):
        word = _bootstrap_plan()
        config = SimpleNamespace(image_kind='firmware', load_address=0,
            image_offset=0, entry=0, ram_base=0x01000000,
            ram_size=0x00800000, flash_size=0x01000000)
        profile = _profile([
            {'base': 0x50000000, 'length': 0x8000},
            {'base': 0x50200000, 'length': 0x4000},
            {'base': 0x50400000, 'length': 0x4000},
            {'base': 0x58000000, 'length': 0x3000},
            {'base': 0x52000000, 'length': 0x1000},
        ])
        plan = self.make_plan(bootstrap_plan=word, reset=False, profile=profile,
                              config=config)
        self.assertEqual(dict(plan.capabilities[0].parameters)['ranges'], (
            (0x50004000, 0x50008000), (0x52000000, 0x52001000),
            (0x58001000, 0x58003000)))
        self.assertEqual(plan_module.project(plan),
            'signal-memory=50004000:4000:52000000:1000:58001000:2000')

    def test_rejects_unsupported_config_and_malformed_source_ranges(self):
        for changes in ({'load_address': 4}, {'ram_base': 0x02000000},
                        {'ram_base': 0x01000000},
                        {'ram_size': 0x0f000000}):
            config = SimpleNamespace(**vars(self.config))
            for key, value in changes.items():
                setattr(config, key, value)
            self.assertFalse(self.make_plan(config=config).capabilities)
        for bad in (
            [{'base': 0x50000001, 'length': 0x1000}],
            [{'base': 0x50000000, 'length': 0x101000}],
            [{'base': 0x50000000, 'length': 0x2000},
             {'base': 0x50001000, 'length': 0x1000}],
        ):
            self.assertFalse(self.make_plan(profile=_profile(bad)).capabilities)

    def test_word_bootstrap_subtraction_fails_closed_when_all_ranges_are_claimed(self):
        profile = _profile([{'base': 0x50000000, 'length': 0x4000}])
        plan = self.make_plan(bootstrap_plan=_bootstrap_plan(), reset=False,
                              profile=profile)
        self.assertFalse(plan.capabilities)

    def test_projection_rejects_tampered_unaligned_parameters(self):
        plan = self.make_plan()
        capability = plan.capabilities[0]
        evidence = capability.evidence
        invalid = Capability(capability.name, capability.required_evidence,
            evidence, properties=(('signal-memory', '50000001:1000'),),
            claims=(ResourceClaim('address', 'source-signal-memory',
                                  0x50000001, 0x50001001),),
            parameters=(('ranges', ((0x50000001, 0x50001001),)),
                        ('source_kind', 'reset-chip-select-initializer')))
        invalid_plan = resolve_proposals((Decision('accepted', capability=invalid),)).plan
        with self.assertRaises(ValueError):
            plan_module.project(invalid_plan)


if __name__ == '__main__':
    unittest.main()
