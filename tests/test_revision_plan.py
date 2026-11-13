"""Synthetic source-binding checks for cached revision machine planning."""
from __future__ import annotations

import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.registry import device_domain

revision_plan = device_domain('boot.revision_plan')


def _revision_profile():
    return {
        'register': 0x0300075c,
        'raw_value': 0x20f5,
        'revision': 0xf025,
        'threshold': 0xf051,
        'evidence': [
            {'span': [0x10, 4], 'extra_spans': [[0x20, 4]]},
            {'span': [0x30, 4]},
        ],
    }


def _cs0a_profile():
    return {'sites': [
        {'kind': 'literal-access', 'operation': 'write', 'address': 0x0a0000a0,
         'span': [0x40, 4], 'extra_spans': [[0x44, 4], [0x48, 8]]},
        {'kind': 'literal-access', 'operation': 'write', 'address': 0x0a0000b0,
         'span': [0x50, 4], 'extra_spans': [[0x54, 4], [0x58, 8]]},
    ]}


def _config(**changes):
    values = dict(image_kind='firmware', load_address=0, image_offset=0,
        entry=0, file_size=0x100, board_revision_register=None,
        board_revision_value=None, missing_overlays=[], ram_bootstrap_profile=None,
        native_nand_profile=None, nand_image=None, secondary_flash_image=None,
        secondary_flash_address=None, upper_flash_image=None, upper_flash_address=None)
    values.update(changes)
    return SimpleNamespace(**values)


class CachedRevisionPlanTests(unittest.TestCase):
    def setUp(self):
        self.original = bytes(range(0x100))
        self.loaded = self.original
        self.config = _config()

    def plan(self, *, original=None, loaded=None, config=None, cs0a=None):
        with patch.object(revision_plan, 'find_cached_revision',
                          return_value=_revision_profile()), \
             patch.object(revision_plan, 'detect_external_cs0a',
                          return_value=(_cs0a_profile() if cs0a is None else cs0a,
                                        'accepted')):
            return revision_plan.machine_plan(
                self.original if original is None else original,
                self.loaded if loaded is None else loaded,
                self.config if config is None else config)

    def test_plan_claims_readonly_register_and_projects_revision(self):
        plan = self.plan()
        self.assertEqual(dict(plan.properties), {'board-revision': '300075c:20f5'})
        self.assertEqual(len(plan.claims), 1)
        claim = plan.claims[0]
        self.assertEqual((claim.start, claim.end), (0x0300075c, 0x0300075e))
        self.assertEqual(claim.semantics, 'read-only')
        self.assertEqual(revision_plan.project(plan), 'board-revision=300075c:20f5')

    def test_existing_ownership_and_nonordinary_loads_are_declined(self):
        for config in (_config(board_revision_register=0x0300075c),
                       _config(board_revision_value=0x20f5),
                       _config(load_address=0x1000),
                       _config(image_offset=0x200)):
            with self.subTest(config=config):
                self.assertFalse(self.plan(config=config).capabilities)

    def test_both_revision_and_reset_bus_source_guards_bind_loaded_bytes(self):
        for offset in (0x10, 0x20, 0x30, 0x40, 0x44, 0x50, 0x54):
            loaded = bytearray(self.loaded)
            loaded[offset] ^= 0xff
            with self.subTest(offset=offset):
                self.assertFalse(self.plan(loaded=bytes(loaded)).capabilities)

    def test_cs0a_requires_both_reset_linked_windows(self):
        for sites in (
            [],
            [_cs0a_profile()['sites'][0]],
            [{**_cs0a_profile()['sites'][0], 'kind': 'unlinked-store'},
             _cs0a_profile()['sites'][1]],
        ):
            with self.subTest(sites=sites):
                self.assertFalse(self.plan(cs0a={'sites': sites}).capabilities)

    def test_project_declines_an_empty_plan(self):
        self.assertIsNone(revision_plan.project(self.plan(loaded=bytes(0x100))))

    def test_project_rejects_tampered_capability_parameters(self):
        plan = self.plan()
        capability = replace(plan.capabilities[0],
            parameters=(('register', 0x0300075c), ('raw_value', 0x20f4),
                        ('revision', 0xf025), ('readonly', True)))
        forged = replace(plan, capabilities=(capability,))
        with self.assertRaises(ValueError):
            revision_plan.project(forged)


if __name__ == '__main__':
    unittest.main()
