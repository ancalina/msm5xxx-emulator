"""Loaded-source guards and native/display ownership for an indexed panel."""
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from msm5xxx_emulator.detection.capabilities import resolve_proposals, Decision
from msm5xxx_emulator.detection.registry import device_domain
from msm5xxx_emulator.devices.display.indexed44 import Indexed44
from msm5xxx_emulator.devices.display.source_plan import apply_source_plan

writers = device_domain('display.source_writers')


def _config(**changes):
    values = dict(image_kind='firmware', load_address=0, image_offset=0,
        entry=0, missing_overlays=[], ram_bootstrap_profile=None,
        ram_base=0x14000000, ram_size=0x800000, width=176, height=220,
        display_geometry_source='auto-default')
    values.update(changes)
    return SimpleNamespace(**values)


def _profile(**changes):
    values = dict(protocol='indexed44-rgb565', width=132, height=176,
        x_origin=0, y_origin=64, command_port=0x18000000, data_port=0x18000010,
        evidence=[{'span': [16, 8], 'extra_spans': [[32, 4]]}])
    values.update(changes)
    return values


class Indexed44PlanTests(unittest.TestCase):
    def plan(self, *, loaded=None, profile=None, config=None):
        image = bytes(0x10000)
        with patch.object(writers, 'find_indexed44', return_value=profile or _profile()):
            return writers.machine_plan(image, image if loaded is None else loaded,
                                        config or _config())

    def test_plan_instantiates_origin_and_projects_only_native_bus_parameters(self):
        plan = self.plan()
        self.assertEqual(writers.machine_properties(plan),
            ',external-lcd-18=on,external-lcd-18-register-offset=16')
        decoder = SimpleNamespace()
        apply_source_plan(decoder, plan)
        panel = decoder._lcd_b0_source_page
        self.assertIsInstance(panel, Indexed44)
        self.assertEqual((panel.width, panel.height, panel.x_origin, panel.y_origin),
                         (132, 176, 0, 64))
        self.assertEqual([(claim.start, claim.end) for claim in plan.claims],
                         [(0x18000000, 0x18000002), (0x18000010, 0x18000012)])

    def test_code_and_literal_guards_reject_changed_loaded_bytes(self):
        for offset in (16, 32):
            loaded = bytearray(0x10000)
            loaded[offset] = 1
            self.assertFalse(self.plan(loaded=bytes(loaded)).capabilities)

    def test_topology_ports_source_evidence_and_explicit_geometry_are_guarded(self):
        for profile in (_profile(evidence=[]),
                        _profile(data_port=0x18000012)):
            self.assertFalse(self.plan(profile=profile).capabilities)
        self.assertFalse(self.plan(config=_config(ram_base=0x01000000)).capabilities)
        self.assertFalse(self.plan(config=_config(width=128, height=160,
            display_geometry_source='external-config')).capabilities)

    def test_projection_rejects_tampered_aperture_claims(self):
        capability = replace(self.plan().capabilities[0], claims=())
        plan = resolve_proposals((Decision('accepted', capability=capability),)).plan
        with self.assertRaises(ValueError):
            writers.machine_properties(plan)
