"""Synthetic device composition and source coverage for watchdog planning."""
import unittest

from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, ResourceClaim, build_machine_plan,
)
from msm5xxx_emulator.detection.facts import bind_facts, fact_scope
from msm5xxx_emulator.detection.image_view import ImageView
from msm5xxx_emulator.detection.devices.ready_poll import ready_poll_plan
from msm5xxx_emulator.detection.watchdog import find_watchdog_profile, watchdog_plan
from test_ready_plan import config, poll_image
from test_watchdog import fixture


class WatchdogPlanTests(unittest.TestCase):
    def devices(self):
        image, service, _ = fixture()
        poll = poll_image(entry=0x1200, pulse=0x03000700)
        image[:4] = poll[:4]
        image[0x1200:len(poll)] = poll[0x1200:]
        image = bytes(image)
        profile, reason = find_watchdog_profile(image)
        self.assertIsNotNone(profile, reason)
        return image, service, watchdog_plan(profile, image)

    def test_native_forwarding_allows_ready_and_watchdog_on_one_byte(self):
        image, _, watchdog = self.devices()
        ready = ready_poll_plan(image, config(image))
        self.assertEqual(len(ready.plan.capabilities), 1)
        combined = build_machine_plan(
            Decision('accepted', capability=item)
            for item in watchdog.plan.capabilities + ready.plan.capabilities)
        self.assertEqual(combined.status, 'accepted')
        self.assertEqual(len(combined.plan.capabilities), 2)

    def test_byte_backend_cannot_share_unforwarded_gpio_bits(self):
        _, _, watchdog = self.devices()
        other = Capability('other-input', ('pin-read',),
                           (Evidence('pin-read', 0x80, (0x1400,)),),
                           claims=(ResourceClaim('gpio', 'input', 0x03000700,
                                                 0x03000701, mask=0x80),))
        combined = build_machine_plan((
            Decision('accepted', capability=watchdog.plan.capabilities[0]),
            Decision('accepted', capability=other),
        ))
        self.assertEqual(combined.status, 'conflict')

    def test_prefix_revalidation_retains_missing_source_coverage(self):
        image, service, _ = fixture()
        profile, _ = find_watchdog_profile(bytes(image))
        extended = bytes(image) + bytes(0x100)
        hole = service + 0x20
        view = ImageView.sparse(((0, extended[:hole]),
                                 (hole + 2, extended[hole + 2:])))
        with fact_scope():
            bind_facts(extended, view)
            resolution = watchdog_plan(profile, extended)
        self.assertEqual(resolution.plan.capabilities, ())
        self.assertIn('source not admitted', resolution.decisions[0].reason)
