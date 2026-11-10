"""Source-bound external device composition over synthetic instruction images."""
import unittest

from msm5xxx_emulator.detection.registry import device_domain
detect_external_bus = device_domain('external_bus.rules').detect_external_bus
from msm5xxx_emulator.detection.registry import device_domain
external_bus_plan = device_domain('external_bus.projection').external_bus_plan
external_bus_property = device_domain('external_bus.projection').external_bus_property
from msm5xxx_emulator.detection.facts import bind_facts, fact_scope
from msm5xxx_emulator.detection.image_view import ImageView
from test_external_bus_transport import chip_select_only_image
from test_external_devices import _external_status_image, ldr_literal, put16, put32
from test_gpio_pmic import _synthetic_image


class ExternalMachinePlanTests(unittest.TestCase):
    def test_chip_select_claim_and_public_property_match_the_static_driver(self):
        image = chip_select_only_image()
        profile, _ = detect_external_bus(image)
        resolution, reason = external_bus_plan(profile, image, None, None)
        self.assertIsNone(reason)
        self.assertEqual(resolution.plan.properties, (("external-cs0a", True),))
        claim, = resolution.plan.claims
        self.assertEqual((claim.start, claim.end), (0x0A000000, 0x0A001000))
        self.assertEqual(external_bus_property(profile, image, None, None),
                         ("external-cs0a=on", None))

    def test_conflicting_gpio_routes_do_not_revoke_an_independent_window(self):
        original, _, _ = _synthetic_image()
        image = bytearray(original)
        controller = chip_select_only_image()
        image[0x20:0x32] = controller[0x20:0x32]
        image[0x100:0x104] = controller[0x100:0x104]
        put16(image, 0x120, ldr_literal(1, 0x120, 0x160),
              0x6848, 0x6800, 10 << 6, 0xD400, 0xE7FE)
        put32(image, 0x160, 0x180)
        put32(image, 0x180, 0, 0x03000720)
        image = bytes(image)
        profile, _ = detect_external_bus(image)
        self.assertFalse(profile["machine_properties"]["gpio-ready-bit21"])
        self.assertFalse(profile["machine_properties"]["experimental-contract-gpio-pmic-serial"])
        resolution, reason = external_bus_plan(profile, image, None, None)
        self.assertIsNone(reason)
        self.assertEqual(resolution.plan.properties, (("external-cs0a", True),))
        self.assertEqual(set(profile["rejections"]),
                         {"external_ram", "gpio_pmic_serial", "gpio_ready_bit21"})
        self.assertTrue(all(guard["role"].startswith("external_cs0a")
                            for guard in profile["source_guards"]))

    def test_explicit_native_status_overlay_can_share_its_ram_window(self):
        image = _external_status_image()
        # Independent window store alongside the reset-linked status reader.
        put16(image, 0x180, ldr_literal(0, 0x180, 0x1C0), 0x6001)
        put32(image, 0x1C0, 0x0B000410)
        image = bytes(image)
        profile, _ = detect_external_bus(image)
        resolution, reason = external_bus_plan(profile, image, None, None)
        self.assertIsNone(reason)
        self.assertEqual(len(resolution.plan.claims), 2)
        self.assertEqual({claim.shared_resource for claim in resolution.plan.claims},
                         {"window-status-0b"})

    def test_absent_literal_bytes_cannot_validate_a_dense_compatibility_plan(self):
        image = chip_select_only_image()
        profile, _ = detect_external_bus(image)
        sparse = ImageView.sparse(((0, image[:0x100]), (0x104, image[0x104:])))
        with fact_scope():
            bind_facts(image, sparse)
            self.assertEqual(external_bus_property(profile, image, None, None),
                             (None, "source-guard-not-supplied"))
