"""Synthetic contract checks for the EEPROM GPIO capability projection."""
import struct
import unittest

from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, ResourceClaim, build_machine_plan,
)
from msm5xxx_emulator.detection.devices.eeprom.projection import (
    _capability_for_eeprom_profile,
    _eeprom_evidence,
)


def evidence():
    return (
        Evidence("eeprom-gpio-driver", (0x100, 0x200), (0x100, 0x200)),
        Evidence("eeprom-gpio-pins", (0x03000720, 0, 0x20, 0, 0x40, 0xC),
                 (0x300, 0x302), "literal"),
        Evidence("eeprom-gpio-capacity", (0x8000, 0x01004000),
                 (0x400, 0x402), "linkage"),
    )


class EEPROMGPIOPlanTests(unittest.TestCase):
    def test_profile_projects_property_claim_and_captured_parameters(self):
        profile = (0x03000720, 0, 0x20, 0, 0x40, 0xC, 0x8000)
        decision = _capability_for_eeprom_profile(profile, evidence())
        self.assertEqual(decision.status, "accepted")
        capability = decision.capability
        self.assertEqual(capability.properties,
                         (("eeprom-24lcxx-gpio", "3000720:0:20:0:40:c:8000"),))
        self.assertEqual(capability.parameters, (("eeprom-gpio-profile", profile),))
        self.assertEqual(capability.claims, (
            ResourceClaim("address", "eeprom-gpio-backing",
                          0x03000720, 0x03000740),))
        self.assertEqual(build_machine_plan((decision,)).status, "accepted")

    def test_literal_sources_locate_pin_and_capacity_evidence(self):
        # Four ordinary Thumb literal loads point at the synthetic ports and
        # geometry object. These are complete, supplied source instructions.
        image = bytearray(28)
        struct.pack_into("<6H", image, 0, 0x4802, 0x4903, 0x4A03,
                         0x4B04, 0x4770, 0x46C0)
        struct.pack_into("<4I", image, 12, 0x03000720, 0x03000720,
                         0x0300072C, 0x01004000)
        config = type("Config", (), {
            "load_address": 0, "eeprom_read_address": 0,
            "eeprom_write_address": 2,
            "eeprom_geometry_address": 0x01004000,
        })()
        profile = (0x03000720, 0, 0x20, 0, 0x40, 0xC, 0x8000)
        located = _eeprom_evidence(bytes(image), config, profile)
        self.assertTrue(all(item.locations for item in located))
        self.assertIn(0, located[1].locations)
        self.assertIn(6, located[2].locations)
        self.assertEqual(_capability_for_eeprom_profile(profile, located).status,
                         "accepted")

    def test_native_aperture_rejects_offsets_outside_twenty_bytes(self):
        profile = (0x03000720, 0x20, 1, 0, 2, 4, 0x8000)
        decision = _capability_for_eeprom_profile(profile, evidence())
        self.assertEqual(decision.status, "missing")
        self.assertEqual(decision.reason, "gpio-profile-outside-native-aperture")

    def test_backing_aperture_conflicts_with_another_device_owner(self):
        profile = (0x03000720, 0, 0x20, 0, 0x40, 0xC, 0x8000)
        eeprom = _capability_for_eeprom_profile(profile, evidence()).capability
        other = Capability(
            "window-owner", ("window-code",),
            (Evidence("window-code", "source", (0x500,)),),
            claims=(ResourceClaim("address", "window-owner",
                                  0x0300072C, 0x03000730),))
        combined = build_machine_plan((Decision("accepted", capability=eeprom),
                                       Decision("accepted", capability=other)))
        self.assertEqual(combined.status, "conflict")


if __name__ == "__main__":
    unittest.main()
