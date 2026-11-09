"""NV profile selection must preserve existing and ambiguous ownership."""
from types import SimpleNamespace
import unittest
from unittest import mock

from msm5xxx_emulator.qemu import transport
from msm5xxx_emulator.detection.capabilities import Capability, Evidence


class NVNORTransportTests(unittest.TestCase):
    def test_unique_source_profile_and_owner_conflicts(self):
        config = SimpleNamespace(load_address=0, flash_size=0x400000,
                                 ram_base=0x1000000, ram_size=0x800000)
        profile = (0x400000, 0x200000, 4, 0x5F)
        capability = Capability(
            "legacy-nv-nor:byte-offset-boot-sectors",
            ("profile",), (Evidence("profile", profile, (0x100,), "data"),),
            parameters=(("legacy-kind", "byte-offset-boot-sectors"),
                        ("legacy-profile", profile)))
        with mock.patch.object(transport, "select_legacy_nv_nor",
                               return_value=capability):
            self.assertEqual(transport.qemu_legacy_nv_nor_profile(b"", config),
                             ("byte-offset-boot-sectors", profile))
        self.assertIsNone(transport.qemu_legacy_nv_nor_profile(
            b"", config, claimed=True))
        for field, value in [("nand_image", "owned"), ("secondary_flash_address", 0),
                             ("upper_flash_address", 0), ("flash_id_address", 0),
                             ("primary_flash_probe_address", 0)]:
            with self.subTest(field=field):
                changed = SimpleNamespace(**vars(config), **{field: value})
                self.assertIsNone(transport.qemu_legacy_nv_nor_profile(b"", changed))
        self.assertIsNone(transport.qemu_legacy_nv_nor_profile(b"", config))


if __name__ == "__main__":
    unittest.main()
