"""NV profile selection must preserve existing and ambiguous ownership."""
from types import SimpleNamespace
import unittest
from unittest import mock

from msm5xxx_emulator.qemu import transport


class NVNORTransportTests(unittest.TestCase):
    def test_unique_source_profile_and_owner_conflicts(self):
        config = SimpleNamespace(load_address=0, flash_size=0x400000,
                                 ram_base=0x1000000, ram_size=0x800000)
        profile = (0x400000, 0x200000, 4, 0x5F)
        with mock.patch.object(transport, "find_word_offset_nv_nor", return_value=None), \
             mock.patch.object(transport, "find_byte_offset_nv_nor", return_value=profile), \
             mock.patch.object(transport, "find_embedded_fujitsu_x16_nor", return_value=None):
            self.assertEqual(transport.qemu_legacy_nv_nor_profile(b"", config),
                             ("byte-offset-boot-sectors", profile))
            self.assertIsNone(transport.qemu_legacy_nv_nor_profile(b"", config, claimed=True))
            for field, value in [("nand_image", "owned"), ("secondary_flash_address", 0),
                                 ("upper_flash_address", 0), ("flash_id_address", 0),
                                 ("primary_flash_probe_address", 0)]:
                with self.subTest(field=field):
                    changed = SimpleNamespace(**vars(config), **{field: value})
                    self.assertIsNone(transport.qemu_legacy_nv_nor_profile(b"", changed))
            with mock.patch.object(transport, "find_word_offset_nv_nor", return_value=profile):
                self.assertIsNone(transport.qemu_legacy_nv_nor_profile(b"", config))
            with mock.patch.object(transport, "find_embedded_fujitsu_x16_nor", return_value=profile):
                self.assertIsNone(transport.qemu_legacy_nv_nor_profile(b"", config))


if __name__ == "__main__":
    unittest.main()
