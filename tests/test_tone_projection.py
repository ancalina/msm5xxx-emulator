"""Synthetic mapping bounds for a linked tone writer."""
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.registry import device_domain

qemu_tone_property = device_domain("audio.transport_projection").qemu_tone_property


class ToneProjectionTests(unittest.TestCase):
    def test_complete_source_must_fit_file_and_primary_nor(self):
        tone = {"static_status": "accepted", "grammar": "linked-divider-cfg-plus-ten-strb-v1",
                "writer_store_offsets": [0x100 + 2 * index for index in range(10)],
                "source_dependencies": [{"offset": 0x100, "size": 0x80},
                                        {"offset": 0x200, "size": 16}]}
        config = SimpleNamespace(tone_generator=tone, flash_size=0x1000)
        sites = ";".join(f"{site:x}" for site in tone["writer_store_offsets"])
        self.assertEqual(qemu_tone_property(bytes(0x300), config),
                         f"tone=on,tone-write-sites={sites}")
        self.assertIsNone(qemu_tone_property(bytes(0x208), config))
        config.flash_size = 0x208
        self.assertIsNone(qemu_tone_property(bytes(0x300), config))
        config.flash_size = 0x1000
        for span in ({"offset": -1, "size": 2}, {"offset": 0, "size": 0},
                     {"offset": True, "size": 4}, {}, None):
            with self.subTest(span=span):
                config.tone_generator = {**tone, "source_dependencies": [span]}
                self.assertIsNone(qemu_tone_property(bytes(0x300), config))
        for spans in (None, [], "source"):
            config.tone_generator = {**tone, "source_dependencies": spans}
            self.assertIsNone(qemu_tone_property(bytes(0x300), config))

    def test_linked_writer_sites_must_be_unique_even_and_inside_source(self):
        tone = {"static_status": "accepted",
                "grammar": "linked-divider-cfg-plus-ten-strb-v1",
                "writer_store_offsets": [0x100 + 2 * index for index in range(10)],
                "source_dependencies": [{"offset": 0x100, "size": 0x20}]}
        config = SimpleNamespace(tone_generator=tone, flash_size=0x400)
        prop = qemu_tone_property(bytes(0x400), config)
        self.assertEqual(prop, "tone=on,tone-write-sites="
                         + ";".join(f"{site:x}" for site in tone["writer_store_offsets"]))
        for sites in ([*tone["writer_store_offsets"][:-1], 0x11f],
                      [*tone["writer_store_offsets"][:-1], 0x200],
                      [*tone["writer_store_offsets"][:-1], tone["writer_store_offsets"][0]],
                      tone["writer_store_offsets"][:-1],
                      [*tone["writer_store_offsets"][:-1], True]):
            with self.subTest(sites=sites):
                config.tone_generator = {**tone, "writer_store_offsets": sites}
                self.assertIsNone(qemu_tone_property(bytes(0x400), config))

    def test_control_writer_serializes_twelve_store_sites(self):
        sites = [0x100 + 2 * index for index in range(12)]
        tone = {"static_status": "accepted",
                "grammar": "linked-divider-cfg-plus-control-strb-v1",
                "writer_store_offsets": sites,
                "source_dependencies": [{"offset": 0x100, "size": 0x20}]}
        config = SimpleNamespace(tone_generator=tone, flash_size=0x200)
        self.assertEqual(qemu_tone_property(bytes(0x120), config),
                         "tone=on,tone-write-sites="
                         + ";".join(f"{site:x}" for site in sites))

    def test_preserves_existing_tone_admission_and_rejection(self):
        config = SimpleNamespace(tone_generator={"static_status": "accepted",
                                 "grammar": "divider-table-plus-ten-strb-v1"})
        self.assertEqual(qemu_tone_property(b"", config), "tone=on")
        config.tone_generator["static_status"] = "rejected"
        self.assertIsNone(qemu_tone_property(b"", config))
        config.tone_generator = None
        self.assertIsNone(qemu_tone_property(b"", config))

    def test_control_pair_writer_requires_the_same_source_bounds(self):
        tone = {"static_status": "accepted",
                "grammar": "linked-divider-cfg-plus-control-strb-v1",
                "writer_store_offsets": [0x100 + 2 * index for index in range(12)],
                "source_dependencies": [{"offset": 0x100, "size": 0x20}]}
        config = SimpleNamespace(tone_generator=tone, flash_size=0x200)
        self.assertTrue(qemu_tone_property(bytes(0x120), config).startswith(
            "tone=on,tone-write-sites="))
        self.assertIsNone(qemu_tone_property(bytes(0x11f), config))
        config.flash_size = 0x11f
        self.assertIsNone(qemu_tone_property(bytes(0x200), config))
