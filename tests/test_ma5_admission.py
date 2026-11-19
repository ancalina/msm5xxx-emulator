"""Synthetic source-profile projection and shared-aperture admission."""
import copy
from types import SimpleNamespace
import unittest
from unittest import mock

from msm5xxx_emulator.detection.registry import device_domain


PROJECTION = device_domain("audio.transport_projection")


def _profile(source_class="ram-counter-synthesized-data-v1", stride=2):
    return {"family": "ma5", "grammar": "ma5-readback-v1",
        "static_status": "candidate", "protocol_status": "temporary-evidence-gated",
        "base": 0x02c00000, "data_offset": stride,
        "structural_evidence": {"transport_class": source_class},
        "nor_dependencies": [[0x100, 0x40]], "ram_dependencies": [[0x01000100, 8]],
        "sites": {"write_0": [0x100], "read_0": [0x110],
            f"write_{stride}": [0x120, 0x130], f"read_{stride}": [0x138]}}


class Ma5AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.config = SimpleNamespace(load_address=0, flash_size=0x1000000,
            ram_base=0x01000000, ram_size=0x800000, audio_transport=None)
        self.image = bytes(0x200)

    def select(self, profile, **options):
        with mock.patch.object(PROJECTION, "find_ma5_readback_candidate", return_value=copy.deepcopy(profile)):
            return PROJECTION.qemu_ma5_temporary_auto_property(self.image, self.config,
                audio_pcm=options.pop("audio_pcm", True), **options)

    def test_all_closed_producer_classes_use_owned_shared_apertures(self):
        classes = (("ram-counter-synthesized-data-v1", 2),
            ("local-counter-literal-data-v1", 128),
            ("local-counter-direction-timing-v1", 4),
            ("alternate-reset-readback-v1", 2),
            ("alternate-direct-reset-readback-v1", 2))
        for source_class, stride in classes:
            with self.subTest(source_class=source_class):
                value, reason = self.select(_profile(source_class, stride))
                self.assertIsNone(reason)
                self.assertIn(f"audio-aperture=2c00000:{stride:x}:ma5", value)
                self.assertIn("audio-sites=w0/100;r0/110;w", value)
                self.assertIn("experimental-ma5-target-rate-hz=48000", value)

    def test_unknown_sources_and_disabled_pcm_remain_unselected(self):
        self.assertEqual(self.select(_profile("unclassified")), (None, None))
        self.assertEqual(self.select(_profile(), audio_pcm=False), (None, None))
        wrong_stride = _profile("local-counter-literal-data-v1", 2)
        self.assertEqual(self.select(wrong_stride), (None, "aperture-unmapped-or-conflicting"))

    def test_shared_lcd_does_not_override_nor_ram_or_audio_owners(self):
        profile = _profile()
        profile["base"] = 0x02800000
        self.assertEqual(self.select(profile, upper_nor_present=True),
                         (None, "aperture-unmapped-or-conflicting"))
        profile = _profile()
        self.config.ram_base, self.config.ram_size = 0x02c00000, 0x100000
        profile["ram_dependencies"] = [[0x02c00100, 8]]
        self.assertEqual(self.select(profile), (None, "aperture-unmapped-or-conflicting"))
        self.config.ram_base, self.config.ram_size = 0x01000000, 0x800000
        self.config.audio_transport = {"static_status": "accepted", "family": "ma3"}
        self.assertEqual(self.select(_profile()), (None, "conflicting-audio-profile"))

    def test_unmapped_source_and_state_dependencies_still_reject(self):
        profile = _profile()
        profile["nor_dependencies"] = [[self.config.flash_size, 4]]
        self.assertEqual(self.select(profile), (None, "primary-nor-out-of-bounds"))
        profile = _profile()
        profile["ram_dependencies"] = [[self.config.ram_base - 4, 4]]
        self.assertEqual(self.select(profile), (None, "consumer-state-unmapped"))


if __name__ == "__main__":
    unittest.main()
