"""Source-qualified standalone MA2 transport decisions."""
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase, mock
from msm5xxx_emulator.qemu import transport


class StandaloneMA2TransportTests(TestCase):
    def setUp(self):
        self.image = bytes(0x200)
        self.config = SimpleNamespace(load_address=0, flash_size=len(self.image))
        self.audio = {
            'family': 'ma2', 'grammar': 'ma2-command-v1',
            'static_status': 'accepted', 'base': 0x02880000,
            'data_offset': 2, 'begin': 0x40,
            'sites': {'write_0': [0x40], 'write_2': [0x46], 'read_2': [0x80]},
        }
        self.digest = SimpleNamespace(hexdigest=lambda: transport._STANDALONE_MA2_DRIVER_SHA256)

    def qualify(self, config=None, audio=None, **kwargs):
        profile = self.audio if audio is None else audio
        with mock.patch.object(transport.hashlib, 'sha256', return_value=self.digest), \
             mock.patch.object(transport, 'find_audio_transport', return_value=self.audio):
            return transport.qemu_standalone_ma2_sites(
                self.image, self.config if config is None else config, profile, **kwargs)

    def test_revalidates_image_profile_and_preserves_default_site_policy(self):
        self.assertIsNone(transport.qemu_audio_sites(self.audio))
        self.assertEqual(self.qualify(), 'r2/80;w0/40;w2/46')
        mismatch = deepcopy(self.audio)
        mismatch['sites']['write_0'] = [0x42]
        self.assertIsNone(self.qualify(audio=mismatch))
        self.assertIsNone(self.qualify(upper_nor_present=True))
        self.assertIsNone(self.qualify(config=SimpleNamespace(load_address=4, flash_size=0x200)))
        self.assertIsNone(self.qualify(config=SimpleNamespace(load_address=0, flash_size=0x80)))

    def test_requires_valid_source_hash(self):
        with mock.patch.object(transport, 'find_audio_transport', return_value=self.audio):
            self.assertIsNone(transport.qemu_standalone_ma2_sites(
                self.image, self.config, self.audio))
