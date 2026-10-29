"""Closed source profiles and persistent serial-NVM input preservation."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

from test_boot_keysense import fixture as key_fixture
from test_spi_nv_detection import _fixture as spi_fixture
from test_rex_legacy_row0 import fixture as row0_fixture
from msm5xxx_emulator.detection.rex import find_rex_legacy_row0_profile
from msm5xxx_emulator.detection.boot_keysense import find_boot_keysense_release
from msm5xxx_emulator.detection.spi_nv import find_spi_nv_profile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/qemu-tcg'))
from qemu_transport import (prepare_spi_nv_state, qemu_boot_keysense_property,
                            qemu_spi_nv_properties, qemu_state_directory, qemu_basic_row0_property)


def configuration(image):
    return SimpleNamespace(load_address=0, image_offset=0, entry=0,
                           flash_size=len(image), ram_base=0x01000000,
                           ram_size=0x800000, ram_bootstrap_profile=None,
                           key_register=None, board_status_input=None,
                           boot_keysense_release=None, spi_nv_profile=None)


class BootStorageTransportTests(unittest.TestCase):
    def test_boot_read_pcs_only_and_source_revalidation(self):
        for prefixed in (False, True):
            image, _ = key_fixture(prefixed)
            image = bytes(image)
            config = configuration(image)
            self.assertEqual(qemu_boot_keysense_property(config, image), (None, None))
            profile, _ = find_boot_keysense_release(image)
            config.boot_keysense_release = json.loads(json.dumps(profile))
            expected = 'boot-keysense-release=' + ':'.join(f'{pc:x}' for pc in profile['read_pcs'])
            self.assertEqual(qemu_boot_keysense_property(config, image), (expected, None))
            config.boot_keysense_release['read_pcs'][0] += 2
            self.assertEqual(qemu_boot_keysense_property(config, image)[1],
                             'boot_keysense_release-source-profile-mismatch')
            config.boot_keysense_release = profile
            changed = bytearray(image)
            changed[profile['read_pcs'][0]] ^= 1
            self.assertIsNone(qemu_boot_keysense_property(config, bytes(changed))[0])
            self.assertIsNone(qemu_boot_keysense_property(config, image, input_claimed=True)[0])
            config.board_status_input = SimpleNamespace(address=0x03000694, mask=0x10)
            self.assertIsNone(qemu_boot_keysense_property(config, image)[0])

    def test_layout_overrides_do_not_activate_boot_device(self):
        image = bytes(key_fixture()[0])
        config = configuration(image)
        config.boot_keysense_release = find_boot_keysense_release(image)[0]
        for field, value in (('load_address', 4), ('image_offset', 4), ('entry', 4)):
            changed = deepcopy(config)
            setattr(changed, field, value)
            self.assertIsNone(qemu_boot_keysense_property(changed, image)[0])

    def test_spi_profile_geometry_and_owner_boundaries(self):
        for index in (0, 1):
            image = bytes(spi_fixture(index))
            config = configuration(image)
            self.assertEqual(qemu_spi_nv_properties(config, image), (None, None))
            profile, _ = find_spi_nv_profile(image)
            config.spi_nv_profile = json.loads(json.dumps(profile))
            expected = ('experimental-spi-nv-write-ns=5000000,'
                        f'spi-nv-source-geometry={profile["descriptor_address"]:x}')
            self.assertEqual(qemu_spi_nv_properties(config, image), (expected, None))
            for kwargs in ({'input_claimed': True}, {'eeprom_claimed': True}):
                self.assertIsNone(qemu_spi_nv_properties(config, image, **kwargs)[0])
            for address in (0x03000660, 0x0300067f):
                config.board_status_input = SimpleNamespace(address=address)
                self.assertIsNone(qemu_spi_nv_properties(config, image)[0])
            config.board_status_input = SimpleNamespace(address=0x03000694)
            self.assertEqual(qemu_spi_nv_properties(config, image), (expected, None))
            config.ram_size = 0x2000
            self.assertEqual(qemu_spi_nv_properties(config, image)[1],
                             'spi-nv-source-state-outside-ram')
            config.ram_size = 0x800000
            config.ram_bootstrap_profile = {
                'reserved_base': profile['descriptor_address'], 'reserved_size': 6}
            self.assertEqual(qemu_spi_nv_properties(config, image)[1],
                             'spi-nv-source-state-in-reserved-span')
            config.ram_bootstrap_profile = None
            config.spi_nv_profile['virtual_capacity'] = 0x2000
            self.assertEqual(qemu_spi_nv_properties(config, image)[1],
                             'spi_nv_profile-source-profile-mismatch')

    def test_source_row0_keeps_idle_none_and_declines_changed_configuration(self):
        for compact in (False, True):
            image, sites = row0_fixture(compact=compact)
            image = bytes(image)
            config = configuration(image)
            config.ram_size = 0x10000
            config.overlays = []
            profile, reason = find_rex_legacy_row0_profile(image, config.ram_base, config.ram_size)
            self.assertEqual(reason, 'accepted')
            config.rex_basic_irq_profile = json.loads(json.dumps(profile))
            for field, value in zip((
                    'rex_irq_wrapper_address', 'rex_irq_handler_address',
                    'rex_irq_handler_slot', 'rex_irq_callback_slot',
                    'rex_irq_status_address', 'rex_irq_enable_address', 'rex_irq_mask'),
                    profile['route']):
                setattr(config, field, value)
            config.rex_idle_address = None
            config.rex_tick_ms = 5
            config.rex_tick_address = profile['callback_file_offset']
            config.rex_irq_arm_address = profile['arm_address']
            expected = 'rex-irq=3000620:3000628:30006e0:200:4c4b40:0'
            self.assertEqual(qemu_basic_row0_property(config, image), (expected, None))
            self.assertIsNone(config.rex_idle_address)
            for field, value in (('rex_idle_address', 0), ('rex_tick_ms', 1),
                                 ('rex_irq_callback_slot', config.rex_irq_callback_slot + 4)):
                changed = deepcopy(config)
                setattr(changed, field, value)
                self.assertEqual(qemu_basic_row0_property(changed, image)[1],
                                 'row0-configuration-source-mismatch')
            changed = bytearray(image)
            changed[sites['callback'] + 0x14] ^= 1
            self.assertIsNone(qemu_basic_row0_property(config, bytes(changed))[0])

    def test_serial_nv_seed_reload_wrong_size_and_input_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'firmware.bin'
            original.write_bytes(b'original firmware')
            state = root / 'spi-nv.raw'
            self.assertEqual(prepare_spi_nv_state(state, (original,)), state)
            self.assertEqual(state.read_bytes(), b'\xff' * 0x4000)
            expected = b'\x9a' + b'\xff' * 0x3fff
            state.write_bytes(expected)
            prepare_spi_nv_state(state, (original,))
            self.assertEqual(state.read_bytes(), expected)
            with self.assertRaisesRegex(ValueError, 'collides'):
                prepare_spi_nv_state(original, (original,))
            alias = root / 'alias.raw'
            alias.hardlink_to(original)
            with self.assertRaisesRegex(ValueError, 'aliases'):
                prepare_spi_nv_state(alias, (original,))
            link = root / 'symlink.raw'
            link.symlink_to(state)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                prepare_spi_nv_state(link, (original,))
            wrong = root / 'wrong.raw'
            wrong.write_bytes(b'keep')
            with self.assertRaisesRegex(ValueError, 'size mismatch'):
                prepare_spi_nv_state(wrong, (original,))
            self.assertEqual(wrong.read_bytes(), b'keep')
            self.assertEqual(original.read_bytes(), b'original firmware')

    def test_serial_nv_is_in_existing_state_identity_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'spi-nv.raw').write_bytes(b'\xff' * 0x4000)
            first = SimpleNamespace(firmware_sha256='a' * 64)
            second = SimpleNamespace(firmware_sha256='b' * 64)
            self.assertEqual(qemu_state_directory(root, first), root)
            self.assertEqual(qemu_state_directory(root, second), root / ('b' * 64))
            self.assertEqual((root / 'spi-nv.raw').read_bytes(), b'\xff' * 0x4000)
