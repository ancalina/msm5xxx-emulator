"""Synthetic checks for SBI raw-input source and wire boundaries."""
from types import SimpleNamespace
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.sbi.raw import (bootstrap_profile_matches, find_sbi_raw_input_profile, qemu_sbi_raw_input_property, qemu_sbi_raw_input_property_for_images, raw_input_profile_matches)
from msm5xxx_emulator.detection.devices.sbi.projection import (bootstrap_property, runtime_properties)


class _ThumbImage:
    """Small assembler for independent, complete Thumb contract fixtures."""
    def __init__(self, size=0x1800):
        self.image = bytearray(size)
        self.position = 0
        self.labels = {}
        self.calls = []
        self.branches = []
        self.unconditional_branches = []
        self.literals = []

    def at(self, address):
        self.position = address

    def label(self, name):
        self.labels[name] = self.position

    def h(self, value):
        struct.pack_into('<H', self.image, self.position, value)
        self.position += 2

    def words(self, *values):
        for value in values:
            self.h(value)

    def ldr(self, register, literal):
        self.literals.append((self.position, register, literal))
        self.h(0x4800 | register << 8)

    def bl(self, target):
        self.calls.append((self.position, target))
        self.h(0xF000)
        self.h(0xF800)

    def bcond(self, condition, target):
        self.branches.append((self.position, condition, target))
        self.h(0xD000 | condition << 8)

    def b(self, target):
        self.unconditional_branches.append((self.position, target))
        self.h(0xE000)

    def pool(self, name, value):
        if self.position & 3:
            self.h(0x46C0)
        self.labels[name] = self.position
        struct.pack_into('<I', self.image, self.position, value)
        self.position += 4

    def finish(self):
        for site, target_name in self.calls:
            target = self.labels[target_name]
            delta = target - site - 4
            struct.pack_into('<2H', self.image, site,
                             0xF000 | (delta >> 12 & 0x7FF),
                             0xF800 | (delta >> 1 & 0x7FF))
        for site, condition, target_name in self.branches:
            delta = self.labels[target_name] - site - 4
            self.image[site:site + 2] = struct.pack(
                '<H', 0xD000 | condition << 8 | ((delta >> 1) & 0xFF))
        for site, target_name in self.unconditional_branches:
            delta = self.labels[target_name] - site - 4
            self.image[site:site + 2] = struct.pack('<H', 0xE000 | (delta >> 1 & 0x7FF))
        for site, register, literal_name in self.literals:
            pool = self.labels[literal_name]
            pc = (site + 4) & ~3
            displacement = pool - pc
            if displacement < 0 or displacement & 3 or displacement > 1020:
                raise AssertionError('synthetic literal is outside Thumb reach')
            struct.pack_into('<H', self.image, site,
                             0x4800 | register << 8 | displacement // 4)
        return bytes(self.image)


def transaction_image(selector=0x40, *, reorder=False, skip_command=False,
                      skip_poll=False, extra_cycle=False, poll_write=False,
                      read_before_entry=False, wrong_forward=False,
                      stack_forward=False, wrong_slot=False,
                      loop_stack_rewrite=False):
    assembler = _ThumbImage()
    assembler.at(0x1000)
    assembler.label('raw')
    assembler.words(0xB500)  # PUSH {lr}
    assembler.ldr(4, 'sbi')
    assembler.ldr(7, 'shadow')
    if skip_poll:
        assembler.words(0x2B00)  # CMP r3, #0: both control paths are feasible
        assembler.bcond(0, 'after_initial_poll')
    if reorder:
        assembler.words(0x206A, 0x2108, 0x0209, 0x4308, 0x80A0)  # control first
    assembler.bl('poll_busy')
    if skip_poll:
        assembler.label('after_initial_poll')
    if not reorder:
        assembler.words(0x206A, 0x2108, 0x0209, 0x4308, 0x80A0)  # control 0x086a
    wire_selector = {0: 0x20, 0x40: 0x40, 0x60: 0x60}[selector]
    assembler.words(0x2100 | (0x80 | wire_selector), 0x7039, 0x7839,
                    0x200A)
    if skip_command:
        assembler.words(0x46C0, 0x46C0)
    else:
        assembler.bl('command')
    assembler.words(0x2100, 0x7421, 0x2101, 0x7421)
    assembler.label('second_poll')
    assembler.bl('poll_busy')
    if extra_cycle:
        assembler.words(0x2B00)
        assembler.bcond(0, 'after_poll_cycle')
        assembler.b('second_poll')
        assembler.label('after_poll_cycle')
    assembler.words(0x7839, 0x227F, 0x4011, 0x7039, 0x7839, 0x200A)
    assembler.bl('command')
    assembler.bl('poll_ready')
    assembler.words(0x208B, 0x0200, 0x81A0)
    assembler.bl('poll_full')
    if read_before_entry:
        assembler.b('data_read')
        assembler.at(0x0F00)
        assembler.label('data_read')
        assembler.words(0x89A0, 0xBD00)
    else:
        assembler.words(0x89A0, 0xBD00)

    assembler.at(0x1200)
    assembler.label('command')
    assembler.words(0x220A, 0x0212, 0x4311)  # OR in the 0x0a00 command prefix
    assembler.ldr(2, 'command_address')
    assembler.words(0x8011, 0x4770)

    for label, pool, status, offset in (
            ('poll_busy', 'poll_busy_base', 0x5F20, 0x1220),
            ('poll_ready', 'poll_ready_base', 0x6A20, 0x1240),
            ('poll_full', 'poll_full_base', 0x6A22, 0x1260)):
        assembler.at(offset)
        assembler.label(label)
        assembler.ldr(1, pool)
        assembler.label(label + '_read')
        assembler.words(0x8808)
        if poll_write and label == 'poll_busy':
            assembler.words(0x8008)  # write the observed status back to the port
        assembler.ldr(2, label + '_status')
        assembler.words(0x4290)
        assembler.bcond(1, label + '_read')
        assembler.words(0x4770)

    assembler.at(0x1300)
    assembler.label('filter')
    assembler.words(0xB500)
    if loop_stack_rewrite:
        assembler.words(0xB081)
        assembler.label('filter_spill_loop')
        assembler.words(0x9000, 0x2020, 0x2900)
        assembler.bcond(1, 'filter_spill_loop')
        assembler.words(0x9800)
    elif stack_forward:
        assembler.words(0xB081, 0x9000,
                        0x9801 if wrong_slot else 0x9800)
    if wrong_forward:
        assembler.words(0x2020)  # Forward a constant instead of outer selector.
    assembler.bl('raw')
    if stack_forward:
        assembler.words(0xB001)
    assembler.words(0xBD00)
    assembler.at(0x1320)
    assembler.label('caller')
    assembler.words(0xB500, 0x2000 | selector, 0x225A)
    assembler.bl('filter')
    assembler.words(0xBD00)

    assembler.at(0x1400)
    assembler.pool('sbi', 0x03000780)
    assembler.pool('shadow', 0x01000000)
    assembler.pool('command_address', 0x0300078C)
    for name in ('poll_busy_base', 'poll_ready_base', 'poll_full_base'):
        assembler.pool(name, 0x03000780)
    for name, value in (('poll_busy_status', 0x5F20),
                        ('poll_ready_status', 0x6A20),
                        ('poll_full_status', 0x6A22)):
        assembler.pool(name, value)
    return assembler.finish()


def profile(source=0x40, selected=0x40, entry=0x500, read_pc=0x686):
    return {
        'signature': 'thumb-sbi-raw-sample-086a-v1',
        'admission': 'temporary-evidence-gated',
        'accepted': True,
        'policy': 'configured-virtual-raw-byte-uncalibrated',
        'base_address': 0x03000780,
        'control': 0x086A,
        'request_prefix': 0x0A80,
        'read_command': 0x8B00,
        'selector_mask': 0x60,
        'source_selector': source,
        'selector_value': selected,
        'entry': entry,
        'entries': [entry],
        'read_pc': read_pc,
    }


class SbiRawInputTests(unittest.TestCase):
    def setUp(self):
        self.config = SimpleNamespace(flash_size=0x2000, load_address=0,
                                      board_adc_value=0x5A)

    def test_wire_uses_transaction_read_site_without_fixed_layout(self):
        for source, selected in ((0, 0x20), (0x40, 0x40), (0x60, 0x60)):
            with self.subTest(source=source):
                value, reason = qemu_sbi_raw_input_property(
                    self.config, profile(source, selected))
                self.assertEqual((value, reason),
                                 (f'sbi-raw-input-profile=686:60:{selected:x}', None))

    def test_invalid_source_contracts_are_rejected(self):
        cases = (
            (profile(1, 0x20), 'raw-input-selector-unclosed'),
            (profile(0x40, 0x20), 'raw-input-selector-unclosed'),
            (profile(read_pc=0x2000), 'raw-input-consumer-unclosed'),
            (profile(read_pc=0x685), 'raw-input-consumer-unclosed'),
        )
        for candidate, reason in cases:
            with self.subTest(reason=reason, candidate=candidate):
                self.assertEqual(qemu_sbi_raw_input_property(self.config, candidate),
                                 (None, reason))

    def test_configuration_requirements(self):
        self.config.load_address = 0x1000
        self.assertEqual(qemu_sbi_raw_input_property(self.config, profile()),
                         (None, 'raw-input-unverified-code-layout'))
        self.config.load_address = 0
        self.config.board_adc_value = None
        self.assertEqual(qemu_sbi_raw_input_property(self.config, profile()),
                         (None, 'raw-input-byte-unavailable'))

    def test_finder_requires_recomputed_bootstrap_evidence(self):
        image = bytes(0x1000)
        self.assertEqual(find_sbi_raw_input_profile(image, None, 0x01000000, 0x800000),
                         (None, 'bootstrap-prerequisite-missing'))
        self.assertEqual(find_sbi_raw_input_profile(
            image, {'signature': 'thumb-sbi-bootstrap-only-v1'}, 0x01000000, 0x800000),
            (None, 'bootstrap-prerequisite-unclosed'))

    def test_source_binding_recomputes_pc_and_selector_for_both_images(self):
        source = profile()
        bootstrap = {'signature': 'bootstrap'}
        with patch('msm5xxx_emulator.detection.devices.sbi.raw.find_sbi_raw_input_profile',
                   side_effect=((source, 'accepted'), (source, 'accepted'))):
            self.assertEqual(qemu_sbi_raw_input_property_for_images(
                self.config, source, bootstrap, (b'original', b'loaded'),
                0x01000000, 0x800000),
                ('sbi-raw-input-profile=686:60:40', None))
        tampered = {**source, 'read_pc': 0x688}
        with patch('msm5xxx_emulator.detection.devices.sbi.raw.find_sbi_raw_input_profile',
                   return_value=(source, 'accepted')):
            self.assertEqual(qemu_sbi_raw_input_property_for_images(
                self.config, tampered, bootstrap, (b'original',),
                0x01000000, 0x800000),
                (None, 'raw-input-source-mismatch'))
        changed_loaded = {**source, 'selector_value': 0x60,
                          'source_selector': 0x60}
        with patch('msm5xxx_emulator.detection.devices.sbi.raw.find_sbi_raw_input_profile',
                   side_effect=((source, 'accepted'), (changed_loaded, 'accepted'))):
            self.assertEqual(qemu_sbi_raw_input_property_for_images(
                self.config, source, bootstrap, (b'original', b'loaded'),
                0x01000000, 0x800000),
                (None, 'raw-input-loaded-source-mismatch'))

    def test_bootstrap_source_binding_rejects_type_coercion(self):
        actual = {'signature': 'typed', 'entries': [0x100], 'layout': 'source-label'}
        with patch('msm5xxx_emulator.detection.devices.sbi.bootstrap.find_sbi_bootstrap_profile',
                   return_value=actual):
            self.assertTrue(bootstrap_profile_matches(b'image', actual))
            self.assertFalse(bootstrap_profile_matches(
                b'image', {'signature': 'typed', 'entries': [True]}))
            self.assertTrue(bootstrap_profile_matches(
                b'image', {**actual, 'layout': 'stale-diagnostic-label'}))

    def _image_with_bootstrap(self, selector=0x40, **kwargs):
        from test_sbi_bootstrap_profile import SbiBootstrapProfileTest
        from msm5xxx_emulator.detection.devices.sbi.bootstrap import (find_sbi_bootstrap_profile)

        bootstrap_code, _ = SbiBootstrapProfileTest._image('direct')
        image = bytearray(transaction_image(selector, **kwargs))
        image[:len(bootstrap_code)] = bootstrap_code
        image = bytes(image)
        return image, find_sbi_bootstrap_profile(image)

    def test_complete_synthetic_transaction_and_cfg_mutations(self):
        for selector, wire in ((0, 0x20), (0x40, 0x40), (0x60, 0x60)):
            image, bootstrap = self._image_with_bootstrap(selector)
            candidate, reason = find_sbi_raw_input_profile(
                image, bootstrap, 0x01000000, 0x1000)
            with self.subTest(selector=selector):
                self.assertEqual(reason, 'accepted')
                self.assertEqual(candidate['selector_value'], wire)
                self.assertEqual(candidate['read_pc'], 0x104A)
                self.assertTrue(candidate['code_intervals'])
                output, output_reason = qemu_sbi_raw_input_property(
                    self.config, candidate)
                self.assertEqual((output, output_reason),
                                 (f'sbi-raw-input-profile=104a:60:{wire:x}', None))

        image, bootstrap = self._image_with_bootstrap(read_before_entry=True)
        candidate, reason = find_sbi_raw_input_profile(
            image, bootstrap, 0x01000000, 0x1000)
        self.assertEqual(reason, 'accepted')
        self.assertLess(candidate['read_pc'], candidate['entry'])
        self.assertEqual(qemu_sbi_raw_input_property(self.config, candidate),
                         ('sbi-raw-input-profile=f00:60:40', None))

        for mutation in ('reorder', 'skip_command', 'skip_poll',
                         'extra_cycle', 'poll_write'):
            image, bootstrap = self._image_with_bootstrap(**{mutation: True})
            candidate, _ = find_sbi_raw_input_profile(
                image, bootstrap, 0x01000000, 0x1000)
            with self.subTest(mutation=mutation):
                self.assertIsNone(candidate)

        image, bootstrap = self._image_with_bootstrap(0x60, wrong_forward=True)
        candidate, _ = find_sbi_raw_input_profile(
            image, bootstrap, 0x01000000, 0x1000)
        self.assertIsNone(candidate)
        image, bootstrap = self._image_with_bootstrap(
            0x60, loop_stack_rewrite=True)
        candidate, _ = find_sbi_raw_input_profile(
            image, bootstrap, 0x01000000, 0x1000)
        self.assertIsNone(candidate)

        image, bootstrap = self._image_with_bootstrap(0x60, stack_forward=True)
        candidate, reason = find_sbi_raw_input_profile(
            image, bootstrap, 0x01000000, 0x1000)
        self.assertEqual(reason, 'accepted')
        self.assertEqual(candidate['source_selector'], 0x60)
        image, bootstrap = self._image_with_bootstrap(
            0x60, stack_forward=True, wrong_slot=True)
        candidate, _ = find_sbi_raw_input_profile(
            image, bootstrap, 0x01000000, 0x1000)
        self.assertIsNone(candidate)

    def test_source_bound_profile_matches_only_original_and_loaded_evidence(self):
        image, bootstrap = self._image_with_bootstrap()
        candidate, reason = find_sbi_raw_input_profile(
            image, bootstrap, 0x01000000, 0x1000)
        self.assertEqual(reason, 'accepted')
        self.assertTrue(raw_input_profile_matches(
            image, bootstrap, candidate, 0x01000000, 0x1000))
        self.assertFalse(raw_input_profile_matches(
            image, bootstrap, {**candidate, 'read_pc': 0x104C},
            0x01000000, 0x1000))
        self.assertEqual(qemu_sbi_raw_input_property_for_images(
            self.config, candidate, bootstrap, (image, image),
            0x01000000, 0x1000),
            ('sbi-raw-input-profile=104a:60:40', None))
        altered, _ = self._image_with_bootstrap(0x60)
        self.assertEqual(qemu_sbi_raw_input_property_for_images(
            self.config, candidate, bootstrap, (image, altered),
            0x01000000, 0x1000),
            (None, 'raw-input-loaded-source-mismatch'))

    def test_owner_and_runtime_source_projections_revalidate_transaction(self):
        image, bootstrap = self._image_with_bootstrap()
        candidate, reason = find_sbi_raw_input_profile(
            image, bootstrap, 0x01000000, 0x1000)
        self.assertEqual(reason, 'accepted')
        config = SimpleNamespace(
                flash_size=len(image), load_address=0, board_adc_value=0x5A,
                ram_base=0x01000000, ram_size=0x1000,
                sbi_bootstrap_profile={**bootstrap, 'raw_input': candidate})
        expected = ('sbi=on,sbi-raw-input-profile=104a:60:40', None)
        self.assertEqual(bootstrap_property(config, original=image, loaded=image),
                         expected)
        self.assertEqual(runtime_properties(image, image, config)[:2], expected)

        config.sbi_bootstrap_profile = {
            **bootstrap, 'raw_input': {**candidate, 'read_pc': 0x104C}}
        self.assertEqual(bootstrap_property(config, original=image, loaded=image),
                         ('sbi=on,sbi-bootstrap-only=on',
                          'raw-input-source-mismatch'))

        config.sbi_bootstrap_profile = {**bootstrap, 'raw_input': candidate}
        changed_loaded, _ = self._image_with_bootstrap(0x60)
        self.assertEqual(bootstrap_property(
            config, original=image, loaded=changed_loaded),
            ('sbi=on,sbi-bootstrap-only=on',
             'raw-input-loaded-source-mismatch'))

    def test_unmocked_bootstrap_and_raw_source_binding(self):
        from test_sbi_bootstrap_profile import SbiBootstrapProfileTest
        from msm5xxx_emulator.detection.devices.sbi.bootstrap import (find_sbi_bootstrap_profile)

        bootstrap_code, bootstrap_entry = SbiBootstrapProfileTest._image('direct')
        original = bytearray(transaction_image())
        original[:len(bootstrap_code)] = bootstrap_code
        original = bytes(original)
        bootstrap = find_sbi_bootstrap_profile(original)
        self.assertIsNotNone(bootstrap)
        self.assertEqual(bootstrap['entries'], [bootstrap_entry])
        raw, reason = find_sbi_raw_input_profile(
            original, bootstrap, 0x01000000, 0x1000)
        self.assertEqual(reason, 'accepted')

        config = SimpleNamespace(
            flash_size=len(original), load_address=0, board_adc_value=0x5A,
            ram_base=0x01000000, ram_size=0x1000,
            sbi_bootstrap_profile={**bootstrap, 'raw_input': raw})
        expected = ('sbi=on,sbi-raw-input-profile=104a:60:40', None)
        self.assertEqual(bootstrap_property(
            config, original=original, loaded=original), expected)
        self.assertEqual(runtime_properties(original, original, config)[:2], expected)

        changed_raw = bytearray(transaction_image(0x60))
        changed_raw[:len(bootstrap_code)] = bootstrap_code
        self.assertEqual(bootstrap_property(
            config, original=original, loaded=bytes(changed_raw)),
            ('sbi=on,sbi-bootstrap-only=on',
             'raw-input-loaded-source-mismatch'))

        changed_bootstrap = bytearray(original)
        changed_bootstrap[bootstrap_entry + 0x30] ^= 1
        self.assertEqual(bootstrap_property(
            config, original=original, loaded=bytes(changed_bootstrap)),
            (None, 'sbi-bootstrap-source-unclosed'))

    def test_thumb_raw_input_requires_thumb_bootstrap_source(self):
        from test_sbi_bootstrap_profile import SbiBootstrapProfileTest
        from msm5xxx_emulator.detection.devices.sbi.bootstrap import (find_sbi_bootstrap_profile)

        arm_bootstrap, _ = SbiBootstrapProfileTest._arm_image()
        image = bytearray(transaction_image())
        image[:len(arm_bootstrap)] = arm_bootstrap
        image = bytes(image)
        bootstrap = find_sbi_bootstrap_profile(image)
        self.assertIsNotNone(bootstrap)
        assert bootstrap is not None
        # The compatibility profile exposes integer offsets. Source mode must
        # come from the Thumb bootstrap query, not that offset or layout text.
        self.assertEqual(bootstrap['entries'], [0x20])
        self.assertIsNone(find_sbi_raw_input_profile(
            image, bootstrap, 0x01000000, 0x1000)[0])


if __name__ == '__main__':
    unittest.main()
