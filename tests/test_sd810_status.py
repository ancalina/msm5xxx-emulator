"""Tests for the SD810 halfword GPIO reader admission."""
import struct
import shutil
import tempfile
from pathlib import Path
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.input_sd810 import (
    sd810_fold_event_source, sd810_fold_irq_source, sd810_gpio_board_status_profile,
)
from msm5xxx_emulator.qemu.transport import qemu_sd810_sxs_menu_selection


def reader(image, start, pointer=0x01816618):
    # Construct a Thumb reader with a PC-relative literal in a synthetic image.
    literal = start + 0x80
    ldr = 0x4800 | ((literal - ((start + 4) & ~3)) // 4)
    words = [ldr, 0x6840, 0x8800, 0x07c1, 0x0fc9, 0x227f,
             0x4800, 0x0112, 0x1810, 0x2900, 0x4c00, 0xd100,
             0x7141, 0x2008, 0xf000, 0xf800, 0x20ff, 0xf000, 0xf800]
    struct.pack_into(f"<{len(words)}H", image, start, *words)
    struct.pack_into("<I", image, literal, pointer)


class SD810StatusTests(unittest.TestCase):
    def test_firmware_signature_is_filename_and_model_independent(self):
        from corpus import FIRMWARE_ROOT, firmware_path
        from msm5xxx_emulator.detection import detect
        from msm5xxx_emulator.qemu.decoder import QemuDecoder

        names = ("LG-SD810-General.bin", "LG-SD810-AfterSKTVer.bin",
                 "archive-copies/LG_SXS1V308_NOR_00000000_len_01800000.bin")
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = (FIRMWARE_ROOT.parent / name if name.startswith("archive-copies/")
                        else firmware_path(name))
                if not path.is_file():
                    self.skipTest(f"private firmware unavailable: {name}")
                copy = Path(directory) / "unrelated-firmware.bin"
                shutil.copyfile(path, copy)
                original = detect(path)
                renamed = detect(copy)
                self.assertEqual(original.sd810_gpio_profile, (0x03000720, 1, 1))
                self.assertEqual(renamed.sd810_gpio_profile, original.sd810_gpio_profile)
                self.assertEqual(renamed.board_status_input, original.board_status_input)
                for config in (original, renamed):
                    config.model = None
                    decoder = QemuDecoder(config)
                    self.assertTrue(decoder._lcd_sd810_enabled())
                    config.sd810_gpio_profile = None
                    self.assertFalse(decoder._lcd_sd810_enabled())

    def test_sxs_menu_selection_requires_matching_source_and_table(self):
        table = 0x25d957
        image = bytearray(table + 30)
        reader(image, 0x100)
        events = list(range(30))
        events[17] = 0x8c
        image[table:table + 30] = bytes(events)
        config = SimpleNamespace(load_address=0, flash_size=len(image))
        profile = dict(function=0x7877c, descriptor_pointer=0x01816618,
                       raw_enqueue=0x784a4, event_table=table,
                       event_codes=events,
                       provisional_mappings={5: {"event": 0x8d},
                                             8: {"event": 0x8c},
                                             11: {"event": 0x31}})
        result = qemu_sd810_sxs_menu_selection(image, config, profile)
        self.assertEqual(result['provisional_mappings'][5]['event'], 0x8c)
        self.assertNotIn(8, result['provisional_mappings'])
        self.assertEqual(result['provisional_mappings'][11]['event'], 0x31)
        self.assertEqual(profile['provisional_mappings'][5]['event'], 0x8d)
        for field in ('function', 'descriptor_pointer', 'raw_enqueue', 'event_table'):
            changed = dict(profile, **{field: profile[field] + 2})
            self.assertIsNone(qemu_sd810_sxs_menu_selection(image, config, changed))
        image[table + 17] ^= 1
        self.assertIsNone(qemu_sd810_sxs_menu_selection(image, config, profile))

    def test_requires_unique_matching_reader(self):
        image = bytearray(0x400)
        reader(image, 0x100)
        self.assertEqual(sd810_gpio_board_status_profile(image),
                         (0x03000720, 1, 1))
        reader(image, 0x200)
        self.assertIsNone(sd810_gpio_board_status_profile(image))

    def test_fold_events_require_both_polarities_and_same_raw_sink(self):
        image = bytearray(0x400)
        start, sink = 0x100, 0x300
        reader(image, start)
        struct.pack_into('<H', image, start + 22, 0xd122)
        for offset, value in ((94, 0x2101), (96, 0x7141), (98, 0x2006),
                              (104, 0x20ff)):
            struct.pack_into('<H', image, start + offset, value)
        for offset in (28, 34, 100, 106):
            displacement = sink - (start + offset + 4)
            struct.pack_into('<2H', image, start + offset,
                             0xf000 | ((displacement >> 12) & 0x7ff),
                             0xf800 | ((displacement >> 1) & 0x7ff))
        self.assertTrue(sd810_fold_event_source(image, sink))
        self.assertFalse(sd810_fold_event_source(image, sink + 2))
        struct.pack_into('<H', image, start + 98, 0x2008)
        self.assertFalse(sd810_fold_event_source(image, sink))

    def test_rejects_wrong_pointer_or_branch(self):
        image = bytearray(0x400)
        reader(image, 0x100, pointer=0x0181661c)
        self.assertIsNone(sd810_gpio_board_status_profile(image))
        reader(image, 0x100)
        struct.pack_into("<H", image, 0x100 + 22, 0xd000)
        self.assertIsNone(sd810_gpio_board_status_profile(image))

    def test_fold_irq_requires_live_source_chain(self):
        from corpus import firmware_path
        from msm5xxx_emulator.detection import detect
        from msm5xxx_emulator.devices.input import InputMixin

        class InputProbe(InputMixin):
            pass

        path = firmware_path('LG-SD810-General.bin')
        config = detect(path)
        probe = InputProbe()
        probe.image = path.read_bytes()
        probe.config = config
        probe._init_input_state(config)
        profile = probe.direct_input_profile
        self.assertIsNotNone(profile)
        from msm5xxx_emulator.qemu.transport import qemu_lg_matrix_irq_property
        config.model = None
        self.assertIsNone(qemu_lg_matrix_irq_property(config, profile))
        route = profile['timer_bridge']['irq_route']
        sink = profile['raw_enqueue'] - config.load_address
        source = sd810_fold_irq_source(probe.image, sink, route)
        self.assertIsNotNone(source)
        self.assertEqual(source[3] + 0x54, source[0])
        self.assertIsNone(sd810_fold_irq_source(
            probe.image, sink, dict(route, callback_slot=route['callback_slot'] + 4)))
        changed = bytearray(probe.image)
        bank = struct.pack('<4I', 0x03000c88, 0x03000ca4, 0x03000cb0, 0x0300074c)
        offset = changed.find(bank)
        self.assertGreaterEqual(offset, 0)
        changed[offset] ^= 1
        self.assertIsNone(sd810_fold_irq_source(bytes(changed), sink, route))
        changed = bytearray(probe.image)
        struct.pack_into('<H', changed, (source[2] & ~1) + 4, 0x2100)
        self.assertIsNone(sd810_fold_irq_source(bytes(changed), sink, route))
