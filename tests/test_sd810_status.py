"""Tests for the SD810 halfword GPIO reader admission."""
import struct
import unittest

from msm5xxx_emulator.detection.input_sd810 import (
    sd810_fold_event_source, sd810_fold_irq_source, sd810_gpio_board_status_profile,
)


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
