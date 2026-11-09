"""Independent UART RX pulse-address and control-flow regressions."""
import struct
import unittest

from msm5xxx_emulator.detection.devices.uart_console.legacy_simple import _initializer, _uart_rx_read_offset
from msm5xxx_emulator.detection.facts import bind_facts, fact_scope
from msm5xxx_emulator.detection.image_view import ImageView


class UartRxFactsTests(unittest.TestCase):
    def fixture(self, adjustment):
        image = bytearray(0xC0)
        start, status, pulse = 0x40, 0x03000F14, 0x03000700
        words = [0, 0x3830, 0x7900, 0x0840, 0xD200, 0,
                 0, 0x3830, 0x7A02, 0x2001, 0]
        if adjustment:
            words.append(0x3100 | adjustment)
        words.extend((0x7008, 0x2000, 0x7008, 0, 0xBC08, 0x4718))
        return_at = start + (len(words) - 2) * 2
        words[5] = 0xE000 | ((return_at - (start + 14)) // 2)
        repeat = len(words) - 3
        words[repeat] = 0xE000 | (((start - (start + repeat * 2 + 4)) // 2) & 0x7FF)
        for index, pool, value in ((0, 0x90, status + 0x2C),
                                   (6, 0x94, status + 0x2C),
                                   (10, 0x98, pulse - adjustment)):
            pc = start + index * 2
            words[index] = (0x4900 if index == 10 else 0x4800) | ((pool - ((pc + 4) & ~3)) // 4)
            struct.pack_into('<I', image, pool, value)
        struct.pack_into('<' + 'H' * len(words), image, start, *words)
        return image, start, status, pulse

    def query(self, image, status, pulse):
        return _uart_rx_read_offset(bytes(image), 0x20, status, pulse)

    def test_direct_and_adjusted_pulse_addresses(self):
        for adjustment in (0, 0xE0):
            image, start, status, pulse = self.fixture(adjustment)
            self.assertEqual(self.query(image, status, pulse), start + 4 - 0x20)

    def test_pulse_adjustment_must_update_pointer_and_reach_expected_port(self):
        image, start, status, pulse = self.fixture(0xE0)
        for opcode in (0x30E0, 0x31DF):
            changed = bytearray(image)
            struct.pack_into('<H', changed, start + 22, opcode)
            self.assertIsNone(self.query(changed, status, pulse))

    def test_empty_exit_and_repeat_targets_are_part_of_the_consumer(self):
        for adjustment in (0, 0xE0):
            image, start, status, pulse = self.fixture(adjustment)
            repeat = start + (30 if adjustment else 28)
            for address in (start + 10, repeat):
                changed = bytearray(image)
                old, = struct.unpack_from('<H', image, address)
                struct.pack_into('<H', changed, address, old ^ 1)
                self.assertIsNone(self.query(changed, status, pulse))

    def test_literal_source_holes_cannot_supply_the_pulse_address(self):
        image, start, status, pulse = self.fixture(0xE0)
        image = bytes(image)
        with fact_scope():
            bind_facts(image, ImageView.sparse(((0, image[:0x98]), (0x9C, image[0x9C:]))))
            self.assertIsNone(_uart_rx_read_offset(image, 0x20, status, pulse))

    def test_instruction_holes_cannot_supply_the_drain_loop(self):
        image, start, status, pulse = self.fixture(0xE0)
        image = bytes(image)
        with fact_scope():
            bind_facts(image, ImageView.sparse(((0, image[:start + 4]),
                                               (start + 6, image[start + 6:]))))
            self.assertIsNone(_uart_rx_read_offset(image, 0x20, status, pulse))

    def test_initializer_requires_supplied_code_and_literal_words(self):
        image = bytearray(0x40)
        struct.pack_into('<9H', image, 0, 0xB500, 0x480B, 0x2100, 0x2200,
                         0x2300, 0x2101, 0x2201, 0xF000, 0xF801)
        struct.pack_into('<I', image, 0x30, 123)
        image = bytes(image)
        self.assertEqual(_initializer(image, 0, 18, 20), [])
        for start, end in ((4, 6), (0x30, 0x34)):
            with fact_scope():
                bind_facts(image, ImageView.sparse(((0, image[:start]),
                                                   (end, image[end:]))))
                self.assertIsNone(_initializer(image, 0, 18, 20))
