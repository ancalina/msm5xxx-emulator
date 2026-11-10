"""Synthetic checks for GPIO PMIC facts-backed decoding."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import bind_facts, fact_scope
from msm5xxx_emulator.detection.registry import device_domain
_instructions = device_domain('external_bus.gpio_pmic')._instructions
_literal = device_domain('external_bus.gpio_pmic')._literal
_memory_base = device_domain('external_bus.gpio_pmic')._memory_base
from msm5xxx_emulator.detection.image_view import ImageView


def words(*values):
    return struct.pack('<' + 'H' * len(values), *values)


class GpioPmicSharedFactsTests(unittest.TestCase):
    def test_literal_uses_bound_view_and_keeps_legacy_value_shape(self):
        image = words(0x4800, 0x4770) + struct.pack('<I', 0x030006E8)
        insn = _instructions(image, 0, 2)[0]
        self.assertEqual(_literal(image, insn), (4, 0x030006E8))

        with fact_scope():
            bind_facts(image, ImageView.sparse(((0, image[:4]),)))
            supplied_insn = _instructions(image, 0, 2)[0]
            self.assertIsNone(_literal(image, supplied_insn))

    def test_memory_base_uses_capstone_operands(self):
        image = words(0x6861)  # LDR r1, [r4, #4]
        instruction = _instructions(image, 0, 2)[0]

        self.assertEqual(_memory_base(instruction), ('r4', 4))


if __name__ == '__main__':
    unittest.main()
