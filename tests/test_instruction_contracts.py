"""Instruction contracts over synthetic supplied and copied execution views."""
import struct
import unittest

from msm5xxx_emulator.detection.contracts import BodySpec
from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.image_view import ImageView, LoadOperation


class InstructionContractTests(unittest.TestCase):
    def test_relocated_thumb_call_and_literal(self):
        image = struct.pack('<6H', 0x4902, 0xF000, 0xF801, 0x4770, 0x4770, 0)
        image += struct.pack('<I', 0x03000720)
        spec = BodySpec.thumb(8, {6: 0x4770}, {0: 1}, (2,))
        for base in (0, 0x1000):
            result = spec.match(FirmwareFacts(image, base=base), base)
            self.assertEqual(result.targets, {2: base + 8})
            self.assertEqual(result.values, {0: 0x03000720})
            self.assertEqual(result.pools, (base + 12,))

    def test_materialized_copy_uses_execution_addresses(self):
        image = struct.pack('<4H', 0x4900, 0x4770, 0x0720, 0x0300)
        view = ImageView.raw(image).materialize((
            LoadOperation('copy', 0, 0x03800000, len(image), (0,)),
        ))
        facts = FirmwareFacts(image, view=view)
        spec = BodySpec.thumb(4, {2: 0x4770}, {0: 1})
        result = spec.match(facts, CodeAddress(0x03800000, phase='post-copy'))
        self.assertEqual(result.values, {0: 0x03000720})
        self.assertEqual(result.pools, (0x03800004,))
        self.assertIsNone(spec.match(facts, CodeAddress(0x03800000)))
        self.assertEqual([body.entry for body in spec.find(facts)], [0])
        self.assertEqual([body.entry for body in spec.find(facts, phase='post-copy')],
                         [0, 0x03800000])
        self.assertEqual(list(spec.find(facts, phase='post-copy', bank='other')), [])

    def test_arm_pool_uses_architectural_register_numbers(self):
        image = struct.pack('<3I', 0xE59FD000, 0xE12FFF1E, 0x14008000)
        spec = BodySpec(8, ((4, 0xE12FFF1E, 0xFFFFFFFF),), ((0, 13),), isa='arm')
        self.assertEqual(spec.match(FirmwareFacts(image), 0).values, {0: 0x14008000})

    def test_missing_pool_and_changed_instruction_reject(self):
        spec = BodySpec.thumb(4, {2: 0x4770}, {0: 1})
        self.assertIsNone(spec.match(FirmwareFacts(struct.pack('<2H', 0x4900, 0x4770)), 0))
        image = struct.pack('<4H', 0x4900, 0x4700, 0x0720, 0x0300)
        self.assertIsNone(spec.match(FirmwareFacts(image), 0))

    def test_compiler_body_decodes_relocated_fields_and_end_target(self):
        template = struct.pack('<4H', 0x4900, 0xF000, 0xF800, 0x4770)
        spec = BodySpec.thumb_body(template, (2,), ((0, 1),))
        image = struct.pack('<4H', 0x4902, 0xF000, 0xF805, 0x4770)
        image += bytes(4) + struct.pack('<I', 0x03000720) + struct.pack('<H', 0x4770)
        body = spec.match(FirmwareFacts(image), 0)
        self.assertEqual(body.targets, {2: len(image) - 2})
        self.assertEqual(body.values, {0: 0x03000720})
        self.assertEqual([found.entry for found in spec.find(FirmwareFacts(image))], [0])
        view = ImageView.sparse(((0, image[:4]), (6, image[6:])))
        self.assertIsNone(spec.match(FirmwareFacts(image, view=view), 0))


if __name__ == '__main__':
    unittest.main()
