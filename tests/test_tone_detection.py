from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.tone import find_tone_generator


_DIVIDERS = (307500, 2152500, 4305000, 8610000)
_WRITES = (
    0x030006C8, 0x030006DC, 0x030006BC, 0x030006B8,
    0x030006C4, 0x030006C0, 0x030006D0, 0x030006CC,
    0x030006D8, 0x030006D4,
)


def _ldr_literal(pc: int, reg: int, literal: int) -> int:
    base = (pc + 4) & ~3
    displacement = literal - base
    assert displacement >= 0 and displacement % 4 == 0
    return 0x4800 | reg << 8 | displacement // 4


def _bl(pc: int, target: int) -> tuple[int, int]:
    displacement = target - (pc + 4)
    assert displacement % 2 == 0
    return (0xF000 | ((displacement >> 12) & 0x7FF),
            0xF800 | ((displacement >> 1) & 0x7FF))


def _fixture(*, complete=True, exact_writer=True) -> bytes:
    image = bytearray(0x400)
    words = []
    image[0x100:0x102] = struct.pack('<H', 0xB580)  # converter prologue
    for index, value in enumerate(_DIVIDERS if complete else _DIVIDERS[:3]):
        pc = 0x120 + index * 8
        literal = 0x180 + index * 4
        image[pc:pc + 2] = struct.pack('<H', _ldr_literal(pc, index, literal))
        image[literal:literal + 4] = struct.pack('<I', value)
    image[0x220:0x222] = struct.pack('<H', 0xB5F0)
    for reg, value in enumerate((0x030006B0, 0x030006C0, 0x030006D0)):
        pc = 0x230 + reg * 4
        literal = 0x2A0 + reg * 4
        image[pc:pc + 2] = struct.pack('<H', _ldr_literal(pc, reg, literal))
        image[literal:literal + 4] = struct.pack('<I', value)
    first_bl = 0x244
    image[first_bl:first_bl + 4] = struct.pack('<2H', *_bl(first_bl, 0x100))
    for index, address in enumerate(_WRITES if exact_writer else _WRITES[:-1]):
        base = address & ~0xF
        reg = {0x030006B0: 0, 0x030006C0: 1, 0x030006D0: 2}[base]
        immediate = address - base
        insn = 0x7000 | immediate << 6 | reg << 3
        pc = 0x250 + index * 2
        image[pc:pc + 2] = struct.pack('<H', insn)
    return bytes(image)


class ToneDetectionTests(unittest.TestCase):
    def test_requires_linked_converter_and_writer(self):
        self.assertEqual(find_tone_generator(_fixture())['static_status'], 'accepted')
        self.assertEqual(find_tone_generator(_fixture(complete=False))['static_status'], 'rejected')
        self.assertEqual(find_tone_generator(_fixture(exact_writer=False))['static_status'], 'rejected')

    def test_rejects_unrelated_bytes(self):
        self.assertEqual(find_tone_generator(b'')['static_status'], 'rejected')


if __name__ == '__main__':
    unittest.main()
