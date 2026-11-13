import struct
import unittest
from capstone import arm as a

from msm5xxx_emulator.detection.devices.memory.dram_commands import (
    _dead_result,
    find_dram_command_profile,
)
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


_BASE = 0xffff0000
_HELPER = 0x100


def _ror(value, count):
    count %= 32
    return ((value >> count) | (value << ((32 - count) & 31))) & 0xffffffff


def _mov(rd, value):
    for rotate in range(16):
        for imm8 in range(256):
            if _ror(imm8, rotate * 2) == value:
                return 0xe3a00000 | rd << 12 | rotate << 8 | imm8
    raise ValueError(hex(value))


def _branch(pc, target, link=False):
    delta = target - pc - 8
    assert delta % 4 == 0
    return (0xeb000000 if link else 0xea000000) | ((delta // 4) & 0xffffff)


def _sample(*, link=True, mode_address=0x63800000, read_width=4,
            first_load=0xe7912002, final_mode_write=True):
    image = bytearray(0x400)
    struct.pack_into('<I', image, 0, _branch(_BASE, _BASE + _HELPER, link=link))
    struct.pack_into('<I', image, 4, 0xe12fff1e)  # bx lr

    code = [
        0xe59f4078,  # ldr r4, [pc, #0x78] -> 0x63800000
        0xe5945020, 0xe3855080, 0xe5845020,
        0xe5945020, 0xe3855001, 0xe5845020,
    ]
    reads = ((0x19000, 0), (0xc800, 0x08000000),
             (0x02000000, 0), (0x01000000, 0x08000000))
    for index, (offset, base) in enumerate(reads):
        code.extend((_mov(2, offset), _mov(1, base),
                     first_load if index == 0 else
                     (0xe7912002 if read_width == 4 else 0xe7d12002)))
    code.extend((0xe5945020, 0xe3855000,
                 0xe5845020 if final_mode_write else 0xe1a00000,
                 0xe12fff1e))
    for index, instruction in enumerate(code):
        struct.pack_into('<I', image, _HELPER + index * 4, instruction)
    # The PC-relative load at helper+0 reads this literal at helper+0x80.
    struct.pack_into('<I', image, _HELPER + 0x80, mode_address)
    return bytes(image)


class DramCommandTests(unittest.TestCase):
    def test_reset_linked_sdram_mode_reads_map_only_external_pages(self):
        profile = find_dram_command_profile(_sample())
        self.assertIsNotNone(profile)
        self.assertEqual(profile['probe_reads'], [0x19000, 0x0800c800,
                                                  0x02000000, 0x09000000])
        self.assertEqual(profile['windows'], [
            {'base': 0x0800c000, 'length': 0x1000},
            {'base': 0x09000000, 'length': 0x1000},
        ])
        self.assertTrue(profile['evidence'])

    def test_unlinked_controller_code_is_not_selected(self):
        self.assertIsNone(find_dram_command_profile(_sample(link=False)))

    def test_changed_controller_register_does_not_match(self):
        self.assertIsNone(find_dram_command_profile(_sample(mode_address=0x63800004)))

    def test_byte_read_does_not_match_word_command_probe(self):
        self.assertIsNone(find_dram_command_profile(_sample(read_width=1)))

    def test_read_result_must_match_address_register(self):
        # The first read no longer writes the register used by its address setup.
        self.assertIsNone(find_dram_command_profile(_sample(first_load=0xe7910002)))

    def test_live_dummy_load_result_is_not_dead(self):
        image = bytearray(16)
        struct.pack_into('<4I', image, 0,
                         0xe7912002,  # ldr r2, [r1, r2]
                         0xe0833002,  # add r3, r3, r2
                         0xe3a02000,  # mov r2, #0
                         0xe12fff1e)  # bx lr
        facts = facts_for(bytes(image))
        entry = CodeAddress(0, 'arm')
        function = facts.function(entry)
        self.assertFalse(_dead_result(function, facts, entry, a.ARM_REG_R2))

    def test_mode_sequence_must_be_closed_by_a_later_write(self):
        self.assertIsNone(find_dram_command_profile(_sample(final_mode_write=False)))
