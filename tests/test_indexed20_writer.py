"""Synthetic code-query checks for indexed halfword display writers."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue
from msm5xxx_emulator.detection.devices.display import indexed20_writer


class ThumbImage:
    def __init__(self, size=0x300):
        self.image = bytearray(size)
        self.literals = []

    def half(self, address, value):
        struct.pack_into('<H', self.image, address, value)

    def literal(self, address, register, value):
        pool = 0x280 + 4 * len(self.literals)
        base = (address + 4) & ~3
        delta = pool - base
        if delta < 0 or delta % 4 or delta // 4 > 255:
            raise AssertionError('literal is outside Thumb range')
        self.half(address, 0x4800 | register << 8 | delta // 4)
        struct.pack_into('<I', self.image, pool, value)
        self.literals.append(pool)

    def bl(self, address, target):
        delta = target - address - 4
        if delta & 1 or not -(1 << 22) <= delta < (1 << 22):
            raise AssertionError('call is outside Thumb range')
        value = delta >> 1
        self.half(address, 0xF000 | ((value >> 11) & 0x7ff))
        self.half(address + 2, 0xF800 | (value & 0x7ff))

    def finish(self):
        return bytes(self.image)


def _store_half(source, base):
    return 0x8000 | base << 3 | source


def _lsl(register, amount):
    return amount << 6 | register << 3 | register


def _indexed_helpers(*, cursor_data_port=0x20080000):
    assembler = ThumbImage()
    command_port, data_port = 0x20000000, 0x20080000
    # Caller linkage makes the helper targets discoverable from call facts.
    assembler.half(0x20, 0xB500)
    assembler.bl(0x22, 0x100)
    assembler.bl(0x26, 0x180)
    assembler.half(0x2a, 0xBD00)
    # The window helper emits register/value pairs using its four arguments.
    assembler.half(0x100, 0xB500)
    assembler.literal(0x102, 4, command_port)
    assembler.literal(0x104, 5, data_port)
    assembler.half(0x106, 0x2600 | 0x21)
    assembler.half(0x108, _lsl(6, 4))
    address = 0x10a
    for register, argument in zip(range(0x210, 0x214), range(4)):
        assembler.half(address, _store_half(6, 4))
        assembler.half(address + 2, _store_half(argument, 5))
        address += 4
        if register != 0x213:
            assembler.half(address, 0x3601)
            address += 2
    assembler.half(address, 0xBD00)
    # The cursor helper emits the two origin-relative cursor registers.
    assembler.half(0x180, 0xB500)
    assembler.literal(0x182, 4, command_port)
    assembler.literal(0x184, 5, cursor_data_port)
    assembler.half(0x186, 0x2600 | 0x20)
    assembler.half(0x188, _lsl(6, 4))
    assembler.half(0x18a, _store_half(6, 4))
    assembler.half(0x18c, _store_half(0, 5))
    assembler.half(0x18e, 0x3601)
    assembler.half(0x190, _store_half(6, 4))
    assembler.half(0x192, _store_half(1, 5))
    assembler.half(0x194, 0xBD00)
    return assembler.finish()


class Indexed20WriterQueries(unittest.TestCase):
    def test_profile_uses_largest_linked_window_on_one_bus(self):
        small = {'width': 96, 'height': 64, 'x_origin': 0, 'y_origin': 0,
                 'command_port': 0x20000000, 'data_port': 0x20040000,
                 '_clear_owner': 0x100}
        full = {'width': 240, 'height': 320, 'x_origin': 0, 'y_origin': 64,
                'command_port': 0x20000000, 'data_port': 0x20040000,
                '_clear_owner': 0x100}
        selected = indexed20_writer._select_profile((small, full))
        self.assertEqual({key: selected[key] for key in full if not key.startswith('_')},
                         {key: full[key] for key in full if not key.startswith('_')})
        self.assertIsNone(indexed20_writer._select_profile(
            (small, {**full, 'data_port': 0x20080000})))
        self.assertIsNone(indexed20_writer._select_profile(
            (full, {**full, 'y_origin': 96})))
        self.assertIsNone(indexed20_writer._select_profile(
            (small, {**full, '_clear_owner': 0x200})))
        self.assertIsNone(indexed20_writer._select_profile(
            (small, {**full, 'y_origin': 32})))
        self.assertNotIn('_clear_owner', selected)

    def test_unknown_geometry_arguments_decline_without_arithmetic_errors(self):
        arguments = {a.ARM_REG_R0: 0, a.ARM_REG_R1: 239,
                     a.ARM_REG_R2: 0, a.ARM_REG_R3: 319}
        self.assertEqual(indexed20_writer._window_geometry(arguments), (240, 320))
        for register in (a.ARM_REG_R1, a.ARM_REG_R3):
            self.assertIsNone(indexed20_writer._window_geometry(
                {**arguments, register: None}))
        self.assertIsNone(indexed20_writer._window_geometry(
            {**arguments, a.ARM_REG_R3: True}))

    def test_rgb332_palette_expands_channels_to_rgb565(self):
        palette = indexed20_writer._rgb332_palette()
        self.assertEqual(len(palette), 512)
        colors = struct.unpack('<256H', palette)
        self.assertEqual(colors[0x00], 0x0000)
        self.assertEqual(colors[0xe0], 0xf800)
        self.assertEqual(colors[0x1c], 0x07e0)
        self.assertEqual(colors[0x03], 0x001f)
        self.assertEqual(colors[0xff], 0xffff)

    def test_palette_values_prove_rgb565_and_reject_mutation_or_bgr555(self):
        palette = indexed20_writer._rgb332_palette()
        self.assertTrue(indexed20_writer._has_rgb565_indexed_palette(
            palette + bytes(512), 0))
        mutated = bytearray(palette)
        mutated[2] ^= 1
        self.assertFalse(indexed20_writer._has_rgb565_indexed_palette(
            bytes(mutated), 0))
        bgr555 = []
        for index in range(256):
            red, green, blue = index >> 5, (index >> 2) & 7, index & 3
            red5 = red << 2 | red >> 1
            green5 = green << 2 | green >> 1
            blue5 = blue << 3 | blue << 1 | blue >> 1
            bgr555.append(blue5 << 10 | green5 << 5 | red5)
        self.assertFalse(indexed20_writer._has_rgb565_indexed_palette(
            struct.pack('<256H', *bgr555), 0))

    def test_synthetic_window_and_cursor_helpers_link_ports_and_origin_values(self):
        image = _indexed_helpers()
        facts = facts_for(image)
        calls, windows, cursors = indexed20_writer._candidate_functions(facts)
        self.assertTrue(calls)
        self.assertEqual(windows, [(0x100, 0x20000000, 0x20080000)])
        self.assertEqual(cursors, [(0x180, 0x20000000, 0x20080000)])

        window = facts.function(CodeAddress(0x100), budget=128,
            initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: 239,
                               a.ARM_REG_R2: 96, a.ARM_REG_R3: 415})
        cursor = facts.function(CodeAddress(0x180), budget=96,
            initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: 96})
        self.assertEqual(tuple(value for _, value in
                         indexed20_writer._writes(window, 0x20000000)),
                         (0x210, 0x211, 0x212, 0x213))
        self.assertEqual(tuple(value for _, value in
                         indexed20_writer._writes(window, 0x20080000)),
                         (0, 239, 96, 415))
        self.assertEqual(tuple(value for _, value in
                         indexed20_writer._writes(cursor, 0x20080000)), (0, 96))

        wrong_origin = facts.function(CodeAddress(0x100), budget=128,
            initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: 239,
                               a.ARM_REG_R2: 95, a.ARM_REG_R3: 414})
        self.assertNotEqual(tuple(value for _, value in
                            indexed20_writer._writes(wrong_origin, 0x20080000)),
                            (0, 239, 96, 415))

    def test_cursor_data_port_mismatch_does_not_close_writer_pair(self):
        facts = facts_for(_indexed_helpers(cursor_data_port=0x20080004))
        _, windows, cursors = indexed20_writer._candidate_functions(facts)
        self.assertEqual(windows, [(0x100, 0x20000000, 0x20080000)])
        self.assertEqual(cursors, [(0x180, 0x20000000, 0x20080004)])
        self.assertFalse(set(windows) & set(cursors))

    def test_clear_pairs_later_parameterized_window_with_its_following_command(self):
        def call(site, target, values):
            registers = tuple((register, value) for register, value in zip(
                (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3), values))
            return SimpleNamespace(site=CodeAddress(site),
                target=SimpleNamespace(address=target), registers=registers)

        clear = SimpleNamespace(
            literals=(SimpleNamespace(value=0x20040000),),
            call_sites=(
                call(0x10, 0x100, (0, 95, 0, 63)),
                call(0x20, 0x180, (0, 0, None, None)),
                call(0x30, 0x100, (0, 239, 0, 319)),
                call(0x40, 0x190, (0, 0, None, None)),
            ),
            accesses=(
                SimpleNamespace(operation='write', address=0x20000000,
                    width=2, value=0x202, instruction=CodeAddress(0x24)),
                SimpleNamespace(operation='write', address=0x20000000,
                    width=2, value=0x202, instruction=CodeAddress(0x44)),
            ),
        )
        with patch.object(indexed20_writer, '_pixel_count_loops', return_value=True):
            setups = indexed20_writer._clear_setups(
                clear, object(), 0x20000000, 0x20040000,
                0x100, {0x180, 0x190}, {0x100})
        self.assertEqual([(item[3], item[4], item[2].instruction.address)
                          for item in setups], [(96, 64, 0x24), (240, 320, 0x44)])

    def test_clear_window_requires_nearest_cursor_and_rejects_bad_origin(self):
        def call(site, target, values):
            registers = tuple((register, value) for register, value in zip(
                (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3), values))
            return SimpleNamespace(site=CodeAddress(site),
                target=SimpleNamespace(address=target), registers=registers)

        clear = SimpleNamespace(
            literals=(SimpleNamespace(value=0x20040000),),
            call_sites=(call(0x10, 0x100, (0, 239, 0, 319)),
                        call(0x20, 0x180, (1, 0, None, None))),
            accesses=(SimpleNamespace(operation='write', address=0x20000000,
                width=2, value=0x202, instruction=CodeAddress(0x24)),))
        with patch.object(indexed20_writer, '_pixel_count_loops', return_value=True):
            self.assertEqual(indexed20_writer._clear_setups(
                clear, object(), 0x20000000, 0x20040000,
                0x100, {0x180}, {0x100}), ())

    def test_bootstrap_metadata_without_linked_code_is_rejected(self):
        image = bytes(0x10000)
        bootstrap = {'stage_source': 0, 'stage_size': len(image), 'evidence': []}
        with patch.object(indexed20_writer, 'find_boot_nand', return_value=bootstrap,
                          create=True):
            self.assertIsNone(indexed20_writer.find_indexed20(image))

    def test_clear_loop_accepts_source_proven_zero_halfword(self):
        class LoopFacts:
            def __init__(self):
                self.instructions = {
                    0x100: SimpleNamespace(id=a.ARM_INS_MOVS, cc=a.ARM_CC_AL,
                        operands=(SimpleNamespace(type=a.ARM_OP_REG, reg=a.ARM_REG_R0),
                                  SimpleNamespace(type=a.ARM_OP_IMM, imm=240))),
                    0x106: SimpleNamespace(id=a.ARM_INS_SUB, cc=a.ARM_CC_AL,
                        operands=(SimpleNamespace(type=a.ARM_OP_REG, reg=a.ARM_REG_R1),
                                  SimpleNamespace(type=a.ARM_OP_IMM, imm=1))),
                    0x108: SimpleNamespace(id=a.ARM_INS_B, cc=a.ARM_CC_HS, operands=()),
                    0x10e: SimpleNamespace(id=a.ARM_INS_SUB, cc=a.ARM_CC_AL,
                        operands=(SimpleNamespace(type=a.ARM_OP_REG, reg=a.ARM_REG_R2),
                                  SimpleNamespace(type=a.ARM_OP_IMM, imm=1))),
                    0x110: SimpleNamespace(id=a.ARM_INS_B, cc=a.ARM_CC_HS, operands=()),
                }

            def decode(self, address):
                return self.instructions.get(address.address)

            def register_value(self, function, address, register, *, cut_edges):
                return SymbolicValue.const(319)

        facts = LoopFacts()

        def function_with_clear(pixel):
            access = SimpleNamespace(operation='write', address=0x20080000,
                width=2, value=pixel, instruction=CodeAddress(0x104))
            return SimpleNamespace(accesses=(access,),
                back_edges=((0x108, 0x102), (0x110, 0x100)))

        self.assertTrue(indexed20_writer._pixel_count_loops(
            function_with_clear(0), facts, 0x20080000, 240, 320))
        self.assertTrue(indexed20_writer._pixel_count_loops(
            function_with_clear(0), facts, 0x20080000, 240, 320, after=0x102))
        self.assertFalse(indexed20_writer._pixel_count_loops(
            function_with_clear(0), facts, 0x20080000, 240, 320, after=0x104))
        self.assertFalse(indexed20_writer._pixel_count_loops(
            function_with_clear(None), facts, 0x20080000, 240, 320))

    def test_custom_palette_requires_byte_index_scale_and_framebuffer_store(self):
        def register(number):
            return SimpleNamespace(type=a.ARM_OP_REG, reg=number)

        def immediate(value):
            return SimpleNamespace(type=a.ARM_OP_IMM, imm=value)

        def memory(base, index=0, displacement=0):
            return SimpleNamespace(type=a.ARM_OP_MEM,
                mem=SimpleNamespace(base=base, index=index, disp=displacement))

        class DecoderFacts:
            def __init__(self, shift, linked=True):
                self.linked = linked
                self.instructions = {
                    0: SimpleNamespace(id=a.ARM_INS_PUSH,
                        operands=(register(a.ARM_REG_R2),)),
                    2: SimpleNamespace(id=a.ARM_INS_MOV,
                        operands=(register(a.ARM_REG_R4), register(a.ARM_REG_R2))),
                    4: SimpleNamespace(id=a.ARM_INS_LSL,
                        operands=(register(a.ARM_REG_R6), register(a.ARM_REG_R6), immediate(shift))),
                    6: SimpleNamespace(id=a.ARM_INS_LDRH,
                        operands=(register(a.ARM_REG_R6), memory(a.ARM_REG_R7, a.ARM_REG_R6))),
                    8: SimpleNamespace(id=a.ARM_INS_ADD,
                        operands=(register(a.ARM_REG_R1), register(a.ARM_REG_R4), register(a.ARM_REG_R0))),
                    10: SimpleNamespace(id=a.ARM_INS_STRH,
                        operands=(register(a.ARM_REG_R6), memory(a.ARM_REG_R1))),
                    12: SimpleNamespace(id=a.ARM_INS_LDRB,
                        operands=(register(a.ARM_REG_R0), memory(a.ARM_REG_R5, displacement=0))),
                    14: SimpleNamespace(id=a.ARM_INS_LDRB,
                        operands=(register(a.ARM_REG_R0), memory(a.ARM_REG_R5, displacement=3))),
                    16: SimpleNamespace(id=a.ARM_INS_LDRB,
                        operands=(register(a.ARM_REG_R0), memory(a.ARM_REG_R5, displacement=4))),
                }

            def decode(self, address):
                return self.instructions.get(address.address)

            def literal(self, address):
                return None

            def function(self, address, *, budget):
                return SimpleNamespace(instructions=())

            def literal_references(self, value):
                if value == 0x400 and self.linked:
                    return (SimpleNamespace(instruction=CodeAddress(6),
                                            register=a.ARM_REG_R7),)
                return ()

        function = SimpleNamespace(instructions=tuple(CodeAddress(pc)
            for pc in range(0, 18, 2)))
        self.assertTrue(indexed20_writer._decoder_shape(
            function, DecoderFacts(1), 0x400, a.ARM_REG_R5, indexed_palette=True))
        self.assertFalse(indexed20_writer._decoder_shape(
            function, DecoderFacts(2), 0x400, a.ARM_REG_R5, indexed_palette=True))
        self.assertFalse(indexed20_writer._decoder_shape(
            function, DecoderFacts(1, linked=False), 0x400,
            a.ARM_REG_R5, indexed_palette=True))


if __name__ == '__main__':
    unittest.main()
