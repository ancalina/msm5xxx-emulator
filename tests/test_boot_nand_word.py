"""Synthetic source-shape checks for the word-command NAND rule."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.storage.boot_nand_word import (
    _stage_callback_functions, find_boot_nand_word,
)
from msm5xxx_emulator.detection.devices.storage.boot_nand_word_helpers import (
    _getter, _fixed_row_installer,
)
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


_BASE = 0xffff0000


def _arm_function(words: tuple[int, ...]):
    image = bytearray(0x100)
    struct.pack_into(f'<{len(words)}I', image, 0x20, *words)
    return image, _BASE + 0x20


class WordNandSourceQueryTests(unittest.TestCase):
    def test_stage_callback_controls_follow_only_complete_two_level_links(self):
        image = bytearray(0x100)
        struct.pack_into('<4I', image, 0, 1, 3, 7, 0)
        make = lambda address, isa='thumb', complete=True, calls=(): NS(
            entry=CodeAddress(address, isa), instructions=(CodeAddress(address, isa),),
            complete=complete, unresolved=(), truncated=False, calls=calls,
            accesses=(),)
        bodies = {
            (0, 'thumb'): make(0, calls=((CodeAddress(0, 'thumb'),
                                         CodeAddress(0x20, 'arm')),)),
            (2, 'thumb'): make(2, calls=((CodeAddress(2, 'thumb'),
                                         CodeAddress(0x20, 'arm')),)),
            (6, 'thumb'): make(6, complete=False,
                               calls=((CodeAddress(6, 'thumb'),
                                       CodeAddress(0x50, 'thumb')),)),
            (0x20, 'arm'): make(0x20, 'arm', calls=((CodeAddress(0x20, 'arm'),
                                                      CodeAddress(0x40, 'thumb')),)),
            (0x40, 'thumb'): make(0x40, calls=((CodeAddress(0x40, 'thumb'),
                                                CodeAddress(0x60, 'arm')),)),
            (0x50, 'thumb'): make(0x50),
            (0x60, 'arm'): make(0x60, 'arm'),
        }
        facts = NS(image=bytes(image))
        def lookup(_facts, pointer, *, budget):
            isa = 'thumb' if pointer & 1 else 'arm'
            return bodies[(pointer & ~1, isa)]
        with patch('msm5xxx_emulator.detection.devices.storage.boot_nand_word._function',
                   side_effect=lookup):
            found = _stage_callback_functions(
                facts, {'table': [0, 16], 'function': object()})
        self.assertEqual({(fn.entry.address, fn.entry.isa) for fn in found},
                         {(0, 'thumb'), (2, 'thumb'), (0x20, 'arm'),
                          (0x40, 'thumb')})

    def test_getter_accepts_word_read_at_requested_field(self):
        image, pointer = _arm_function((0xE590006C, 0xE12FFF1E))
        found = _getter(facts_for(bytes(image), base=_BASE), pointer, 0x6c)
        self.assertIsNotNone(found)

    def test_getter_rejects_wrong_offset_width_and_return(self):
        cases = (
            ((0xE5900068, 0xE12FFF1E), 0x6c),  # Wrong field.
            ((0xE5D0006C, 0xE12FFF1E), 0x6c),  # Byte read.
            ((0xE590006C, 0xE12FFF10), 0x6c),  # BX through another register.
        )
        for words, field in cases:
            with self.subTest(words=words):
                image, pointer = _arm_function(words)
                self.assertIsNone(_getter(facts_for(bytes(image), base=_BASE),
                                          pointer, field))

    def test_capacity_getter_accepts_two_word_reads_and_subtract(self):
        image, pointer = _arm_function((
            0xE5901060,  # LDR r1, [r0, #0x60]
            0xE590005C,  # LDR r0, [r0, #0x5c]
            0xE0410000,  # SUB r0, r1, r0
            0xE12FFF1E,  # BX lr
        ))
        found = _getter(facts_for(bytes(image), base=_BASE), pointer, 'capacity')
        self.assertIsNotNone(found)

    def test_capacity_getter_rejects_wrong_offset_or_return(self):
        cases = (
            (0xE590105C, 0xE590005C, 0xE0410000, 0xE12FFF1E),
            (0xE5901060, 0xE590005C, 0xE0410000, 0xE12FFF10),
        )
        for words in cases:
            with self.subTest(words=words):
                image, pointer = _arm_function(words)
                self.assertIsNone(_getter(facts_for(bytes(image), base=_BASE),
                                          pointer, 'capacity'))

    def test_metadata_and_table_without_reset_linkage_do_not_match(self):
        image = bytearray(0x14000)
        struct.pack_into('<3I', image, 0x2000, 0x4000, 0, 0x4000)
        struct.pack_into('<14I', image, 0x100,
                         0xffff0101, 0xffff0101, 0xffff0101, 0xffff0101,
                         0xffff0101, 0xffff0101, 0xffff0101, 0xffff0101,
                         0xffff0101, 0xffff0101, 0xffff0101, 0,
                         0xffff0101, 0xffff0101)
        struct.pack_into('<9I', image, 0x15c,
                         0xffff0200, 0x1000, 32, 512, 528, 0x98, 0x76, 1, 0)
        struct.pack_into('<9I', image, 0x180,
                         0xffff0204, 0x800, 32, 512, 528, 0x98, 0x75, 2, 0)
        struct.pack_into('<II', image, 0x300, 0x64000300, 0x80000940)
        self.assertIsNone(find_boot_nand_word(bytes(image)))

    @staticmethod
    def _fixed_row_sample(*, discriminator=2, branch_condition=None,
                          branch_target_delta=0, table_delta=0, row_store=True,
                          copy_sizes=(0x5c, 0x24)):
        arm = __import__('capstone').arm
        mem = lambda base, disp: NS(type=arm.ARM_OP_MEM,
                                    mem=NS(base=base, disp=disp))
        imm = lambda value: NS(type=arm.ARM_OP_IMM, imm=value)
        reg = lambda value: NS(type=arm.ARM_OP_REG, reg=value)
        instructions = {
            0x00: NS(id=arm.ARM_INS_MOVS, size=2, operands=[reg(arm.ARM_REG_R0), imm(0)]),
            0x02: NS(id=arm.ARM_INS_MOVS, size=2, operands=[reg(arm.ARM_REG_R3), imm(0x24)]),
            0x04: NS(id=arm.ARM_INS_MUL, size=2, operands=[reg(arm.ARM_REG_R0),
                     reg(arm.ARM_REG_R3), reg(arm.ARM_REG_R0)]),
            0x06: NS(id=arm.ARM_INS_LDR, size=2, operands=[reg(arm.ARM_REG_R1),
                     mem(arm.ARM_REG_PC, 0x100)]),
            0x08: NS(id=arm.ARM_INS_ADD, size=2, operands=[reg(arm.ARM_REG_R5),
                     reg(arm.ARM_REG_R0), reg(arm.ARM_REG_R1)]),
            0x0a: NS(id=arm.ARM_INS_LDR, size=2, operands=[reg(arm.ARM_REG_R0),
                     mem(arm.ARM_REG_R5, 0x1c)]),
            0x0c: NS(id=arm.ARM_INS_CMP, size=2, operands=[reg(arm.ARM_REG_R0),
                     imm(discriminator)]),
            0x0e: NS(id=arm.ARM_INS_B, size=2,
                     cc=arm.ARM_CC_NE if branch_condition is None else branch_condition,
                     operands=[imm(0x1c + branch_target_delta)]),
            0x10: NS(id=arm.ARM_INS_SUBS, size=2,
                     operands=[reg(arm.ARM_REG_R0), imm(3)]),
            0x12: NS(id=arm.ARM_INS_POP, size=2, operands=[reg(arm.ARM_REG_PC)]),
            0x30: NS(id=arm.ARM_INS_MOVS, size=2, operands=[reg(arm.ARM_REG_R2), imm(0x5c)]),
            0x32: NS(id=arm.ARM_INS_SUBS, size=2, operands=[reg(arm.ARM_REG_R1), imm(0x5c)]),
            0x34: NS(id=arm.ARM_INS_ADD, size=2, operands=[reg(arm.ARM_REG_R0),
                     reg(arm.ARM_REG_R4), imm(0)]),
            0x36: NS(id=arm.ARM_INS_BLX, size=2, operands=[imm(0x200)]),
            0x38: NS(id=arm.ARM_INS_MOVS, size=2, operands=[reg(arm.ARM_REG_R2), imm(0x24)]),
            0x3a: NS(id=arm.ARM_INS_ADD, size=2, operands=[reg(arm.ARM_REG_R1),
                     reg(arm.ARM_REG_R5), imm(0)]),
            0x3c: NS(id=arm.ARM_INS_ADD, size=2, operands=[reg(arm.ARM_REG_R0),
                     reg(arm.ARM_REG_R4), imm(0)]),
            0x3e: NS(id=arm.ARM_INS_ADD, size=2, operands=[reg(arm.ARM_REG_R0), imm(0x64)]),
            0x40: NS(id=arm.ARM_INS_BLX, size=2, operands=[imm(0x200)]),
            0x42: NS(id=arm.ARM_INS_MOVS, size=2, operands=[reg(arm.ARM_REG_R0), imm(0)]),
            0x44: NS(id=arm.ARM_INS_STR, size=2,
                     operands=[reg(arm.ARM_REG_R0), mem(arm.ARM_REG_R4, 0x5c)]),
            0x46: NS(id=arm.ARM_INS_LDR, size=2,
                     operands=[reg(arm.ARM_REG_R0), mem(arm.ARM_REG_R5, 4)]),
            0x48: NS(id=arm.ARM_INS_STR if row_store else arm.ARM_INS_STRB, size=2,
                     operands=[reg(arm.ARM_REG_R0), mem(arm.ARM_REG_R4, 0x60)]),
            0x2e: NS(id=arm.ARM_INS_LDR, size=2,
                     operands=[reg(arm.ARM_REG_R1), mem(arm.ARM_REG_PC, 0x100)]),
        }
        pool_image = bytearray(0x200)
        struct.pack_into('<I', pool_image, 0x108, _BASE + 0x500 + table_delta)
        pc = lambda address: NS(address=_BASE + address)
        target = CodeAddress(0x200, 'arm')
        site_addresses = (0x36, 0x40)
        sites = tuple(NS(site=CodeAddress(_BASE + site_address, 'thumb'), target=target,
            registers=((arm.ARM_REG_R2, size),
            (arm.ARM_REG_R1, _BASE + 0x500 - 0x5c if size == 0x5c else None)))
            for site_address, size in zip(site_addresses, copy_sizes))
        branch_target = _BASE + 0x2e + branch_target_delta
        function = NS(complete=True, unresolved=(), truncated=False,
                      literals=(NS(value=_BASE + 0x500),),
                      instructions=tuple(pc(address) for address in instructions),
                      call_sites=sites,
                      control_edges=((CodeAddress(_BASE + 0x0e, 'thumb'),
                                      CodeAddress(branch_target, 'thumb')),
                                     (CodeAddress(_BASE + 0x0e, 'thumb'),
                                      CodeAddress(_BASE + 0x10, 'thumb'))))
        facts = NS(base=_BASE, image=bytes(pool_image),
                   decode=lambda item: instructions[item.address - _BASE])
        return facts, function

    def test_fixed_row_installer_proves_mode_reject_and_two_copy_sizes(self):
        facts, function = self._fixed_row_sample()
        with patch('msm5xxx_emulator.detection.devices.storage.boot_nand_word_helpers._copy_provider',
                   return_value=object()):
            result = _fixed_row_installer(facts, function, _BASE + 0x500)
        self.assertIsNotNone(result)
        self.assertEqual(len(result[1]), 2)

    def test_fixed_row_installer_rejects_changed_mode_copy_and_installation(self):
        cases = (
            {'discriminator': 3},
            {'branch_condition': __import__('capstone').arm.ARM_CC_EQ},
            {'branch_target_delta': 2},
            {'table_delta': 4},
            {'copy_sizes': (0x5c, 0x20)},
            {'row_store': False},
        )
        for changes in cases:
            facts, function = self._fixed_row_sample(**changes)
            with self.subTest(changes=changes), patch(
                    'msm5xxx_emulator.detection.devices.storage.boot_nand_word_helpers._copy_provider',
                    return_value=object()):
                self.assertIsNone(_fixed_row_installer(facts, function, _BASE + 0x500))


if __name__ == '__main__':
    unittest.main()
