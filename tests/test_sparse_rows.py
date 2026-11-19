"""Synthetic instruction evidence for descriptor-owned sparse GPIO rows."""
from __future__ import annotations

import struct
import copy
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from nor_fixtures import copy_consumer_fixture
from test_startup_entry import reset_entry_fixture
from msm5xxx_emulator.detection.devices.input.event_projection import (
    _matrix_input_position,
)
from msm5xxx_emulator.detection.devices.input.sparse_rows import (
    find_sparse_row_scanners,
    sparse_row_property,
)
from msm5xxx_emulator.detection.devices.input.startup_copy import (
    reset_linked_input_copy,
)
from msm5xxx_emulator.detection.devices.input.row_execution import _row_outputs
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import (
    matrix_input_command,
)
from msm5xxx_emulator.detection.registry import device_domain

HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


def _put16(image: bytearray, address: int, value: int) -> None:
    struct.pack_into("<H", image, address, value)


def _put32(image: bytearray, address: int, value: int) -> None:
    struct.pack_into("<I", image, address, value)


def _branch(image: bytearray, site: int, condition: int, target: int) -> None:
    delta = (target - site - 4) // 2
    assert -128 <= delta <= 127
    _put16(image, site, 0xD000 | (condition << 8) | (delta & 0xFF))


def _unconditional(image: bytearray, site: int, target: int) -> None:
    delta = (target - site - 4) // 2
    assert -1024 <= delta <= 1023
    _put16(image, site, 0xE000 | (delta & 0x7FF))


def _linked_copy_reset_fixture() -> bytearray:
    """Emit a reset-linked Thumb word copier and three-cell copy row."""
    image = bytearray(0x5000)
    ram, entry, table = 0x01000000, 0x100, 0x300
    image[:0x100] = reset_entry_fixture()[:0x100]

    # The copier dereferences source, destination, and length cells that are
    # also used by its code-proven word loop.
    for offset, word in ((0x00, 0x4800 | (0x7C // 4)),
                         (0x02, 0x4F00 | (0x80 // 4)),
                         (0x04, 0x6802),       # LDR r2, [r0]
                         (0x06, 0x683F),       # LDR r7, [r7]
                         (0x08, 0x19D6),       # ADDS r6, r2, r7
                         (0x0A, 0x4B00 | (0x7C // 4)),
                         (0x0C, 0x681D),       # LDR r5, [r3]
                         (0x0E, 0x6804),       # LDR r4, [r0]
                         (0x10, 0xE003),       # B to loop compare
                         (0x12, 0x6828),       # LDR r0, [r5]
                         (0x14, 0x6020),       # STR r0, [r4]
                         (0x16, 0x3504),       # ADDS r5, #4
                         (0x18, 0x3404),       # ADDS r4, #4
                         (0x1A, 0x42B4),       # CMP r4, r6
                         (0x1C, 0xD3F9),       # BLO loop load
                         (0x1E, 0x4770)):      # BX LR
        _put16(image, entry + offset, word)
    _put32(image, entry + 0x80, table + 4)
    _put32(image, entry + 0x84, table + 8)
    _put32(image, entry + 0x88, table)
    _put32(image, table, 0x1000)
    _put32(image, table + 4, ram)
    _put32(image, table + 8, 0x1000)
    image[0x1000:0x2000] = bytes((index & 255) for index in range(0x1000))
    return image


def _call_linked_copy_reset_fixture(*, orphan=False, wrong_argument=False,
                                    short_copy=False) -> bytearray:
    """Emit reset -> Thumb call -> argument BX -> ARM vector -> Thumb copier."""
    image = _linked_copy_reset_fixture()
    ram, copier, table = 0x01000000, 0x300, 0x500
    image[0x100:0x122] = bytes(0x22)
    # The caller passes a code address to a tiny BX-R0 argument stub.
    _put16(image, 0x100, 0x4800 | (0x7C // 4))  # LDR r0,[PC,#0x7c] -> 0x180
    _bl(image, 0x102, 0x120)
    _put16(image, 0x106, 0x4770)
    _put32(image, 0x180, (0x200 if not wrong_argument else 0x5F01))
    _put16(image, 0x120, 0x4700)  # BX r0 -> ARM vector 0x200
    _put32(image, 0x200, 0xE59F1004)  # LDR r1,[PC,#4] -> 0x20c
    _put32(image, 0x204, 0xE12FFF11)  # BX r1 -> Thumb veneer 0x240
    _put32(image, 0x20C, 0x241)
    _put16(image, 0x240, 0xE05E)  # B 0x300, the copier body
    body = _linked_copy_reset_fixture()
    image[copier:copier + 0x20] = body[0x100:0x120]
    _put32(image, copier + 0x80, table + 4)
    _put32(image, copier + 0x84, table + 8)
    _put32(image, copier + 0x88, table)
    _put32(image, table, 0x1000)
    _put32(image, table + 4, ram)
    _put32(image, table + 8, 0x1000 if not short_copy else 0x800)
    if orphan:
        # Remove the caller's only reset-rooted entry by changing the reset
        # vector branch to a disjoint valid instruction loop.
        _put32(image, 0, 0xEA00003E)
    return image


def _bl(image: bytearray, site: int, target: int) -> None:
    delta = target - site - 4
    _put16(image, site, 0xF000 | ((delta >> 12) & 0x7FF))
    _put16(image, site + 2, 0xF800 | ((delta >> 1) & 0x7FF))


def _mapped_irq_helper(image: bytearray, entry: int, *, enable: bool) -> None:
    """Emit the accepted source-qualified ARM body behind a Thumb BX LR stub."""
    _put16(image, entry, 0x4778)  # BX LR
    _put16(image, entry + 2, 0x0000)
    words = (0xE10F0000,
             0xE3C010C0 if enable else 0xE38010C0,
             0xE121F001, 0xE20000C0, 0xE12FFF1E)
    for offset, word in enumerate(words):
        _put32(image, entry + 4 + offset * 4, word)


def _image(*, preloop_clear: bool = False) -> bytearray:
    image = bytearray(0x5000)
    ram, descriptor_rom = 0x01000000, 0x1100
    descriptor, row_table_rom = ram + 0x100, 0x1200
    event_table, column_table = 0x1800, 0x1900
    function, loop = 0x400, 0x4FC if preloop_clear else 0x500
    sense = 0x5C8
    end = sense + 24
    pool = 0x800
    pool_values: dict[int, int] = {}

    # Link the source fixture through reset and a bounded copy consumer.
    consumer, copy_row = copy_consumer_fixture()
    image[0x100:len(consumer)] = consumer[0x100:]
    image[:0x100] = reset_entry_fixture()[:0x100]
    _put32(image, 0x80, ram + 0x1000)
    struct.pack_into("<5I", image, copy_row.table,
                     0x1000, ram, 0x1000, ram + 0x1000, 0x40)
    _put32(image, descriptor_rom + 0x10, 0x03000720)
    _put32(image, descriptor_rom + 0x20, ram + 0x200)
    _put32(image, descriptor_rom + 0x34, 0x0300072C)
    physical_bits = (4, 0, 5, 2, 3, 1)
    struct.pack_into("<6H", image, row_table_rom,
                     *(0xFFFF ^ (1 << bit) for bit in physical_bits))

    def literal(site: int, register: int, value: int) -> None:
        nonlocal pool
        slot = pool_values.get(value)
        if slot is None:
            slot = pool
            pool += 4
            pool_values[value] = slot
            _put32(image, slot, value)
        displacement = slot - ((site + 4) & ~3)
        assert 0 <= displacement <= 1020 and displacement % 4 == 0
        _put16(image, site, 0x4800 | (register << 8) | (displacement // 4))

    # Establish a zero row counter and make a descriptor-backed presence read.
    _put16(image, function, 0xB580)       # PUSH {r7, lr}
    _put16(image, function + 2, 0x2700)   # MOVS r7, #0
    literal(function + 0x1C, 4, descriptor)
    _put16(image, function + 0x1E, 0x6B60)
    presence = function + 0x20
    for offset, word in enumerate((0x8800, 0x0700, 0x0F00, 0x280F)):
        _put16(image, presence + offset * 2, word)
    _unconditional(image, presence + 8, loop)

    # Dispatch each logical row to a code arm. The six physical wires are
    # permuted across 0x720 and 0x724, with one selected active-low pin each.
    if preloop_clear:
        clear = 0x1080
        clear_pool = 0x1100
        _bl(image, loop, clear)
        _put16(image, clear, 0xB500)  # PUSH {lr}
        _bl(image, clear + 2, 0x1000)
        _put16(image, clear + 6, 0x4900 | ((clear_pool - (((clear + 6) + 4) & ~3)) // 4))
        _put32(image, clear_pool, descriptor)
        clear_words = {
            8: 0x233F, 10: 0x8B8A, 12: 0x021B, 14: 0x439A,
            16: 0x838A, 18: 0x8B8A, 20: 0x6909, 22: 0x800A,
            24: 0x2800, 32: 0xBC08, 34: 0x4718,
        }
        for offset, value in clear_words.items():
            _put16(image, clear + offset, value)
        _branch(image, clear + 26, 1, clear + 32)
        _bl(image, clear + 28, 0x1020)
        _mapped_irq_helper(image, 0x1000, enable=False)
        _mapped_irq_helper(image, 0x1020, enable=True)

    cursor = loop + (4 if preloop_clear else 0)
    _put16(image, cursor, 0x2F06)  # CMP r7,#6; outer row bound
    _branch(image, cursor + 2, 2, sense)  # BHS after the six-row scan
    cursor += 4
    _bl(image, cursor, 0x1000)  # CPSR lock helper
    cursor += 4
    dispatch: list[tuple[int, int]] = []
    for row in range(6):
        _put16(image, cursor, 0x2F00 | row)
        _put16(image, cursor + 2, 0xD000)
        dispatch.append((cursor + 2, row))
        cursor += 4
    default_branch = cursor
    cursor += 2
    arms = []
    selected_wires = ((0x03000720, 0x0010),
                      (0x03000720, 0x0001),
                      (0x03000724, 0x0020),
                      (0x03000720, 0x0004),
                      (0x03000724, 0x0008),
                      (0x03000724, 0x0002))
    exits = []
    for selected_port, selected_mask in selected_wires:
        arms.append(cursor)
        for port, shadow_offset in ((0x03000720, 0x0C),
                                    (0x03000724, 0x1C)):
            if port == selected_port:
                literal(cursor, 4, descriptor); cursor += 2
                _put16(image, cursor,
                       0x8800 | (shadow_offset // 2 << 6) | (4 << 3))
                cursor += 2  # LDRH r0,[r4,#shadow_offset]
                literal(cursor, 1, 0xFFFF); cursor += 2
                _put16(image, cursor, 0x4308); cursor += 2  # ORRS r0,r1
                literal(cursor, 1, selected_mask); cursor += 2
                _put16(image, cursor, 0x4388); cursor += 2  # BICS r0,r1
                _put16(image, cursor,
                       0x8000 | (shadow_offset // 2 << 6) | (4 << 3))
                cursor += 2  # STRH r0,[r4,#shadow_offset]
            else:
                literal(cursor, 0, 0xFFFF); cursor += 2
            literal(cursor, 4, port); cursor += 2
            _put16(image, cursor, 0x8020); cursor += 2  # STRH r0,[r4]
        exits.append(cursor)
        _put16(image, cursor, 0xE000)  # patched to the common unlock
        cursor += 2
    common = cursor
    _bl(image, common, 0x1020)  # CPSR unlock helper
    _put16(image, common + 4, 0x46C0)  # Harmless fallthrough to the scan read.
    for branch_site, row in dispatch:
        _branch(image, branch_site, 0, arms[row])
    _unconditional(image, default_branch, common)
    for site in exits:
        _unconditional(image, site, common)
    assert common + 6 == sense - 4

    # Descriptor pointer, active-low column read, and an arithmetic event
    # lookup: a nibble table maps the four column sense values, then MULS 6
    # and ADDS row form column*6+row before the byte load.
    literal(sense - 4, 4, descriptor)
    _put16(image, sense - 2, 0x6B60)
    for offset, word in enumerate((0x8800, 0x0700, 0x0F00, 0x280F)):
        _put16(image, sense + offset * 2, word)
    cursor = sense + 10
    literal(cursor, 2, column_table); cursor += 2
    _put16(image, cursor, 0x5C10); cursor += 2  # LDRB r0,[r2,r0]
    _put16(image, cursor, 0x2106); cursor += 2  # MOVS r1,#6
    _put16(image, cursor, 0x4348); cursor += 2  # MULS r0,r1
    _put16(image, cursor, 0x19C0); cursor += 2  # ADDS r0,r0,r7
    literal(cursor, 2, event_table); cursor += 2
    load_site = cursor
    _put16(image, load_site, 0x5C13); cursor += 2  # LDRB r3,[r2,r0]
    assert cursor == end

    for offset, word in enumerate((0x3701, 0x063F, 0x0E3F, 0x2F06)):
        _put16(image, end + offset * 2, word)
    _branch(image, end + 8, 11, loop)
    _branch(image, sense + 8, 0, end)
    _mapped_irq_helper(image, 0x1000, enable=False)
    _mapped_irq_helper(image, 0x1020, enable=True)

    column_map = bytearray(16)
    for raw, column in zip((14, 13, 11, 7), range(4)):
        column_map[raw] = column
    image[column_table:column_table + len(column_map)] = column_map
    image[event_table:event_table + 24] = bytes(range(0x40, 0x4C)) + b"123456789*0#"
    return image


def _seven_row_image(*, stack_counter: bool = False,
                     copied_masks: bool = False) -> tuple[bytearray, dict[str, int]]:
    """Emit a seven-row table switch with optional stack and copied-byte masks."""
    image = bytearray(0x5000)
    ram, descriptor_rom = 0x01000000, 0x2100
    descriptor, row_table_rom = ram + 0x100, 0x2200
    table, event_table = ram + 0x300, 0x1800
    mask_source = 0x2300
    function, loop = ((0x404, 0x802) if stack_counter else (0x402, 0x800))
    dispatch_table = loop + (26 if stack_counter else 24)
    stack_slot = 0x10 if stack_counter else None
    function_pool, code_pool = 0x700, 0xC00
    literal_values: dict[int, int] = {}
    next_literal = code_pool

    consumer, copy_row = copy_consumer_fixture()
    image[0x100:len(consumer)] = consumer[0x100:]
    image[:0x100] = reset_entry_fixture()[:0x100]
    _put32(image, 0x80, ram + 0x1000)
    struct.pack_into("<5I", image, copy_row.table,
                     0x2000, ram, 0x1000, ram + 0x1000, 0x40)
    _put32(image, descriptor_rom + 0x10, 0x03000720)
    _put32(image, descriptor_rom + 0x20, ram + 0x200)
    _put32(image, descriptor_rom + 0x34, 0x0300072C)

    def literal(site: int, register: int, value: int, *, pool: int | None = None) -> int:
        nonlocal next_literal
        if pool is None:
            slot = literal_values.get(value)
            if slot is None:
                slot = next_literal
                next_literal += 4
                literal_values[value] = slot
                _put32(image, slot, value)
        else:
            slot = pool
            _put32(image, slot, value)
        displacement = slot - ((site + 4) & ~3)
        assert 0 <= displacement <= 1020 and displacement % 4 == 0
        _put16(image, site, 0x4800 | register << 8 | displacement // 4)
        return slot

    # The descriptor's status field yields a pointer before the presence read.
    _put16(image, function, 0xB520)       # PUSH {r5, lr}
    if stack_counter:
        _put16(image, function + 2, 0xB088)  # SUB SP, #0x20
        _put16(image, function + 4, 0x2500)  # MOVS r5, #0
        literal(function + 6, 4, descriptor, pool=function_pool)
        _put16(image, function + 8, 0x6B61)  # LDR r1, [r4, #0x34]
        presence = function + 10
        for offset, word in enumerate((0x8808, 0x0700, 0x0F00, 0x280F)):
            _put16(image, presence + offset * 2, word)
        _unconditional(image, presence + 8, loop - 4)
        _put16(image, loop - 4, 0x2500)   # Dominating zero initialization.
        _put16(image, loop - 2, 0x9504)   # STR r5, [SP, #0x10]
    else:
        _put16(image, function + 2, 0x2500)  # MOVS r5, #0
        literal(function + 4, 4, descriptor, pool=function_pool)
        _put16(image, function + 6, 0x6B61)  # LDR r1, [r4, #0x34]
        presence = function + 8
        for offset, word in enumerate((0x8808, 0x0700, 0x0F00, 0x280F)):
            _put16(image, presence + offset * 2, word)
        _unconditional(image, presence + 8, loop)

    # Lock, compute a table address from row*2, load a halfword displacement,
    # and branch through PC. The table is based exactly at ADD PC's PC value.
    if stack_counter:
        _put16(image, loop, 0x9D04)        # LDR r5, [SP, #0x10]
        _put16(image, loop + 2, 0x2D07)    # CMP r5, #7
        _put16(image, loop + 4, 0xD200)    # patched BHS to the sense entry
        _bl(image, loop + 6, 0x1000)
        _put16(image, loop + 10, 0x46C0)
        _put16(image, loop + 12, 0xA403)   # ADR r4, dispatch_table
        _put16(image, loop + 14, 0x006A)   # LSLS r2, r5, #1
        _put16(image, loop + 16, 0x18A4)   # ADDS r4, r4, r2
        _put16(image, loop + 18, 0x8822)   # LDRH r2, [r4]
        _put16(image, loop + 20, 0x0052)   # LSLS r2, r2, #1
        _put16(image, loop + 22, 0x4497)   # ADD pc, r2
    else:
        _put16(image, loop, 0x2D07)        # CMP r5, #7
        _put16(image, loop + 2, 0xD200)    # patched BHS to the sense entry
        _bl(image, loop + 4, 0x1000)
        _put16(image, loop + 8, 0x46C0)
        _put16(image, loop + 10, 0xA403)   # ADR r4, dispatch_table
        _put16(image, loop + 12, 0x006A)   # LSLS r2, r5, #1
        _put16(image, loop + 14, 0x18A4)   # ADDS r4, r4, r2
        _put16(image, loop + 16, 0x8822)   # LDRH r2, [r4]
        _put16(image, loop + 18, 0x0052)   # LSLS r2, r2, #1
        _put16(image, loop + 20, 0x4497)   # ADD pc, r2
    row_table_start = dispatch_table
    arms_start = row_table_start + 14
    selected = ((0x03000720, 0x0004), (0x03000724, 0x0008),
                (0x03000720, 0x0001), (0x03000724, 0x0020),
                (0x03000720, 0x0040), (0x03000724, 0x0004),
                (0x03000720, 0x0002))
    arm_sites = []
    arm_exits = []
    cursor = arms_start
    for selected_port, selected_mask in selected:
        arm_sites.append(cursor)
        for port, shadow_offset in ((0x03000720, 0x0C),
                                    (0x03000724, 0x1C)):
            if port == selected_port:
                literal(cursor, 4, descriptor); cursor += 2
                _put16(image, cursor,
                       0x8800 | (shadow_offset // 2 << 6) | (4 << 3))
                cursor += 2
                literal(cursor, 1, 0xFFFF); cursor += 2
                _put16(image, cursor, 0x4308); cursor += 2
                if copied_masks:
                    literal(cursor, 3, table); cursor += 2
                    _put16(image, cursor, 0x5D59)  # LDRB r1, [r3, r5]
                    cursor += 2
                else:
                    literal(cursor, 1, selected_mask); cursor += 2
                _put16(image, cursor, 0x4388); cursor += 2
                _put16(image, cursor,
                       0x8000 | (shadow_offset // 2 << 6) | (4 << 3))
                cursor += 2
            else:
                literal(cursor, 0, 0xFFFF); cursor += 2
            literal(cursor, 4, port); cursor += 2
            _put16(image, cursor, 0x8020); cursor += 2
        arm_exits.append(cursor)
        _put16(image, cursor, 0xE000)      # patched to common unlock
        cursor += 2
    common = cursor
    for index, arm in enumerate(arm_sites):
        _put16(image, row_table_start + index * 2,
               (arm - row_table_start) // 2)
    _bl(image, common, 0x1020)
    _put16(image, common + 4, 0x46C0)
    _branch(image, loop + (4 if stack_counter else 2), 2, common + 10)
    for site in arm_exits:
        _unconditional(image, site, common)

    sense = common + 10
    literal(sense - 4, 4, descriptor)
    _put16(image, sense - 2, 0x6B60)      # LDR r0, [r4, #0x34]
    for offset, word in enumerate((0x8800, 0x0700, 0x0F00, 0x280F)):
        _put16(image, sense + offset * 2, word)

    # Four bounded column iterations test one active-low bit and load the
    # column-major event cell at (column * 7) + row before appending it.
    cursor = sense + 10
    if stack_counter:
        _put16(image, cursor, 0x9D04)      # Reload row from the same SP slot.
        cursor += 2
    _put16(image, cursor, 0x0701); cursor += 2  # LSLS r1, r0, #28
    _put16(image, cursor, 0x0F09); cursor += 2  # LSRS r1, r1, #28
    _put16(image, cursor, 0x2000); cursor += 2  # MOVS r0, #0
    _put16(image, cursor, 0x2201); cursor += 2  # MOVS r2, #1
    column_loop = cursor
    _put16(image, cursor, 0x4082); cursor += 2  # LSLS r2, r2, r0
    _put16(image, cursor, 0x438A); cursor += 2  # BICS r2, r1
    branch_skip = cursor
    _put16(image, cursor, 0xD000); cursor += 2  # patched BEQ to skip append
    _put16(image, cursor, 0x00C2); cursor += 2  # LSLS r2, r0, #3
    literal(cursor, 3, event_table + 0x80); cursor += 2
    _put16(image, cursor, 0x1A12); cursor += 2  # SUBS r2, r2, r0
    _put16(image, cursor, 0x3B80); cursor += 2  # SUBS r3, #0x80
    _put16(image, cursor, 0x18D2); cursor += 2  # ADDS r2, r2, r3
    event_load = cursor
    _put16(image, cursor, 0x5D56); cursor += 2  # LDRB r6, [r2, r5]
    _put16(image, cursor, 0x9600); cursor += 2  # STR r6, [sp]
    skip_append = cursor
    _branch(image, branch_skip, 0, skip_append)
    _put16(image, cursor, 0x3001); cursor += 2  # ADDS r0, #1
    _put16(image, cursor, 0x2201); cursor += 2  # reset one-hot mask
    _put16(image, cursor, 0x2804); cursor += 2  # CMP r0, #4
    _branch(image, cursor, 1, column_loop); cursor += 2

    end = cursor
    if stack_counter:
        _put16(image, end, 0x9D04)        # LDR r5, [SP, #0x10]
        _put16(image, end + 2, 0x3501)    # ADDS r5, #1
        _put16(image, end + 4, 0x062D)    # LSLS r5, r5, #24
        _put16(image, end + 6, 0x0E2D)    # LSRS r5, r5, #24
        _put16(image, end + 8, 0x9504)    # STR r5, [SP, #0x10]
        _put16(image, end + 10, 0x2D07)  # CMP r5, #7
        _branch(image, end + 12, 10, end + 16)  # BGE full-buffer exit
        _unconditional(image, end + 14, loop)
        _put16(image, end + 16, 0x4770)
    else:
        _put16(image, end, 0x3501)        # ADDS r5, #1
        _put16(image, end + 2, 0x062D)    # LSLS r5, r5, #24
        _put16(image, end + 4, 0x0E2D)    # LSRS r5, r5, #24
        _put16(image, end + 6, 0x2D07)    # CMP r5, #7
        _branch(image, end + 8, 10, end + 12)  # BGE full-buffer exit
        _unconditional(image, end + 10, loop)
        _put16(image, end + 12, 0x4770)
    _branch(image, sense + 8, 0, end)

    _mapped_irq_helper(image, 0x1000, enable=False)
    _mapped_irq_helper(image, 0x1020, enable=True)
    struct.pack_into("<7H", image, row_table_rom,
                     *(0xFFFF ^ (1 << bit) for bit in (2, 3, 0, 5, 6, 4, 1)))
    copied_mask_bytes = (4, 8, 1, 0x20, 0x40, 4, 2)
    image[mask_source:mask_source + 7] = bytes(copied_mask_bytes)

    column_map = bytearray(16)
    for raw, column in zip((14, 13, 11, 7), range(4)):
        column_map[raw] = column
    image[0x1900:0x1910] = column_map
    events = bytearray(0x40 + index for index in range(28))
    for column, row, event in ((0, 0, ord("1")), (0, 1, ord("4")),
                               (0, 2, ord("7")), (0, 3, ord("*")),
                               (1, 0, ord("2")), (1, 1, ord("5")),
                               (1, 2, ord("8")), (1, 3, ord("0")),
                               (2, 0, ord("3")), (2, 1, ord("6")),
                               (2, 2, ord("9")), (2, 3, ord("#"))):
        events[column * 7 + row] = event
    image[event_table:event_table + 28] = events
    return image, {"presence": presence, "sense": sense, "loop": loop,
                   "end": end, "table": row_table_start,
                   "event_table": event_table, "event_load": event_load,
                   "mask_pool": literal_values.get(0x0002, -1), "rows": 7,
                   "table_row0": arm_sites[0], "stack_counter": int(stack_counter),
                   "init": loop - 4, "footer_store": end + (8 if stack_counter else 6),
                   "row_slot": 0x10 if stack_counter else -1,
                   "mask_source": mask_source, "mask_target": table}


class SparseRowScannerTests(unittest.TestCase):
    def test_reset_copy_follows_bounded_call_argument_and_interworking_chain(self):
        image = _call_linked_copy_reset_fixture()
        copy = reset_linked_input_copy(
            image, ((0x01000BDC, 4),), ram_base=0x01000000,
            ram_size=0x00800000, flash_size=len(image))
        self.assertIsNotNone(copy)
        self.assertEqual((copy.source, copy.target, copy.size),
                         (0x1000, 0x01000000, 0x1000))

    def test_reset_copy_call_graph_rejects_orphan_argument_and_short_extent(self):
        for image in (_call_linked_copy_reset_fixture(orphan=True),
                      _call_linked_copy_reset_fixture(wrong_argument=True),
                      _call_linked_copy_reset_fixture(short_copy=True)):
            with self.subTest(image=image[:4]):
                self.assertIsNone(reset_linked_input_copy(
                    image, ((0x01000BDC, 4),), ram_base=0x01000000,
                    ram_size=0x00800000, flash_size=len(image)))

    def test_reset_linked_thumb_word_copy_requires_literal_cell_and_loop_proof(self):
        image = _linked_copy_reset_fixture()
        proof = reset_linked_input_copy(
            image, ((0x01000100, 0x38), (0x01000300, 12)),
            ram_base=0x01000000, ram_size=0x00800000,
            flash_size=len(image))
        self.assertIsNotNone(proof)
        self.assertEqual((proof.source, proof.target, proof.size),
                         (0x1000, 0x01000000, 0x1000))
        self.assertIn((0x300, 12), proof.evidence)

        orphan = _linked_copy_reset_fixture()
        _put32(orphan, 0, 0)
        self.assertIsNone(reset_linked_input_copy(
            orphan, ((0x01000100, 0x38), (0x01000300, 12)),
            ram_base=0x01000000, ram_size=0x00800000,
            flash_size=len(orphan)))

    def test_reset_linked_layout_copy_requires_reachable_consumer_and_full_extent(self):
        consumer, row = copy_consumer_fixture()
        image = bytearray(0x1800)
        image[:len(consumer)] = consumer
        image[:0x100] = reset_entry_fixture()[:0x100]
        struct.pack_into("<5I", image, row.table,
                         0x800, 0x01000000, 0x1000, 0x01001000, 0x1000)
        proof = reset_linked_input_copy(
            image, ((0x01000100, 0x38), (0x01000800, 0x100)),
            ram_base=0x01000000, ram_size=0x00800000,
            flash_size=len(image))
        self.assertIsNotNone(proof)
        self.assertEqual((proof.source, proof.target, proof.size),
                         (0x800, 0x01000000, 0x1000))

        orphan = bytearray(image)
        _put32(orphan, 0, 0)
        self.assertIsNone(reset_linked_input_copy(
            orphan, ((0x01000100, 0x38),),
            ram_base=0x01000000, ram_size=0x00800000,
            flash_size=len(orphan)))

        self.assertIsNone(reset_linked_input_copy(
            image, ((0x01000100, 0x38),),
            ram_base=0x01000000, ram_size=0x00800000,
            flash_size=0x17ff))

    def test_unknown_signed_compare_keeps_both_paths_conservative(self):
        image = bytearray(0x500)
        _put16(image, 0x400, 0x2800)       # CMP r0,#0; r0 is unknown
        _branch(image, 0x402, 10, 0x408)   # BGE to the shared scan endpoint
        _put16(image, 0x404, 0x46C0)       # NOP on the fallthrough path
        _unconditional(image, 0x406, 0x408)
        result = _row_outputs(image, 0x400, 0x408, {}, 0x100, 0)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], {})

    def test_six_row_switch_projects_wires_numeric_events_and_relocated_copy(self):
        image = _image()
        profile_list = find_sparse_row_scanners(image)
        self.assertEqual(len(profile_list), 1)
        profile = profile_list[0]
        self.assertEqual(profile["grammar"], "sparse-halfword-six-row-v1")
        self.assertEqual((profile["rows"], profile["columns"]), (6, 4))
        self.assertEqual(profile["descriptor"], 0x01000100)
        self.assertEqual(profile["row_ports"], [0x03000720, 0x03000724])
        self.assertEqual(profile["row_masks"], [0x15, 0x2A])
        self.assertEqual(profile["row_wire_order"], [2, 0, 5, 1, 4, 3])
        self.assertEqual(struct.unpack_from("<6H", image, 0x1200),
                         tuple(0xFFFF ^ (1 << bit)
                               for bit in (4, 0, 5, 2, 3, 1)))
        self.assertEqual(profile["single_key_column_sense"], [14, 13, 11, 7])
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        prop, admitted = sparse_row_property(image, config)
        self.assertEqual(prop,
            "matrix-halfword-wires=1000100:420:5c8:3000720:15:3000724:2a")
        self.assertEqual({key: admitted[key] for key in profile if key != "dependencies"},
                         {key: value for key, value in profile.items() if key != "dependencies"})

        owner = SimpleNamespace(matrix_input_profile=profile)
        position = _matrix_input_position(owner, 11, None)
        self.assertEqual(position, (ord("1"), 0, 2))
        self.assertEqual(matrix_input_command(profile, position, True),
                         bytes((HOST_INPUT, 1, 2, 11)))
        self.assertEqual(matrix_input_command(profile, None, False),
                         bytes((HOST_INPUT, 0, 0, 0)))

    def test_public_finder_uses_reset_linked_copy_when_shared_layout_is_unavailable(self):
        image = _image()
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        with patch("msm5xxx_emulator.detection.devices.input.sparse_rows.layouts",
                   return_value=[]):
            profiles = find_sparse_row_scanners(image, config)
            self.assertEqual(len(profiles), 1)
            self.assertEqual((profiles[0]["copy_source"], profiles[0]["copy_target"],
                              profiles[0]["copy_size"]), (0x1000, 0x01000000, 0x1000))
            prop, _ = sparse_row_property(image, config)
        self.assertIsNotNone(prop)

    def test_six_row_switch_closes_valid_row_clear_helper_before_bound_check(self):
        profiles = find_sparse_row_scanners(_image(preloop_clear=True))
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["rows"], 6)
        self.assertTrue(any(start == 0x1080 for start, _ in
                            profiles[0]["dependencies"]))

    def test_seven_row_pc_table_and_presence_pointer_project_all_wires(self):
        image, sites = _seven_row_image()
        profiles = find_sparse_row_scanners(image)
        self.assertEqual(len(profiles), 1)
        profile = profiles[0]
        self.assertEqual(profile["grammar"], "sparse-halfword-seven-row-v1")
        self.assertEqual(profile["rows"], 7)
        self.assertEqual(profile["row_masks"], [0x47, 0x2C])
        self.assertEqual(profile["row_wire_order"], [2, 5, 0, 6, 3, 4, 1])
        self.assertEqual(profile["presence_site"], sites["presence"])
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        prop, admitted = sparse_row_property(image, config)
        self.assertIsNotNone(prop)
        self.assertEqual({key: admitted[key] for key in profile if key != "dependencies"},
                         {key: value for key, value in profile.items() if key != "dependencies"})

        owner = SimpleNamespace(matrix_input_profile=profile)
        one = _matrix_input_position(owner, 11, None)
        zero = _matrix_input_position(owner, 21, None)
        self.assertEqual(one, (ord("1"), 0, 0))
        self.assertEqual(zero, (ord("0"), 3, 1))
        self.assertEqual(matrix_input_command(profile, one, True),
                         bytes((HOST_INPUT, 1, 2, 14)))
        self.assertEqual(matrix_input_command(profile, zero, True),
                         bytes((HOST_INPUT, 1, 6, 13)))

    def test_seven_row_rejects_bad_table_target_and_collapsed_wire(self):
        image, sites = _seven_row_image()
        row_three = struct.unpack_from("<H", image, sites["table"] + 6)[0]
        row_two = struct.unpack_from("<H", image, sites["table"] + 4)[0]
        self.assertNotEqual(row_three, row_two)
        _put16(image, sites["table"] + 6, row_two)
        self.assertEqual(find_sparse_row_scanners(image), [])

        image, sites = _seven_row_image()
        # The seventh arm now clears an already-owned bit, leaving six wires.
        _put32(image, sites["mask_pool"], 0x0004)
        self.assertEqual(find_sparse_row_scanners(image), [])

    def test_seven_row_output_must_preserve_row_counter_for_event_lookup(self):
        image, sites = _seven_row_image()
        self.assertEqual(len(find_sparse_row_scanners(image)), 1)
        # The seven-row row-output arm must leave r5 as the selected row.
        _put16(image, sites["sense"] - 6, 0x2500)
        self.assertEqual(find_sparse_row_scanners(image), [])

    def test_seven_row_stack_counter_projects_and_rejects_broken_lifecycle(self):
        image, sites = _seven_row_image(stack_counter=True)
        profiles = find_sparse_row_scanners(image)
        self.assertEqual(len(profiles), 1)
        profile = profiles[0]
        self.assertEqual(profile["grammar"], "sparse-halfword-seven-row-v1")
        self.assertEqual(profile["row_counter"], {"stack_offset": 0x10})
        self.assertEqual(profile["row_masks"], [0x47, 0x2C])
        self.assertEqual(profile["row_wire_order"], [2, 5, 0, 6, 3, 4, 1])
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        prop, admitted = sparse_row_property(image, config)
        self.assertIsNotNone(prop)
        self.assertEqual({key: admitted[key] for key in profile if key != "dependencies"},
                         {key: value for key, value in profile.items() if key != "dependencies"})
        owner = SimpleNamespace(matrix_input_profile=profile)
        one = _matrix_input_position(owner, 11, None)
        self.assertEqual(one, (ord("1"), 0, 0))
        self.assertEqual(matrix_input_command(profile, one, True),
                         bytes((HOST_INPUT, 1, 2, 14)))

        image, sites = _seven_row_image(stack_counter=True)
        _put16(image, sites["init"], 0x2501)
        self.assertEqual(find_sparse_row_scanners(image), [])

        image, sites = _seven_row_image(stack_counter=True)
        _unconditional(image, sites["presence"] + 8, sites["loop"])
        self.assertEqual(find_sparse_row_scanners(image), [])

        image, sites = _seven_row_image(stack_counter=True)
        _put16(image, sites["footer_store"], 0x9005)
        self.assertEqual(find_sparse_row_scanners(image), [])

        image, sites = _seven_row_image(stack_counter=True)
        _put16(image, sites["sense"] - 6, 0x9004)  # STR r0, [SP, #0x10]
        self.assertEqual(find_sparse_row_scanners(image), [])

    def test_seven_row_stack_counter_reads_copied_ram_masks(self):
        image, sites = _seven_row_image(stack_counter=True, copied_masks=True)
        profiles = find_sparse_row_scanners(image)
        self.assertEqual(len(profiles), 1)
        profile = profiles[0]
        self.assertEqual(profile["row_masks"], [0x47, 0x2C])
        self.assertEqual(profile["row_wire_order"], [2, 5, 0, 6, 3, 4, 1])
        self.assertEqual(profile["ram_dependencies"],
                         [(sites["mask_target"] + index, 1) for index in range(7)])
        self.assertIn((0x200, 20), profile["dependencies"])
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        prop, admitted = sparse_row_property(image, config)
        self.assertIsNotNone(prop)
        self.assertEqual({key: admitted[key] for key in profile if key != "dependencies"},
                         {key: value for key, value in profile.items() if key != "dependencies"})
        owner = SimpleNamespace(matrix_input_profile=profile)
        one = _matrix_input_position(owner, 11, None)
        self.assertEqual(one, (ord("1"), 0, 0))
        self.assertEqual(matrix_input_command(profile, one, True),
                         bytes((HOST_INPUT, 1, 2, 14)))

        duplicate, sites = _seven_row_image(stack_counter=True, copied_masks=True)
        duplicate[sites["mask_source"] + 1] = duplicate[sites["mask_source"]]
        self.assertEqual(find_sparse_row_scanners(duplicate), [])

        bounded, _ = _seven_row_image(stack_counter=True, copied_masks=True)
        config.ram_size = 0x200  # Still contains the descriptor, excludes mask bytes.
        self.assertEqual(sparse_row_property(bounded, config), (None, None))

    def test_second_gpio_bank_requires_matching_row_and_sense_bank(self):
        image = _image()
        for at in range(0, len(image) - 3, 4):
            word = struct.unpack_from("<I", image, at)[0]
            if word in (0x03000720, 0x03000724, 0x0300072C):
                _put32(image, at, word - 0xC0)
        profile, = find_sparse_row_scanners(image)
        self.assertEqual(profile["row_ports"], [0x03000660, 0x03000664])
        self.assertEqual(profile["sense_address"], 0x0300066C)
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        prop, _ = sparse_row_property(image, config)
        self.assertIn(":3000660:", prop)
        _put32(image, 0x1100 + 0x34, 0x0300072C)
        self.assertEqual(find_sparse_row_scanners(image), [])

    def test_matching_scan_paths_merge_only_identical_numeric_contacts(self):
        image = _image()
        first, = find_sparse_row_scanners(image)
        second = copy.deepcopy(first)
        second.update(presence_site=0x1200, sense_site=0x1240,
                      event_load_site=0x1260, event_register=1)
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        detector = "msm5xxx_emulator.detection.devices.input.sparse_rows.find_sparse_row_scanners"
        with patch(detector, return_value=[second, first]):
            prop, profile = sparse_row_property(image, config)
        self.assertTrue(prop.endswith(":1200:1240"))
        self.assertEqual(len(profile["source_sites"]), 2)
        for mutation in ("descriptor", "sense_address", "presence_site", "event_codes"):
            invalid = copy.deepcopy(second)
            if mutation == "event_codes":
                events = list(invalid[mutation])
                one, two = events.index(ord("1")), events.index(ord("2"))
                events[one], events[two] = events[two], events[one]
                invalid[mutation] = events
            elif mutation == "presence_site":
                invalid[mutation] = first[mutation]
            else:
                invalid[mutation] += 4
            with self.subTest(mutation=mutation), patch(detector, return_value=[first, invalid]):
                self.assertEqual(sparse_row_property(image, config), (None, None))

    def test_rejects_scan_shape_and_wiring_mutations(self):
        mutations = {
            "row stride": lambda image: _put16(image, 0x5E2, 0x0E47),
            "no-key branch": lambda image: _put16(image, 0x5D0, 0xD100),
            "nonzero row initialization": lambda image: _put16(image, 0x402, 0x2701),
            "duplicate row wire": lambda image: _put32(
                image, next(at for at in range(0x800, 0x900, 4)
                            if struct.unpack_from("<I", image, at)[0] == 1), 0x10),
            "unsupported row instruction": lambda image: _put16(image, 0x528, 0xB000),
            "descriptor MMIO pointer": lambda image: _put32(image, 0x1100 + 0x34, 0x03000720),
            "column lookup arithmetic": lambda image: _put16(image, 0x5D6, 0x2105),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                image = _image()
                mutate(image)
                self.assertEqual(find_sparse_row_scanners(image), [])

    def test_row_output_rejects_high_register_move_to_pc(self):
        image = _image()
        self.assertEqual(len(find_sparse_row_scanners(image)), 1)
        # Replace the harmless post-unlock NOP with MOV pc,r0. The interpreter
        # must model this as control flow rather than an abstract register write.
        _put16(image, 0x5C2, 0x4687)
        self.assertEqual(find_sparse_row_scanners(image), [])

    def test_row_output_rejects_unknown_conditional_self_loop(self):
        image = _image()
        self.assertEqual(len(find_sparse_row_scanners(image)), 1)
        # BL unlock leaves flags unknown; BNE to itself has a feasible
        # nonterminating arm alongside the fallthrough path to the scan read.
        _put16(image, 0x5C2, 0xD1FE)
        self.assertEqual(find_sparse_row_scanners(image), [])

    def test_six_row_output_must_preserve_row_counter_for_event_lookup(self):
        image = _image()
        self.assertEqual(len(find_sparse_row_scanners(image)), 1)
        # The row-output arm must not reset r7 before the event lookup.
        _put16(image, 0x5C2, 0x2700)
        self.assertEqual(find_sparse_row_scanners(image), [])

    def test_property_rejects_unowned_or_unavailable_source_ranges(self):
        image = _image()
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        self.assertEqual(sparse_row_property(
            image, config, status_descriptor_claimed=True), (None, None))
        config.ram_base = 0x01200000
        self.assertEqual(sparse_row_property(image, config), (None, None))
        config.ram_base = 0x01000000
        config.flash_size = 0x1000
        self.assertEqual(sparse_row_property(image, config), (None, None))

    def test_property_rejects_orphan_layout_and_truncated_copy_ranges(self):
        image = _image()
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        orphan = bytearray(image)
        _put32(orphan, 0, 0)
        self.assertEqual(len(find_sparse_row_scanners(orphan)), 1)
        self.assertEqual(sparse_row_property(orphan, config), (None, None))

        config.flash_size = 0x1800
        self.assertEqual(sparse_row_property(image, config), (None, None))
        config.flash_size = len(image)
        config.ram_size = 0x800
        self.assertEqual(sparse_row_property(image, config), (None, None))


if __name__ == "__main__":
    unittest.main()
