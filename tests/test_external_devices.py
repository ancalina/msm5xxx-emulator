"""Synthetic instruction-shape checks for external device profiles."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.external_devices import (
    detect_boot_strap, detect_boot_uart, detect_external_lcd,
    detect_external_cs0a, detect_external_cs09, detect_external_ram,
    detect_external_status, detect_external_windows,
    detect_external_panel_writers, detect_gpio_ready_bit21,
    _literal_window_accesses_many,
    detect_boot_gpio_bit9,
)
from msm5xxx_emulator.detection.external_bus import detect_external_bus


def put16(image: bytearray, offset: int, *words: int) -> None:
    struct.pack_into(f"<{len(words)}H", image, offset, *words)


def put32(image: bytearray, offset: int, *words: int) -> None:
    struct.pack_into(f"<{len(words)}I", image, offset, *words)


def ldr_literal(register: int, instruction: int, literal: int) -> int:
    pc = (instruction + 4) & ~3
    delta = literal - pc
    assert delta >= 0 and delta % 4 == 0 and delta // 4 < 256
    return 0x4800 | (register << 8) | (delta // 4)


def _arm_ldr_literal(register: int, instruction: int, literal: int) -> int:
    delta = literal - instruction - 8
    assert 0 <= delta < 0x1000 and delta % 4 == 0
    return 0xE59F0000 | (register << 12) | delta


def _reset_helper(image: bytearray, address: int, target: int, pool: int) -> None:
    target_literal = pool
    return_literal = pool + 4
    words = (0xE59F4000 | (target_literal - address - 8),
             0xE3140001,
             0x159FE000 | (pool + 8 - address - 16),
             0x059FE000 | (return_literal - address - 20),
             0xE12FFF14)
    put32(image, address, *words)
    put32(image, target_literal, target, address + 24)
    put32(image, return_literal, address + 24)
    if target & 1:
        put16(image, address + 20, 0x4778)
        thumb_return = address + 16 + (words[2] & 0xFFF)
        put32(image, thumb_return, address + 20 | 1)


def _external_status_image() -> bytearray:
    image = bytearray(0x200)
    put32(image, 0, 0xEA000006)
    _reset_helper(image, 0x20, 0x81, 0x140)
    put16(image, 0x80, 0xB500,
          ldr_literal(0, 0x82, 0x100),
          0x8900, 0x0600, 0x0E00, 0x2801,
          0xD100 | (((0xA0 - (0x8C + 4)) // 2) & 0xFF),
          0x4770)
    put32(image, 0x100, 0x0B000400)
    return image


def _ram_readback_image(*, independent_terminal_helper: bool,
                        extent: int = 0x7FFFFF) -> bytes:
    image = bytearray(0x4000)
    put32(image, 0, 0xEA000006)  # Reset branch to 0x20.
    body = 0x1000
    table = body - 28
    _reset_helper(image, 0x20, body, 0x200)
    if independent_terminal_helper:
        push = 0x3000
        _reset_helper(image, 0x40, push | 1, 0x220)
        size = (extent + 0x1000) & ~0xFFF
        page = 0x14000000 + size - 0x1000
        put16(image, push, 0xB500,
              ldr_literal(0, push + 2, 0x3100), 0x6900, 0x2108,
              0x4308, ldr_literal(1, push + 10, 0x3104), 0x6108, 0xE7FE)
        put32(image, 0x3100, page, page)
    # Prefix loads descriptor fields through literal pools.
    put32(image, body, 0xE59F0154, 0xE5900000, 0xE3A01001,
          0xE3A02000, 0xE59F3148, 0xE5933000, 0xE0834000,
          0xE5801000, 0xE5842000, 0xE5903000, 0xE1530001)
    failure = body + 11 * 4
    target = body + 0x148
    put32(image, failure, 0x1A000000 | (((target - (failure + 8)) >> 2) & 0xFFFFFF),
          0xE1A01081, 0xE3510C80)
    branch = body + 14 * 4
    put32(image, branch, 0xDA000000 | (((body + 0x1C - (branch + 8)) >> 2) & 0xFFFFFF))
    put32(image, table, 0x14000000, extent, 0x10, 0x55AA0F,
          0xAA0F, 0x55, 0x030006D0)
    fields = ((0, 0, body + 0x15C), (0x10, 8, body + 0x160),
              (0x40, 24, body + 0x164), (0x6C, 4, body + 0x168),
              (0x80, 4, body + 0x16C), (0xF4, 12, body + 0x170),
              (0x108, 16, body + 0x174), (0x11C, 20, body + 0x178))
    for offset, field, literal in fields:
        if offset in (0, 0x10):
            instruction = struct.unpack_from("<I", image, body + offset)[0]
        else:
            instruction = _arm_ldr_literal(0, body + offset, literal)
            put32(image, body + offset, instruction)
        effective = body + offset + 8 + (instruction & 0xFFF)
        put32(image, effective, table + field)
    return bytes(image)


def _thumb_bl(at: int, target: int) -> tuple[int, int]:
    displacement = target - (at + 4)
    assert displacement % 2 == 0 and -(1 << 22) <= displacement < (1 << 22)
    encoded = displacement & ((1 << 23) - 1)
    return 0xF000 | ((encoded >> 12) & 0x7FF), 0xF800 | ((encoded >> 1) & 0x7FF)


def _thumb_beq(at: int, target: int) -> int:
    displacement = target - (at + 4)
    assert displacement % 2 == 0 and -256 <= displacement < 256
    return 0xD000 | ((displacement >> 1) & 0xFF)


def _boot_gpio_bit9_image(*, descriptor_register: int = 6,
                          clobber_descriptor: bool = False,
                          clobber_status: bool = False) -> bytes:
    """Synthetic reset, GPIO status, and panel-selection instruction chain."""
    image = bytearray(0x5000)
    caller, reader, status_helper, panel = 0x2000, 0x3000, 0x4000, 0x4100
    descriptor, descriptor_pool = 0x500, 0x3080
    status_pool, helper_pool, panel_pool = 0x3090, 0x4080, 0x4180
    status_base = 0x14001000
    put32(image, 0, 0xEA00003E)
    _reset_helper(image, 0x100, caller | 1, 0x180)
    call_hi, call_lo = _thumb_bl(caller + 2, reader)
    put16(image, caller, 0xB500, call_hi, call_lo, 0x4770)

    reader_words = [
        0xB5FE,
        ldr_literal(descriptor_register, reader + 2, descriptor_pool),
        0x46C0, 0x46C0, 0x46C0, 0x46C0,
        0x6800 | (1 << 6) | (descriptor_register << 3),  # LDR r0,[base,#4]
        0x6800, 0x0580,  # LDR r0,[r0]; LSLS r0,#22
        ldr_literal(1, reader + 0x12, status_pool),
        0x0FC0, 0x390C, 0x7048,  # LSRS #31; SUBS #12; STRB [r1,#1]
    ]
    first_hi, first_lo = _thumb_bl(reader + 0x1A, status_helper)
    second_hi, second_lo = _thumb_bl(reader + 0x1E, panel)
    reader_words.extend((first_hi, first_lo, second_hi, second_lo, 0x4770))
    put16(image, reader, *reader_words)
    if clobber_descriptor:
        if descriptor_register < 4:
            # A call clobbers a caller-saved descriptor register before use.
            call_hi, call_lo = _thumb_bl(reader + 4, 0x4200)
            put16(image, reader + 4, call_hi, call_lo)
        else:
            put16(image, reader + 8, 0x2000 | (descriptor_register << 8))
    if descriptor_register < 4 and clobber_descriptor:
        put16(image, 0x4200, 0x4770)

    put32(image, descriptor + 4, 0x03000720)
    put32(image, descriptor_pool, descriptor)
    put32(image, status_pool, status_base + 12)

    helper_words = [
        0xB4F0, ldr_literal(0, status_helper + 2, helper_pool),
        0x260F, 0x7844,  # LDRB r4,[r0,#1]
        0x2003, 0x06C0, 0x2520, 0x2201, 0x2302, 0x2100,
        0x2C00, _thumb_beq(status_helper + 0x16, status_helper + 0x40),
    ]
    put16(image, status_helper, *helper_words)
    put16(image, status_helper + 0x40, 0x4770)
    if clobber_status:
        put16(image, status_helper + 8, 0x2400)  # MOVS r4,#0 before CMP.
    put32(image, helper_pool, status_base)

    panel_branch = panel + 10
    low_target = panel + 20
    panel_words = [
        ldr_literal(0, panel, panel_pool), 0x7841,
        0x2003, 0x06C0, 0x2900, _thumb_beq(panel_branch, low_target),
        0x2151, 0x7001, 0x2100, 0xE000,
        0x21AF, 0x7001, 0x4770,
    ]
    put16(image, panel, *panel_words)
    put32(image, panel_pool, status_base)
    return bytes(image)


def _boot_gpio_bit9_panel_image() -> bytes:
    """Synthetic reset-linked GPIO selector with two panel command paths."""
    image = bytearray(0x5000)
    caller, wrapper, leaf, low = 0x2000, 0x4200, 0x3000, 0x3080
    descriptor, descriptor_pool = 0x500, 0x3100
    status_pool, handler_pool = 0x3110, 0x3120
    low_handler_pool = 0x3124
    put32(image, 0, 0xEA00003E)
    _reset_helper(image, 0x100, caller | 1, 0x180)
    call_hi, call_lo = _thumb_bl(caller + 2, wrapper)
    put16(image, caller, 0xB500, call_hi, call_lo, 0x4770)
    leaf_hi, leaf_lo = _thumb_bl(wrapper + 4, leaf)
    put16(image, wrapper, 0xB51C, 0x1C04, leaf_hi, leaf_lo, 0x4770)

    branch_at = leaf + 0x20
    words = [
        ldr_literal(0, leaf, descriptor_pool), 0xB4F0,
        0x6840, 0x6800, 0x0580, 0x0FC1,
        ldr_literal(0, leaf + 0x0C, status_pool),
        0x2603, 0x06F6, 0x2220, 0x230F, 0x2401, 0x2502, 0x2700,
        0x2900, 0x7081, _thumb_beq(branch_at, low),
        ldr_literal(1, branch_at + 2, handler_pool),
        0x6041, 0x202C, 0x7030,
    ]
    put16(image, leaf, *words)
    put16(image, low,
          ldr_literal(1, low, low_handler_pool), 0x3908, 0x6041,
          0x20D1, 0x7030, 0x4770)
    put32(image, descriptor + 4, 0x03000720)
    put32(image, descriptor_pool, descriptor)
    put32(image, status_pool, 0x146586E0)
    put32(image, handler_pool, 0x5F84)
    put32(image, low_handler_pool, 0x5F84)
    return bytes(image)


def _external_cs0a_reset_image() -> bytes:
    """Synthetic reset-reachable writes to both CS0A configuration addresses."""
    image = bytearray(0x4000)
    put32(image, 0, 0xEA000006)
    _reset_helper(image, 0x20, 0x1001, 0x200)
    put16(image, 0x1000,
          ldr_literal(2, 0x1000, 0x1200), 0x6211,
          ldr_literal(2, 0x1004, 0x1200), 0x6311,
          0x4770)
    put32(image, 0x1200, 0x0A000080)
    return bytes(image)


class ExternalDeviceDetectionTests(unittest.TestCase):
    def test_boot_gpio_bit9_requires_linked_status_and_panel_branches(self) -> None:
        image = _boot_gpio_bit9_image()
        profile, reason = detect_boot_gpio_bit9(image)
        self.assertEqual(reason, "accepted")
        self.assertEqual((profile["gpio"], profile["bit"], profile["value"]),
                         (0x03000720, 9, 0))
        self.assertEqual(len(profile["sites"]), 1)
        site = profile["sites"][0]
        self.assertGreater(site["span"][1], 0)
        self.assertTrue(any(span == [0x504, 4] for span in site["extra_spans"]))

    def test_boot_gpio_bit9_rejects_unlinked_or_unproven_inputs(self) -> None:
        image = bytearray(_boot_gpio_bit9_image())
        put32(image, 0x504, 0x03000724)
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        image = bytearray(_boot_gpio_bit9_image())
        put32(image, 0x180, 0x2101)
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        image = bytearray(_boot_gpio_bit9_image())
        put16(image, 0x3010, 0x0540)  # Wrong extracted bit.
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        image = bytearray(_boot_gpio_bit9_image())
        put32(image, 0x4180, 0x14001004)  # Panel tests a different status field.
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        self.assertIsNone(detect_boot_gpio_bit9(bytes(64))[0])

    def test_boot_gpio_bit9_rejects_clobbered_descriptor_and_status(self) -> None:
        self.assertIsNone(detect_boot_gpio_bit9(_boot_gpio_bit9_image(
            clobber_descriptor=True))[0])
        self.assertIsNone(detect_boot_gpio_bit9(_boot_gpio_bit9_image(
            descriptor_register=2, clobber_descriptor=True))[0])
        self.assertIsNone(detect_boot_gpio_bit9(_boot_gpio_bit9_image(
            clobber_status=True))[0])

    def test_boot_gpio_bit9_panel_selector_is_reset_linked_and_independent(self) -> None:
        image = _boot_gpio_bit9_panel_image()
        profile, reason = detect_boot_gpio_bit9(image)
        self.assertEqual(reason, "accepted")
        self.assertEqual((profile["bit"], profile["value"]), (9, 0))
        self.assertEqual(len(profile["sites"]), 1)
        site = profile["sites"][0]
        self.assertEqual(site["status_branch"], 0x3020)
        self.assertEqual(site["panel_low_branch"], 0x3080)

        plan, reason = detect_external_bus(image)
        self.assertEqual(reason, "accepted")
        properties = plan["machine_properties"]
        self.assertTrue(properties["experimental-contract-gpio-bit9-low"])
        self.assertFalse(properties["gpio-ready-bit21"])
        self.assertNotIn("external-lcd-18", properties)

    def test_boot_gpio_bit9_panel_selector_rejects_bad_pointer_branch_and_link(self) -> None:
        image = bytearray(_boot_gpio_bit9_panel_image())
        put32(image, 0x504, 0x03000724)
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        image = bytearray(_boot_gpio_bit9_panel_image())
        put16(image, 0x3008, 0x0540)
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        image = bytearray(_boot_gpio_bit9_panel_image())
        put16(image, 0x3020, 0xD000)  # BEQ falls through rather than taking low path.
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        image = bytearray(_boot_gpio_bit9_panel_image())
        put32(image, 0x3124, 0x5F80)  # Handler pointer no longer matches high path.
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        image = bytearray(_boot_gpio_bit9_panel_image())
        put32(image, 0x180, 0x2101)
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

        image = bytearray(_boot_gpio_bit9_panel_image())
        put16(image, 0x3012, 0x2100)  # Clobber r1 before the status comparison.
        self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

    def test_external_cs0a_accepts_only_reset_linked_literal_writes(self) -> None:
        profile, reason = detect_external_cs0a(_external_cs0a_reset_image())
        self.assertEqual(reason, "accepted")
        literal_sites = [site for site in profile["sites"]
                         if site["kind"] == "literal-access"]
        self.assertEqual({site["address"] for site in literal_sites},
                         {0x0A0000A0, 0x0A0000B0})
        self.assertTrue(all(site["operation"] == "write" for site in literal_sites))
        plan, reason = detect_external_bus(_external_cs0a_reset_image())
        self.assertEqual(reason, "accepted")
        self.assertTrue(plan["machine_properties"]["external-cs0a"])
        self.assertNotIn("external-ram-base", plan["machine_properties"])

        image = bytearray(_external_cs0a_reset_image())
        put32(image, 0x200, 0x1101)
        self.assertIsNone(detect_external_cs0a(bytes(image))[0])

        image = bytearray(_external_cs0a_reset_image())
        put32(image, 0x200, 0x1000)  # ARM entry cannot prove Thumb stores.
        self.assertIsNone(detect_external_cs0a(bytes(image))[0])

        image = bytearray(_external_cs0a_reset_image())
        put16(image, 0x1006, 0x6B11)  # Read from +0x30 instead of programming it.
        self.assertIsNone(detect_external_cs0a(bytes(image))[0])

    def test_boot_gpio_bit9_rejects_base_writeback_and_unreachable_reader(self) -> None:
        for instruction in (0xC601, 0xBA0E, 0xE7FE):
            with self.subTest(instruction=instruction):
                image = bytearray(_boot_gpio_bit9_image())
                put16(image, 0x3008, instruction)
                self.assertIsNone(detect_boot_gpio_bit9(bytes(image))[0])

    def test_reset_linked_ram_readback_is_independent_of_terminal_helper(self) -> None:
        image = _ram_readback_image(independent_terminal_helper=False)
        profile, reason = detect_external_ram(image)
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["ram_test"]["base"], 0x14000000)
        self.assertEqual(profile["ram_test"]["size"], 0x00800000)
        plan, reason = detect_external_bus(
            image, ram_base=0x01000000, ram_size=0x800000)
        self.assertEqual(reason, "accepted")
        self.assertEqual(plan["machine_properties"]["external-ram-base"], 0x14000000)
        for extent, expected_size in ((0x3FFDFF, 0x00400000),
                                      (0x001FFFFF, 0x00200000)):
            with self.subTest(extent=extent):
                profile, reason = detect_external_ram(_ram_readback_image(
                    independent_terminal_helper=True, extent=extent))
                self.assertEqual(reason, "accepted")
                self.assertEqual(profile["ram_test"]["size"], expected_size)

    def test_reset_linked_two_mib_readback_extent(self) -> None:
        image = _ram_readback_image(
            independent_terminal_helper=False, extent=0x001FFFFF)
        profile, reason = detect_external_ram(image)
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["ram_test"]["extent"], 0x001FFFFF)
        self.assertEqual(profile["ram_test"]["size"], 0x00200000)
        plan, reason = detect_external_bus(
            image, ram_base=0x01000000, ram_size=0x00800000)
        self.assertEqual(reason, "accepted")
        self.assertEqual(
            plan["machine_properties"]["external-ram-size"], 0x00200000)
    def test_two_mib_extent_rejects_unclosed_body_table_link_or_extent(self) -> None:
        image = bytearray(_ram_readback_image(
            independent_terminal_helper=False, extent=0x001FFFFF))
        put32(image, 0x1000 + 8, 0xE3A01002)  # Walking bit no longer starts at one.
        self.assertIsNone(detect_external_ram(bytes(image))[0])

        image = bytearray(_ram_readback_image(
            independent_terminal_helper=False, extent=0x001FFFFF))
        put32(image, 0x1000 - 28, 0x14001000)  # Table base disagrees with the test.
        self.assertIsNone(detect_external_ram(bytes(image))[0])

        image = bytearray(_ram_readback_image(
            independent_terminal_helper=False, extent=0x001FFFFF))
        put32(image, 0x200, 0x1004)  # Reset no longer calls the body.
        self.assertIsNone(detect_external_ram(bytes(image))[0])

        for extent in (0x001FFFFE, 0x001FEFFF, 0x00200000):
            with self.subTest(extent=extent):
                image = _ram_readback_image(
                    independent_terminal_helper=False, extent=extent)
                self.assertIsNone(detect_external_ram(image)[0])

    def test_ram_chip_select_program_shape(self) -> None:
        image = bytearray(0x180)
        # LDR r1, =0x0A000080; STR r0, [r1,#0x20]; STR r0,+0x28/+0x24
        put16(image, 0x20, ldr_literal(1, 0x20, 0x100), 0x6208, 0x2000,
              0x6288, 0x6248, ldr_literal(1, 0x2a, 0x100), 0x3140,
              0x6108)
        put32(image, 0x100, 0x0A000080)
        profile, reason = detect_external_cs0a(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["sites"][0]["kind"], "controller-config")
        self.assertIsNone(detect_external_ram(bytes(image))[0])
        self.assertIsNone(detect_external_cs0a(bytes(64))[0])
        plan, reason = detect_external_bus(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertTrue(plan["machine_properties"]["external-cs0a"])
        self.assertNotIn("external-ram-base", plan["machine_properties"])

    def test_cs09_window_requires_its_own_access(self) -> None:
        image = bytearray(0x100)
        put16(image, 0x20, ldr_literal(0, 0x20, 0x80), 0x7001)
        put32(image, 0x80, 0x09000000)
        self.assertEqual(detect_external_cs09(bytes(image))[1], "accepted")
        put32(image, 0x80, 0x09000070)
        put16(image, 0x22, 0x7801)  # The known single-byte strap read is separate.
        self.assertIsNone(detect_external_cs09(bytes(image))[0])

        put16(image, 0x22, 0x6801)  # A word read at +0x70 is independent access.
        self.assertEqual(detect_external_cs09(bytes(image))[1], "accepted")

        put32(image, 0x80, 0x09000060)
        put16(image, 0x22, 0x8881)  # LDRH r1,[r0,#4] reads +0x64.
        profile, reason = detect_external_cs09(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["accesses"][0]["address"], 0x09000064)
        self.assertEqual(profile["accesses"][0]["access_size"], 2)

    def test_literal_linked_window_accesses_are_separate(self) -> None:
        image = bytearray(0x100)
        put16(image, 0x20, ldr_literal(0, 0x20, 0x80), 0x7801)
        put32(image, 0x80, 0x08C00000)
        windows, reason = detect_external_windows(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertEqual(windows["08c00000"][0]["operation"], "read")
        self.assertEqual(windows["08c00000"][0]["literal"], 0x80)
        self.assertTrue(windows["08c00000"][0]["thumb"])
        self.assertEqual(windows["08c00000"][0]["instruction_width"], 2)
        self.assertFalse(windows["1a000000"])

    def test_08c_shifted_base_store_is_independent_window_evidence(self) -> None:
        image = bytearray(0x80)
        register = 3
        mov = 0x2000 | (register << 8) | 0x23
        shift = (22 << 6) | (register << 3) | register
        store = 0x6000 | (register << 3) | 1 | (1 << 6)  # STR r1,[r3,#4]
        put16(image, 0x20, mov, shift, store)
        put16(image, 0x30, mov, shift,
              0x6000 | (register << 3) | 1 | (3 << 6))

        windows, reason = detect_external_windows(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertEqual(len(windows["08c00000"]), 2)
        access = windows["08c00000"][0]
        self.assertEqual(access["address"], 0x08C00004)
        self.assertEqual(access["access_size"], 4)
        self.assertEqual(access["operation"], "write")
        self.assertEqual((access["load"], access["use"], access["literal"]),
                         (0x20, 0x24, None))
        plan, reason = detect_external_bus(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertTrue(plan["machine_properties"]["external-window-08c"])
        self.assertNotIn("external-ram-base", plan["machine_properties"])

    def test_08c_shifted_base_rejects_wrong_shift_source_and_offset(self) -> None:
        register = 2
        mov = 0x2000 | (register << 8) | 0x23
        shift = (22 << 6) | (register << 3) | register
        good_store = 0x6000 | (register << 3) | 1 | (1 << 6)

        for words in (
                (0x2222, shift, good_store),  # wrong base immediate
                (mov, (21 << 6) | (register << 3) | register, good_store),
                (mov, shift, good_store | (1 << 3)),  # wrong base register
                (mov, shift, 0x6000 | (register << 3) | 1 | (4 << 6)),
                (mov, 0x2000, shift, good_store),  # intervening clobber
        ):
            with self.subTest(words=words):
                image = bytearray(0x80)
                put16(image, 0x20, *words)
                windows, _ = detect_external_windows(bytes(image))
                self.assertFalse((windows or {}).get("08c00000", []))

    def test_arm_literal_access_supports_signed_literal_and_immediate_offset(self) -> None:
        image = bytearray(0x100)
        pc, literal, base = 0x40, 0x30, 0x08C00000
        displacement = pc + 8 - literal
        ldr_literal = (0x10000000 | 0x051F0000 | (displacement & 0xFFF))
        put32(image, pc, ldr_literal, 0x15901004)
        put32(image, literal, base)

        accesses = _literal_window_accesses_many(image, (base,))[base]
        self.assertEqual(len(accesses), 1)
        self.assertEqual(accesses[0]["address"], base + 4)
        self.assertEqual(accesses[0]["literal"], literal)
        self.assertFalse(accesses[0]["thumb"])
        self.assertEqual(accesses[0]["instruction_width"], 4)
        self.assertEqual(accesses[0]["operation"], "read")
        self.assertEqual(accesses[0]["access_size"], 4)

    def test_arm_literal_byte_store_reports_byte_access_size(self) -> None:
        image = bytearray(0x100)
        pc, literal, base = 0x40, 0x30, 0x08C00000
        displacement = pc + 8 - literal
        ldr_literal = 0x10000000 | 0x051F0000 | (displacement & 0xFFF)
        put32(image, pc, ldr_literal, 0x15C01004)  # STRBNE r1, [r0, #4]
        put32(image, literal, base)

        accesses = _literal_window_accesses_many(image, (base,))[base]
        self.assertEqual(len(accesses), 1)
        self.assertEqual(accesses[0]["address"], base + 4)
        self.assertEqual(accesses[0]["operation"], "write")
        self.assertEqual(accesses[0]["access_size"], 1)

    def test_literal_access_must_fit_inside_window(self) -> None:
        base = 0x08C00000
        image = bytearray(0x100)
        pc, literal = 0x40, 0x30
        put32(image, pc, 0xE51F0018, 0xE5801FFF)  # LDR base; STR word at +0xfff.
        put32(image, literal, base)
        self.assertEqual(_literal_window_accesses_many(image, (base,))[base], [])

        put32(image, pc + 4, 0xE5C01FFF)  # STRB at +0xfff fits exactly.
        accesses = _literal_window_accesses_many(image, (base,))[base]
        self.assertEqual(len(accesses), 1)
        self.assertEqual(accesses[0]["access_size"], 1)
        self.assertEqual(accesses[0]["address"], base + 0xFFF)

    def test_arm_window_access_rejects_register_postindex_pc_and_reserved_forms(self) -> None:
        base = 0x08C00000
        invalid_uses = (0xE4901004,  # post-index immediate
                        0xE7901002,  # register-offset immediate load
                        0xE590F004)  # load to PC
        for use in invalid_uses:
            with self.subTest(use=hex(use)):
                image = bytearray(0x100)
                pc, literal = 0x20, 0x28
                put32(image, pc, 0xE59F0000, use)
                put32(image, literal, base)
                self.assertEqual(_literal_window_accesses_many(
                    image, (base,))[base], [])

        image = bytearray(0x100)
        put32(image, 0x20, 0xF59F0000, 0xE5901004)
        put32(image, 0x28, base)
        self.assertEqual(_literal_window_accesses_many(image, (base,))[base], [])

        image = bytearray(0x100)
        put32(image, 0x20, 0xE59FF000, 0xE5901004)
        put32(image, 0x28, base)
        self.assertEqual(_literal_window_accesses_many(image, (base,))[base], [])

        image = bytearray(0x100)
        # A conditional literal load cannot feed an access under another condition.
        put32(image, 0x20, 0x159F0000, 0xE5901004)
        put32(image, 0x28, base)
        self.assertEqual(_literal_window_accesses_many(image, (base,))[base], [])

    def test_arm_window_access_accepts_all_valid_conditions(self) -> None:
        base = 0x1A000000
        image = bytearray(0x100)
        pc, literal = 0x20, 0x28
        # AL LDR from PC followed by a conditionally executed STR.
        put32(image, pc, 0xE59F0000, 0xC5801008)
        put32(image, literal, base)
        accesses = _literal_window_accesses_many(image, (base,))[base]
        self.assertEqual(len(accesses), 1)
        self.assertEqual(accesses[0]["operation"], "write")
        self.assertEqual(accesses[0]["address"], base + 8)

        image = bytearray(0x100)
        # Matching non-AL conditions can safely share the loaded base.
        put32(image, pc, 0x159F0000, 0x15801004)
        put32(image, literal, base)
        self.assertEqual(len(_literal_window_accesses_many(image, (base,))[base]), 1)

    def test_window_candidates_allow_newline_bytes_and_overlapping_modes(self) -> None:
        base = 0x08C00000
        image = bytearray(0x100)
        put16(image, 0x20, ldr_literal(1, 0x20, 0x80), 0x700A)
        put32(image, 0x80, base)
        self.assertEqual(len(_literal_window_accesses_many(image, (base,))[base]), 1)

        # This ARM LDR's low halfword also resembles a Thumb literal load.
        # Both decoders must be tried at the same byte offset.
        image = bytearray(0x900)
        pc, literal = 0x20, 0x848
        put32(image, pc, 0xE59F4820, 0xE5841000)
        put32(image, literal, base)
        accesses = _literal_window_accesses_many(image, (base,))[base]
        self.assertEqual(len(accesses), 1)
        self.assertFalse(accesses[0]["thumb"])
        self.assertEqual(accesses[0]["literal"], literal)

    def test_terminal_helper_cannot_override_ram_probe_evidence(self) -> None:
        image = bytearray(_ram_readback_image(independent_terminal_helper=True))
        put16(image, 0x3008, 0x4388)  # BICS clears the flag.
        self.assertIsNotNone(detect_external_ram(bytes(image))[0])
        image = bytearray(_ram_readback_image(independent_terminal_helper=True))
        put32(image, 0x220, 0x3201)  # Reset calls a different Thumb entry.
        self.assertIsNotNone(detect_external_ram(bytes(image))[0])

    def test_boot_uart_requires_command_init_and_bit3_poll(self) -> None:
        image = bytearray(0x100)
        # CR init at 0x20, followed by the ready poll at 0x28.
        put16(image, 0x20, 0x2020, ldr_literal(1, 0x22, 0x80), 0x7308, 0x7308)
        poll = 0x28
        words = [ldr_literal(0, poll, 0x84), 0x7900, 0x0700, 0xD400,
                 0x2001, ldr_literal(1, poll + 10, 0x88), 0x7008,
                 0x2000, 0x7008]
        # Poll branch at +16 returns to its initial literal load.
        branch_at = poll + 18
        displacement = (poll - (branch_at + 4)) // 2
        words.append(0xE000 | (displacement & 0x7FF))
        put16(image, poll, *words)
        put32(image, 0x80, 0x03000B10)
        put32(image, 0x84, 0x03000B10)
        put32(image, 0x88, 0x030006D0)
        profile, reason = detect_boot_uart(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertTrue(profile["polls"])
        malformed = bytearray(image)
        put32(malformed, 0x88, 0x03000720)
        self.assertIsNone(detect_boot_uart(bytes(malformed))[0])

    def test_boot_strap_direct_and_adjusted_literals(self) -> None:
        for base, add in ((0x09000070, None), (0x09000060, 0x10),
                          (0x09000020, 0x50)):
            image = bytearray(0x100)
            if add is None:
                put16(image, 0x20, ldr_literal(0, 0x20, 0x80), 0x7800,
                      0x0740, 0xD401)
            else:
                put16(image, 0x20, ldr_literal(0, 0x20, 0x80),
                      0x3000 | add, 0x7800, 0x0740, 0xD401)
            put32(image, 0x80, base)
            self.assertEqual(detect_boot_strap(bytes(image))[1], "accepted")
        wrong_bit = bytearray(image)
        put16(wrong_bit, 0x26, 0x0780)  # shift by 30
        self.assertIsNone(detect_boot_strap(bytes(wrong_bit))[0])

    def test_external_status_halfword_read(self) -> None:
        image = _external_status_image()
        self.assertEqual(detect_external_status(bytes(image))[1], "accepted")
        profile = detect_external_status(bytes(image))[0]
        self.assertEqual(profile["sites"][0]["span"], [0x82, 12])
        self.assertTrue(any(span[0] == 0x20 for span in profile["sites"][0]["extra_spans"]))
        plan, reason = detect_external_bus(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertTrue(plan["machine_properties"]["experimental-contract-status-0b408"])
        self.assertNotIn("experimental-contract-window-0b", plan["machine_properties"])
        put32(image, 0x100, 0x0B000800)
        self.assertIsNone(detect_external_status(bytes(image))[0])

    def test_external_status_requires_branch_and_reset_linkage(self) -> None:
        image = bytearray(_external_status_image())
        put16(image, 0x8C, 0x2000)  # CMP no longer controls a conditional branch.
        self.assertIsNone(detect_external_status(bytes(image))[0])
        image = bytearray(_external_status_image())
        put32(image, 0x20, 0xEAFFFFFE)  # The reset vector no longer reaches the consumer.
        self.assertIsNone(detect_external_status(bytes(image))[0])

    def test_external_lcd_writer_and_malformed_store(self) -> None:
        image = bytearray(0x40)
        put16(image, 0x10, 0x2007, (26 << 6), 0x8000)
        profile, reason = detect_external_lcd(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertTrue(profile["writers"])
        self.assertFalse(profile["bit21"])
        self.assertEqual(detect_external_panel_writers(bytes(image))[1], "accepted")
        self.assertIsNone(detect_gpio_ready_bit21(bytes(image))[0])
        plan, reason = detect_external_bus(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertTrue(plan["machine_properties"]["external-lcd-1c"])
        self.assertFalse(plan["machine_properties"]["gpio-ready-bit21"])
        self.assertFalse(plan["machine_properties"]["external-lcd-18"])
        put16(image, 0x14, 0x80C0)
        self.assertIsNone(detect_external_lcd(bytes(image))[0])
        overwritten = bytearray(0x40)
        put16(overwritten, 0x10, 0x2007, 26 << 6, 0x2003, 0x8000)
        self.assertIsNone(detect_external_lcd(bytes(overwritten))[0])

        odd_lanes = bytearray(0x40)
        put16(odd_lanes, 0x10, 0x2107, (26 << 6) | (1 << 3) | 1,
              0x7000 | (1 << 3) | (1 << 6))  # STRB [base,#1]
        put16(odd_lanes, 0x20, 0x2107, (26 << 6) | (1 << 3) | 1,
              0x7000 | (1 << 3) | (3 << 6))  # STRB [base,#3]
        odd_profile, reason = detect_external_lcd(bytes(odd_lanes))
        self.assertEqual(reason, "accepted")
        self.assertEqual(len(odd_profile["writers"]), 2)

    def test_literal_linked_lcd_ports_are_independent_from_gpio(self) -> None:
        image = bytearray(0x100)
        put16(image, 0x20, ldr_literal(0, 0x20, 0x80), 0x8001)
        put32(image, 0x80, 0x1A000078)  # Halfword command-index write.
        put16(image, 0x30, ldr_literal(1, 0x30, 0x84), 0x8348)
        put32(image, 0x84, 0x1C0000E0)  # Halfword data write at +0x1a.

        profile, reason = detect_external_lcd(bytes(image))
        self.assertEqual(reason, "accepted")
        ports = {writer["address"] for writer in profile["writers"]}
        self.assertEqual(ports, {0x1A000000, 0x1C000000})
        data = next(writer for writer in profile["writers"]
                    if writer["address"] == 0x1C000000)
        self.assertEqual(data["effective_address"], 0x1C0000FA)
        self.assertEqual(data["access_size"], 2)
        self.assertEqual(data["literal"], 0x84)

        plan, reason = detect_external_bus(bytes(image))
        self.assertEqual(reason, "accepted")
        props = plan["machine_properties"]
        self.assertTrue(props["external-lcd-1a"])
        self.assertTrue(props["external-lcd-1c"])
        self.assertFalse(props["gpio-ready-bit21"])

    def test_literal_lcd_binding_rejects_reads_words_and_other_offsets(self) -> None:
        for pointer, store in ((0x1A000078, 0x8801),  # LDRH
                               (0x1A000078, 0x6001),  # STR word
                               (0x1A000078, 0x8041)):
            with self.subTest(pointer=hex(pointer), store=hex(store)):
                image = bytearray(0x100)
                put16(image, 0x20, ldr_literal(0, 0x20, 0x80), store)
                put32(image, 0x80, pointer)
                self.assertIsNone(detect_external_lcd(bytes(image))[0])

    def test_external_lcd_ready_level_spin(self) -> None:
        image = bytearray(0x80)
        ldr_at = 0x10
        struct_at = 0x60
        pool_at = 0x40
        put16(image, ldr_at, ldr_literal(1, ldr_at, pool_at),
              0x6848, 0x6800, 10 << 6, 0xD400, 0xE7FE)
        put32(image, pool_at, struct_at)
        put32(image, struct_at, 0, 0x03000720)
        profile, reason = detect_external_lcd(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["bit21"][0]["gpio"], 0x03000720)
        self.assertEqual(detect_gpio_ready_bit21(bytes(image))[1], "accepted")
        put32(image, struct_at + 4, 0x030006F4)
        self.assertIsNone(detect_external_lcd(bytes(image))[0])


if __name__ == "__main__":
    unittest.main()
