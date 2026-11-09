from __future__ import annotations

import struct
import random
import unittest
from unittest.mock import patch
from corpus import snippet

from msm5xxx_emulator.detection.devices.ready_poll import (
    find_ready_poll_profile, _UART_RX_EMPTY_READ, _called_mmio_candidates,
)
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.fact_context import FirmwareFacts
from msm5xxx_emulator.detection.devices.ready_poll import semantic


def fixture(status_base: int = 0x030007B0,
            pulse: int = 0x03000600) -> bytes:
    code = bytearray.fromhex("00f002f800000000")
    code.extend(snippet("test_ready_poll", "ready_poll_fixture_code"))
    code.extend(struct.pack("<2I", status_base, pulse))
    return bytes(code)


def semantic_register_fixture(status_base: int = 0x030007B0,
                              pulse: int = 0x03000600) -> bytes:
    """Generated Thumb loop with relocated registers and fact-derived ports."""
    code = bytearray(0x28)
    struct.pack_into("<2H", code, 0, 0xF000, 0xF802)  # BL entry at 8.
    struct.pack_into("<H", code, 4, 0x4770)
    struct.pack_into("<10H", code, 8,
                     0x4A05,       # LDR r2, status base
                     0x7913,       # LDRB r3, [r2, #4]
                     0x091B,       # LSRS r3, r3, #4
                     0xD205,       # BHS return
                     0x2401,       # MOVS r4, #1
                     0x4D04,       # LDR r5, pulse address
                     0x702C,       # STRB r4, [r5]
                     0x2400,       # MOVS r4, #0
                     0x702C,       # STRB r4, [r5]
                     0xE7F5)       # B loop
    struct.pack_into("<H", code, 0x1C, 0x4770)
    struct.pack_into("<2I", code, 0x20, status_base, pulse)
    return bytes(code)


def called_mmio_noise_fixture(count: int = 24) -> bytes:
    """Many called MMIO readers with no required branch/return contract."""
    code = bytearray(semantic_register_fixture())
    entries = [0x100 + index * 0x20 for index in range(count)]
    call_base = 0x100 + count * 0x20
    code.extend(b"\x00" * (call_base + count * 4 + 4 - len(code)))
    for index, entry in enumerate(entries):
        struct.pack_into("<3H", code, entry,
                         0x4802,  # LDR r0, literal at entry+12
                         0x7801,  # LDRB r1,[r0]
                         0x4770)  # no required conditional branch
        struct.pack_into("<I", code, entry + 12,
                         0x03000100 + 4 * index)
        site = call_base + 4 * index
        displacement = entry - site - 4
        struct.pack_into("<2H", code, site,
                         0xF000 | (displacement >> 12 & 0x7FF),
                         0xF800 | (displacement >> 1 & 0x7FF))
    return bytes(code)


def control_fixture(status_base: int = 0x03000F10,
                    pulse: int = 0x03000700) -> bytes:
    code = bytearray.fromhex("00f002f800000000")
    code.extend(snippet("test_ready_poll", "control_fixture_code"))
    code.extend(struct.pack("<2I", status_base, pulse))
    return bytes(code)


def independent_control_fixture(status_base: int = 0x03000F14,
                                pulse: int = 0x03000700,
                                control: int = 0x03000F1C) -> bytes:
    """Small independent Thumb control-loop fixture, without snippet bytes."""
    code = bytearray(0x68)
    struct.pack_into("<2H", code, 0, 0xF000, 0xF802)  # BL entry at 8
    struct.pack_into("<H", code, 4, 0x4770)
    struct.pack_into("<20H", code, 8,
                     0xBF00,  # NOP
                     0x4811,  # LDR r0, status
                     0x7801,  # LDRB r1,[r0]
                     0x0909,  # LSRS r1,r1,#4
                     0xD20D,  # BHS return at entry+38
                     0x4A10,  # LDR r2, pulse
                     0x4B10,  # LDR r3, one
                     0x4C11,  # LDR r4, zero
                     0x4E11,  # LDR r6, 0x20
                     0xD1F6,  # BNE entry+2
                     0x4D11,  # LDR r5, control
                     0xBF00,
                     0x7013,  # STRB r3,[r2]
                     0xBF00,
                     0x7014,  # STRB r4,[r2]
                     0xBF00,
                     0xBF00,
                     0x702E,  # STRB r6,[r5]
                     0xD1ED,  # BNE entry+2
                     0x4770)  # BX LR
    struct.pack_into("<6I", code, 0x50,
                     status_base, pulse, 1, 0, 0x20, control)
    return bytes(code)


def control_uart_empty_fixture(status_base: int = 0x03000F10,
                               pulse: int = 0x03000700) -> bytes:
    code = bytearray(control_fixture(status_base, pulse))
    helper, read, literals = 0x60, 0x66, 0xC0
    code.extend(b"\x00" * (0x100 - len(code)))

    def bl(position: int, target: int) -> None:
        displacement = target - position - 4
        struct.pack_into(
            "<2H", code, position,
            0xF000 | (displacement >> 12 & 0x7FF),
            0xF800 | (displacement >> 1 & 0x7FF),
        )

    def ldr_literal(position: int, register: int, literal: int) -> None:
        base = (position + 4) & ~3
        struct.pack_into("<H", code, position,
                         0x4800 | register << 8 | ((literal - base) // 4))

    bl(0x50, helper)
    struct.pack_into("<H", code, helper, 0xB500)
    bl(helper + 2, 8)
    ldr_literal(read, 0, literals)
    struct.pack_into("<17H", code, read,
                     struct.unpack_from("<H", code, read)[0],
                     0x3830, 0x7900, 0x0840, 0xD200, 0xE008,
                     0, 0x3830, 0x7A02, 0x2001, 0,
                     0x7008, 0x2000, 0x7008, 0xE7F0, 0xBC08, 0x4718)
    ldr_literal(read + 12, 0, literals)
    ldr_literal(read + 20, 1, literals + 4)
    struct.pack_into("<2I", code, literals, status_base + 0x30, pulse)
    return bytes(code)


def rotated_fixture(status_base: int = 0x03000F10,
                    pulse: int = 0x03000700) -> bytes:
    code = bytearray.fromhex("00f002f800000000")
    code.extend(snippet("test_ready_poll", "rotated_fixture_code"))
    code.extend(struct.pack("<2I", pulse, status_base))
    return bytes(code)


def arithmetic_rotated_fixture(subtract: bool = False,
                               pulse: int = 0x03000600) -> bytes:
    producer = ("cf1fff3f01226a3f" if subtract else "cf1dff370122aa37")
    return (bytes.fromhex("00f002f80000000090b407490020" + producer
                         + "01e00a7008703c792309fad390bc70470000")
            + struct.pack("<I", pulse))


def rotated_uart_clock_fixture(pulse: int = 0x03000600) -> bytes:
    code = bytearray(arithmetic_rotated_fixture(pulse=pulse))
    code.extend(b"\x00" * (0x240 - len(code)))
    code[0x80:0x112] = snippet("test_ready_poll", "rotated_uart_clock_code")
    for callsite, target in ((0x5C, 8), (0x60, 0x80), (0x82, 0x150),
                             (0xA0, 0x154), (0xA4, 8)):
        displacement = target - callsite - 4
        struct.pack_into("<2H", code, callsite,
                         0xF000 | (displacement >> 12 & 0x7FF),
                         0xF800 | (displacement >> 1 & 0x7FF))
    struct.pack_into("<4I", code, 0x114,
                     0x03000700, 0xFFFF, pulse + 0x140, pulse)
    code[0x150:0x156] = bytes.fromhex("704700007047")
    return bytes(code)


def rotated_with_uart_rx_fixture(status_base: int = 0x03000F10,
                                 pulse: int = 0x03000700) -> bytes:
    code = bytearray(rotated_fixture(status_base, pulse))
    entry = 8
    uart_rx = entry + 0xA8
    callsite = len(code)
    displacement = uart_rx - callsite - 4
    code.extend(struct.pack(
        "<2H", 0xF000 | (displacement >> 12 & 0x7FF),
        0xF800 | (displacement >> 1 & 0x7FF),
    ))
    code.extend(b"\x00" * (uart_rx - len(code)))
    code.extend(snippet("test_ready_poll", "rotated_uart_rx_code"))
    code.extend(struct.pack("<3I", status_base, pulse, 0x001E8480))
    return bytes(code)


def uart_csr_sr_fixture(status_base: int = 0x030007B0,
                        pulse: int = 0x03000600) -> bytes:
    code = bytearray(fixture(status_base, pulse))
    caller, entry, read = 0x60, 0x80, 0x90
    code.extend(b"\x00" * (0xB8 - len(code)))

    def bl(position: int, target: int) -> None:
        displacement = target - position - 4
        struct.pack_into(
            "<2H", code, position,
            0xF000 | (displacement >> 12 & 0x7FF),
            0xF800 | (displacement >> 1 & 0x7FF),
        )

    bl(caller, entry)
    struct.pack_into("<H", code, entry, 0xB500)
    bl(entry + 2, 8)
    struct.pack_into("<8H", code, read,
                     0x4807, 0x7900, 0x0840, 0xD306,
                     0x7A03, 0x2001, 0x4905, 0x7008)
    struct.pack_into("<4H", code, read + 16,
                     0x2000, 0x7008, 0xE7F4, 0xBD00)
    struct.pack_into("<2I", code, 0xB0, status_base, pulse)
    return bytes(code)


def uart_csr_sr_framed_fixture(status_base: int = 0x030007B0,
                               pulse: int = 0x03000600) -> bytes:
    code = bytearray(uart_csr_sr_fixture(status_base, pulse))
    code.extend(b"\x00" * (0x180 - len(code)))

    def bl(position: int, target: int) -> None:
        displacement = target - position - 4
        struct.pack_into(
            "<2H", code, position,
            0xF000 | (displacement >> 12 & 0x7FF),
            0xF800 | (displacement >> 1 & 0x7FF),
        )

    def branch(position: int, target: int) -> None:
        struct.pack_into("<H", code, position,
                         0xE000 | ((target - position - 4) // 2 & 0x7FF))

    entry, read = 0xC0, 0xD4
    struct.pack_into("<2H", code, entry, 0xB480, 0x1C02)
    struct.pack_into("<H", code, read - 2, 0x4824)
    struct.pack_into("<12H", code, read,
                     0x7901, 0x0848, 0xD302, 0x1C08,
                     0xBC80, 0x46F7, 0x2001, 0x4F21,
                     0x7038, 0x2000, 0x7038, 0)
    branch(read + 22, entry + 4)
    struct.pack_into("<H", code, 0x100, 0xB590)
    struct.pack_into("<H", code, 0x102, 0x2001)
    bl(0x104, entry)
    struct.pack_into("<H", code, 0x10C, 0x2000)
    bl(0x10E, entry)
    struct.pack_into("<2H", code, 0x11E, 0x4811, 0x7A00)
    struct.pack_into("<2I", code, 0x164, status_base, pulse)
    return bytes(code)


def lcd_halfword_fixture(prefix: bytes = b"") -> bytes:
    helper = len(prefix)
    entry = helper + 22
    callsite = entry + 2
    displacement = helper - callsite - 4
    branch = struct.pack(
        "<2H", 0xF000 | (displacement >> 12 & 0x7FF),
        0xF800 | (displacement >> 1 & 0x7FF),
    )
    code = bytearray(prefix + bytes.fromhex(
        "0521c90508818889704700bf380100020843021c00b50820"
    ) + branch + bytes.fromhex(
        "0009fad206200521c90508818a8108bc1847"
    ))
    caller = len(code)
    displacement = entry - 8 - caller - 4
    code.extend(struct.pack(
        "<2H", 0xF000 | (displacement >> 12 & 0x7FF),
        0xF800 | (displacement >> 1 & 0x7FF),
    ))
    return bytes(code)


class ReadyPollDetectionTests(unittest.TestCase):
    def test_exact_poll_returns_firmware_addresses(self) -> None:
        self.assertEqual(find_ready_poll_profile(fixture()), {
            "signature": "thumb-lsrs-bhs-pulse-v1",
            "status_address": 0x030007B4,
            "mask": 0x08,
            "pulse_address": 0x03000600,
            "entries": [8],
        })

    def test_semantic_loop_accepts_relocated_registers(self) -> None:
        self.assertEqual(find_ready_poll_profile(semantic_register_fixture()), {
            "signature": "thumb-lsrs-bhs-pulse-v1",
            "status_address": 0x030007B4,
            "mask": 0x08,
            "pulse_address": 0x03000600,
            "entries": [8],
        })

    def test_candidate_discovery_skips_unrelated_call_targets(self) -> None:
        image = bytearray(semantic_register_fixture())
        image.extend(b"\0" * (0x5000 - len(image)))
        for target in range(0x1000, 0x5000, 0x400):
            call = target - 4
            displacement = target - call - 4
            struct.pack_into("<2H", image, call,
                             0xF000 | (displacement >> 12 & 0x7FF),
                             0xF800 | (displacement >> 1 & 0x7FF))
            struct.pack_into("<H", image, target, 0x4770)
        self.assertEqual(_called_mmio_candidates(facts_for(bytes(image)), 'thumb'),
                         (8,))

    def test_semantic_precheck_avoids_analyzing_unqualified_mmio_owners(self) -> None:
        image = called_mmio_noise_fixture()
        facts = FirmwareFacts(image)
        with patch.object(semantic, "facts_for", return_value=facts):
            members = semantic._semantic_pulse_members(image)
        self.assertEqual(members, [{
            "signature": "thumb-lsrs-bhs-pulse-v1",
            "status_address": 0x030007B4,
            "mask": 0x08,
            "pulse_address": 0x03000600,
            "entries": [8],
        }])
        self.assertEqual(len(facts._functions), 1)

    def test_control_precheck_avoids_unqualified_mmio_owners(self) -> None:
        image = bytearray(independent_control_fixture())
        count = 24
        entries = [0x200 + index * 0x20 for index in range(count)]
        call_base = 0x200 + count * 0x20
        image.extend(b"\x00" * (call_base + count * 4 + 4 - len(image)))
        for index, entry in enumerate(entries):
            struct.pack_into("<3H", image, entry,
                             0x4802, 0x7801, 0x4770)
            struct.pack_into("<I", image, entry + 12,
                             0x03000200 + 4 * index)
            site = call_base + 4 * index
            displacement = entry - site - 4
            struct.pack_into("<2H", image, site,
                             0xF000 | (displacement >> 12 & 0x7FF),
                             0xF800 | (displacement >> 1 & 0x7FF))
        image = bytes(image)
        facts = FirmwareFacts(image)
        with patch.object(semantic, "facts_for", return_value=facts):
            profile = semantic._find_control_ready_poll_profile(image)
        self.assertEqual(profile, {
            "signature": "thumb-byte-ready-pulse-control-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x03000F14,
            "mask": 0x08,
            "pulse_address": 0x03000700,
            "control_address": 0x03000F1C,
            "control_value": 0x20,
            "status_read_pc_offset": 4,
            "pulse_set_pc_offset": 0x18,
            "pulse_clear_pc_offset": 0x1C,
            "control_pc_offset": 0x22,
            "entries": [8],
        })
        self.assertEqual(len(facts._functions), 1)

    def test_near_miss_and_conflicting_contract_fail_closed(self) -> None:
        near = bytearray(fixture())
        near[16] ^= 1
        self.assertIsNone(find_ready_poll_profile(bytes(near)))
        self.assertIsNone(find_ready_poll_profile(
            fixture() + fixture(0x03000F10, 0x03000700)
        ))
        self.assertIsNone(find_ready_poll_profile(fixture()[8:]))
        self.assertIsNone(find_ready_poll_profile(b"\x00" + fixture()))

    def test_control_poll_returns_all_firmware_sites(self) -> None:
        self.assertEqual(find_ready_poll_profile(control_fixture()), {
            "signature": "thumb-byte-ready-pulse-control-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x03000F14,
            "mask": 0x08,
            "pulse_address": 0x03000700,
            "control_address": 0x03000F1C,
            "control_value": 0x20,
            "status_read_pc_offset": 4,
            "pulse_set_pc_offset": 0x18,
            "pulse_clear_pc_offset": 0x1C,
            "control_pc_offset": 0x22,
            "entries": [8],
        })

    def test_control_uart_empty_requires_exact_post_control_helper(self) -> None:
        self.assertEqual(find_ready_poll_profile(control_uart_empty_fixture()), {
            "signature": "thumb-byte-ready-pulse-control-uart-empty-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x03000F14,
            "mask": 0x08,
            "pulse_address": 0x03000700,
            "control_address": 0x03000F1C,
            "control_value": 0x20,
            "status_read_pc_offset": 4,
            "pulse_set_pc_offset": 0x18,
            "pulse_clear_pc_offset": 0x1C,
            "control_pc_offset": 0x22,
            "uart_rx_empty_read_pc_offset": 0x62,
            "entries": [8],
        })
        near = bytearray(control_uart_empty_fixture())
        near[0x66 + 28] ^= 1
        self.assertEqual(find_ready_poll_profile(bytes(near))["signature"],
                         "thumb-byte-ready-pulse-control-v1")

    def test_rotated_poll_uses_explicit_firmware_pc_offsets(self) -> None:
        self.assertEqual(find_ready_poll_profile(rotated_fixture()), {
            "signature": "thumb-lsrs-bcc-pulse-rotated-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x03000F14,
            "mask": 0x08,
            "pulse_address": 0x03000700,
            "status_read_pc_offset": 0x10,
            "pulse_set_pc_offset": 0x0C,
            "pulse_clear_pc_offset": 0x0E,
            "entries": [8],
        })
        near = bytearray(rotated_fixture())
        near[8 + 20] ^= 1
        self.assertIsNone(find_ready_poll_profile(bytes(near)))
        duplicate = find_ready_poll_profile(rotated_fixture() + rotated_fixture())
        self.assertEqual([member["entries"] for member in duplicate["variants"]],
                         [[8], [len(rotated_fixture()) + 8]])

    def test_uart_rx_helper_is_not_promoted_to_ready_poll(self) -> None:
        profile = find_ready_poll_profile(rotated_with_uart_rx_fixture())

        self.assertEqual(profile["signature"],
                         "thumb-lsrs-bcc-pulse-rotated-v1")
        self.assertNotIn("followup_entry", profile)

    def test_arithmetic_rotated_poll_requires_closed_producer_and_unique_caller(self) -> None:
        for subtract, pulse, status in (
                (False, 0x03000600, 0x030007B4),
                (True, 0x03001080, 0x03000F14),
                (False, 0x03002000, 0x030021B4)):
            code = arithmetic_rotated_fixture(subtract, pulse)
            with self.subTest(subtract=subtract, pulse=pulse):
                self.assertEqual(find_ready_poll_profile(code), {
                    "signature": "thumb-lsrs-bcc-pulse-rotated-v1",
                    "admission": "temporary-evidence-gated",
                    "status_address": status, "mask": 0x08,
                    "pulse_address": pulse, "entries": [8],
                    "status_read_pc_offset": 0x14,
                    "pulse_set_pc_offset": 0x10,
                    "pulse_clear_pc_offset": 0x12,
                })
                for offset in (0, 8 + 6, 8 + 12, 8 + 16, 8 + 24):
                    near = bytearray(code)
                    near[offset] ^= 1
                    self.assertIsNone(find_ready_poll_profile(bytes(near)))
                self.assertIsNone(find_ready_poll_profile(code[8:]))
                self.assertIsNone(find_ready_poll_profile(code[:-1]))
                self.assertEqual(len(find_ready_poll_profile(code + code)["variants"]), 2)
                combined = find_ready_poll_profile(
                    rotated_fixture(status - 4, pulse) + code)
                self.assertEqual([p["status_read_pc_offset"]
                                  for p in combined["variants"]], [0x10, 0x14])
                self.assertIsNone(find_ready_poll_profile(code + control_fixture()))
        self.assertIsNone(find_ready_poll_profile(
            arithmetic_rotated_fixture(pulse=0x02000600)))
        self.assertIsNone(find_ready_poll_profile(
            arithmetic_rotated_fixture(True, pulse=0x03000000)))

    def test_same_contract_variants_preserve_relocated_shapes(self) -> None:
        def mixed(compact: bytes, rotated: bytes,
                  compact_base: int, rotated_base: int) -> bytes:
            code = bytearray(max(compact_base + len(compact),
                                 rotated_base + len(rotated)))
            for base, body in ((compact_base, compact),
                               (rotated_base, rotated)):
                code[base:base + len(body)] = body
                # Relocate the actual caller BL with its helper, not a finder mock.
                displacement = base + 8 - (base + 4)
                struct.pack_into("<2H", code, base,
                                 0xF000 | (displacement >> 12 & 0x7FF),
                                 0xF800 | (displacement >> 1 & 0x7FF))
            return bytes(code)

        for compact in (fixture(), uart_csr_sr_fixture(),
                        uart_csr_sr_framed_fixture()):
            compact_profile = find_ready_poll_profile(compact)
            rotated = arithmetic_rotated_fixture()
            rotated_profile = find_ready_poll_profile(rotated)
            for compact_base, rotated_base in ((0x40, 0x300), (0x100, 0x500)):
                with self.subTest(signature=compact_profile["signature"],
                                  compact_base=compact_base):
                    image = mixed(compact, rotated, compact_base, rotated_base)
                    self.assertEqual(find_ready_poll_profile(image), {
                        "signature": "thumb-byte-ready-pulse-variants-v1",
                        "admission": "temporary-evidence-gated",
                        "status_address": 0x030007B4,
                        "mask": 0x08,
                        "pulse_address": 0x03000600,
                        "variants": [
                            {**compact_profile,
                             "entries": [compact_base + 8]},
                            {**rotated_profile,
                             "entries": [rotated_base + 8]},
                        ],
                    })
                    self.assertIsNone(find_ready_poll_profile(
                        image + control_fixture()))
                    self.assertIsNone(find_ready_poll_profile(mixed(
                        compact, arithmetic_rotated_fixture(pulse=0x03002000),
                        compact_base, rotated_base)))
                    # Same status but a foreign pulse also cannot be merged.
                    self.assertIsNone(find_ready_poll_profile(mixed(
                        compact, rotated_fixture(0x030007B0, 0x03000700),
                        compact_base, rotated_base)))

    def test_multiple_rotated_members_flatten_and_keep_call_proof(self) -> None:
        bodies = [fixture(0x03000F10, 0x03000700), rotated_fixture(),
                  rotated_fixture()]
        bases = [0x40, 0x100, 0x200]
        image = bytearray(0x300)
        for base, body in zip(bases, bodies):
            image[base:base + len(body)] = body
        profile = find_ready_poll_profile(bytes(image))
        self.assertEqual([p["entries"] for p in profile["variants"]],
                         [[0x48], [0x108], [0x208]])
        self.assertTrue(all("variants" not in p for p in profile["variants"]))
        foreign = bytearray(image)
        struct.pack_into("<I", foreign, 0x200 + 36, 0x030007B0)
        self.assertIsNone(find_ready_poll_profile(bytes(foreign)))
        for offset in (0x100, 0x200):
            near = bytearray(image)
            near[offset:offset + 4] = b"\x00" * 4
            remaining = find_ready_poll_profile(bytes(near))
            self.assertNotIn([offset + 8],
                             [p["entries"] for p in remaining["variants"]])
            near = bytearray(image)
            near[offset + 8 + 20] ^= 1
            remaining = find_ready_poll_profile(bytes(near))
            self.assertNotIn([offset + 8],
                             [p["entries"] for p in remaining["variants"]])
        # A relocated caller aimed at the other helper proves only that target.
        near = bytearray(image)
        displacement = 0x108 - (0x200 + 4)
        struct.pack_into("<2H", near, 0x200,
                         0xF000 | (displacement >> 12 & 0x7FF),
                         0xF800 | (displacement >> 1 & 0x7FF))
        self.assertEqual([p["entries"] for p in
                          find_ready_poll_profile(bytes(near))["variants"]],
                         [[0x48], [0x108]])

    def test_rx_prefilter_positions_equal_halfword_scan(self) -> None:
        rng = random.Random(0x79000840)
        pattern = bytes.fromhex("00794008")
        images = [bytes(rng.randrange(256) for _ in range(n))
                  for n in range(100)]
        for length in range(4, 40):
            for at in range(length - 3):
                code = bytearray(length)
                code[at:at + 4] = pattern
                images.append(bytes(code))
        images.extend(pattern[:n] for n in range(5))
        images.append(pattern * 20)
        for image in images:
            legacy = [at for at in range(4, len(image) - 6, 2)
                      if struct.unpack_from("<2H", image, at) == (0x7900, 0x0840)]
            filtered = [m.start() for m in _UART_RX_EMPTY_READ.finditer(image, 4)
                        if not m.start() & 1 and m.start() < len(image) - 6]
            self.assertEqual(filtered, legacy, (len(image), image.hex()))

    def test_uart_status_literal_sub_and_add_require_exact_derived_alias(self) -> None:
        for operation, literal in ((0x3810, 0x030007C0), (0x3010, 0x030007A0)):
            code = bytearray(uart_csr_sr_fixture())
            struct.pack_into("<2H", code, 0x8E, 0x4808, operation)
            struct.pack_into("<I", code, 0xB0, literal)
            profile = find_ready_poll_profile(bytes(code))
            self.assertEqual(profile["signature"], "thumb-uart-csr-sr-rx-empty-v1")
            self.assertEqual(profile["uart_rx_empty_read_pc_offset"], 0x8A)
            # Relocating the whole closed helper keeps its literals and branches bound.
            self.assertEqual(find_ready_poll_profile(bytes(0x40) + code)["entries"], [0x48])
            for offset in (0x90, 0xB0, 0x9C):
                near = bytearray(code)
                near[offset] ^= 1
                self.assertEqual(find_ready_poll_profile(bytes(near))["signature"],
                                 "thumb-lsrs-bhs-pulse-v1")

    def test_multiple_compact_members_upgrade_independently_and_merge_flat(self) -> None:
        first = uart_csr_sr_fixture()
        second = uart_csr_sr_fixture()
        profile = find_ready_poll_profile(first + second)
        self.assertEqual([p["entries"] for p in profile["variants"]],
                         [[8], [len(first) + 8]])
        self.assertTrue(all(p["signature"] == "thumb-uart-csr-sr-rx-empty-v1"
                            for p in profile["variants"]))
        near = bytearray(first + second)
        near[len(first) + 0x94] ^= 1
        profile = find_ready_poll_profile(bytes(near))
        self.assertEqual([p["signature"] for p in profile["variants"]],
                         ["thumb-uart-csr-sr-rx-empty-v1", "thumb-lsrs-bhs-pulse-v1"])
        profile = find_ready_poll_profile(bytes(near) + arithmetic_rotated_fixture())
        self.assertEqual(len(profile["variants"]), 3)
        self.assertTrue(all("variants" not in p for p in profile["variants"]))
        self.assertIsNone(find_ready_poll_profile(
            bytes(near) + arithmetic_rotated_fixture(pulse=0x03002000)))

    def test_ambiguous_rx_helpers_preserve_compact_fallback(self) -> None:
        code = bytearray(uart_csr_sr_fixture())
        code.extend(bytes(0x1B8 - len(code)))
        code[0x180:0x1B8] = code[0x80:0xB8]
        for callsite, target in ((0x64, 0x180), (0x182, 8)):
            displacement = target - callsite - 4
            struct.pack_into("<2H", code, callsite,
                             0xF000 | (displacement >> 12 & 0x7FF),
                             0xF800 | (displacement >> 1 & 0x7FF))
        self.assertEqual(find_ready_poll_profile(bytes(code))["signature"],
                         "thumb-lsrs-bhs-pulse-v1")

    def test_uart_csr_sr_pair_requires_exact_rx_empty_helper(self) -> None:
        self.assertEqual(find_ready_poll_profile(uart_csr_sr_fixture()), {
            "signature": "thumb-uart-csr-sr-rx-empty-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x030007B4,
            "mask": 0x08,
            "pulse_address": 0x03000600,
            "status_read_pc_offset": 2,
            "pulse_set_pc_offset": 0x0C,
            "pulse_clear_pc_offset": 0x10,
            "uart_rx_empty_read_pc_offset": 0x8A,
            "entries": [8],
        })
        near = bytearray(uart_csr_sr_fixture())
        near[0x94] ^= 1
        self.assertEqual(find_ready_poll_profile(bytes(near))["signature"],
                         "thumb-lsrs-bhs-pulse-v1")

    def test_rotated_uart_requires_mapped_clock_setup_and_called_drain(self) -> None:
        code = rotated_uart_clock_fixture()
        expected = {
            **find_ready_poll_profile(arithmetic_rotated_fixture()),
            "signature": "thumb-uart-csr-sr-rx-empty-v1",
            "uart_rx_empty_read_pc_offset": 0xFE,
        }
        self.assertEqual(find_ready_poll_profile(code), expected)
        # UART2 map is the same class; a different/unmapped status stays native.
        self.assertEqual(find_ready_poll_profile(
            rotated_uart_clock_fixture(0x03000200))["signature"],
            "thumb-uart-csr-sr-rx-empty-v1")
        self.assertEqual(find_ready_poll_profile(
            rotated_uart_clock_fixture(0x03002000))["signature"],
            "thumb-lsrs-bcc-pulse-rotated-v1")
        for offset in (0x5C, 0x60, 0x80, 0x99, 0x9E, 0xA4,
                       0xA8, 0xD8, 0xDA, 0xDC, 0xDE, 0xE4, 0xF0,
                       0xFA, 0x100, 0x104, 0x106, 0x10A, 0x110,
                       0x11C, 0x120):
            with self.subTest(offset=offset):
                near = bytearray(code)
                near[offset] ^= 1
                self.assertEqual(find_ready_poll_profile(bytes(near))["signature"],
                                 "thumb-lsrs-bcc-pulse-rotated-v1")
        self.assertEqual(find_ready_poll_profile(code[:0x111])["signature"],
                         "thumb-lsrs-bcc-pulse-rotated-v1")
        # Relocating both literals preserves their relationship and the class.
        moved = bytearray(code)
        for address, register in ((0xA8, 1), (0xB8, 1), (0xC0, 1),
                                  (0xCE, 1), (0xD6, 2), (0xFA, 1)):
            literal = 0x140 if register == 2 or address != 0xFA else 0x144
            struct.pack_into("<H", moved, address,
                             0x4800 | register << 8
                             | ((literal - ((address + 4) & ~3)) // 4))
        moved[0x140:0x148] = moved[0x11C:0x124]
        self.assertEqual(find_ready_poll_profile(bytes(moved)), expected)
        # An exact drain in data or behind an early return must not be admitted.
        for address in (0x80, 0xA8):
            decoy = bytearray(code)
            decoy[address:address + 2] = bytes.fromhex("7047")
            self.assertEqual(find_ready_poll_profile(bytes(decoy))["signature"],
                             "thumb-lsrs-bcc-pulse-rotated-v1")
        # Two complete called receivers are ambiguous; preserve the base class.
        duplicate = bytearray(code)
        duplicate[0x180:0x224] = code[0x80:0x124]
        for callsite, target in ((0x70, 8), (0x74, 0x180),
                                 (0x1A4, 8)):
            displacement = target - callsite - 4
            struct.pack_into("<2H", duplicate, callsite,
                             0xF000 | (displacement >> 12 & 0x7FF),
                             0xF800 | (displacement >> 1 & 0x7FF))
        self.assertEqual(find_ready_poll_profile(bytes(duplicate))["signature"],
                         "thumb-lsrs-bcc-pulse-rotated-v1")

    def test_uart_csr_sr_framed_reader_requires_fifo_consumer(self) -> None:
        profile = find_ready_poll_profile(uart_csr_sr_framed_fixture())

        self.assertEqual(profile["uart_rx_empty_frame_read_pc_offset"], 0xCC)
        near = bytearray(uart_csr_sr_framed_fixture())
        near[0x120] ^= 1
        profile = find_ready_poll_profile(bytes(near))
        self.assertNotIn("uart_rx_empty_frame_read_pc_offset", profile)

    def test_control_near_miss_and_mixed_classes_fail_closed(self) -> None:
        near = bytearray(control_fixture())
        near[8 + 34] ^= 1
        self.assertIsNone(find_ready_poll_profile(bytes(near)))
        self.assertIsNone(find_ready_poll_profile(control_fixture()[8:]))
        self.assertIsNone(find_ready_poll_profile(
            fixture() + control_fixture()
        ))

    def test_lcd_halfword_poll_requires_exact_helper_and_caller(self) -> None:
        self.assertEqual(find_ready_poll_profile(lcd_halfword_fixture()), {
            "signature": "thumb-lcd-halfword-busy-clear-v1",
            "admission": "experimental-only",
            "status_address": 0x0280000C,
            "mask": 0x08,
            "command_address": 0x02800008,
            "command_value": 0x08,
            "status_read_pc_offset": 6,
            "command_write_pc_offset": 4,
            "entries": [0],
        })
        near = bytearray(lcd_halfword_fixture())
        near[-4] ^= 1
        self.assertIsNone(find_ready_poll_profile(bytes(near)))
        near = bytearray(lcd_halfword_fixture())
        near[12] ^= 1
        self.assertEqual(find_ready_poll_profile(bytes(near))["signature"],
                         "thumb-lcd-halfword-busy-clear-v1")
        near = bytearray(lcd_halfword_fixture())
        near[14] ^= 1
        self.assertIsNone(find_ready_poll_profile(bytes(near)))
        self.assertIsNone(find_ready_poll_profile(
            lcd_halfword_fixture(lcd_halfword_fixture())
        ))
        self.assertEqual(
            find_ready_poll_profile(lcd_halfword_fixture(fixture()))["signature"],
            "thumb-lsrs-bhs-pulse-v1",
        )


class TransportGateTests(unittest.TestCase):
    def test_variants_preserve_sites_and_reject_malformed_ownership(self) -> None:
        from copy import deepcopy
        from tests.test_qemu_input_transport import MODULE

        uart = find_ready_poll_profile(uart_csr_sr_fixture())
        uart["entries"] = [0x27D4]
        uart["uart_rx_empty_read_pc_offset"] = 0xA0
        rotated = find_ready_poll_profile(arithmetic_rotated_fixture())
        rotated["entries"] = [0x1158]
        profile = {
            "signature": "thumb-byte-ready-pulse-variants-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x030007B4,
            "mask": 8,
            "pulse_address": 0x03000600,
            "variants": [uart, rotated],
        }
        self.assertEqual(MODULE.qemu_ready_poll_property(profile), (
            "ready-poll-sites=30007b4:8:3000600:"
            "27d4,,2,,c,,10,,a0;1158,,14,,10,,12", None))
        framed = deepcopy(profile)
        framed["variants"][0]["uart_rx_empty_frame_read_pc_offset"] = 0x100
        self.assertEqual(MODULE.qemu_ready_poll_property(framed), (
            "ready-poll-sites=30007b4:8:3000600:"
            "27d4,,2,,c,,10,,a0,,100;1158,,14,,10,,12", None))
        plain = deepcopy(profile)
        plain["variants"][0] = {
            **find_ready_poll_profile(fixture()), "entries": [0x27D4],
        }
        self.assertEqual(MODULE.qemu_ready_poll_property(plain), (
            "ready-poll-sites=30007b4:8:3000600:"
            "27d4,,2,,c,,10;1158,,14,,10,,12", None))

        invalid = []
        bad = deepcopy(profile)
        bad["admission"] = "experimental-only"
        invalid.append(("admission", bad, "unsupported-admission"))
        bad = deepcopy(profile)
        bad["variants"][0] = deepcopy(profile)
        invalid.append(("nested", bad, "unsupported-variant"))
        bad = deepcopy(profile)
        bad["variants"][1]["pulse_address"] += 4
        invalid.append(("contract", bad, "variant-contract-mismatch"))
        bad = deepcopy(profile)
        bad["variants"][1]["entries"] = [0x27D4]
        invalid.append(("duplicate", bad, "duplicate-variant-entry"))
        for label, field, value in (
                ("odd", "status_read_pc_offset", 3),
                ("oversized", "uart_rx_empty_read_pc_offset", 0x1002),
                ("duplicate-offset", "status_read_pc_offset", 0xC)):
            bad = deepcopy(profile)
            bad["variants"][0][field] = value
            invalid.append((label, bad, "malformed-variant-offsets"))
        bad = deepcopy(profile)
        bad["variants"][0]["entries"] = [0xFFFFFFFE]
        invalid.append(("wrap", bad, "wrapped-variant-pc"))
        bad = deepcopy(profile)
        # Rotated read aliases the UART read without duplicating its entry.
        bad["variants"][1]["entries"] = [0x27D4 + 2 - 0x14]
        invalid.append(("ownership", bad, "overlapping-variant-sites"))
        bad = deepcopy(plain)
        bad["variants"][0]["entries"] = [0x100 * index for index in range(1, 9)]
        invalid.append(("total-count", bad, "entry-count-limit"))
        bad = deepcopy(framed)
        bad["variants"][0]["uart_rx_empty_frame_read_pc_offset"] = 0xA0
        invalid.append(("frame-alias", bad, "malformed-variant-offsets"))
        for label, bad, reason in invalid:
            with self.subTest(reason=label):
                self.assertEqual(MODULE.qemu_ready_poll_property(bad),
                                 (None, reason))


if __name__ == "__main__":
    unittest.main()
