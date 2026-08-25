from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.ready_poll import find_ready_poll_profile


def fixture(status_base: int = 0x030007B0,
            pulse: int = 0x03000600) -> bytes:
    code = bytearray.fromhex("00f002f800000000")
    code.extend(bytes.fromhex(
        "05480079000905d201200449087000200870f5e7f7460000"
    ))
    code.extend(struct.pack("<2I", status_base, pulse))
    return bytes(code)


def control_fixture(status_base: int = 0x03000F10,
                    pulse: int = 0x03000700) -> bytes:
    code = bytearray.fromhex("00f002f800000000")
    code.extend(bytes.fromhex(
        "00200949097909090dd2011c421c101c4908f6d30121054a"
        "1170002111702021014a1173ede77047"
    ))
    code.extend(struct.pack("<2I", status_base, pulse))
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
    code.extend(bytes.fromhex(
        "90b400200122064f044901e00a7008703c792309fad390bc70470000"
    ))
    code.extend(struct.pack("<2I", pulse, status_base))
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
    code.extend(bytes.fromhex(
        "b0b40127002400280a4a0b4b0cd00b491079450806d21f701c700139"
        "0029f7dc0120c043b0bc704710794108fad21f701c70f9e7"
    ))
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
        self.assertIsNone(find_ready_poll_profile(
            rotated_fixture() + rotated_fixture()
        ))

    def test_uart_rx_helper_is_not_promoted_to_ready_poll(self) -> None:
        profile = find_ready_poll_profile(rotated_with_uart_rx_fixture())

        self.assertEqual(profile["signature"],
                         "thumb-lsrs-bcc-pulse-rotated-v1")
        self.assertNotIn("followup_entry", profile)

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


if __name__ == "__main__":
    unittest.main()
