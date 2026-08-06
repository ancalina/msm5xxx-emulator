"""Static C80 controller/callback candidates must fail closed."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.core.emulator import GenericMSMEmulator
from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.rex import find_rex_static_controller_callback_candidate
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_SP


def _bl(source: int, target: int) -> bytes:
    displacement = target - source - 4
    return struct.pack("<2H", 0xF000 | (displacement >> 12 & 0x7FF),
                       0xF800 | (displacement >> 1 & 0x7FF))


def _literal(
        image: bytearray, position: int, register: int, value: int, pool: int,
) -> None:
    base = (position + 4) & ~3
    assert pool >= base and (pool - base) % 4 == 0
    struct.pack_into("<H", image, position,
                     0x4800 | register << 8 | (pool - base) // 4)
    struct.pack_into("<I", image, pool, value)


def _candidate_image() -> tuple[bytearray, dict[str, int]]:
    image = bytearray(0x1400)
    handler, registrar, registration = 0x400, 0x700, 0xA00
    callback, advance, seed_at = 0xC00, 0xE00, 0x1000
    masks, status, enable, table = 0x01004000, 0x03000C80, 0x03000C94, 0x01005000
    default = handler - 0x68 | 1
    struct.pack_into("<I", image, 0x18, 0xEA3FFFF8)
    struct.pack_into("<7I", image, seed_at, status, enable, 0x200, masks,
                     masks + 6, default, 0)

    wrapper, handler_slot, setter, handler_registration = (
        0x100, 0x01007000, 0xD00, 0xB80)
    struct.pack_into("<4I", image, wrapper, 0xE24EE004, 0xE92D540F,
                     0xE14F0000, 0xE92D0001)
    struct.pack_into("<I", image, wrapper + 0x28, 0xE59F3000)
    struct.pack_into("<I", image, wrapper + 0x30, handler_slot)

    handler_words = [0] * 64
    handler_words[:4] = (0xB5F0, 0xB086, 0, 0)
    handler_words[5:9] = (0x88D1, 0x9102, 0x8911, 0x9101)
    handler_words[10] = 0x8838
    handler_words[12:26] = (
        0x8813, 0x9902, 0x4019, 0x4001, 0x9104, 0x88B8,
        0x8853, 0x9901, 0x4019, 0x4008, 0x9904, 0x9003,
        0x4308, 0xD101,
    )
    struct.pack_into("<64H", image, handler, *handler_words)
    image[handler + 4:handler + 8] = _bl(handler + 4, 0x600)
    image[handler + 52:handler + 56] = _bl(handler + 52, 0x680)
    for offset, register, value, pool in (
            (handler + 8, 2, masks, 0x580),
            (handler + 18, 7, status, 0x584),
            (handler + 22, 2, masks, 0x588),
            (handler + 0x70, 2, masks, 0x58C),
            (handler + 0x74, 7, status, 0x590),
            (handler + 0x90, 1, status, 0x594)):
        _literal(image, offset, register, value, pool)
    for offset in (handler + 0x80, handler + 0x88):
        struct.pack_into("<H", image, offset, 0x6978)
        image[offset + 2:offset + 6] = _bl(offset + 2, 0x600)
    image[0x600:0x602] = b"\x00\x47"
    struct.pack_into("<H", image, handler + 0x92, 0x8008)

    registrar_words = [0] * 34
    registrar_words[:3] = (0xB5F8, 0x1C04, 0x1C0F)
    registrar_words[5:7] = (0x1C05, 0x2F00)
    registrar_words[8:13] = (0xD100, 0x1C37, 0x2C00, 0xDB01, 0x2C1F)
    registrar_words[13] = 0xDB01
    registrar_words[16:21] = (0x2200, 0x9200, 0x2300, 0x1C22, 0xA118)
    registrar_words[24] = 0x201C
    registrar_words[26:34] = (
        0x4360, 0x1840, 0x2C00, 0xD102, 0,
        0x630F, 0xE000, 0x6147,
    )
    struct.pack_into("<34H", image, registrar, *registrar_words)
    image[registrar + 6:registrar + 10] = _bl(registrar + 6, 0x680)
    image[registrar + 28:registrar + 32] = _bl(registrar + 28, 0x684)
    image[registrar + 44:registrar + 48] = _bl(registrar + 44, 0x688)
    for offset, register, value, pool in (
            (registrar + 14, 6, default, 0x900),
            (registrar + 42, 0, 0x01006000, 0x904),
            (registrar + 50, 1, 0x01006000, 0x908),
            (registrar + 60, 1, table, 0x90C)):
        _literal(image, offset, register, value, pool)

    _literal(image, registration - 8, 1, 0x030007A0, 0xB00)
    struct.pack_into("<2H", image, registration - 6, 0x2002, 0x7008)
    _literal(image, registration - 2, 1, callback | 1, 0xB04)
    struct.pack_into("<H", image, registration, 0x201E)
    image[registration + 2:registration + 6] = _bl(registration + 2, registrar)

    _literal(image, handler_registration, 1, handler | 1, 0xBC0)
    struct.pack_into("<H", image, handler_registration + 2, 0x2000)
    image[handler_registration + 4:handler_registration + 8] = _bl(
        handler_registration + 4, setter)
    struct.pack_into("<7H", image, setter, 0x4A0F, 0x2800, 0xD101,
                     0x6011, 0x4770, 0x6051, 0x4770)
    _literal(image, setter, 2, handler_slot, 0xD40)

    callback_words = [0] * 34
    callback_words[0] = 0xB580
    for index, value in ((3, 0x0407), (4, 0x0C3F), (5, 0x2105),
                         (12, 0x0880), (13, 0xD301), (15, 0xE000),
                         (17, 0x6808), (18, 0x3805), (19, 0x6008),
                         (20, 0x2005), (23, 0x2105), (27, 0x2F00),
                         (28, 0xD101), (31, 0xBC80), (32, 0xBC08),
                         (33, 0x4718)):
        callback_words[index] = value
    for index in (6, 9, 14, 16, 24):
        callback_words[index] = 0x4800
    struct.pack_into("<34H", image, callback, *callback_words)
    image[callback + 0x2A:callback + 0x2E] = _bl(callback + 0x2A, advance)
    image[callback + 0x32:callback + 0x36] = _bl(callback + 0x32, 0xF00)
    struct.pack_into("<16H", image, advance,
                     0xB5F0, 0, 0, 0, 0, 0x42A0, 0,
                     0x2000, 0x60B8, 0, 0, 0, 0x68F8, 0x6939, 0, 0)
    image[advance + 28:advance + 32] = _bl(advance + 28, 0xF00)
    return image, {
        "handler": handler, "registrar": registrar, "registration": registration,
        "callback": callback, "advance": advance, "seed": seed_at,
        "wrapper": wrapper, "handler_slot": handler_slot,
        "setter": setter, "handler_registration": handler_registration,
    }


class StaticControllerCandidateTests(unittest.TestCase):
    def test_620_pending_reads_consume_only_addressed_bank(self) -> None:
        status, enable = 0x03000620, 0x03000628
        route = {
            "signature":
                "experimental-static-msm5000-620-controller-route-v1",
            "controller_class":
                "legacy-msm5000-620-two-bank-read-consume-v1",
            "status": status,
            "enable": enable,
            "status_banks": (status, status + 4),
            "mask_set_banks": (status, status + 4),
            "mask_output_banks": (enable, enable + 4),
            "controller_aperture": (status, enable + 8),
            "status_bank_count": 2,
            "group_row_size": 12,
            "pending_read_semantics": "consume-on-read",
        }
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(rex_irq_status_address=status)
        emulator.direct_input_profile = None
        emulator._rex_candidate_route = route
        emulator._rex_irq_pending = [0x0200, 0x0040]
        emulator.rex_controller_pending_acks = 0
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x03000000, 0x10000)

        emulator._rex_irq_status_write(
            uc, 0, status, 2, 0xFFFF, None
        )
        self.assertEqual(emulator._rex_irq_pending, [0x0200, 0x0040])
        emulator._rex_irq_status_read(uc, 0, enable, 2, 0, None)
        self.assertEqual(emulator._rex_irq_pending, [0x0200, 0x0040])
        emulator._rex_irq_status_read(uc, 0, status, 2, 0, None)
        self.assertEqual(
            struct.unpack("<H", uc.mem_read(status, 2))[0], 0x0200
        )
        self.assertEqual(emulator._rex_irq_pending, [0, 0x0040])
        emulator._rex_irq_status_read(uc, 0, status + 4, 2, 0, None)
        self.assertEqual(
            struct.unpack("<H", uc.mem_read(status + 4, 2))[0], 0x0040
        )
        self.assertEqual(emulator._rex_irq_pending, [0, 0])
        self.assertEqual(emulator.rex_controller_pending_acks, 2)

    def test_620_two_peer_topology_is_telemetry_only(self) -> None:
        root = Path(__file__).resolve().parents[2] / "firmwares"
        expected = {
            "SPH-X7509.bin": (0x92320, 0x92520, 0x1A128, 0x926BC,
                               0x20CC04, 0x010C892C, 0x010035EC),
            "SPH-X7500-X75.00-WD01.bin": (
                0x8D948, 0x8DB48, 0x16CAC, 0x8DCE4,
                0x1FEAD4, 0x010BCD9C, 0x01003304,
            ),
        }
        for name, addresses in expected.items():
            image = (root / name).read_bytes()
            candidate = find_rex_static_controller_callback_candidate(image)
            self.assertIsNotNone(candidate)
            assert candidate is not None
            self.assertTrue(candidate["accepted"])
            self.assertFalse(candidate["active"])
            self.assertEqual(
                candidate["signature"],
                "static-msm5000-620-controller-callback-v1",
            )
            self.assertEqual(
                candidate["controller_class"],
                "legacy-msm5000-620-two-bank-read-consume-v1",
            )
            self.assertEqual(candidate["pending_read_semantics"],
                             "consume-on-read")
            self.assertEqual(tuple(candidate[field] for field in (
                "handler_file_offset", "registrar_file_offset",
                "callback_file_offset", "timer_advance_file_offset",
                "wrapper_file_offset", "handler_slot", "callback_slot",
            )), addresses)

            changed = bytearray(image)
            changed[addresses[0] + 0x20] ^= 1
            rejected = find_rex_static_controller_callback_candidate(changed)
            self.assertIsNotNone(rejected)
            assert rejected is not None
            self.assertFalse(rejected["accepted"])
            self.assertEqual(
                rejected["reject_reason"],
                "two-bank-read-consume-handler-not-closed",
            )

    def test_closed_static_candidate_accepts_and_mutations_reject(self) -> None:
        image, offsets = _candidate_image()
        result = find_rex_static_controller_callback_candidate(image)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["handler_file_offset"], offsets["handler"])
        self.assertEqual(result["registrar_file_offset"], offsets["registrar"])
        self.assertEqual(result["callback_file_offset"], offsets["callback"])
        self.assertEqual(result["timer_advance_file_offset"], offsets["advance"])
        self.assertEqual(result["wrapper_file_offset"], offsets["wrapper"])
        self.assertEqual(result["handler_slot"], offsets["handler_slot"])
        self.assertEqual(result["handler_setter_file_offset"], offsets["setter"])
        self.assertEqual(result["handler_registration_file_offset"], offsets["handler_registration"])
        self.assertEqual(result["callback_slot"], 0x01004368)
        self.assertEqual(result["clear_banks"], (0x03000C80, 0x03000C84))
        self.assertEqual(result["controller_write_banks"], (0x03000C94, 0x03000C98))
        self.assertEqual(result["controller_aperture"], (0x03000C80, 0x03000C9A))
        self.assertEqual(result["callback_delta"], 5)
        self.assertEqual(result["callback_validation_size"], 68)
        self.assertEqual(result["callback_validation_shape"], (21, 25))
        self.assertEqual(result["wrapper_validation_size"], 0x34)
        self.assertEqual(result["handler_validation_size"], 0x100)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["active"])
        self.assertEqual(
            result["controller_class"],
            "legacy-c80-index1e-delta5-controller-candidate-v1",
        )
        self.assertIn("static topology only", result["semantic_limit"])

        unaligned = bytearray(image)
        duplicate = offsets["wrapper"] + 0x81
        struct.pack_into("<4I", unaligned, duplicate, 0xE24EE004,
                         0xE92D540F, 0xE14F0000, 0xE92D0001)
        struct.pack_into("<I", unaligned, duplicate + 0x28, 0xE59F3000)
        struct.pack_into("<I", unaligned, duplicate + 0x30,
                         offsets["handler_slot"])
        self.assertTrue(find_rex_static_controller_callback_candidate(
            unaligned)["accepted"])

        mutations = (
                (0x18, 0, 4),
                (offsets["seed"] + 8, 0x100, 4),
                (offsets["handler"] + 28, 0, 2),
                (offsets["handler"] + 0x92, 0, 2),
                (offsets["wrapper"] + 0x30, 0, 4),
                (offsets["handler_registration"], 0, 2),
                (offsets["registration"], 0, 2),
                (offsets["callback"] + 0x28, 0, 2),
                (offsets["advance"] + 24, 0, 2))
        for index, (offset, value, width) in enumerate(mutations):
            changed = bytearray(image)
            struct.pack_into("<I" if width == 4 else "<H", changed, offset, value)
            rejected = find_rex_static_controller_callback_candidate(changed)
            if index == 1:  # No exact C80 seed remains, so no telemetry class.
                self.assertIsNone(rejected)
                continue
            self.assertIsNotNone(rejected)
            assert rejected is not None
            self.assertFalse(rejected["accepted"])
            self.assertIn("reject_reason", rejected)

        self.assertIsNone(find_rex_static_controller_callback_candidate(bytearray(0x200)))

    def test_detection_keeps_candidate_inactive_and_reports_rejection(self) -> None:
        accepted = {
            "signature": "static-c80-controller-callback-v1",
            "accepted": True,
            "active": False,
            "semantic_limit": "static topology only",
        }
        rejected = {
            **accepted,
            "accepted": False,
            "reject_reason": "two-bank-handler-not-closed",
        }
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / "firmware.bin"
            firmware.write_bytes(b"\xff" * 0x100)
            for candidate, note in (
                    (accepted, "native pending, IRQ, and idle remain unproven"),
                    (rejected, "two-bank-handler-not-closed")):
                with patch(
                    "msm5xxx_emulator.detection.firmware."
                    "find_rex_static_controller_callback_candidate",
                    return_value=candidate,
                ):
                    config = detect(firmware)
                self.assertIs(config.rex_static_controller_candidate, candidate)
                self.assertFalse(config.rex_static_controller_candidate["active"])
                self.assertIn(note, " ".join(config.detection_notes))
                if candidate["accepted"]:
                    self.assertFalse(
                        config.rex_static_controller_experimental
                    )
                    self.assertIsNone(config.rex_tick_address)
                    self.assertEqual((
                        config.rex_irq_wrapper_address,
                        config.rex_irq_handler_address,
                        config.rex_irq_handler_slot,
                        config.rex_irq_callback_slot,
                        config.rex_irq_status_address,
                        config.rex_irq_enable_address,
                        config.rex_irq_arm_address,
                        config.rex_irq_mask,
                    ), (None, None, None, None, None, None, None, 0))

    def test_runtime_gate_waits_for_installed_route_then_activates(self) -> None:
        image, offsets = _candidate_image()
        candidate = find_rex_static_controller_callback_candidate(image)
        assert candidate is not None and candidate["accepted"]
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            rex_static_controller_candidate=candidate,
            rex_static_controller_experimental=False,
            ram_base=0x01000000, ram_size=0x10000,
            load_address=0, flash_size=0x2000, overlays=(), linker=None,
            rex_tick_address=None, rex_irq_wrapper_address=None,
            rex_irq_handler_address=None, rex_irq_handler_slot=None,
            rex_irq_callback_slot=None, rex_irq_status_address=None,
            rex_irq_enable_address=None, rex_irq_arm_address=None,
            rex_irq_mask=0, rex_tick_ms=1000,
        )
        emulator.original_image = bytes(image) + b"\xff" * (0x2000 - len(image))
        emulator.direct_input_profile = None
        emulator.instructions = 10
        emulator._rex_candidate_route = None
        emulator._rex_candidate_shadow_hooks = []
        emulator._rex_candidate_gate_terminal = False
        emulator._rex_candidate_gate_next_instruction = 0
        emulator._rex_irq_controller_aperture = None
        emulator._rex_irq_pending = [0, 0]
        emulator.rex_controller_gate_attempts = 0
        emulator.rex_controller_gate_accepts = 0
        emulator.rex_controller_gate_reason = None
        emulator.rex_controller_activation_instruction = None
        emulator.rex_controller_pending_assertions = 0
        emulator.rex_controller_pending_acks = 0

        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0, 0x2000)
        uc.mem_write(0, emulator.original_image)
        uc.mem_map(0x01000000, 0x10000)
        uc.mem_map(0x03000000, 0x10000)
        displacement = (offsets["wrapper"] - 0x01000000 - 8) >> 2
        uc.mem_write(
            0x01000000,
            struct.pack("<I", 0xEA000000 | displacement & 0x00FFFFFF),
        )
        uc.mem_write(
            offsets["handler_slot"],
            struct.pack("<I", offsets["handler"] | 1),
        )
        old = 0xD3
        uc.reg_write(UC_ARM_REG_CPSR, (old & ~0xBF) | 0x92)
        uc.reg_write(UC_ARM_REG_SP, 0x0100F000)
        uc.reg_write(UC_ARM_REG_CPSR, (old & ~0xBF) | 0x9F)
        uc.reg_write(UC_ARM_REG_SP, 0x0100E000)
        uc.reg_write(UC_ARM_REG_CPSR, old)

        self.assertFalse(emulator._rex_try_static_candidate_route(uc))
        self.assertEqual(
            emulator.rex_controller_gate_reason,
            "experimental-opt-in-required",
        )
        self.assertEqual(emulator.rex_controller_gate_attempts, 0)
        self.assertEqual(
            emulator._rex_controller_telemetry()["status"],
            "experimental-disabled",
        )

        emulator.config.rex_static_controller_experimental = True
        self.assertFalse(emulator._rex_try_static_candidate_route(uc))
        self.assertEqual(
            emulator.rex_controller_gate_reason,
            "runtime-callback-not-installed",
        )
        self.assertIsNone(emulator.config.rex_tick_address)
        self.assertEqual(emulator._rex_candidate_shadow_hooks, [])

        uc.mem_write(
            int(candidate["callback_slot"]),
            struct.pack("<I", offsets["callback"] | 1),
        )
        emulator.instructions = emulator._rex_candidate_gate_next_instruction
        self.assertTrue(emulator._rex_try_static_candidate_route(uc))
        self.assertFalse(candidate["active"])
        self.assertEqual(emulator.rex_controller_gate_attempts, 2)
        self.assertEqual(emulator.rex_controller_gate_accepts, 1)
        self.assertEqual(
            emulator.config.rex_tick_address, offsets["callback"]
        )
        self.assertEqual(len(emulator._rex_candidate_shadow_hooks), 2)
        self.assertEqual(
            emulator._rex_controller_telemetry()["status"], "active"
        )
