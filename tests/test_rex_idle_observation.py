"""Passive REX idle call-site observation must not invent a timer tick."""
from __future__ import annotations

from collections import Counter, deque
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from unicorn import (
    Uc, UC_ARCH_ARM, UC_HOOK_BLOCK, UC_HOOK_CODE, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE, UC_MODE_ARM,
)
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_SP,
    UC_ARM_REG_SPSR,
)

from msm5xxx import GenericMSMEmulator


class RexIdleObservationTests(unittest.TestCase):
    def test_trace_skips_disabled_audio_probe_and_primary_rom_read(self) -> None:
        def harness(audio_player: object | None) -> GenericMSMEmulator:
            emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
            emulator.config = SimpleNamespace(
                load_address=0, entry=0x100, audio_play_address=None,
                missing_overlays=(), runtime_overlays=(),
            )
            emulator._flash_restore = {}
            emulator._restore_flash_once = Mock()
            emulator._rex_irq_pending = [0, 0]
            emulator._rex_irq_boundary = Mock(return_value=False)
            emulator.tail = deque(maxlen=64)
            emulator.hot = Counter()
            emulator.reset_entries = 0
            emulator.audio_player = audio_player
            emulator.audio_discovered_address = None
            emulator.image = b"\x01" * 0x100
            emulator.primary_rom_end = len(emulator.image)
            emulator.zero_fetches = 0
            emulator.fault = None
            emulator.hot_loop_hle_used = False
            emulator._try_hot_arm_memory_clear = Mock(return_value=False)
            emulator._try_hot_thumb_memory_loop = Mock(return_value=False)
            emulator._probe_audio_call = Mock()
            return emulator

        uc = Mock()
        disabled = harness(None)
        disabled._trace(uc, 0x10, 4, None)
        disabled._probe_audio_call.assert_not_called()
        disabled._restore_flash_once.assert_not_called()
        disabled._rex_irq_boundary.assert_not_called()
        disabled._try_hot_thumb_memory_loop.assert_not_called()
        uc.mem_read.assert_not_called()

        for _ in range(62):
            disabled._trace(uc, 0x10, 4, None)
        disabled._try_hot_thumb_memory_loop.assert_not_called()
        disabled._trace(uc, 0x10, 4, None)
        disabled._try_hot_thumb_memory_loop.assert_called_once_with(uc, 0x10)

        disabled._flash_restore[0] = b"x"
        disabled._rex_irq_pending[0] = 1
        disabled._trace(uc, 0x10, 4, None)
        disabled._restore_flash_once.assert_called_once_with(uc, 0x10, 4, None)
        disabled._rex_irq_boundary.assert_called_once_with(uc, 0x10)

        enabled = harness(object())
        enabled._trace(uc, 0x10, 4, None)
        enabled._probe_audio_call.assert_called_once_with(uc, 0x10)

    def test_idle_only_signature_observes_without_changing_cpu(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(rex_tick_address=None, rex_tick_ms=1000)
        emulator.rex_idle_entries = 0
        emulator.rex_ticks = 0
        emulator.rex_elapsed_ms = 0
        emulator.rex_next_instruction = 0
        emulator.instructions = 10
        emulator._thumb_runtime_matches = lambda *args, **kwargs: True
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        for register, value in (
            (UC_ARM_REG_R0, 0x11111111),
            (UC_ARM_REG_LR, 0x22222223),
            (UC_ARM_REG_PC, 0x33333332),
            (UC_ARM_REG_CPSR, 0xF0000033),
        ):
            uc.reg_write(register, value)
        before = tuple(uc.reg_read(register) for register in (
            UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR
        ))

        emulator._rex_tick(uc, 0x1000, 2, None)

        after = tuple(uc.reg_read(register) for register in (
            UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR
        ))
        self.assertEqual(emulator.rex_idle_entries, 1)
        self.assertEqual(emulator.rex_ticks, 0)
        self.assertEqual(emulator.rex_elapsed_ms, 0)
        self.assertEqual(emulator.rex_next_instruction, 0)
        self.assertEqual(after, before)

        emulator._thumb_runtime_matches = lambda *args, **kwargs: False
        emulator._rex_tick(uc, 0x1000, 2, None)
        self.assertEqual(emulator.rex_idle_entries, 1)

    def test_detected_tick_path_keeps_existing_hle_behavior(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(rex_tick_address=0x2000, rex_tick_ms=1000)
        emulator.rex_idle_entries = 0
        emulator.rex_ticks = 0
        emulator.rex_elapsed_ms = 0
        emulator.rex_next_instruction = 0
        emulator.instructions = 10
        emulator._thumb_runtime_matches = lambda *args, **kwargs: True
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        emulator._rex_tick(uc, 0x1000, 2, None)

        self.assertEqual(emulator.rex_idle_entries, 1)
        self.assertEqual(emulator.rex_ticks, 1)
        self.assertEqual(emulator.rex_elapsed_ms, 1000)
        self.assertEqual(emulator.rex_next_instruction, 100010)
        self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 1000)
        self.assertEqual(uc.reg_read(UC_ARM_REG_LR), 0x1005)
        self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x2000)

    def test_5ms_post_sleep_without_complete_irq_route_fails_closed(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(rex_tick_address=0x2000, rex_tick_ms=5)
        emulator.rex_idle_entries = 0
        emulator.rex_ticks = 0
        emulator.rex_elapsed_ms = 0
        emulator.rex_next_instruction = 0
        emulator._rex_tick_return_address = None
        emulator._rex_tick_context = None
        emulator.instructions = 10
        emulator._thumb_runtime_matches = lambda *args, **kwargs: False
        emulator._original_runtime_bytes = lambda address, size: b"\0" * size
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x2000)
        before = {
            register: value for register, value in (
                (UC_ARM_REG_R0, 0x10), (UC_ARM_REG_R1, 0x11),
                (UC_ARM_REG_R2, 0x12), (UC_ARM_REG_R3, 0x13),
                (UC_ARM_REG_R12, 0x1C), (UC_ARM_REG_LR, 0x1223),
                (UC_ARM_REG_CPSR, 0xA0000033),
            )
        }
        for register, value in before.items():
            uc.reg_write(register, value)

        with (patch("msm5xxx_emulator.soc.rex.rex_sleep_call_at", return_value=42),
              patch("msm5xxx_emulator.soc.rex.rex_5ms_callback_at", return_value=0)):
            emulator._rex_tick(uc, 0x102E, 2, None)
            self.assertEqual(emulator.rex_idle_entries, 1)
        self.assertEqual(emulator.rex_ticks, 0)
        self.assertEqual(emulator.rex_elapsed_ms, 0)
        self.assertEqual(emulator.rex_next_instruction, 0)
        for register, value in before.items():
            self.assertEqual(uc.reg_read(register), value)

    def test_irq_status_shadow_partial_w1c_and_word_reads(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(rex_irq_status_address=0x03000620)
        emulator._rex_irq_pending = [0, 0]
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x03000000, 0x1000)

        for index, bank in enumerate((0x03000620, 0x03000624)):
            emulator._rex_irq_pending[index] = 0xFFFF
            for address, size, value, expected in (
                (bank, 1, 0x0F, 0xFFF0),
                (bank + 1, 1, 0xF0, 0x0FF0),
                (bank, 2, 0x00F0, 0x0F00),
            ):
                emulator._rex_irq_status_write(
                    uc, 0, address, size, value, None
                )
                self.assertEqual(emulator._rex_irq_pending[index], expected)
            emulator._rex_irq_pending[index] = 0xFFFF
            emulator._rex_irq_status_write(
                uc, 0, bank, 4, 0xFFFFFFFF, None
            )
            self.assertEqual(emulator._rex_irq_pending[index], 0)

        emulator._rex_irq_pending[:] = [0x1234, 0xABCD]
        uc.mem_write(0x03000620, b"\xff" * 8)
        uc.mem_write(0x03000628, struct.pack("<2I", 0x11223344, 0x55667788))
        emulator._rex_irq_status_read(uc, 0, 0x03000620, 8, 0, None)
        self.assertEqual(
            struct.unpack("<2I", uc.mem_read(0x03000620, 8)),
            (0x1234, 0xABCD),
        )
        self.assertEqual(
            struct.unpack("<2I", uc.mem_read(0x03000628, 8)),
            (0x11223344, 0x55667788),
        )

    def test_irq_boundary_accepts_any_enabled_pending_route(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            rex_irq_enable_address=0x03000628,
            rex_irq_mask=0x0200,
        )
        emulator._rex_irq_pending = [0x0080, 0]
        emulator.rex_irq_deliveries = 0
        emulator._rex_irq_route_valid = Mock(return_value=True)
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0, 0x2000)
        uc.mem_map(0x03000000, 0x1000)
        uc.mem_write(0x03000628, struct.pack("<H", 0x0080))
        uc.reg_write(UC_ARM_REG_CPSR, 0x92)
        uc.reg_write(UC_ARM_REG_SP, 0x1900)
        uc.reg_write(UC_ARM_REG_CPSR, 0x1F)
        uc.reg_write(UC_ARM_REG_SP, 0x1800)

        self.assertTrue(emulator._rex_irq_boundary(uc, 0x1200))
        self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x18)
        self.assertEqual(uc.reg_read(UC_ARM_REG_LR), 0x1204)
        self.assertEqual(emulator.rex_irq_deliveries, 1)

    def test_5ms_controller_vector_irq_return_and_task_switch(self) -> None:
        def bl(source: int, target: int) -> bytes:
            displacement = target - source - 4
            return struct.pack(
                "<2H", 0xF000 | (displacement >> 12 & 0x7FF),
                0xF800 | (displacement >> 1 & 0x7FF),
            )

        def arm_b(source: int, target: int) -> bytes:
            return struct.pack(
                "<I", 0xEA000000 | ((target - source - 8) >> 2 & 0xFFFFFF)
            )

        image = bytearray(b"\xff" * 0x6000)
        sleep = bytes.fromhex(
            "134c2078012806d112480078012802d11148007800e00820"
            "00f000f800f000f80421071c0920c005227800f000f8002f"
            "01d100f000f880e7"
        )
        image[0x1000:0x1000 + len(sleep)] = sleep
        image[0x18:0x1C] = arm_b(0x18, 0x01300800)
        interrupted = 0x1200
        old_block_marker = 0x01302044
        image[interrupted:interrupted + 8] = struct.pack(
            "<4H", 0x4801, 0x2101, 0x6001, 0xE7FE
        )
        struct.pack_into("<I", image, interrupted + 8, old_block_marker)

        image[0x2280:0x2298] = bytes.fromhex(
            "04480168012902d1022101607047ff210160704740203001"
        )
        image[0x2300:0x2320] = bytes.fromhex(
            "04480121016004480449016001220a717047c04640203001"
            "0020300110203001"
        )
        image[0x2340:0x2342] = bytes.fromhex("7047")

        tick = bytearray(bytes.fromhex(
            "80b500f000f807043f0c05210c4800f000f80c4800f000f8"
            "800801d30a4800e00a48016805390160052000000000"
            "0848052100f000f8002f01d100f000f880bd"
        ))
        for offset, target in ((2, 0x2300), (14, 0x2340), (20, 0x2340),
                               (42, 0x2340), (50, 0x2340), (58, 0x2340)):
            tick[offset:offset + 4] = bl(0x2400 + offset, target)
        image[0x2400:0x2400 + len(tick)] = tick
        for literal in range(0x2440, 0x2454, 4):
            struct.pack_into("<I", image, literal, 0x01300100)

        wrapper = bytes.fromhex(
            "04e04ee20f542de900004fe101002de92c029fe5b010d0e1011081e2"
            "b010c0e19ff021e300402de918329fe5003093e5010013e310e29f151"
            "0e29f0513ff2fe1784700000040bde892f021e3f0019fe5b010d0e101"
            "1051e2b010c0e12000001aec019fe5000090e5e8119fe5001091e5010"
            "050e11a00000a0100bde800f068e100f061e10f54bde893f021e304d0"
            "4de2ff5f2de904d04de20d10a0e1b0019fe5002090e5001082e592f02"
            "1e33ce081e500304fe1003081e593f021e394119fe5001091e5001080e"
            "500d091e50100bde800f068e100f061e10d10a0e13cd08de2ffdfd1e8"
            "0100bde800f068e100f061e10f94fde8"
        )
        image[0x4000:0x4000 + len(wrapper)] = wrapper
        for offset, value in (
            (0x240, 0x01300014), (0x244, 0x0130000C),
            (0x248, 0x4040), (0x24C, 0x4044),
            (0x250, 0x01300004), (0x254, 0x01300008),
            (0x258, 0x416C),
        ):
            struct.pack_into("<I", image, 0x4004 + offset, value)

        handler = bytes.fromhex(
            "f0b5094c20880949084006d00848006800f012f805490748018000f00ef8"
            "0028fbd10120f0bdc04620060003000200000010300120060003004790b5"
            "074800f010f800240700002806d0f868b96800f007f83c71012090bd2000"
            "90bd00203001084701680022026008007047"
        )
        image[0x5000:0x5000 + len(handler)] = handler

        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            rex_tick_address=0x2400, rex_tick_ms=5,
            rex_irq_wrapper_address=0x4000,
            rex_irq_handler_address=0x5000,
            rex_irq_handler_slot=0x0130000C,
            rex_irq_callback_slot=0x01301000,
            rex_irq_status_address=0x03000620,
            rex_irq_enable_address=0x03000628,
            rex_irq_mask=0x0200,
            ram_base=0x01300000, ram_size=0x3000,
            load_address=0, entry=0,
            audio_play_address=0, missing_overlays=(), runtime_overlays=(),
        )
        emulator.rex_idle_entries = 0
        emulator.rex_ticks = 0
        emulator.rex_elapsed_ms = 0
        emulator.rex_next_instruction = 0
        emulator._rex_irq_pending = [0, 0]
        emulator.rex_irq_deliveries = 0
        emulator._rex_tick_return_address = None
        emulator._rex_tick_context = None
        emulator.instructions = 10
        emulator._thumb_runtime_matches = lambda *args, **kwargs: False
        emulator._original_runtime_bytes = (
            lambda address, size: bytes(image[address:address + size])
        )
        emulator.image = bytes(image)
        emulator.primary_rom_end = len(image)
        emulator.tail = deque(maxlen=64)
        emulator.hot = Counter()
        emulator.reset_entries = 0
        emulator.audio_discovered_address = None
        emulator.zero_fetches = 0
        emulator.fault = None
        emulator.hot_loop_hle_used = False
        emulator._try_hot_thumb_memory_loop = lambda *args: False
        emulator._flash_restore = {}

        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0, 0x6000)
        uc.mem_map(0x01300000, 0x3000)
        uc.mem_map(0x03000000, 0x1000)
        uc.mem_write(0, bytes(image))
        uc.mem_write(0x01300800, arm_b(0x01300800, 0x4000))
        uc.mem_write(0x01300004, struct.pack("<I", 0x01300200))
        uc.mem_write(0x01300008, struct.pack("<I", 0x01300200))
        uc.mem_write(0x0130000C, struct.pack("<I", 0x5001))
        uc.mem_write(0x01301000, struct.pack("<I", 0x2401))
        uc.mem_write(0x01300100, struct.pack("<I", 10))
        uc.mem_write(0x01302014, b"\0")
        uc.mem_write(0x01302018, struct.pack("<II", 0x2281, 0x1234))
        uc.mem_write(old_block_marker, b"\0" * 4)
        uc.hook_add(
            UC_HOOK_MEM_WRITE, emulator._rex_irq_status_write,
            begin=0x03000620, end=0x03000627,
        )
        uc.hook_add(
            UC_HOOK_MEM_READ, emulator._rex_irq_status_read,
            begin=0x03000620, end=0x03000627,
        )
        registers = (
            UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
            UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
            UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
            UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR,
        )
        before = tuple(0x100 + index for index in range(len(registers)))
        before = (*before[:-2], 0x01302FF0, 0xA80000F3)
        for register, value in zip(registers, before):
            uc.reg_write(register, value)
        uc.reg_write(UC_ARM_REG_CPSR, 0xDF)
        uc.reg_write(UC_ARM_REG_SP, 0x013027F0)
        uc.reg_write(UC_ARM_REG_CPSR, 0xD2)
        uc.reg_write(UC_ARM_REG_SP, 0x01302BF0)
        uc.reg_write(UC_ARM_REG_CPSR, before[-1])

        emulator._restore_flash_once = lambda *args: None
        returned: list[tuple[int, ...]] = []
        entered: list[tuple[int, int, int, int]] = []

        def stop_after_return(machine: Uc, address: int, size: int,
                              user_data: object) -> None:
            if struct.unpack(
                    "<I", machine.mem_read(0x01302040, 4))[0] != 2:
                return
            returned.append(tuple(machine.reg_read(item) for item in registers))
            machine.emu_stop()

        uc.hook_add(
            UC_HOOK_CODE,
            lambda machine, address, size, data: entered.append((
                machine.reg_read(UC_ARM_REG_CPSR),
                machine.reg_read(UC_ARM_REG_SPSR),
                machine.reg_read(UC_ARM_REG_LR),
                machine.reg_read(UC_ARM_REG_SP),
            )),
            begin=0x18, end=0x18,
        )
        uc.hook_add(
            UC_HOOK_CODE, stop_after_return,
            begin=interrupted, end=interrupted,
        )
        uc.hook_add(UC_HOOK_BLOCK, emulator._trace)

        vector_word = struct.unpack("<I", uc.mem_read(0x18, 4))[0]
        stub_word = struct.unpack("<I", uc.mem_read(0x01300800, 4))[0]
        for address, word in ((0x18, vector_word),
                              (0x01300800, stub_word)):
            for opcode in (0x1A000000, 0xEB000000):
                uc.mem_write(address, struct.pack(
                    "<I", opcode | (word & 0x00FFFFFF)
                ))
                self.assertFalse(emulator._rex_irq_route_valid(uc))
            uc.mem_write(address, struct.pack("<I", word))
        old_cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        system_cpsr = (old_cpsr & ~0xBF) | 0x9F
        uc.reg_write(UC_ARM_REG_CPSR, system_cpsr)
        uc.reg_write(UC_ARM_REG_SP, 0)
        uc.reg_write(UC_ARM_REG_CPSR, old_cpsr)
        invalid_stack_state = tuple(
            uc.reg_read(register) for register in registers
        )
        self.assertFalse(emulator._rex_irq_route_valid(uc, stack=True))
        self.assertEqual(
            tuple(uc.reg_read(register) for register in registers),
            invalid_stack_state,
        )
        uc.reg_write(UC_ARM_REG_CPSR, system_cpsr)
        uc.reg_write(UC_ARM_REG_SP, 0x013027F0)
        uc.reg_write(UC_ARM_REG_CPSR, old_cpsr)
        self.assertTrue(emulator._rex_irq_route_valid(uc, stack=True))

        emulator._rex_irq_status_write(
            uc, 0, 0x03000620, 2, 0xFFFF, None
        )
        self.assertEqual(emulator._rex_irq_pending, [0, 0])
        emulator._rex_tick(uc, 0x102E, 2, None)
        self.assertEqual(emulator._rex_irq_pending, [0x0200, 0])
        self.assertFalse(emulator._rex_irq_boundary(uc, 0x102E))
        self.assertEqual(emulator.rex_irq_deliveries, 0)
        emulator.instructions = 100009
        emulator._rex_tick(uc, 0x102E, 2, None)
        self.assertEqual(emulator.rex_ticks, 1)
        self.assertEqual(emulator.rex_next_instruction, 100010)
        emulator._rex_irq_status_read(uc, 0, 0x03000620, 2, 0, None)
        self.assertEqual(
            struct.unpack("<H", uc.mem_read(0x03000620, 2))[0], 0x0200
        )

        uc.reg_write(UC_ARM_REG_CPSR, before[-1] & ~0x80)
        self.assertFalse(emulator._rex_irq_boundary(uc, interrupted))
        uc.mem_write(0x03000628, struct.pack("<H", 0x0200))
        old_cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        system_cpsr = (old_cpsr & ~0xBF) | 0x9F
        uc.reg_write(UC_ARM_REG_CPSR, system_cpsr)
        uc.reg_write(UC_ARM_REG_SP, 0)
        uc.reg_write(UC_ARM_REG_CPSR, old_cpsr)
        boundary_state = (
            uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_CPSR),
            emulator.rex_irq_deliveries,
        )
        self.assertFalse(emulator._rex_irq_boundary(uc, interrupted))
        self.assertEqual((
            uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_CPSR),
            emulator.rex_irq_deliveries,
        ), boundary_state)
        uc.reg_write(UC_ARM_REG_CPSR, system_cpsr)
        uc.reg_write(UC_ARM_REG_SP, 0x013027F0)
        uc.reg_write(UC_ARM_REG_CPSR, old_cpsr)
        uc.emu_start(interrupted | 1, 0x6000, count=500)

        expected_return = (*before[:-1], before[-1] & ~0x80)
        self.assertEqual(returned, [expected_return])
        self.assertEqual(entered, [
            (0xA80000D2, 0xA8000073, interrupted + 4, 0x01302BF0)
        ])
        self.assertEqual(uc.mem_read(old_block_marker, 4), b"\0" * 4)
        emulator._rex_irq_status_read(uc, 0, 0x03000620, 2, 0, None)
        self.assertEqual(struct.unpack("<H", uc.mem_read(0x03000620, 2))[0], 0)
        self.assertEqual(emulator._rex_irq_pending, [0, 0])
        self.assertEqual(struct.unpack("<I", uc.mem_read(0x01300014, 4))[0], 0)
        self.assertEqual(struct.unpack("<I", uc.mem_read(0x01302000, 4))[0], 0)
        self.assertEqual(uc.mem_read(0x01302014, 1), b"\0")
        self.assertEqual(struct.unpack("<I", uc.mem_read(0x01302040, 4))[0], 2)
        self.assertEqual(emulator.rex_irq_deliveries, 1)
        self.assertEqual(emulator.rex_ticks, 1)
        self.assertEqual(emulator.rex_next_instruction, 100010)

        uc.reg_write(UC_ARM_REG_CPSR, 0xD2)
        self.assertEqual(uc.reg_read(UC_ARM_REG_SPSR), expected_return[-1])
        self.assertEqual(uc.reg_read(UC_ARM_REG_LR), interrupted)
        self.assertEqual(uc.reg_read(UC_ARM_REG_SP), 0x01302BF0)
        uc.reg_write(UC_ARM_REG_CPSR, expected_return[-1])

        current_tcb = 0x01300200
        best_tcb = 0x01300240
        best_frame = 0x01302400
        next_cpsr = 0x60000033
        next_registers = tuple(0x200 + index for index in range(13))
        next_lr = 0x3333
        uc.mem_write(0x01300004, struct.pack("<I", current_tcb))
        uc.mem_write(0x01300008, struct.pack("<I", best_tcb))
        uc.mem_write(best_tcb, struct.pack("<I", best_frame))
        uc.mem_write(best_frame, struct.pack(
            "<16I", next_cpsr, *next_registers, next_lr, 0x1100
        ))
        switched: list[tuple[int, ...]] = []
        uc.hook_add(
            UC_HOOK_CODE,
            lambda machine, address, size, data: (
                switched.append(tuple(machine.reg_read(item) for item in registers)),
                machine.emu_stop(),
            ),
            begin=0x1100, end=0x1100,
        )
        uc.reg_write(UC_ARM_REG_CPSR, 0x500000F3)
        uc.reg_write(UC_ARM_REG_SP, 0x01302FF0)
        emulator.instructions = 100010
        emulator._rex_tick(uc, 0x102E, 2, None)
        self.assertEqual(emulator._rex_irq_pending, [0x0200, 0])
        uc.reg_write(UC_ARM_REG_CPSR, 0x50000073)
        uc.emu_start(interrupted | 1, 0x6000, count=500)

        self.assertEqual(len(switched), 1)
        self.assertEqual(switched[0][:13], next_registers)
        self.assertEqual(switched[0][13:],
                         (next_lr, best_frame + 0x40, next_cpsr))
        self.assertEqual(
            struct.unpack("<I", uc.mem_read(0x01300004, 4))[0], best_tcb
        )
        saved = struct.unpack("<I", uc.mem_read(current_tcb, 4))[0]
        self.assertEqual(saved, 0x01302FB0)
        self.assertEqual(
            struct.unpack("<I", uc.mem_read(saved, 4))[0], 0x50000073
        )
        self.assertEqual(emulator._rex_irq_pending, [0, 0])
        self.assertEqual(emulator.rex_irq_deliveries, 2)
        self.assertEqual(emulator.rex_ticks, 2)
        self.assertEqual(emulator.rex_next_instruction, 200010)


if __name__ == "__main__":
    unittest.main()
