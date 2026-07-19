"""Regression tests for bounded dynamic device mapping and MMIO polls."""
from __future__ import annotations

from collections import Counter, deque
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from unicorn import (Uc, UC_ARCH_ARM, UC_MEM_WRITE_UNMAPPED, UC_MODE_ARM,
                     UC_PROT_READ, UC_PROT_WRITE)
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC

from msm5xxx import (GenericMSMEmulator, HostBackendFault, LCD_MMIO_PRIMARY_COMMAND_SIZE,
                     LCD_MMIO_PRIMARY_END, LCD_MMIO_PRIMARY_START)


class LCDMMIOApertureTests(unittest.TestCase):
    def _emulator(self) -> GenericMSMEmulator:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.last_unmapped = None
        emulator._chunk_unmapped = None
        emulator._lcd_mmio_extended_mapped = False
        emulator.dynamic_pages = set()
        emulator.fault = None
        emulator._attach_lazy_secondary_nor = lambda *args: False
        return emulator

    def test_extended_lcd_aperture_is_mapped_once_without_dynamic_page_budget(self) -> None:
        emulator = self._emulator()
        uc = Mock()

        self.assertTrue(emulator._unmapped(
            uc, UC_MEM_WRITE_UNMAPPED, 0x02001000, 2, 0x1234, None
        ))
        self.assertTrue(emulator._unmapped(
            uc, UC_MEM_WRITE_UNMAPPED, 0x027FD000, 2, 0x5678, None
        ))

        uc.mem_map.assert_called_once_with(
            LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE,
            LCD_MMIO_PRIMARY_END
            - (LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE),
            UC_PROT_READ | UC_PROT_WRITE,
        )
        self.assertEqual(emulator.dynamic_pages, set())
        self.assertEqual(emulator.last_unmapped["address"], 0x027FD000)

    def test_rejected_bus_access_has_actionable_fault_detail(self) -> None:
        emulator = self._emulator()

        self.assertFalse(emulator._unmapped(
            Mock(), UC_MEM_WRITE_UNMAPPED, 0x80000000, 4, 0xDEADBEEF, None
        ))

        self.assertEqual(
            emulator._unmapped_fault_detail(),
            "; unmapped write address=0x80000000 size=4 value=0xDEADBEEF",
        )


class OpenBusReadTests(unittest.TestCase):
    def _emulator(self, dynamic_pages: set[int]) -> GenericMSMEmulator:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.secondary_flash = None
        emulator.secondary_base = None
        emulator.config = SimpleNamespace(secondary_flash_size=0)
        emulator.dynamic_pages = dynamic_pages
        return emulator

    def test_dynamic_page_read_preserves_prior_guest_data(self) -> None:
        uc = Mock()
        emulator = self._emulator({0x01098000})

        emulator._open_bus_read(uc, 0, 0x01098BF0, 4, 0, None)

        uc.mem_write.assert_not_called()

    def test_untouched_open_bus_page_reads_as_ff(self) -> None:
        uc = Mock()
        emulator = self._emulator(set())

        emulator._open_bus_read(uc, 0, 0x01098BF0, 4, 0, None)

        uc.mem_write.assert_called_once_with(0x01098BF0, b"\xff" * 4)

    def test_cross_page_read_keeps_dynamic_prefix(self) -> None:
        uc = Mock()
        emulator = self._emulator({0x01098000})

        emulator._open_bus_read(uc, 0, 0x01098FFE, 4, 0, None)

        uc.mem_write.assert_called_once_with(0x01099000, b"\xff" * 2)


class HardwarePollTests(unittest.TestCase):
    def _infer(self, code: bytes, initial: int = 0xFFFF,
               size: int = 2) -> tuple[int, int, bool] | None:
        pc, address = 0x1000, 0x03000780
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(pc, 0x1000)
        uc.mem_map(0x03000000, 0x1000)
        uc.mem_write(pc, code)
        uc.mem_write(address, initial.to_bytes(size, "little"))
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.uc = uc
        return emulator._infer_thumb_poll_value(pc, address, size)

    def test_split_halfword_poll_releases_clear_bit_and_requires_read_backedge(self) -> None:
        self.assertEqual(
            self._infer(bytes.fromhex("0b88db07db0f012bfad0"), 0x00C5),
            (0x00C4, 0, False),
        )
        self.assertIsNone(self._infer(bytes.fromhex("0b80db07db0f012bfad0")))
        self.assertIsNone(self._infer(bytes.fromhex("0b88db07db0f012bfad1")))
        self.assertIsNone(self._infer(bytes.fromhex("0b88db07db0f012bfbd0")))

    def test_lsr_blo_retry_body_returns_set_bit(self) -> None:
        self.assertEqual(
            self._infer(
                bytes.fromhex(
                    "0179480802d3081c80bc704701200020002000200020f3e7"
                ),
                0xFE, 1,
            ),
            (0xFF, 0, True),
        )
        self.assertEqual(
            self._infer(
                bytes.fromhex(
                    "0179480802d3081c80bd704701200020002000200020f3e7"
                ),
                0xFE, 1,
            ),
            (0xFE, 0, False),
        )
        # First retry-body branch at target + 0x22 is outside the proved
        # MOV/POP/BX return-tail grammar; it must not reverse BLO polarity.
        self.assertEqual(
            self._infer(
                bytes.fromhex(
                    "0179480802d3081c80bc70470120" + "0020" * 16 + "e8e7"
                ),
                0xFE, 1,
            ),
            (0xFE, 0, False),
        )

    @staticmethod
    def _poll_harness(
            hot_loop: bool = False,
            backend_error: bool = False,
    ) -> tuple[GenericMSMEmulator, object, list[int]]:
        pc, mmio = 0x1000, 0x03000780

        class ScriptedUc:
            def __init__(self, emulator: GenericMSMEmulator) -> None:
                self.base = Uc(UC_ARCH_ARM, UC_MODE_ARM)
                self.base.mem_map(pc, 0x1000)
                self.base.mem_map(0x03000000, 0x1000)
                self.base.mem_write(pc, bytes.fromhex("0b88db07db0f012bfad0"))
                self.base.mem_write(mmio, (0x00C5).to_bytes(2, "little"))
                self.base.reg_write(UC_ARM_REG_PC, pc)
                self.base.reg_write(UC_ARM_REG_CPSR, 0)
                self.base.reg_write(UC_ARM_REG_LR, 0x2001 if hot_loop else 0)
                self.emulator = emulator
                self.elapsed = 0
                self.writes: list[tuple[int, int, int, int]] = []
                self.hook_add_calls = 0
                self.hook_del_calls = 0
                self.emu_start_calls = 0
                self.mem_read_calls = 0
                self.reg_read_calls = 0

            def hook_add(self, *args: object, **kwargs: object) -> int:
                self.hook_add_calls += 1
                return 1

            def hook_del(self, handle: int) -> None:
                del handle
                self.hook_del_calls += 1

            def emu_start(self, begin: int, end: int, *, count: int) -> None:
                del end
                self.emu_start_calls += 1
                if backend_error:
                    raise OSError("exception: access violation writing 0x12345678")
                start, self.elapsed = self.elapsed, self.elapsed + count
                if hot_loop:
                    self.emulator.hot[pc] += count
                else:
                    self.emulator.mmio_reads[(pc, mmio, 2)] += max(
                        0, self.elapsed - max(start, 200_000)
                    )
                self.base.reg_write(UC_ARM_REG_PC, begin & ~1)

            def mem_read(self, address: int, size: int) -> bytes:
                self.mem_read_calls += 1
                return bytes(self.base.mem_read(address, size))

            def mem_write(self, address: int, value: bytes) -> None:
                self.writes.append((self.emulator.instructions, address,
                                    len(value), int.from_bytes(value, "little")))
                self.base.mem_write(address, value)

            def reg_read(self, register: int) -> int:
                self.reg_read_calls += 1
                return self.base.reg_read(register)

            def reg_write(self, register: int, value: int) -> None:
                self.base.reg_write(register, value)

        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            load_address=pc, entry=0, flash_size=0x1000,
            ram_base=0x01000000, ram_size=0x1000,
            secondary_flash_address=None, secondary_flash_size=0,
            rex_irq_status_address=None, key_register=0x03000F00,
            board_revision_register=None,
            fast_boot_address=None if hot_loop else 0,
            linker=(SimpleNamespace(table_offset=0x10028, data_size=0x1000)
                    if hot_loop else None),
            framebuffer_address=None, framebuffer_flush_address=None,
            framebuffer_rect_flush_address=None, width=1, height=1,
            model="poll-window-harness", chipset="MSM5xxx", audio_play_address=None,
            ma2_silent_boot_address=None, missing_overlays=[],
            firmware_identity=lambda: {
                "basename": "harness.bin", "bytes": 0x1000,
                "sha256": "0" * 64,
            },
            to_dict=lambda: {"model": "poll-window-harness"},
        )
        emulator.instructions = 0
        emulator.fault = None
        emulator._host_backend_fault = None
        emulator._logged_fault = None
        emulator.hot = Counter()
        emulator.mmio_reads = Counter()
        emulator.mmio_read_totals = Counter()
        emulator._poll_candidate_chunks = Counter()
        emulator._poll_escape_keys = set()
        emulator.poll_escapes = []
        emulator.ready_bits = {}
        emulator.fast_boot_used = not hot_loop
        emulator.hot_loop_hle_used = False
        emulator._chunk_unmapped = None
        emulator.tail = deque(maxlen=64)
        emulator.reset_entries = 0
        emulator.flash = SimpleNamespace(ids=None, telemetry=lambda: {})
        emulator.ram_seed_size = 0
        emulator.dynamic_pages = set()
        emulator.last_unmapped = None
        emulator.lcd_writes = 0
        emulator._lcd_protocol = "unknown"
        emulator._lcd_frame_protocol = "none"
        emulator.lcd_port_writes = Counter()
        emulator.frame_sequence = 0
        emulator.firmware_frame_sequence = 0
        emulator.rex_idle_entries = 0
        emulator.rex_ticks = 0
        emulator.rex_elapsed_ms = 0
        emulator.rex_irq_deliveries = 0
        emulator.board_adc_reads = 0
        emulator.flash_id_reads = 0
        emulator.secondary_flash = None
        emulator.secondary_flash_reads = 0
        emulator.secondary_flash_writes = 0
        emulator.legacy_efs_page_reads = 0
        emulator.eeprom_capacity = 0
        emulator.eeprom_reads = 0
        emulator.eeprom_read_bytes = 0
        emulator.eeprom_writes = 0
        emulator.eeprom_write_bytes = 0
        emulator.eeprom_data = bytearray()
        emulator.eeprom_loaded_from_state = False
        emulator.eeprom_state_path = "unused"
        emulator.eeprom_enabled = False
        emulator.eeprom_error = None
        emulator.input_profile = None
        emulator.firmware_key_events = 0
        emulator.input_error = ""
        emulator.input_events = 0
        emulator.audio_discovered_address = None
        emulator.audio_play_requests = 0
        emulator.audio_last_size = 0
        emulator.ma2_silent_boot_calls = 0
        emulator.audio_player = None
        emulator.nand_commands = []
        emulator.nand_image = bytearray()
        emulator.nand_reads = 0
        emulator.nand_writes = 0
        emulator.nand_bad_block_probes = 0
        emulator.fast_memory_clears = 0
        emulator.fast_memory_copies = 0
        emulator.fast_register_ramps = 0
        emulator.fast_arm_memory_copies = 0
        emulator.fast_crc16_calls = 0
        emulator.fast_dmd_downloads = 0
        emulator._restore_flash_once = lambda *args: None
        emulator._lcd_page_flush_current = lambda: None
        emulator._flush_indexed_frame = lambda: None
        emulator._control_sink_from_tail = lambda *args: None
        uc = ScriptedUc(emulator)
        emulator.uc = uc
        service_calls: list[int] = []
        release = emulator._release_hardware_poll

        def record_release() -> bool:
            service_calls.append(emulator.instructions)
            return release()

        emulator._release_hardware_poll = record_release
        return emulator, uc, service_calls

    def test_poll_release_uses_global_observation_windows(self) -> None:
        expected_service = [100_000, 200_000, 300_000, 400_000, 500_000]
        for partition in ([100_000] * 5, [250_000, 250_000]):
            for probe in (100_000, 25_000):
                with self.subTest(partition=partition, probe=probe):
                    emulator, uc, service_calls = self._poll_harness()
                    for steps in partition:
                        emulator.run(steps, fast_boot_probe=probe)

                    self.assertEqual(service_calls, expected_service)
                    self.assertEqual(uc.writes, [
                        (400_000, 0x03000780, 2, 0x00C4),
                    ])
                    self.assertEqual(emulator.ready_bits[(0x03000780, 2)], (0, 1))
                    self.assertEqual(int.from_bytes(uc.mem_read(0x03000780, 2), "little"),
                                     0x00C4)
                    self.assertEqual(emulator._poll_window_remaining, 100_000)

    def test_fast_boot_hle_uses_global_observation_windows(self) -> None:
        for partition in ([100_000] * 5, [250_000, 250_000]):
            for probe in (100_000, 25_000):
                with self.subTest(partition=partition, probe=probe):
                    emulator, _uc, _service_calls = self._poll_harness(hot_loop=True)
                    applied: list[int] = []

                    def apply_linker() -> None:
                        applied.append(emulator.instructions)
                        emulator.fast_boot_used = True

                    emulator._apply_linker = apply_linker
                    for steps in partition:
                        emulator.run(steps, fast_boot_probe=probe)

                    self.assertEqual(applied, [100_000])

    def test_host_backend_error_is_terminal_without_unicorn_reuse(self) -> None:
        emulator, uc, _service_calls = self._poll_harness(backend_error=True)
        restore = Mock()
        emulator._restore_flash_once = restore

        with self.assertRaises(HostBackendFault) as raised:
            emulator.run(25_000)

        fault = raised.exception
        self.assertIn("access violation", str(fault))
        self.assertEqual(fault.diagnostic["firmware"]["basename"], "harness.bin")
        self.assertEqual(fault.diagnostic["registers"]["pc"], "0x00001000")
        self.assertEqual(fault.diagnostic["chunk_steps"], 25_000)
        self.assertEqual(uc.emu_start_calls, 1)
        self.assertEqual(uc.hook_del_calls, 0)
        restore.assert_not_called()

        calls_after_failure = (
            uc.hook_add_calls, uc.hook_del_calls, uc.emu_start_calls,
            uc.mem_read_calls, uc.reg_read_calls,
        )
        with self.assertRaises(HostBackendFault) as repeated:
            emulator.run(1)
        self.assertIs(repeated.exception, fault)
        self.assertEqual(calls_after_failure, (
            uc.hook_add_calls, uc.hook_del_calls, uc.emu_start_calls,
            uc.mem_read_calls, uc.reg_read_calls,
        ))

    def test_trace_hook_is_reused_across_run_chunks(self) -> None:
        emulator, uc, _service_calls = self._poll_harness()

        emulator.run(25_000)
        emulator.run(25_000)

        self.assertEqual(uc.hook_add_calls, 1)
        self.assertEqual(uc.hook_del_calls, 0)


if __name__ == "__main__":
    unittest.main()
