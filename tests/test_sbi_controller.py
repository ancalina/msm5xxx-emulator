"""Focused tests for runtime-admitted MSM5000 SBI aliases."""
from __future__ import annotations

from types import SimpleNamespace
import unittest

from msm5xxx_emulator.soc.sbi import DC0_BOARD_ADC_CONTROL
from msm5xxx_emulator.soc.sbi import DC0_BOARD_ADC_READ
from msm5xxx_emulator.soc.sbi import DC0_CONTROL
from msm5xxx_emulator.soc.sbi import DC0_DATA
from msm5xxx_emulator.soc.sbi import DC0_EPOCH_LIMIT
from msm5xxx_emulator.soc.sbi import DC0_START
from msm5xxx_emulator.soc.sbi import DC0_STATUS
from msm5xxx_emulator.soc.sbi import SBI_BASE
from msm5xxx_emulator.soc.sbi import SbiMixin
from unicorn import UC_ARCH_ARM
from unicorn import UC_HOOK_MEM_READ
from unicorn import UC_MODE_ARM
from unicorn import Uc
from unicorn.arm_const import UC_ARM_REG_PC


class Harness(SbiMixin):
    def __init__(self, *, eligible: bool = True) -> None:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(0x03000000, 0x1000)
        self._init_sbi_state(SimpleNamespace(
            chipset="MSM5000" if eligible else "MSM5100",
            board_adc_reader_address=0x4050,
            board_adc_value=0xC2,
        ))


class SbiControllerTest(unittest.TestCase):
    @staticmethod
    def write(emulator: Harness, address: int, size: int, value: int) -> None:
        emulator._sbi_write(emulator.uc, 0, address, size, value, None)
        emulator.uc.mem_write(address, value.to_bytes(size, "little"))

    @staticmethod
    def read(emulator: Harness, address: int, size: int = 2) -> int:
        emulator._sbi_read(emulator.uc, 0, address, size, 0, None)
        return int.from_bytes(emulator.uc.mem_read(address, size), "little")

    def admit(self, emulator: Harness) -> None:
        for address, size, value in (
            (SBI_BASE, 1, 0x45),
            (SBI_BASE, 1, 0xC5),
            (SBI_BASE + 4, 2, 0x085F),
            (SBI_BASE + 0x0C, 2, 0x041F),
            (SBI_BASE + 0x10, 1, 0),
            (SBI_BASE + 0x10, 1, 1),
        ):
            self.write(emulator, address, size, value)
        self.assertEqual(self.read(emulator, SBI_BASE), 0x5F20)
        self.write(emulator, SBI_BASE + 0x0C, 2, 0x0900)
        self.assertEqual(self.read(emulator, SBI_BASE), 0x5F20)
        self.assertEqual(emulator._sbi_profile_status, "accepted")

    def test_admits_exact_bootstrap_and_closes_read_buffer(self) -> None:
        emulator = Harness()
        self.admit(emulator)
        self.write(emulator, SBI_BASE + 4, 2, 0x086A)
        self.write(emulator, SBI_BASE + 0x0C, 2, 0x8B00)

        self.assertEqual(self.read(emulator, SBI_BASE), 0x6A22)
        emulator.uc.mem_write(SBI_BASE + 0x0C, b"\xC2\x8B")
        self.assertEqual(self.read(emulator, SBI_BASE + 0x0C), 0x8BC2)
        self.assertEqual(self.read(emulator, SBI_BASE), 0x6A20)

    def test_hook_install_keeps_existing_sbi_read_path(self) -> None:
        emulator = Harness()
        calls = []
        emulator.uc = SimpleNamespace(
            hook_add=lambda *args, **kwargs: calls.append((args, kwargs))
        )

        emulator._install_sbi_hooks()

        self.assertTrue(any(
            args[0] == UC_HOOK_MEM_READ
            and args[1].__name__ == "_sbi_read"
            and kwargs == {"begin": SBI_BASE, "end": SBI_BASE + 0x10}
            for args, kwargs in calls
        ))

    def test_ineligible_firmware_keeps_native_backing(self) -> None:
        emulator = Harness(eligible=False)
        emulator.uc.mem_write(SBI_BASE, b"\xA5\xA5")
        self.assertEqual(self.read(emulator, SBI_BASE), 0xA5A5)
        self.assertEqual(emulator._sbi_telemetry()["status"], "not-detected")

    def test_candidate_mismatch_restores_native_backing(self) -> None:
        emulator = Harness()
        for address, size, value in (
            (SBI_BASE, 1, 0x45),
            (SBI_BASE, 1, 0xC5),
            (SBI_BASE + 4, 2, 0x085F),
            (SBI_BASE + 0x0C, 2, 0x041F),
            (SBI_BASE + 0x10, 1, 0),
            (SBI_BASE + 0x10, 1, 1),
        ):
            self.write(emulator, address, size, value)
        self.assertEqual(self.read(emulator, SBI_BASE), 0x5F20)

        self.assertEqual(self.read(emulator, SBI_BASE), 0x00C5)
        self.assertEqual(emulator._sbi_profile_status, "rejected")
        self.assertIsNone(emulator._sbi_poll_aperture)

    def test_dc0_observer_records_order_without_changing_backing(self) -> None:
        emulator = Harness(eligible=False)
        emulator.instructions = 123
        emulator.uc.reg_write(UC_ARM_REG_PC, 0x1000)
        before_status = b"\x34\x12"
        before_data = b"\x00\xB2"
        emulator.uc.mem_write(DC0_STATUS, before_status)
        emulator.uc.mem_write(DC0_DATA, before_data)

        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_CONTROL, 2, 0x0040, None
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_DATA, 2, 0xB200, None
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_START, 2, 0, None
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_START, 2, 1, None
        )
        emulator._dc0_observer_read(
            emulator.uc, 0, DC0_STATUS, 2, 0, None
        )
        pending = emulator._dc0_transport_telemetry()["pending_epoch"]
        self.assertEqual(pending["write_word"], "0xB200")
        self.assertEqual(pending["start_values"], ["0x0000", "0x0001"])
        self.assertEqual(pending["status_reads"][0]["backing"], "0x1234")
        pending["start_values"].append("0xFFFF")
        pending["status_reads"][0]["backing"] = "0xFFFF"
        fresh_pending = emulator._dc0_transport_telemetry()["pending_epoch"]
        self.assertEqual(fresh_pending["start_values"], ["0x0000", "0x0001"])
        self.assertEqual(fresh_pending["status_reads"][0]["backing"], "0x1234")
        emulator._dc0_observer_read(
            emulator.uc, 0, DC0_DATA, 2, 0, None
        )

        self.assertEqual(emulator.uc.mem_read(DC0_STATUS, 2), before_status)
        self.assertEqual(emulator.uc.mem_read(DC0_DATA, 2), before_data)
        telemetry = emulator._dc0_transport_telemetry()
        self.assertEqual(telemetry["status"], "observed")
        self.assertEqual(telemetry["semantic_status"], "unclassified")
        self.assertEqual(telemetry["counts"], {
            "control_writes": 1, "data_writes": 1, "start_writes": 2,
            "status_reads": 1, "data_reads": 1,
            "completed_readback_epochs": 1,
            "board_adc_responses": 0,
        })
        epoch = telemetry["readback_epochs"][0]
        self.assertEqual(epoch["instruction_checkpoint"], 123)
        self.assertEqual(epoch["write_word"], "0xB200")
        self.assertEqual(epoch["start_values"], ["0x0000", "0x0001"])
        self.assertEqual(epoch["status_reads"][0]["backing"], "0x1234")
        self.assertEqual(epoch["readback_word"], "0xB200")
        self.assertTrue(epoch["readback_matches_write"])
        self.assertIsNone(telemetry["pending_epoch"])

        counts = dict(telemetry["counts"])
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_DATA, 1, 0x12, None
        )
        emulator._dc0_observer_read(
            emulator.uc, 0, DC0_STATUS + 2, 2, 0, None
        )
        self.assertEqual(emulator._dc0_transport_telemetry()["counts"], counts)

        for value in range(DC0_EPOCH_LIMIT + 2):
            emulator._dc0_observer_write(
                emulator.uc, 0, DC0_DATA, 2, value, None
            )
            emulator.uc.mem_write(DC0_DATA, value.to_bytes(2, "little"))
            emulator._dc0_observer_read(
                emulator.uc, 0, DC0_DATA, 2, 0, None
            )
        self.assertEqual(
            len(emulator._dc0_transport_telemetry()["readback_epochs"]),
            DC0_EPOCH_LIMIT,
        )

    def test_dc0_exact_adc_read_returns_configured_input(self) -> None:
        emulator = Harness(eligible=False)
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_CONTROL, 2, DC0_BOARD_ADC_CONTROL, None
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_DATA, 2, DC0_BOARD_ADC_READ, None
        )
        emulator.uc.mem_write(DC0_DATA, DC0_BOARD_ADC_READ.to_bytes(2, "little"))
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_START, 2, 0, None
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_START, 2, 1, None
        )

        self.assertEqual(
            int.from_bytes(emulator.uc.mem_read(DC0_DATA, 2), "little"),
            0xB2C2,
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_START, 2, 1, None
        )
        self.assertEqual(emulator._dc0_counts["board_adc_responses"], 1)
        emulator._dc0_observer_read(
            emulator.uc, 0, DC0_DATA, 2, 0, None
        )
        telemetry = emulator._dc0_transport_telemetry()
        self.assertEqual(telemetry["semantic_status"], "board-adc-read")
        self.assertEqual(telemetry["counts"]["board_adc_responses"], 1)
        self.assertEqual(
            telemetry["readback_epochs"][0]["emulated_response_word"],
            "0xB2C2",
        )

    def test_dc0_noncontiguous_request_keeps_native_backing(self) -> None:
        emulator = Harness(eligible=False)
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_CONTROL, 2, DC0_BOARD_ADC_CONTROL, None
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_DATA, 2, DC0_BOARD_ADC_READ, None
        )
        emulator.uc.mem_write(DC0_DATA, DC0_BOARD_ADC_READ.to_bytes(2, "little"))
        emulator._dc0_observer_read(
            emulator.uc, 0, DC0_STATUS, 2, 0, None
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_START, 2, 0, None
        )
        emulator._dc0_observer_write(
            emulator.uc, 0, DC0_START, 2, 1, None
        )

        self.assertEqual(
            int.from_bytes(emulator.uc.mem_read(DC0_DATA, 2), "little"),
            DC0_BOARD_ADC_READ,
        )
        self.assertEqual(emulator._dc0_counts["board_adc_responses"], 0)


if __name__ == "__main__":
    unittest.main()
