"""Runtime-admitted MSM5000 serial bus register behavior."""
from __future__ import annotations

from unicorn import UC_HOOK_MEM_READ
from unicorn import UC_HOOK_MEM_WRITE
from unicorn import Uc
from unicorn.arm_const import UC_ARM_REG_PC


SBI_BASE = 0x03000780
SBI_CONTROL = SBI_BASE + 4
SBI_DATA = SBI_BASE + 0x0C
SBI_START = SBI_BASE + 0x10
SBI_BOOTSTRAP = (
    (SBI_BASE, 1, 0x45),
    (SBI_BASE, 1, 0xC5),
    (SBI_CONTROL, 2, 0x085F),
    (SBI_DATA, 2, 0x041F),
    (SBI_START, 1, 0),
    (SBI_START, 1, 1),
)
DC0_STATUS = 0x03000C84
DC0_CONTROL = 0x03000DC4
DC0_DATA = 0x03000DCC
DC0_START = 0x03000DD0
DC0_EPOCH_LIMIT = 8
DC0_BOARD_ADC_CONTROL = 0x887E
DC0_BOARD_ADC_READ = 0xB200


class SbiMixin:
    def _init_sbi_state(self, config: object) -> None:
        self._sbi_eligible = (
            getattr(config, "chipset", None) == "MSM5000"
            and getattr(config, "board_adc_reader_address", None) is not None
        )
        self._sbi_profile_status = (
            "observing" if self._sbi_eligible else "not-detected"
        )
        self._sbi_reject_reason: str | None = None
        self._sbi_bootstrap_phase = 0
        self._sbi_validation_phase = 0
        self._sbi_clock = 0
        self._sbi_control = 0
        self._sbi_started = False
        self._sbi_read_pending = False
        self._sbi_read_full = False
        self._sbi_native_status_backing: bytes | None = None
        self._sbi_poll_aperture: tuple[int, int] | None = None
        self._sbi_counts = {
            "clock_writes": 0,
            "control_writes": 0,
            "data_writes": 0,
            "start_writes": 0,
            "status_reads": 0,
            "data_reads": 0,
            "read_requests": 0,
        }
        self._dc0_sequence = 0
        self._dc0_board_adc_value = getattr(config, "board_adc_value", None)
        self._dc0_last_control: dict[str, object] | None = None
        self._dc0_last_control_word: int | None = None
        self._dc0_pending: dict[str, object] | None = None
        self._dc0_readback_epochs: list[dict[str, object]] = []
        self._dc0_counts = {
            "control_writes": 0,
            "data_writes": 0,
            "start_writes": 0,
            "status_reads": 0,
            "data_reads": 0,
            "completed_readback_epochs": 0,
            "board_adc_responses": 0,
        }

    def _install_sbi_hooks(self) -> None:
        self.uc.hook_add(
            UC_HOOK_MEM_WRITE, self._dc0_observer_write,
            begin=DC0_CONTROL, end=DC0_START + 1,
        )
        self.uc.hook_add(
            UC_HOOK_MEM_READ, self._dc0_observer_read,
            begin=DC0_STATUS, end=DC0_STATUS + 1,
        )
        self.uc.hook_add(
            UC_HOOK_MEM_READ, self._dc0_observer_read,
            begin=DC0_DATA, end=DC0_DATA + 1,
        )
        if not self._sbi_eligible:
            return
        self.uc.hook_add(
            UC_HOOK_MEM_WRITE, self._sbi_write,
            begin=SBI_BASE, end=SBI_START,
        )
        self.uc.hook_add(
            UC_HOOK_MEM_READ, self._sbi_read,
            begin=SBI_BASE, end=SBI_START,
        )

    def _dc0_observer_write(
            self, uc: Uc, access: int, address: int, size: int,
            value: int, user_data: object) -> None:
        del access, user_data
        if size != 2 or address not in {DC0_CONTROL, DC0_DATA, DC0_START}:
            return
        self._dc0_sequence += 1
        pc = uc.reg_read(UC_ARM_REG_PC)
        if address == DC0_CONTROL:
            self._dc0_counts["control_writes"] += 1
            self._dc0_last_control_word = value & 0xFFFF
            self._dc0_last_control = {
                "sequence": self._dc0_sequence,
                "pc": f"0x{pc:08X}",
                "word": f"0x{value & 0xFFFF:04X}",
            }
        elif address == DC0_DATA:
            self._dc0_counts["data_writes"] += 1
            self._dc0_pending = {
                "sequence": self._dc0_sequence,
                "instruction_checkpoint": getattr(self, "instructions", 0),
                "write_pc": f"0x{pc:08X}",
                "write_word": f"0x{value & 0xFFFF:04X}",
                "control": dict(self._dc0_last_control or {}),
                "start_values": [],
                "status_reads": [],
            }
        else:
            self._dc0_counts["start_writes"] += 1
            pending = self._dc0_pending
            if pending is not None:
                starts = pending["start_values"]
                if isinstance(starts, list) and len(starts) < 4:
                    starts.append(f"0x{value & 0xFFFF:04X}")
                if (starts[-2:] == ["0x0000", "0x0001"]
                        and "emulated_response_word" not in pending
                        and self._dc0_last_control_word == DC0_BOARD_ADC_CONTROL
                        and self._dc0_last_control is not None
                        and self._dc0_last_control.get("sequence")
                        == self._dc0_sequence - 3
                        and pending.get("write_word")
                        == f"0x{DC0_BOARD_ADC_READ:04X}"
                        and isinstance(self._dc0_board_adc_value, int)
                        and 0 <= self._dc0_board_adc_value <= 0xFF):
                    response = DC0_BOARD_ADC_READ | self._dc0_board_adc_value
                    uc.mem_write(DC0_DATA, response.to_bytes(2, "little"))
                    pending["emulated_response_word"] = f"0x{response:04X}"
                    self._dc0_counts["board_adc_responses"] += 1

    def _dc0_observer_read(
            self, uc: Uc, access: int, address: int, size: int,
            value: int, user_data: object) -> None:
        del access, value, user_data
        if size != 2 or address not in {DC0_STATUS, DC0_DATA}:
            return
        self._dc0_sequence += 1
        pc = uc.reg_read(UC_ARM_REG_PC)
        backing = int.from_bytes(uc.mem_read(address, 2), "little")
        pending = self._dc0_pending
        if address == DC0_STATUS:
            self._dc0_counts["status_reads"] += 1
            if pending is not None:
                reads = pending["status_reads"]
                if isinstance(reads, list) and len(reads) < 4:
                    reads.append({
                        "sequence": self._dc0_sequence,
                        "pc": f"0x{pc:08X}",
                        "backing": f"0x{backing:04X}",
                    })
            return
        self._dc0_counts["data_reads"] += 1
        if pending is None:
            return
        epoch = dict(pending)
        write_word = epoch.get("write_word")
        epoch.update({
            "read_sequence": self._dc0_sequence,
            "read_pc": f"0x{pc:08X}",
            "readback_word": f"0x{backing:04X}",
            "readback_matches_write": write_word == f"0x{backing:04X}",
        })
        self._dc0_readback_epochs.append(epoch)
        del self._dc0_readback_epochs[:-DC0_EPOCH_LIMIT]
        self._dc0_counts["completed_readback_epochs"] += 1
        self._dc0_pending = None

    def _dc0_transport_telemetry(self) -> dict[str, object]:
        counts = dict(getattr(self, "_dc0_counts", {}))
        pending = getattr(self, "_dc0_pending", None)
        return {
            "status": "observed" if any(counts.values()) else "unobserved",
            "semantic_status": (
                "board-adc-read"
                if counts.get("board_adc_responses", 0) else "unclassified"
            ),
            "counts": counts,
            "pending_epoch": (
                self._dc0_epoch_snapshot(pending)
                if isinstance(pending, dict) else None
            ),
            "readback_epochs": [
                self._dc0_epoch_snapshot(epoch) for epoch in getattr(
                    self, "_dc0_readback_epochs", ()
                )
            ],
        }

    @staticmethod
    def _dc0_epoch_snapshot(epoch: dict[str, object]) -> dict[str, object]:
        snapshot = dict(epoch)
        snapshot["control"] = dict(epoch.get("control") or {})
        snapshot["start_values"] = list(epoch.get("start_values") or ())
        snapshot["status_reads"] = [
            dict(item) for item in epoch.get("status_reads") or ()
            if isinstance(item, dict)
        ]
        return snapshot

    def _sbi_write(self, uc: Uc, access: int, address: int, size: int,
                   value: int, user_data: object) -> None:
        del access, user_data
        event = (address, size, value)
        became_candidate = False
        if self._sbi_profile_status == "observing":
            expected = SBI_BOOTSTRAP[self._sbi_bootstrap_phase]
            if event == expected:
                self._sbi_bootstrap_phase += 1
                if self._sbi_bootstrap_phase == len(SBI_BOOTSTRAP):
                    self._sbi_profile_status = "candidate"
                    self._sbi_poll_aperture = (SBI_BASE, SBI_START + 1)
                    became_candidate = True
            else:
                self._sbi_bootstrap_phase = int(event == SBI_BOOTSTRAP[0])

        if self._sbi_profile_status == "candidate" and not became_candidate:
            if (self._sbi_validation_phase == 1
                    and event == (SBI_DATA, 2, 0x0900)):
                self._sbi_validation_phase = 2
            else:
                self._sbi_reject(uc, "validation-write-mismatch")

        if address == SBI_BASE and size == 1:
            self._sbi_clock = value & 0xFF
            self._sbi_counts["clock_writes"] += 1
        elif address == SBI_CONTROL and size == 2:
            self._sbi_control = value & 0x0FFF
            self._sbi_counts["control_writes"] += 1
        elif address == SBI_DATA and size == 2:
            self._sbi_counts["data_writes"] += 1
            if self._sbi_profile_status == "accepted":
                self._sbi_read_pending = bool(value & 0x8000)
                if self._sbi_read_pending:
                    self._sbi_counts["read_requests"] += 1
                    if self._sbi_started:
                        self._sbi_read_pending = False
                        self._sbi_read_full = True
        elif address == SBI_START and size == 1:
            self._sbi_counts["start_writes"] += 1
            self._sbi_started = bool(value & 1)
            if (self._sbi_profile_status == "accepted"
                    and self._sbi_started and self._sbi_read_pending):
                self._sbi_read_pending = False
                self._sbi_read_full = True

    def _sbi_read(self, uc: Uc, access: int, address: int, size: int,
                  value: int, user_data: object) -> None:
        del access, value, user_data
        if self._sbi_profile_status == "candidate":
            if address != SBI_BASE or size != 2:
                self._sbi_reject(uc, "validation-read-mismatch")
                return
            if self._sbi_validation_phase == 0:
                self._sbi_native_status_backing = bytes(
                    uc.mem_read(SBI_BASE, 2)
                )
                self._sbi_validation_phase = 1
            elif self._sbi_validation_phase == 2:
                self._sbi_profile_status = "accepted"
                self._sbi_validation_phase = 3
                self._sbi_native_status_backing = None
            else:
                self._sbi_reject(uc, "validation-status-order-mismatch")
                return

        if (address == SBI_BASE and size == 2
                and self._sbi_profile_status in {"candidate", "accepted"}):
            status = self._sbi_status_value()
            uc.mem_write(address, status.to_bytes(2, "little"))
            self._sbi_counts["status_reads"] += 1
        elif (address == SBI_DATA and size == 2
              and self._sbi_profile_status == "accepted"):
            self._sbi_counts["data_reads"] += 1
            self._sbi_read_full = False

    def _sbi_reject(self, uc: Uc, reason: str) -> None:
        if self._sbi_native_status_backing is not None:
            uc.mem_write(SBI_BASE, self._sbi_native_status_backing)
        self._sbi_profile_status = "rejected"
        self._sbi_reject_reason = reason
        self._sbi_native_status_backing = None
        self._sbi_poll_aperture = None
        self._sbi_read_pending = False
        self._sbi_read_full = False

    def _sbi_status_value(self) -> int:
        return (
            (self._sbi_control & 0x00C0) << 8
            | (self._sbi_control & 0x003F) << 8
            | (self._sbi_control & 0x0600) >> 3
            | (self._sbi_control & 0x0800) >> 6
            | (0x02 if self._sbi_read_full else 0)
        )

    def _sbi_telemetry(self) -> dict[str, object]:
        profile_status = getattr(self, "_sbi_profile_status", "not-detected")
        control = getattr(self, "_sbi_control", 0)
        return {
            "profile": (
                "msm5000-sbi-runtime-v1"
                if profile_status in {"candidate", "accepted"}
                else None
            ),
            "status": profile_status,
            "reject_reason": getattr(self, "_sbi_reject_reason", None),
            "bootstrap_phase": getattr(self, "_sbi_bootstrap_phase", 0),
            "control": f"0x{control:04X}",
            "status_value": (
                f"0x{self._sbi_status_value():04X}"
                if hasattr(self, "_sbi_control") else "0x0000"
            ),
            "started": getattr(self, "_sbi_started", False),
            "read_buffer_full": getattr(self, "_sbi_read_full", False),
            "counts": dict(getattr(self, "_sbi_counts", {})),
        }
