"""Runtime-admitted MSM5000 serial bus register behavior."""
from __future__ import annotations

from unicorn import UC_HOOK_MEM_READ
from unicorn import UC_HOOK_MEM_WRITE
from unicorn import Uc


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

    def _install_sbi_hooks(self) -> None:
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
