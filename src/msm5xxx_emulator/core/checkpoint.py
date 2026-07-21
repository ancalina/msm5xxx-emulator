"""Fault context and host checkpoint methods."""
from __future__ import annotations

from collections import deque
from .config import CopyLayout
from unicorn import UC_MEM_FETCH_UNMAPPED
from unicorn import UC_MEM_READ_UNMAPPED
from unicorn import UC_MEM_WRITE_UNMAPPED
from unicorn import UcError
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_R3
from unicorn.arm_const import UC_ARM_REG_R4
from unicorn.arm_const import UC_ARM_REG_R5
from unicorn.arm_const import UC_ARM_REG_R6
from unicorn.arm_const import UC_ARM_REG_R7
from unicorn.arm_const import UC_ARM_REG_SP
import hashlib


class CheckpointMixin:
    def _unmapped_fault_detail(self) -> str:
        """Describe the failing bus access without confusing successful probes."""
        event = self._chunk_unmapped
        if event is None:
            return ""
        labels = {
            UC_MEM_FETCH_UNMAPPED: "fetch",
            UC_MEM_READ_UNMAPPED: "read",
            UC_MEM_WRITE_UNMAPPED: "write",
        }
        label = labels.get(event["access"], f"access-{event['access']}")
        return ("; unmapped %s address=0x%08X size=%d value=0x%X"
                % (label, event["address"], event["size"], event["value"]))

    def _fault_context(self) -> dict[str, object] | None:
        if self.fault is None:
            return None
        pc = self.uc.reg_read(UC_ARM_REG_PC) & 0xFFFFFFFF
        lr = self.uc.reg_read(UC_ARM_REG_LR) & 0xFFFFFFFF
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR) & 0xFFFFFFFF
        thumb = bool(cpsr & 0x20)
        try:
            instruction = bytes(self.uc.mem_read(pc, 2 if thumb else 4)).hex()
        except UcError:
            instruction = None
        missing_overlay = next((
            item for item in self.config.missing_overlays
            if item.target <= pc < item.target + item.size
        ), None)
        if missing_overlay is not None:
            region = "missing-overlay-target"
        elif (self.primary_rom_end <= pc
              < self.config.load_address + len(self.image)):
            region = "erased-primary-padding"
        elif (self.config.load_address <= pc
              < self.config.load_address + len(self.image)):
            region = "primary-rom"
        elif self.config.ram_base <= pc < self.config.ram_base + self.config.ram_size:
            region = "ram"
        elif 0x03800000 <= pc < 0x03A00000:
            region = "internal-ram"
        else:
            region = "unconfigured"
        return {
            "pc": f"0x{pc:08X}",
            "lr": f"0x{lr:08X}",
            "cpsr": f"0x{cpsr:08X}",
            "cpu_state": "thumb" if thumb else "arm",
            "instruction_bytes": instruction,
            "region": region,
            "previous_block": (f"0x{self.tail[-2]:08X}"
                               if len(self.tail) >= 2 else None),
        }

    @staticmethod
    def _control_sink_from_tail(tail: deque[int] | list[int],
                                instruction: bytes = b"") -> int | None:
        """Identify only a proven one-instruction ARM/Thumb self-branch."""
        recent = list(tail)[-32:]
        if (len(recent) == 32 and len(set(recent)) == 1
                and (instruction.startswith(b"\xfe\xe7")
                     or instruction.startswith(b"\xfe\xff\xff\xea"))):
            return recent[0]
        return None

    @staticmethod
    def _missing_overlay_error(overlay: CopyLayout) -> str:
        return (
            "required executable overlay is absent from partial dump "
            f"(ROM 0x{overlay.source:X}..0x{overlay.source + overlay.size:X}; "
            f"target 0x{overlay.target:08X}.."
            f"0x{overlay.target + overlay.size:08X})"
        )

    def _host_backend_checkpoint(self, next_pc: int,
                                 count: int) -> dict[str, object]:
        """Capture only Python state and pre-call Unicorn reads for a terminal error."""
        identity_method = getattr(self.config, "firmware_identity", None)
        identity = (identity_method() if callable(identity_method) else {
            "basename": "unknown", "bytes": None, "sha256": None,
        })
        registers = {
            **{f"r{index}": f"0x{self.uc.reg_read(register) & 0xFFFFFFFF:08X}"
               for index, register in enumerate((
                   UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                   UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                   UC_ARM_REG_R6, UC_ARM_REG_R7,
               ))},
            "sp": f"0x{self.uc.reg_read(UC_ARM_REG_SP) & 0xFFFFFFFF:08X}",
            "pc": f"0x{self.uc.reg_read(UC_ARM_REG_PC) & 0xFFFFFFFF:08X}",
            "lr": f"0x{self.uc.reg_read(UC_ARM_REG_LR) & 0xFFFFFFFF:08X}",
            "cpsr": f"0x{self.uc.reg_read(UC_ARM_REG_CPSR) & 0xFFFFFFFF:08X}",
        }
        try:
            width, height, frame = self.display_snapshot()
        except AttributeError:  # Minimal test harnesses need no GUI snapshot.
            width = int(getattr(self.config, "width", 0))
            height = int(getattr(self.config, "height", 0))
            frame = bytes(getattr(self, "display_frame", b""))
        reads = (getattr(self, "mmio_read_totals", None)
                 or getattr(self, "mmio_reads", None))
        hottest = max(reads.items(), key=lambda item: item[1]) if reads else None
        last_unmapped = getattr(self, "last_unmapped", None)
        unmapped_accesses = getattr(self, "unmapped_accesses", ())
        safe_unmapped = None
        if last_unmapped is not None:
            safe_unmapped = {
                "access": last_unmapped.get("access"),
                "address": f"0x{last_unmapped['address']:08X}",
                "size": last_unmapped.get("size"),
                "value": f"0x{last_unmapped['value']:X}",
            }
        safe_unmapped_accesses = [
            {
                **event,
                "address": f"0x{event['address']:08X}",
                "value": f"0x{event['value']:X}",
                **({"pc": f"0x{event['pc']:08X}"} if "pc" in event else {}),
            }
            for event in unmapped_accesses
        ]
        secondary = getattr(self, "secondary_flash", None)
        return {
            "firmware": identity,
            "model": getattr(self.config, "model", "unknown"),
            "chipset": getattr(self.config, "chipset", "unknown"),
            "next_pc": f"0x{next_pc & 0xFFFFFFFF:08X}",
            "chunk_steps": count,
            "instructions": self.instructions,
            "registers": registers,
            "tail": [f"0x{address:08X}" for address in self.tail],
            "display": {
                "width": width,
                "height": height,
                "sha256": hashlib.sha256(frame).hexdigest(),
                "frame_sequence": self.frame_sequence,
                "firmware_frame_sequence": self.firmware_frame_sequence,
            },
            "counters": {
                "reset_entries": self.reset_entries,
                "lcd_writes": self.lcd_writes,
                "rex_idle_entries": self.rex_idle_entries,
                "rex_ticks": self.rex_ticks,
                "rex_elapsed_ms": self.rex_elapsed_ms,
                "storage": {
                    "eeprom_reads": self.eeprom_reads,
                    "eeprom_writes": self.eeprom_writes,
                    "eeprom_changed_bytes": (
                        len(self.eeprom_data) - self.eeprom_data.count(0xFF)
                    ),
                    "secondary_nor_reads": self.secondary_flash_reads,
                    "secondary_nor_writes": self.secondary_flash_writes,
                    "secondary_nor_changed_pages": len(
                        getattr(secondary, "changed_pages", ())
                    ),
                    "nand_reads": self.nand_reads,
                    "nand_writes": self.nand_writes,
                    "nand_commands": len(self.nand_commands),
                },
            },
            "dynamic_pages": len(self.dynamic_pages),
            "last_unmapped": safe_unmapped,
            "unmapped_accesses": safe_unmapped_accesses,
            "dynamic_page_first_accesses": [
                {**event,
                 "address": f"0x{event['address']:08X}",
                 "page": f"0x{event['page']:08X}",
                 "value": f"0x{event['value']:X}",
                 **({"pc": f"0x{event['pc']:08X}"} if "pc" in event else {})}
                for event in getattr(self, "dynamic_page_first_accesses", ())
            ],
            "hottest_mmio_read": (
                {"pc": f"0x{hottest[0][0]:08X}",
                 "address": f"0x{hottest[0][1]:08X}",
                 "size": hottest[0][2], "reads": hottest[1]}
                if hottest is not None else None
            ),
        }
