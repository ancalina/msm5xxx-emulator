"""HLE behavior owned by common."""
from __future__ import annotations

from ..detection.firmware import ADDRESS_SPACE
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn import Uc
from unicorn import UcError
import struct


class HleCommonMixin:
    @staticmethod
    def _thumb_loop_exit(uc: Uc, address: int) -> int | None:
        branch = struct.unpack("<H", uc.mem_read(address + 2, 2))[0]
        if branch & 0xFF00 != 0xD200:  # BHS
            return None
        displacement = (branch & 0xFF) * 2
        if displacement & 0x100:
            displacement -= 0x200
        return address + 6 + displacement

    def _original_runtime_bytes(self, address: int, length: int) -> bytes | None:
        """Map relocated runtime code back to the pristine firmware image."""
        end = address + length
        if length <= 0 or not 0 <= address < end <= ADDRESS_SPACE:
            return None
        offsets: list[int] = []
        for overlay in self.config.overlays:
            if overlay.target <= address and end <= overlay.target + overlay.size:
                offsets.append(overlay.source + address - overlay.target)
        if not offsets:
            layout = self.config.linker
            if (layout is not None and layout.data_target <= address
                    and end <= layout.data_target + layout.data_size):
                offsets.append(layout.data_source + address - layout.data_target)
            elif (self.config.load_address <= address
                  and end <= self.config.load_address + self.config.flash_size):
                offsets.append(address - self.config.load_address)
            else:
                return None
        original = self.original_image
        candidates = [original[offset:offset + length] for offset in offsets
                      if 0 <= offset and offset + length <= len(original)]
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        # Several runtime overlays can deliberately reuse the same internal-RAM
        # target.  Resolve the active bank from the bytes firmware actually
        # copied instead of treating the first table entry as permanent.
        try:
            runtime = bytes(self.uc.mem_read(address, length))
        except UcError:
            return None
        matching = [candidate for candidate in candidates if candidate == runtime]
        return matching[0] if matching else None

    def _thumb_runtime_matches(self, uc: Uc, address: int,
                               signature: bytes | None = None,
                               prefix_size: int = 32) -> bool:
        """Accept HLE only while Thumb code still matches its pristine body."""
        try:
            if not uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
                return False
            expected = (signature if signature is not None
                        else self._original_runtime_bytes(address, prefix_size))
            return (expected is not None
                    and bytes(uc.mem_read(address, len(expected))) == expected)
        except UcError:
            return False

    def _hle_destination_is_ram(self, address: int, length: int) -> bool:
        end = address + length
        return (0 <= address <= end <= ADDRESS_SPACE
                and (self.config.ram_base <= address <= end
                     <= self.config.ram_base + self.config.ram_size
                     or 0x03800000 <= address <= end <= 0x03A00000))

    def _hle_destination_is_declared(self, address: int, length: int) -> bool:
        """Accept structural Thumb HLE only for a proven load destination.

        A valid Thumb clear/copy shape by itself is not enough: old BSPs also
        use the same loop for temporary work areas whose lifetime depends on
        device callbacks.  The automatic HLE therefore restricts itself to
        the detected scatter-load data/BSS interval or a boot overlay target.
        Explicit per-signature HLEs retain their existing RAM checks.
        """
        if not self._hle_destination_is_ram(address, length):
            return False
        end = address + length
        ranges: list[tuple[int, int]] = []
        if self.config.linker is not None:
            ranges.append((
                self.config.linker.data_target,
                self.config.linker.bss_target + self.config.linker.bss_size,
            ))
        ranges.extend((overlay.target, overlay.target + overlay.size)
                      for overlay in self.config.overlays)
        return any(start <= address <= end <= stop for start, stop in ranges)

    def _primary_nor_contains(self, address: int, end: int) -> bool:
        return (self.flash.phase == "idle"
                and self.config.load_address <= address <= end
                <= self.primary_rom_end)

    def _hle_source_is_safe(self, address: int, length: int) -> bool:
        end = address + length
        if not 0 <= address <= end <= ADDRESS_SPACE:
            return False
        ranges = [
            (self.config.ram_base, self.config.ram_base + self.config.ram_size),
            (0x03800000, 0x03A00000),
            *((item.target, item.target + item.size)
              for item in self.config.overlays),
        ]
        if self.flash.phase == "idle":
            ranges.append((self.config.load_address,
                           self.config.load_address + self.config.flash_size))
        secondary = self.config.secondary_flash_address
        if (secondary not in (None, 0) and self.secondary_flash is not None
                and self.secondary_flash.phase == "idle"):
            ranges.append((secondary,
                           secondary + self.config.secondary_flash_size))
        return any(start <= address <= end <= stop for start, stop in ranges)

    @staticmethod
    def _thumb_unconditional_target(address: int, instruction: int) -> int | None:
        """Return the target of a 16-bit Thumb unconditional branch."""
        if instruction & 0xF800 != 0xE000:
            return None
        displacement = (instruction & 0x7FF) << 1
        if displacement & 0x800:
            displacement -= 0x1000
        return address + 4 + displacement

    @staticmethod
    def _thumb_conditional_target(address: int, instruction: int) -> int | None:
        """Return the target of a 16-bit Thumb conditional branch."""
        if instruction & 0xF000 != 0xD000:
            return None
        displacement = (instruction & 0xFF) << 1
        if displacement & 0x100:
            displacement -= 0x200
        return address + 4 + displacement

    @staticmethod
    def _thumb_add3(instruction: int) -> tuple[int, int, int] | None:
        """Decode ``ADDS Rd, Rs, #imm3`` (including the MOV alias)."""
        if instruction & 0xFE00 != 0x1C00:
            return None
        return instruction & 7, instruction >> 3 & 7, instruction >> 6 & 7

    @staticmethod
    def _thumb_memory_zero(instruction: int, opcode: int) -> tuple[int, int] | None:
        """Decode a zero-offset Thumb LDR/STR word as (Rt, Rn)."""
        if (instruction & 0xF800) != opcode or (instruction >> 6 & 0x1F):
            return None
        return instruction & 7, instruction >> 3 & 7

    @staticmethod
    def _thumb_movs_zero(instruction: int) -> int | None:
        if instruction & 0xF800 != 0x2000 or instruction & 0xFF:
            return None
        return instruction >> 8 & 7

    @staticmethod
    def _thumb_lsls_immediate(instruction: int) -> tuple[int, int, int] | None:
        if instruction & 0xF800:
            return None
        return instruction & 7, instruction >> 3 & 7, instruction >> 6 & 0x1F

    @staticmethod
    def _set_thumb_cmp_equal_flags(uc: Uc) -> None:
        """Leave the flags produced by an equal unsigned CMP (Z=1, C=1)."""
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        cpsr &= ~0x90000000  # N and V
        uc.reg_write(UC_ARM_REG_CPSR, cpsr | 0x60000020)

    def _return_if_thumb_signature(self, uc: Uc, address: int, size: int,
                                   user_data: object) -> None:
        if (isinstance(user_data, bytes)
                and self._thumb_runtime_matches(uc, address, user_data)):
            self._return_to_lr(uc, address, size, user_data)

    @staticmethod
    def _return_to_lr(uc: Uc, address: int, size: int, user_data: object) -> None:
        lr = uc.reg_read(UC_ARM_REG_LR)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_PC, lr & ~1)
        uc.reg_write(UC_ARM_REG_CPSR, cpsr | 0x20 if lr & 1 else cpsr & ~0x20)
