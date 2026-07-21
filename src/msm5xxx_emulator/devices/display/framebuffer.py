"""Display methods owned by framebuffer."""
from __future__ import annotations

from ...core.constants import FRAMEBUFFER_FORMATS
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_R3
from unicorn.arm_const import UC_ARM_REG_SP
from unicorn import Uc
from unicorn import UcError
import struct


class FramebufferMixin:
    def set_framebuffer_format(self, framebuffer_format: str) -> None:
        """Apply a verified framebuffer colour interpretation without rebooting."""
        if framebuffer_format not in FRAMEBUFFER_FORMATS:
            raise ValueError(f"unsupported framebuffer format: {framebuffer_format}")
        if self.config.framebuffer_address is None:
            raise ValueError("framebuffer format requires a framebuffer address")
        if framebuffer_format == "none":
            raise ValueError("framebuffer format cannot be none while it is mapped")
        if self.config.framebuffer_format == framebuffer_format:
            return
        self.config.framebuffer_format = framebuffer_format
        self._render_framebuffer_region(
            0, 0, self.config.width - 1, self.config.height - 1, force=True,
            firmware_originated=False,
        )

    def _render_framebuffer_region(self, x0: int, y0: int, x1: int, y1: int,
                                   force: bool = True, *,
                                   firmware_originated: bool = True) -> bool:
        address = self.config.framebuffer_address
        if address is None:
            return False
        x0, y0 = max(0, x0), max(0, y0)
        x1 = min(self.config.width - 1, x1)
        y1 = min(self.config.height - 1, y1)
        if x0 > x1 or y0 > y1:
            return False
        endian = "big" if self.config.framebuffer_format.endswith("be") else "little"
        bgr = self.config.framebuffer_format.startswith("bgr")
        changed = False
        for y in range(y0, y1 + 1):
            row = self.uc.mem_read(
                address + y * self.config.framebuffer_stride + x0 * 2,
                (x1 - x0 + 1) * 2,
            )
            for column, offset in enumerate(range(0, len(row), 2), x0):
                value = int.from_bytes(row[offset:offset + 2], endian)
                if bgr:
                    value = ((value & 0x07E0) | (value & 0x001F) << 11
                             | (value >> 11 & 0x001F))
                target = (y * self.config.width + column) * 3
                before = self.framebuffer[target:target + 3]
                self._pixel(y * self.config.width + column, value)
                changed |= before != self.framebuffer[target:target + 3]
        if force or changed:
            self._lcd_protocol = f"framebuffer-{self.config.framebuffer_format}"
            self._publish_frame(firmware_originated=firmware_originated)
        return changed

    def _framebuffer_rows(self, uc: Uc, address: int, size: int,
                          user_data: object) -> None:
        if uc.reg_read(UC_ARM_REG_R0) != self.config.framebuffer_address:
            return
        self.lcd_writes += 1
        self._render_framebuffer_region(
            0, uc.reg_read(UC_ARM_REG_R1), self.config.width - 1,
            uc.reg_read(UC_ARM_REG_R2),
        )

    def _framebuffer_rect(self, uc: Uc, address: int, size: int,
                          user_data: object) -> None:
        if uc.reg_read(UC_ARM_REG_R0) != self.config.framebuffer_address:
            return
        try:
            y1 = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
        except (UcError, struct.error):
            return
        self.lcd_writes += 1
        self._render_framebuffer_region(
            uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2),
            uc.reg_read(UC_ARM_REG_R3), y1,
        )
