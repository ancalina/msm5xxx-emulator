"""Focused regression for the SE47-class guest-owned status register."""
from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from unicorn.arm_const import (UC_ARM_REG_CPSR, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2)

from msm5xxx import GenericMSMEmulator
from msm5xxx_emulator.detection.boot import (
    GUEST_OWNED_STATUS_72C_CONSUMER,
    GUEST_OWNED_STATUS_72C_POWERDOWN_TAIL,
)
from msm5xxx_emulator.detection.firmware import detect


def thumb_bl(source: int, target: int) -> bytes:
    displacement = (target - source - 4) & 0x7FFFFF
    return struct.pack(
        "<2H",
        0xF000 | displacement >> 12 & 0x7FF,
        0xF800 | displacement >> 1 & 0x7FF,
    )


class GuestOwnedStatus72CTests(unittest.TestCase):
    @staticmethod
    def _image() -> bytearray:
        image = bytearray(b"\xff" * 0x600)
        for offset in range(0, 32, 4):
            struct.pack_into("<I", image, offset, 0xEA000000)
        caller, function, sink = 0x100, 0x200, 0x300
        consumer = function + 0x2E
        image[function:function + 6] = bytes.fromhex("f0b5071c8408")
        image[consumer:consumer + len(GUEST_OWNED_STATUS_72C_CONSUMER)] = (
            GUEST_OWNED_STATUS_72C_CONSUMER
        )
        struct.pack_into("<I", image, consumer + 0x36, 0x03000720)
        struct.pack_into("<H", image, caller, 0x4803)
        image[caller + 2:caller + 6] = thumb_bl(caller + 2, function)
        image[caller + 6:caller + 10] = bytes.fromhex("002801d1")
        image[caller + 10:caller + 14] = thumb_bl(caller + 10, sink)
        struct.pack_into("<I", image, caller + 0x10, 0x2EE)
        terminal = sink + 0x20
        image[terminal:terminal + len(GUEST_OWNED_STATUS_72C_POWERDOWN_TAIL)] = (
            GUEST_OWNED_STATUS_72C_POWERDOWN_TAIL
        )
        unlock = terminal + len(GUEST_OWNED_STATUS_72C_POWERDOWN_TAIL)
        image[unlock:unlock + 4] = thumb_bl(unlock, 0x3C0)
        image[unlock + 4:unlock + 6] = b"\xfe\xe7"
        return image

    @staticmethod
    def _guest_write_then_read(config: object) -> tuple[int, int]:
        emulator = GenericMSMEmulator(config)
        try:
            register = 0x0300072C
            assert bytes(emulator.uc.mem_read(register, 1)) == b"\x14"
            code = config.ram_base
            emulator.uc.mem_write(code, bytes.fromhex("017002787047"))
            emulator.uc.reg_write(UC_ARM_REG_R0, register)
            emulator.uc.reg_write(UC_ARM_REG_R1, 0)
            emulator.uc.reg_write(UC_ARM_REG_CPSR, 0x30)
            emulator.uc.emu_start(code | 1, 0, count=2)
            return (emulator.uc.reg_read(UC_ARM_REG_R2),
                    emulator.uc.mem_read(register, 1)[0])
        finally:
            emulator.close()

    def test_exact_signature_owns_72c_and_near_miss_is_rejected(self) -> None:
        exact = self._image()
        near_miss = bytearray(exact)
        struct.pack_into("<I", near_miss, 0x22E + 0x36, 0x030001A0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exact_path, near_path = root / "exact.bin", root / "near.bin"
            exact_path.write_bytes(exact)
            near_path.write_bytes(near_miss)
            exact_config, near_config = detect(exact_path), detect(near_path)

            self.assertTrue(exact_config.guest_owned_status_72c)
            self.assertIn("guest-write-owned", " ".join(exact_config.detection_notes))
            self.assertFalse(near_config.guest_owned_status_72c)
            self.assertIn("candidate rejected", " ".join(near_config.detection_notes))

            self.assertEqual(self._guest_write_then_read(exact_config), (0, 0))
            # Default/KTFT behavior remains reset-on-read.
            self.assertEqual(self._guest_write_then_read(near_config), (0x14, 0x14))


if __name__ == "__main__":
    unittest.main()
