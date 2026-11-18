"""W1C default-handler trampoline is BX r0, optionally via one ARM veneer."""
import struct
import unittest

from msm5xxx_emulator.detection.devices.rex.rules.controller import (
    _thumb_bx_r0_trampoline,
)


class W1CTrampolineTests(unittest.TestCase):
    def test_direct_and_veneer_land_on_bx_r0(self):
        image = bytearray(b"\xff" * 0x40)
        image[0x10:0x12] = b"\x00\x47"
        self.assertTrue(_thumb_bx_r0_trampoline(bytes(image), 0x10))
        self.assertFalse(_thumb_bx_r0_trampoline(bytes(image), 0x11))
        veneer = bytes.fromhex("7847c04600c09fe51cff2fe1") + struct.pack("<I", 0x11)
        image[0x20:0x20 + len(veneer)] = veneer
        self.assertTrue(_thumb_bx_r0_trampoline(bytes(image), 0x20))
        image[0x20 + 12:0x20 + 16] = struct.pack("<I", 0x10)
        self.assertFalse(_thumb_bx_r0_trampoline(bytes(image), 0x20))
        image[0x20:0x22] = b"\xff\xff"
        self.assertFalse(_thumb_bx_r0_trampoline(bytes(image), 0x20))
        self.assertFalse(_thumb_bx_r0_trampoline(bytes(image), 0x30))

    def test_veneer_resolves_lock_helper_landing(self):
        from msm5xxx_emulator.detection.devices.rex.rules.controller import (
            _arm_thumb_veneer_landing,
        )
        image = bytearray(b"\xff" * 0x40)
        body = bytes.fromhex("78470000") + b"\x00" * 24
        image[0x10:0x10 + len(body)] = body
        self.assertEqual(_arm_thumb_veneer_landing(bytes(image), 0x10), 0x10)
        veneer = bytes.fromhex("7847c04600c09fe51cff2fe1") + struct.pack("<I", 0x11)
        image[0x20:0x20 + len(veneer)] = veneer
        self.assertEqual(_arm_thumb_veneer_landing(bytes(image), 0x20), 0x10)
