from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.ready_poll import find_ready_poll_profile


def fixture(status_base: int = 0x030007B0,
            pulse: int = 0x03000600) -> bytes:
    code = bytearray.fromhex("00f002f800000000")
    code.extend(bytes.fromhex(
        "05480079000905d201200449087000200870f5e7f7460000"
    ))
    code.extend(struct.pack("<2I", status_base, pulse))
    return bytes(code)


class ReadyPollDetectionTests(unittest.TestCase):
    def test_exact_poll_returns_firmware_addresses(self) -> None:
        self.assertEqual(find_ready_poll_profile(fixture()), {
            "signature": "thumb-lsrs-bhs-pulse-v1",
            "status_address": 0x030007B4,
            "mask": 0x08,
            "pulse_address": 0x03000600,
            "entries": [8],
        })

    def test_near_miss_and_conflicting_contract_fail_closed(self) -> None:
        near = bytearray(fixture())
        near[16] ^= 1
        self.assertIsNone(find_ready_poll_profile(bytes(near)))
        self.assertIsNone(find_ready_poll_profile(
            fixture() + fixture(0x03000F10, 0x03000700)
        ))
        self.assertIsNone(find_ready_poll_profile(fixture()[8:]))
        self.assertIsNone(find_ready_poll_profile(b"\x00" + fixture()))


if __name__ == "__main__":
    unittest.main()
