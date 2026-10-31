"""NOR command and persistence telemetry regressions."""
from __future__ import annotations


from pathlib import Path
import tempfile
import unittest


from msm5xxx_emulator.detection.storage import qualcomm_efs_seed
from msm5xxx_emulator.devices.storage.nor import FUJITSU_MB84VD2219X_IDS, NORFlash


class NORTelemetryTests(unittest.TestCase):
    def test_equal_logged_state_skips_python_unlogged_scan(self) -> None:
        class UnindexedBytearray(bytearray):
            def __getitem__(self, key: object) -> int | bytearray:
                raise AssertionError("equal state must not use Python indexing")

        with tempfile.TemporaryDirectory() as directory:
            flash = NORFlash(b"\xff" * 0x1000, Path(directory) / "flash.json")
            self.assertEqual(flash.program(0x20, b"\xaa"), b"\xaa")
            flash.data = UnindexedBytearray(flash.data)

            self.assertEqual(flash._unlogged_operations(), [])

    def test_capture_efs_seed_is_limited_to_msm5500(self) -> None:
        erased = b"\xff" * 0x200
        self.assertEqual(qualcomm_efs_seed(0x200, "MSM5000"), erased)
        self.assertNotEqual(qualcomm_efs_seed(0x200, "MSM5500"), erased)

    def test_fujitsu_bottom_boot_sector_geometry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            flash = NORFlash(b"\x00" * 0x400000,
                             Path(directory) / "flash.json")
            flash.ids = FUJITSU_MB84VD2219X_IDS

            flash._erase(*flash._sector_bounds(0x2345))
            self.assertEqual(bytes(flash.data[:0x2000]), b"\x00" * 0x2000)
            self.assertEqual(bytes(flash.data[0x2000:0x4000]), b"\xff" * 0x2000)
            self.assertEqual(bytes(flash.data[0x4000:0x6000]), b"\x00" * 0x2000)

            flash._erase(*flash._sector_bounds(0x12345))
            self.assertEqual(bytes(flash.data[0x10000:0x20000]),
                             b"\xff" * 0x10000)

    def test_program_read_and_sector_erase_are_counted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            flash = NORFlash(b"\xff" * 0x20000, Path(directory) / "flash.json")

            flash.write(0xAAA, 1, 0xAA)
            flash.write(0x554, 1, 0x55)
            flash.write(0xAAA, 1, 0xA0)
            flash.write(0x1234, 2, 0x55AA)
            self.assertEqual(flash.read(0x1234, 2), bytes.fromhex("aa55"))

            flash.write(0xAAA, 1, 0xAA)
            flash.write(0x554, 1, 0x55)
            flash.write(0xAAA, 1, 0x80)
            flash.write(0xAAA, 1, 0xAA)
            flash.write(0x554, 1, 0x55)
            flash.write(0x1234, 1, 0x30)

            telemetry = flash.telemetry()
            self.assertEqual(telemetry["reads"], 1)
            self.assertEqual(telemetry["read_bytes"], 2)
            self.assertEqual(telemetry["programs"], 1)
            self.assertEqual(telemetry["program_bytes"], 2)
            self.assertEqual(telemetry["last_program_address"], 0x1234)
            self.assertEqual(telemetry["erases"], 1)
            self.assertEqual(telemetry["erase_bytes"], 0x10000)
            self.assertEqual(telemetry["last_erase_address"], 0)

    def test_independent_secondary_nor_sessions_merge_persistent_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "secondary.json"
            original = b"\xff" * 0x1000
            first = NORFlash(original, state)
            second = NORFlash(original, state)
            self.assertEqual(first.program(0x20, b"\xaa"), b"\xaa")
            self.assertEqual(second.program(0x30, b"\x55"), b"\x55")

            first.save()
            second.save()

            warm = NORFlash(original, state)
            self.assertEqual(bytes(warm.data[0x20:0x21]), b"\xaa")
            self.assertEqual(bytes(warm.data[0x30:0x31]), b"\x55")


if __name__ == "__main__":
    unittest.main()
