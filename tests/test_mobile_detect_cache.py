import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "android/app/src/main/python"))
import msm5xxx_android_runtime as runtime  # noqa: E402


class DetectCacheTests(unittest.TestCase):
    def test_reuses_result_until_firmware_or_detector_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            firmware = Path(folder) / "image.bin"
            firmware.write_bytes(b"\x00" * 64)
            calls = []
            fake = lambda path: calls.append(path) or {"notes": [len(calls)]}
            runtime._detect_memo.clear()
            with mock.patch("msm5xxx_emulator.detection.detect", fake), \
                 mock.patch.object(runtime, "_detector_fingerprint_value", "v1"):
                first = runtime.detect_cached(firmware)
                first["notes"].append("caller mutation")
                self.assertEqual(runtime.detect_cached(firmware), {"notes": [1]})
                runtime._detect_memo.clear()
                self.assertEqual(runtime.detect_cached(firmware), {"notes": [1]})  # file cache
                self.assertEqual(len(calls), 1)
                firmware.write_bytes(b"\x01" * 64)
                runtime.detect_cached(firmware)
                self.assertEqual(len(calls), 2)
            runtime._detect_memo.clear()
            with mock.patch("msm5xxx_emulator.detection.detect", fake), \
                 mock.patch.object(runtime, "_detector_fingerprint_value", "v2"):
                runtime.detect_cached(firmware)
                self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
