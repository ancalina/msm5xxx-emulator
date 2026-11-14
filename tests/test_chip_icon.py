import datetime
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("chip_icon", Path(__file__).resolve().parents[1] / "branding" / "chip_icon.py")
chip_icon = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(chip_icon)


class ChipIconTests(unittest.TestCase):
    def test_marking_follows_build_data(self):
        lines = chip_icon.marking_lines("0.1.0", datetime.date(2026, 11, 14), "8b4652bdb86c", "win x64")
        self.assertEqual(lines, ["EMULATOR", "QT10-V0010-0", "14 26468B465", "BM 2646K1114", "261114QEM A", "WIN X64"])

    def test_iso_week_at_year_boundary(self):
        # 2027-01-01 belongs to ISO week 53 of 2026
        self.assertEqual(chip_icon.marking_lines("1.2.3", datetime.date(2027, 1, 1), "abcdef0", "LNX X64")[1:4],
                         ["QT10-V1023-0", "14 2653ABCDE", "BM 2653K0101"])

    @unittest.skipUnless(chip_icon.HERSHEY.is_file(), "Inkscape Hershey font not installed")
    def test_layers_are_svg(self):
        layers = chip_icon.layers("0.1.0", datetime.date(2026, 11, 14), "8b4652b", "MAC X64")
        self.assertEqual(set(layers), {"full", "plate", "marking", "small", "small-marking"})
        self.assertTrue(all(text.startswith("<svg") and text.endswith("</svg>") for text in layers.values()))
        self.assertNotIn("<path", layers["plate"])


if __name__ == "__main__":
    unittest.main()
