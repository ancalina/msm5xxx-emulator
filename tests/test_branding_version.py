"""Prerelease tags retain their numeric version on every platform's chip icon."""
import datetime
import importlib.util
from pathlib import Path
import unittest


class BrandingVersionTests(unittest.TestCase):
    def test_prerelease_markings(self):
        root = Path(__file__).resolve().parents[1]
        paths = [root / 'branding/chip_icon.py', *root.glob('desktop/*/[Bb]randing/chip_icon.py')]
        self.assertEqual(len(paths), 4)
        for path in paths:
            with self.subTest(path=path):
                spec = importlib.util.spec_from_file_location('chip_icon', path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for version in ('0.2.0-rc', '0.2.0+build.1', '0.2.0a0', '0.2.0'):
                    self.assertEqual(module.marking_lines(version, datetime.date(2026, 11, 28), 'abcdef0', 'TEST')[1], 'QT10-V0020-0')


if __name__ == '__main__':
    unittest.main()
