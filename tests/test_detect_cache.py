from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import msm5xxx_emulator.detection.plan as boot_plan
from msm5xxx_emulator.gui import controls


class DesktopDetectCacheTest(unittest.TestCase):
    def test_reuses_result_by_content_from_memory_and_disk(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / 'a.bin', root / 'b.bin'
            first.write_bytes(b'firmware')
            second.write_bytes(b'firmware')
            detector = Mock(side_effect=lambda path: SimpleNamespace(path=path, model='M'))
            with patch.object(boot_plan, 'detect', detector), patch.object(controls, 'detect', detector), \
                    patch.object(controls, 'DEFAULT_STATE_ROOT', root / 'state'), \
                    patch.dict(controls._detect_memo, clear=True):
                self.assertEqual(controls.detect_cached(first).path, first)
                self.assertEqual(controls.detect_cached(second).path, second)
                controls._detect_memo.clear()
                self.assertEqual(controls.detect_cached(first).model, 'M')
                first.write_bytes(b'changed')
                controls.detect_cached(first)
            self.assertEqual(detector.call_count, 2)
            self.assertEqual(len(list((root / 'state' / 'detect-cache').glob('*.pickle'))), 2)

    def test_substituted_detector_is_not_cached(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / 'a.bin'
            path.write_bytes(b'x')
            detector = Mock(return_value=SimpleNamespace(path=path))
            with patch.object(controls, 'detect', detector), patch.object(controls, 'DEFAULT_STATE_ROOT', Path(tmp) / 'state'):
                controls.detect_cached(path)
                controls.detect_cached(path)
            self.assertEqual(detector.call_count, 2)
            self.assertFalse((Path(tmp) / 'state').exists())


if __name__ == '__main__':
    unittest.main()
