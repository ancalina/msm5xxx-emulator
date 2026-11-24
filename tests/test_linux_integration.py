"""The desktop launcher preserves paths through both desktop-file escaping layers."""
import importlib.util
from pathlib import Path
import tempfile
import time
import unittest

try:
    import gi
    gi.require_version('GioUnix', '2.0')
    from gi.repository import GioUnix
except (ImportError, ValueError):
    GioUnix = None


@unittest.skipIf(GioUnix is None, 'Linux GIO desktop integration')
class DesktopEntryTests(unittest.TestCase):
    def test_special_character_paths_launch_exact_file(self):
        spec = importlib.util.spec_from_file_location('integration', Path(__file__).resolve().parents[1]/'packaging/linux/runtime.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); result=root/'result'
            for name in ('space name', 'quote"name', 'dollar$name', 'tick`name', 'back\\name', 'percent%name'):
                with self.subTest(name=name):
                    executable=root/name
                    executable.write_text('#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\nPath('+repr(str(result))+').write_text(sys.argv[0])\n')
                    executable.chmod(0o755)
                    desktop=root/'test.desktop'
                    desktop.write_text('[Desktop Entry]\nType=Application\nName=Test\nExec=/usr/bin/env '+module.quoted(str(executable))+'\n')
                    GioUnix.DesktopAppInfo.new_from_filename(str(desktop)).launch([],None)
                    deadline=time.monotonic()+3
                    while not result.exists() and time.monotonic()<deadline: time.sleep(.02)
                    self.assertEqual(result.read_text(),str(executable))
                    result.unlink()


if __name__ == '__main__': unittest.main()
