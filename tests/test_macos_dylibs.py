import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('macos_dylibs', Path(__file__).parents[1]/'packaging/macos/dylibs.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DylibTests(unittest.TestCase):
    def test_recursive_dependency_closure_and_relative_load_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root/'bin/qemu-system-arm';executable.parent.mkdir();executable.write_bytes(b'executable')
            source = root/'source';source.mkdir()
            first = source/'first.dylib';first.write_bytes(b'first')
            second = source/'second.dylib';second.write_bytes(b'second')
            def dependencies(command, **kwargs):
                name = Path(command[-1]).name
                children = {'qemu-system-arm': [first], 'first.dylib': [second], 'second.dylib': []}[name]
                return name+':\n'+''.join('\t'+str(child)+' (compatibility version 1.0.0)\n' for child in children)+'\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n'
            with patch.object(module.subprocess,'check_output',side_effect=dependencies),patch.object(module.subprocess,'run') as change:
                result = module.bundle(executable,root/'lib')
            self.assertEqual(result,{'first.dylib':first,'second.dylib':second})
            commands = [call.args[0] for call in change.call_args_list]
            self.assertIn(['install_name_tool','-change',str(first),'@executable_path/../lib/first.dylib',str(executable)],commands)
            self.assertIn(['install_name_tool','-change',str(second),'@loader_path/second.dylib',str(root/'lib/first.dylib')],commands)
            self.assertEqual((root/'lib/second.dylib').read_bytes(),b'second')
