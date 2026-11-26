"""Source companion inputs must be literal and checksum pinned."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('runtime_sources',Path(__file__).parents[1]/'packaging/runtime_sources.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class RuntimeSourceTests(unittest.TestCase):
    def test_formula_sources_and_patches(self):
        digest='a'*64
        recipe=f'url "https://example.org/library.tar.xz"\nsha256 "{digest}"\npatch do\n  url "https://example.org/fix.diff"\n  sha256 "{digest}"\nend'
        self.assertEqual(module.formula_inputs(recipe),[('https://example.org/library.tar.xz',digest),('https://example.org/fix.diff',digest)])
        for invalid in ('url "https://example.org/unpinned"',f'url "https://example.org/#{{version}}"\nsha256 "{digest}"'):
            with self.assertRaises(ValueError): module.formula_inputs(invalid)
