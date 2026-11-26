"""Source companion inputs must be literal and checksum pinned."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
import hashlib

spec=importlib.util.spec_from_file_location('runtime_sources',Path(__file__).parents[1]/'packaging/runtime_sources.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class RuntimeSourceTests(unittest.TestCase):
    def test_formula_sources_and_patches(self):
        digest='a'*64
        recipe=f'url "https://example.org/library.tar.xz"\nsha256 "{digest}"\npatch do\n  url "https://example.org/fix.diff"\n  sha256 "{digest}"\nend'
        self.assertEqual(module.formula_inputs(recipe),[('https://example.org/library.tar.xz',digest),('https://example.org/fix.diff',digest)])
        for invalid in ('url "https://example.org/unpinned"',f'url "https://example.org/#{{version}}"\nsha256 "{digest}"'):
            with self.assertRaises(ValueError): module.formula_inputs(invalid)

    def test_cached_sources_require_matching_packages_and_complete_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);runtime=root/'runtime';stage=root/'sources';runtime.mkdir();stage.mkdir()
            (runtime/'PACKAGES.txt').write_text('library:amd64 1.0\n')
            (stage/'PACKAGES.json').write_text(json.dumps({'library:amd64':{'version':'1.0'}}))
            (stage/'library.tar.xz').write_bytes(b'source')
            (stage/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in stage.iterdir() if p.name!='SHA256SUMS'))
            self.assertTrue(module.cached_sources(runtime,stage,'linux'))
            (runtime/'PACKAGES.txt').write_text('library:amd64 2.0\n')
            self.assertFalse(module.cached_sources(runtime,stage,'linux'))
            (runtime/'PACKAGES.txt').write_text('library:amd64 1.0\n')
            (stage/'library.tar.xz').write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'checksum mismatch'):module.cached_sources(runtime,stage,'linux')

    def test_homebrew_cache_requires_matching_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);runtime=root/'runtime';stage=root/'sources';(runtime/'licenses').mkdir(parents=True);stage.mkdir()
            inventory='library 1.0\n'
            (runtime/'licenses/HOMEBREW_PACKAGES.txt').write_text(inventory)
            (stage/'HOMEBREW_PACKAGES.txt').write_text(inventory)
            (stage/'SHA256SUMS').write_text(hashlib.sha256(inventory.encode()).hexdigest()+'  HOMEBREW_PACKAGES.txt\n')
            self.assertTrue(module.cached_sources(runtime,stage,'macos'))
            (runtime/'licenses/HOMEBREW_PACKAGES.txt').write_text('library 2.0\n')
            self.assertFalse(module.cached_sources(runtime,stage,'macos'))
