import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('release_packaging',Path(__file__).parents[1]/'packaging/release.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_tag_provenance_and_manifest_exclude_private_work_files(self):
        self.assertEqual(release.release_version('v0.2.0-rc'),'0.2.0-rc')
        for invalid in ['0.2.0','v0.2','v0.2.0/other','v0.2.0;command']:
            with self.assertRaises(ValueError):release.release_version(invalid)
        with patch.object(release,'output',side_effect=['tag-commit','different-head']):
            with self.assertRaises(ValueError):release.source('v0.2.0-rc')
        with patch.object(release,'output',side_effect=['commit','commit',' M tracked-source']):
            with self.assertRaises(ValueError):release.source('v0.2.0-rc')
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary);(folder/'installer.dmg').write_bytes(b'installer')
            (folder/'owner.keystore').write_text('not an artifact')
            (folder/'.work').mkdir();(folder/'.work/test-private-key').write_text('not an artifact')
            release.manifest(folder,'0.2.0-rc','commit','macos',True)
            release.manifest(folder,'0.2.0-rc','commit','macos',True)
            data=json.loads((folder/'release.json').read_text())
            self.assertEqual([f['name'] for f in data['files']],['installer.dmg'])
            self.assertEqual(data['files'][0]['sha256'],release.digest(folder/'installer.dmg'))
            self.assertEqual(data['commit'],'commit')
            self.assertTrue(data['dry_run'])
