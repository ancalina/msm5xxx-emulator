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
            (folder/'MSM5xxx-QEMU-macos-runtime-sources.tar.xz').write_bytes(b'corresponding sources')
            (folder/'private.tar.xz').write_bytes(b'not a release asset')
            (folder/'.work').mkdir();(folder/'.work/test-private-key').write_text('not an artifact')
            release.manifest(folder,'0.2.0-rc','commit','macos',True)
            release.manifest(folder,'0.2.0-rc','commit','macos',True)
            data=json.loads((folder/'release.json').read_text())
            self.assertEqual([f['name'] for f in data['files']],['MSM5xxx-QEMU-macos-runtime-sources.tar.xz','installer.dmg'])
            self.assertEqual(data['files'][1]['sha256'],release.digest(folder/'installer.dmg'))
            self.assertEqual(data['commit'],'commit')
            self.assertTrue(data['dry_run'])

    def test_windows_previous_packages_are_inputs_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)
            for name in ['previous-full.nupkg','current-full.nupkg','current-delta.nupkg','Setup.exe']:
                (folder/name).write_bytes(name.encode())
            (folder/'releases.win.json').write_text(json.dumps({'Assets':[
                {'Version':'0.1.99','FileName':'previous-full.nupkg'},
                {'Version':'0.2.0-rc','FileName':'current-full.nupkg'},
                {'Version':'0.2.0-rc','FileName':'current-delta.nupkg'}]}))
            release.manifest(folder,'0.2.0-rc','commit','windows',True)
            files={f['name'] for f in json.loads((folder/'release.json').read_text())['files']}
            self.assertNotIn('previous-full.nupkg',files)
            self.assertTrue((folder/'previous-full.nupkg').exists())
            self.assertIn('current-delta.nupkg',files)
            self.assertEqual(len(json.loads((folder/'releases.win.json').read_text())['Assets']),2)

    def test_source_companion_removes_named_and_compressed_firmware_without_changing_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'original';source.mkdir()
            (source/'COPYING').write_text('GPL');(source/'main.c').write_text('source')
            (source/'meson.build').write_text("subdir('tests')\nsubdir('tests/qtest/fuzz')\n")
            bios=source/'pc-bios';bios.mkdir()
            (bios/'meson.build').write_text("if unpack_edk2_blobs\nendif\nblobs = ['openbios-ppc','skiboot.lid','edk2-licenses.txt']\n")
            for name in ['openbios-ppc','skiboot.lid','edk2-aarch64-code.fd.bz2','edk2-licenses.txt']:(bios/name).write_bytes(b'blob')
            for name in ['.git','tests','roms','__pycache__']:
                (source/name).mkdir();(source/name/'payload').write_text('omitted')
            release.prepare_qemu_source(source,root/'staged')
            staged=root/'staged'
            self.assertTrue((bios/'openbios-ppc').exists())
            self.assertEqual((staged/'main.c').read_text(),'source')
            self.assertEqual(set(p.name for p in (staged/'pc-bios').iterdir()),{'meson.build','edk2-licenses.txt'})
            self.assertIn('if false',(staged/'pc-bios/meson.build').read_text())
            self.assertNotIn("subdir('tests",(staged/'meson.build').read_text())
            self.assertFalse((staged/'.git').exists())
            with self.assertRaises(ValueError):release.prepare_qemu_source(source,source/'nested')
            self.assertTrue((source/'COPYING').exists())
