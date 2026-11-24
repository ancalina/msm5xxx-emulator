"""Native release metadata, integrity and atomic AppImage replacement."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from msm5xxx_emulator import update


class UpdateTests(unittest.TestCase):
    def test_versions_and_invalid_metadata(self):
        versions = ['0.1.99', '0.2.0-rc.1', '0.2.0-rc.2', '0.2.0', '0.10.0']
        self.assertEqual(versions, sorted(versions, key=update.version_key))
        for value in ('../0.2.0', '0.02.0', '0.2.0-rc..1', '0.2.0-01', 'x', None):
            with self.subTest(value=value), self.assertRaises(update.UpdateError):
                update.version_key(value)
        self.assertEqual(update.version_key('v0.2.0+build.1'), update.version_key('0.2.0'))

    def test_local_feed_verified_apply_and_corruption_preserve_install_and_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = b'\x7fELF\x00\x00\x00\x00AI\x02old'
            new = b'\x7fELF\x00\x00\x00\x00AI\x02new'
            image = root / 'app.AppImage'; image.write_bytes(old); image.chmod(0o755)
            asset = root / 'release.AppImage'; asset.write_bytes(new)
            state = root / 'state'; state.mkdir()
            saved = state / 'saved-state'; saved.write_bytes(b'keep')
            feed = root / 'release.json'
            metadata = {'tag_name':'v0.2.0-rc', 'prerelease':True,
                        'html_url':f'https://github.com/{update.REPOSITORY}/releases/tag/v0.2.0-rc',
                        'assets':[{'name':'MSM5xxx-0.2.0-rc-linux-x86_64.AppImage',
                                   'browser_download_url':asset.as_uri(), 'size':len(new),
                                   'digest':'sha256:'+hashlib.sha256(new).hexdigest()}]}
            feed.write_text(json.dumps(metadata))
            with mock.patch.dict(os.environ, {'MSM5XXX_UPDATE_FEED':str(feed), 'APPIMAGE':str(image)}):
                release = update.check_for_update('0.1.99')
                self.assertEqual(release['version'], '0.2.0-rc')
                self.assertIsNone(update.check_for_update('0.2.0'))
                update.prepare_update(release, state)
                (state/'updates/pending.AppImage').write_bytes(b'bad')
                with self.assertRaises(update.UpdateError): update.apply_prepared_update(state)
                self.assertEqual(image.read_bytes(), old)
                update.prepare_update(release, state)
                with mock.patch.object(update.subprocess, 'Popen') as restart:
                    update.apply_prepared_update(state)
                    self.assertTrue(restart.call_args.kwargs['start_new_session'])
                self.assertEqual(image.read_bytes(), new)
                self.assertEqual((root/'app.AppImage.old').read_bytes(), old)
                self.assertEqual(image.stat().st_mode & 0o777, 0o755)
                self.assertEqual(saved.read_bytes(), b'keep')
                metadata['assets'][0]['digest']='sha256:'+'0'*64
                feed.write_text(json.dumps(metadata))
                with self.assertRaises(update.UpdateError):
                    update.prepare_update(update.check_for_update('0.1.99'), state)
                self.assertEqual(image.read_bytes(), new)
                metadata['html_url']='https://example.com/redirect'
                feed.write_text(json.dumps(metadata))
                with self.assertRaises(update.UpdateError): update.check_for_update('0.1.99')


if __name__ == '__main__':
    unittest.main()
