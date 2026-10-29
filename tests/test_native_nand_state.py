"""Qualified full-raw codec fixtures; no firmware corpus or native guest."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

from msm5xxx_emulator.qemu import nand_state as state


class NativeNandStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blank = b'\xff' * state.RAW_BYTES
        raw = bytearray(cls.blank)
        raw[:4] = bytes.fromhex('3412cdab')
        raw[512:516] = bytes.fromhex('00ff5aa5')
        raw[528 + 512:528 + 516] = bytes.fromhex('ff00a55a')
        raw[-2:] = bytes.fromhex('7856')
        cls.programmed = bytes(raw)
        cls.firmware_hash = hashlib.sha256(b'own firmware fixture').hexdigest()
        cls.seed_hash = hashlib.sha256(cls.blank).hexdigest()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'nand.state'

    def record(self):
        state.save_state(self.path, self.blank, self.firmware_hash, self.seed_hash)
        return json.loads(self.path.read_bytes())

    def write_record(self, record):
        self.path.write_text(json.dumps(record), encoding='utf-8')

    def load(self):
        return state.load_state(self.path, self.firmware_hash, self.seed_hash)

    def test_missing_only_returns_none(self):
        self.assertIsNone(self.load())
        self.path.write_bytes(b'')
        with self.assertRaises(ValueError):
            self.load()
        with self.assertRaises(ValueError):
            state.load_state(self.path, 'invalid', self.seed_hash)

    def test_blank_and_programmed_main_oob_roundtrip(self):
        for raw in (self.blank, self.programmed):
            with self.subTest(raw_sha256=hashlib.sha256(raw).hexdigest()):
                state.save_state(self.path, raw, self.firmware_hash, self.seed_hash)
                self.assertEqual(self.load(), raw)
        record = json.loads(self.path.read_bytes())
        self.assertEqual(record['geometry'], [65536, 512, 16, 32, 2])
        self.assertEqual(record['schema'], 'msm5xxx-timed-nand-v1')

    def test_programmed_state_reloads_in_new_process(self):
        state.save_state(self.path, self.programmed, self.firmware_hash, self.seed_hash)
        code = (
            'import hashlib,sys;sys.path.insert(0,sys.argv[1]);'
            'from pathlib import Path;'
            'from msm5xxx_emulator.qemu.nand_state import load_state;'
            'raw=load_state(Path(sys.argv[2]),sys.argv[3],sys.argv[4]);'
            'assert hashlib.sha256(raw).hexdigest()==sys.argv[5]'
        )
        subprocess.run([sys.executable, '-B', '-c', code,
                        str(Path(state.__file__).resolve().parents[1]), str(self.path),
                        self.firmware_hash, self.seed_hash,
                        hashlib.sha256(self.programmed).hexdigest()],
                       check=True, timeout=30, capture_output=True)

    def test_wrong_identity_and_strict_hash_fields(self):
        original = self.record()
        for field in ('firmware_sha256', 'seed_sha256', 'raw_sha256'):
            for invalid in ('0' * 64, 'X' * 64, None, 1):
                record = dict(original)
                record[field] = invalid
                self.write_record(record)
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    self.load()
        self.write_record(original)
        for firmware, seed in (('0' * 64, self.seed_hash), (self.firmware_hash, '0' * 64)):
            with self.assertRaises(ValueError):
                state.load_state(self.path, firmware, seed)

    def test_wrong_geometry_schema_and_field_types(self):
        original = self.record()
        for field, value in (
                ('geometry', [65536, 512, 16, 64, 2]),
                ('geometry', [65536.0, 512, 16, 32, 2]),
                ('geometry', '65536:512:16:32:2'),
                ('schema', 'unknown'), ('schema', None),
                ('raw_b64_zlib', []), ('raw_b64_zlib', {})):
            record = dict(original)
            record[field] = value
            self.write_record(record)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.load()
        for record in ([], None, {**original, 'extra': 1}):
            self.write_record(record)
            with self.assertRaises(ValueError):
                self.load()

    def test_duplicate_fields_and_trailing_json_reject(self):
        original = self.record()
        encoded = json.dumps(original)
        for malformed in ('{"schema":"wrong",' + encoded[1:], encoded + '{}', encoded[:-1],
                          '[' * 2000 + '0' + ']' * 2000):
            self.path.write_text(malformed, encoding='utf-8')
            with self.assertRaises(ValueError):
                self.load()

    def test_base64_zlib_truncation_checksum_and_trailing_stream_reject(self):
        original = self.record()
        compressed = base64.b64decode(original['raw_b64_zlib'])
        corrupt = bytearray(compressed)
        corrupt[-1] ^= 1
        for payload in (b'not zlib', compressed[:-1], bytes(corrupt), compressed + b'x',
                        compressed + zlib.compress(b'extra'), zlib.compress(b'')):
            record = dict(original)
            record['raw_b64_zlib'] = base64.b64encode(payload).decode('ascii')
            self.write_record(record)
            with self.subTest(payload_size=len(payload)), self.assertRaises(ValueError):
                self.load()
        for invalid in ('!', original['raw_b64_zlib'] + '\n', '\u2603'):
            record = dict(original)
            record['raw_b64_zlib'] = invalid
            self.write_record(record)
            with self.assertRaises(ValueError):
                self.load()

    def test_oversized_decompressed_payload_rejects(self):
        record = self.record()
        compressor = zlib.compressobj()
        chunk = b'\xff' * (1024 * 1024)
        compressed = b''.join(compressor.compress(chunk) for _ in range(64)) + compressor.flush()
        record['raw_b64_zlib'] = base64.b64encode(compressed).decode('ascii')
        self.write_record(record)
        with self.assertRaises(ValueError):
            self.load()

    def test_oversized_record_rejects_before_parsing(self):
        with self.path.open('wb') as output:
            output.truncate(48 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            self.load()

    def test_save_rejects_invalid_inputs_before_atomic_writer(self):
        with patch.object(state, 'atomic_write_bytes') as write:
            for raw, firmware, seed in (
                    (b'', self.firmware_hash, self.seed_hash),
                    (self.blank[:-1], self.firmware_hash, self.seed_hash),
                    (bytearray(self.blank), self.firmware_hash, self.seed_hash),
                    (self.blank, 'invalid', self.seed_hash),
                    (self.blank, self.firmware_hash, None)):
                with self.assertRaises(ValueError):
                    state.save_state(self.path, raw, firmware, seed)
            write.assert_not_called()

    def test_failed_replace_preserves_last_good_record_and_seed(self):
        state.save_state(self.path, self.blank, self.firmware_hash, self.seed_hash)
        previous = self.path.read_bytes()
        seed = self.path.with_name('seed.raw')
        seed.write_bytes(self.blank)
        with patch('msm5xxx_emulator.state_io.os.replace', side_effect=OSError('own pre-replace failure')):
            with self.assertRaises(OSError):
                state.save_state(self.path, self.programmed, self.firmware_hash, self.seed_hash)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.load(), self.blank)
        self.assertEqual(hashlib.sha256(seed.read_bytes()).hexdigest(), self.seed_hash)
        self.assertEqual(list(self.path.parent.glob('.*.tmp')), [])


if __name__ == '__main__':
    unittest.main()
