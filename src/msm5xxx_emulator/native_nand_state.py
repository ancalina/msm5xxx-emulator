"""Atomic full-raw NAND records; callers hold the existing state-family lock.

The fixed geometry is a virtual address policy, not a physical chip identity.
Only the caller can qualify a native session's raw bytes for saving.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import zlib

from .state_io import atomic_write_bytes


RAW_BYTES = 65536 * 528
_MAX_RECORD_BYTES = 48 * 1024 * 1024
_SCHEMA = 'msm5xxx-timed-nand-v1'
_GEOMETRY = (65536, 512, 16, 32, 2)
_FIELDS = {'schema', 'geometry', 'firmware_sha256', 'seed_sha256',
           'raw_sha256', 'raw_b64_zlib'}


def _valid_hash(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value))


def _unique_fields(pairs: list[tuple]) -> dict:
    record = {}
    for key, value in pairs:
        if key in record:
            raise ValueError('duplicate NAND state field')
        record[key] = value
    return record


def load_state(path: Path, firmware_sha256: str, seed_sha256: str) -> bytes | None:
    """Return a qualified raw record, or None only when the path is missing."""
    if not all(_valid_hash(value) for value in (firmware_sha256, seed_sha256)):
        raise ValueError('invalid NAND state identity hash')
    try:
        with path.open('rb') as source:
            encoded = source.read(_MAX_RECORD_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(encoded) > _MAX_RECORD_BYTES:
        raise ValueError('NAND state record exceeds size limit')
    try:
        record = json.loads(encoded.decode('utf-8'), object_pairs_hook=_unique_fields)
    except RecursionError as error:
        raise ValueError('invalid NAND state JSON nesting') from error
    if type(record) is not dict or set(record) != _FIELDS or record['schema'] != _SCHEMA:
        raise ValueError('incompatible NAND state record')
    geometry = record['geometry']
    if (type(geometry) is not list or not all(type(value) is int for value in geometry)
            or tuple(geometry) != _GEOMETRY):
        raise ValueError('incompatible NAND state geometry')
    if (not all(_valid_hash(record[key]) for key in
                ('firmware_sha256', 'seed_sha256', 'raw_sha256'))
            or record['firmware_sha256'] != firmware_sha256
            or record['seed_sha256'] != seed_sha256):
        raise ValueError('NAND state identity mismatch')
    if type(record['raw_b64_zlib']) is not str:
        raise ValueError('invalid NAND state payload type')
    payload = base64.b64decode(record['raw_b64_zlib'], validate=True)
    decoder = zlib.decompressobj()
    try:
        raw = decoder.decompress(payload, RAW_BYTES + 1)
    except zlib.error as error:
        raise ValueError('invalid NAND state compression') from error
    if (len(raw) != RAW_BYTES or not decoder.eof or decoder.unused_data
            or decoder.unconsumed_tail
            or hashlib.sha256(raw).hexdigest() != record['raw_sha256']):
        raise ValueError('invalid NAND state raw payload')
    return raw


def save_state(path: Path, raw: bytes, firmware_sha256: str, seed_sha256: str) -> None:
    """Atomically replace one complete record after validating caller inputs."""
    if type(raw) is not bytes or len(raw) != RAW_BYTES:
        raise ValueError('NAND state requires an exact full-raw image')
    if not all(_valid_hash(value) for value in (firmware_sha256, seed_sha256)):
        raise ValueError('invalid NAND state identity hash')
    record = {
        'schema': _SCHEMA, 'geometry': list(_GEOMETRY),
        'firmware_sha256': firmware_sha256, 'seed_sha256': seed_sha256,
        'raw_sha256': hashlib.sha256(raw).hexdigest(),
        'raw_b64_zlib': base64.b64encode(zlib.compress(raw)).decode('ascii'),
    }
    encoded = (json.dumps(record, separators=(',', ':')) + '\n').encode('utf-8')
    if len(encoded) > _MAX_RECORD_BYTES:
        raise ValueError('NAND state record exceeds size limit')
    atomic_write_bytes(path, encoded)
