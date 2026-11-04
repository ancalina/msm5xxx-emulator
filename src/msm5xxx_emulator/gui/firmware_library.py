"""Filesystem firmware library data; never starts an emulator."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Callable

from ..detection.firmware_image import (
    MAX_HEX_SOURCE_SIZE, MAX_HXB_SOURCE_SIZE, MAX_LOGICAL_IMAGE_SIZE,
)
from ..state_io import atomic_write_text


def source_size_limit(path: Path) -> int:
    suffix = path.suffix.casefold()
    if suffix == '.hex':
        return MAX_HEX_SOURCE_SIZE
    if suffix == '.hxb':
        return MAX_HXB_SOURCE_SIZE
    return MAX_LOGICAL_IMAGE_SIZE


def display_name(model: object, filename: str) -> str:
    return model.strip() if isinstance(model, str) and model.strip() else filename


def source_hash(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    maximum = source_size_limit(path) if limit is None else limit
    total = 0
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            total += len(chunk)
            if total > maximum:
                raise ValueError('library source exceeds size limit')
            digest.update(chunk)
    return digest.hexdigest()


def describe_file(path: Path, cache: dict, *, detector: Callable | None = None,
                  name: str | None = None) -> dict:
    """Describe one readable source, sharing the library's SHA-indexed cache."""
    size = path.stat().st_size
    maximum = source_size_limit(Path(name) if name else path)
    if not path.is_file() or size > maximum:
        raise ValueError('invalid library source')
    digest = source_hash(path, maximum)
    if digest not in cache:
        if detector is None:
            from ..detection.firmware import detect
            detector = detect
        try:
            config = detector(path)
            cache[digest] = {'model': getattr(config, 'model', None),
                             'chipset': getattr(config, 'chipset', None)}
        except (OSError, ValueError):
            cache[digest] = {'model': None, 'chipset': None}
    metadata = cache[digest]
    return {'sha256': digest, 'model': metadata.get('model'),
            'chipset': metadata.get('chipset'), 'size': size,
            'name': display_name(metadata.get('model'), name or path.name)}


class FirmwareLibrary:
    """JSON-backed folder and file references with SHA-indexed detection cache."""
    def __init__(self, path: Path, *, detector: Callable | None = None, private_root: Path | None = None):
        self.path = path
        self.detector = detector
        self.private_root = private_root.resolve() if private_root is not None else None
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('invalid library')
        except (OSError, ValueError):
            data = {}
        self.folders = [str(x) for x in data.get('folders', []) if isinstance(x, str)]
        self.entries = [x for x in data.get('entries', []) if isinstance(x, dict)]
        self.cache = data.get('cache', {}) if isinstance(data.get('cache'), dict) else {}
        self.excluded = [str(x) for x in data.get('excluded', []) if isinstance(x, str)]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, json.dumps({'schema': 1, 'folders': self.folders,
            'entries': self.entries, 'cache': self.cache, 'excluded': self.excluded},
            ensure_ascii=False, indent=2) + '\n')

    def add_folder(self, path: Path) -> None:
        folder = str(path.expanduser().resolve())
        if folder not in self.folders:
            self.folders.append(folder)
        self.save()

    def add_file(self, path: Path, *, imported: bool = False) -> None:
        name = str(path.expanduser().resolve())
        if name in self.excluded:
            self.excluded.remove(name)
        if not any(entry.get('path') == name for entry in self.entries):
            self.entries.append({'path': name, 'imported': imported})
        self.save()

    def remove(self, path: Path) -> None:
        name = str(path.expanduser().resolve())
        entry = next((item for item in self.entries if item.get('path') == name), None)
        if entry is None:
            return
        if entry.get('imported'):
            if self.private_root is None or not Path(name).is_relative_to(self.private_root):
                raise ValueError('private library path unavailable')
            Path(name).unlink(missing_ok=True)
        if name not in self.excluded:
            self.excluded.append(name)
        self.entries.remove(entry)
        self.save()

    def scan(self) -> list[dict]:
        known = {entry.get('path') for entry in self.entries}
        for folder in self.folders:
            try:
                children = list(Path(folder).iterdir())
            except OSError:
                continue
            for child in children:
                try:
                    if not child.is_file() or child.stat().st_size > source_size_limit(child):
                        continue
                    name = str(child.resolve())
                    if name not in known and name not in self.excluded:
                        self.entries.append({'path': name, 'imported': False})
                        known.add(name)
                except OSError:
                    continue
        seen: set[str] = set()
        result = []
        for entry in self.entries:
            path = Path(entry['path'])
            try:
                stat = path.stat()
                if not path.is_file() or stat.st_size > source_size_limit(path):
                    continue
                fingerprint = [stat.st_size, stat.st_mtime_ns]
                if entry.get('fingerprint') != fingerprint or not entry.get('sha256'):
                    entry['sha256'] = source_hash(path)
                    entry['fingerprint'] = fingerprint
                digest = entry['sha256']
                if digest in seen:
                    continue
                seen.add(digest)
                if digest not in self.cache:
                    described = describe_file(path, self.cache, detector=self.detector)
                    entry['sha256'] = described['sha256']
                entry.update(self.cache[entry['sha256']])
                entry['size'] = stat.st_size
                entry['available'] = True
            except (OSError, ValueError):
                if path.exists():
                    continue
                entry['available'] = False
            entry['name'] = display_name(entry.get('model'), path.name)
            result.append(dict(entry))
        self.save()
        return result
