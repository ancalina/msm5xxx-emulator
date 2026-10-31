from __future__ import annotations

import hashlib
from pathlib import Path


def _prepared_profile_matches(
        prepared: tuple[object, dict[str, object]] | None,
        firmware: Path, overrides: dict[str, object]) -> bool:
    """Reuse settings detection only while the source identity is unchanged."""
    if (prepared is None or prepared[1] != overrides
            or Path(getattr(prepared[0], "path", "")).resolve()
            != firmware.resolve()):
        return False
    try:
        if firmware.stat().st_size != getattr(prepared[0], "file_size", None):
            return False
        digest = hashlib.sha256()
        with firmware.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return False
    return digest.hexdigest() == getattr(
        prepared[0], "firmware_sha256", None
    )
