from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import shutil

from ..diagnostics.runtime_log import current_session_log
from ..state_io import atomic_write_text

LOGGER = logging.getLogger("gui")


def firmware_telemetry(config: object) -> dict[str, object]:
    """Return identity safe to put in a shared user log."""
    identity = config.firmware_identity()  # type: ignore[attr-defined]
    digest = identity.get("sha256") if isinstance(identity, dict) else identity
    return {
        "basename": Path(config.path).name,  # type: ignore[attr-defined]
        "bytes": config.file_size,  # type: ignore[attr-defined]
        "sha256": digest,
    }


def _safe_log_name(value: str) -> str:
    return "".join(character if character.isalnum() or character in "-_."
                   else "_" for character in value)[:48] or "firmware"


def _diagnostic_session_log() -> Path | None:
    session = current_session_log()
    if session is not None:
        return session
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            return Path(handler.baseFilename)
    return None


def _diagnostic_directory() -> Path:
    session = _diagnostic_session_log()
    return (session.parent if session is not None
            else Path(__file__).resolve().parent / "logs")


def _diagnostic_session_token() -> str:
    session = _diagnostic_session_log()
    return _safe_log_name(session.stem) if session is not None else "session"


def _repro_state_files(emulator: object) -> tuple[tuple[str, Path, bool], ...]:
    """Use actual lazily-resolved sidecars; only NOR/EEPROM snapshots copy."""
    files: list[tuple[str, Path, bool]] = []
    primary = getattr(getattr(emulator, "flash", None), "state_path", None)
    if isinstance(primary, Path):
        files.append(("primary-flash-state", primary, True))
    secondary = getattr(getattr(emulator, "secondary_flash", None), "state_path", None)
    if isinstance(secondary, Path):
        files.append(("secondary-flash-state", secondary, True))
    eeprom = getattr(emulator, "eeprom_state_path", None)
    if getattr(emulator, "eeprom_enabled", False) and isinstance(eeprom, Path):
        files.append(("eeprom-state", eeprom, True))
    nand = getattr(emulator, "nand_state_path", None)
    if (getattr(getattr(emulator, "config", None), "nand_enabled", False)
            and isinstance(nand, Path)):
        # NAND backing can be 256 MiB. Keep an identity manifest, not a copy.
        files.extend((
            ("nand-state", nand, False),
            ("nand-metadata", Path(str(nand).removesuffix(".bin") + ".json"), False),
        ))
    return tuple(files)


def _file_hash_size(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _capture_repro_state(emulator: object, directory: Path,
                         phase: str) -> list[dict[str, object]]:
    """Copy existing NOR/EEPROM sidecars and identify every known state sidecar."""
    directory.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, object]] = []
    for index, (role, source, copy_allowed) in enumerate(_repro_state_files(emulator)):
        entry: dict[str, object] = {"role": role, "exists": source.is_file()}
        if not source.is_file():
            manifest.append(entry)
            continue
        target: Path | None = None
        try:
            size, digest = _file_hash_size(source)
            entry.update({"bytes": size, "sha256": digest})
            if copy_allowed:
                target = directory / f"{index:02d}-{role}"
                try:
                    shutil.copyfile(source, target)
                except OSError:
                    target.unlink(missing_ok=True)
                    raise
                snapshot_size, snapshot_digest = _file_hash_size(target)
                entry["snapshot"] = {
                    "file": f"{phase}/{target.name}",
                    "bytes": snapshot_size,
                    "sha256": snapshot_digest,
                }
        except OSError as error:
            entry["error"] = type(error).__name__
        manifest.append(entry)
    return manifest


def _repro_document(config: object, overrides: dict[str, object], generation: int,
                    pre: list[dict[str, object]],
                    post: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "schema": 1,
        "generation": generation,
        "firmware": firmware_telemetry(config),
        "resolved_config": config.diagnostic_config(),  # type: ignore[attr-defined]
        "override_keys": sorted(str(name) for name in overrides),
        "state_files": {"pre": pre, "post": post},
    }


def _new_repro_directory(generation: int) -> Path:
    root = _diagnostic_directory()
    root.mkdir(parents=True, exist_ok=True)
    stem = f"repro-{_diagnostic_session_token()}-g{generation}"
    for suffix in range(10_000):
        directory = root / (stem if suffix == 0 else f"{stem}-{suffix}")
        try:
            directory.mkdir()
            return directory
        except FileExistsError:
            continue
    raise OSError("diagnostic repro filename space exhausted")


def create_repro_bundle(config: object, emulator: object, overrides: dict[str, object],
                        generation: int) -> tuple[Path, list[dict[str, object]]] | None:
    """Capture terminal run-start sidecars immediately before close."""
    try:
        directory = _new_repro_directory(generation)
        pre = _capture_repro_state(emulator, directory / "pre", "pre")
        atomic_write_text(
            directory / "metadata.json",
            json.dumps(_repro_document(config, overrides, generation, pre),
                       ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )
        return directory, pre
    except (OSError, TypeError, ValueError) as error:
        LOGGER.warning("diagnostic repro pre-run failed generation=%d error=%s",
                       generation, type(error).__name__)
        return None


def finish_repro_bundle(bundle: tuple[Path, list[dict[str, object]]], config: object,
                        emulator: object, overrides: dict[str, object],
                        generation: int) -> None:
    """Capture actual post-close NOR/EEPROM state; failure never changes emulation."""
    directory, pre = bundle
    try:
        post = _capture_repro_state(emulator, directory / "post", "post")
        atomic_write_text(
            directory / "metadata.json",
            json.dumps(_repro_document(config, overrides, generation, pre, post),
                       ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )
    except (OSError, TypeError, ValueError) as error:
        LOGGER.warning("diagnostic repro post-run failed generation=%d error=%s",
                       generation, type(error).__name__)
