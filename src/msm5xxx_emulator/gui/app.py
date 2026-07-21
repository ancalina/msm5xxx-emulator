#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import locale
import logging
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

from ..probe.boot import boot_event, boot_phase, visible_pixels
from ..core.emulator import (BUILD_CODENAME, DEFAULT_STATE_ROOT,
                             DISABLEABLE_ADDRESS_FIELDS, GenericMSMEmulator,
                             HostBackendFault, MAX_FLASH_SIZE,
                             MAX_NAND_BACKING_SIZE, MAX_NAND_DATA_SIZE,
                             MAX_RAM_SIZE, PAGE, detect)
from ..state_io import atomic_write_text, exclusive_path_lock
from ..diagnostics.runtime_log import (current_session_log, install_runtime_logging,
                                       record_diagnostic, record_exception)
from ..update import (UpdateError, UpdateInfo, application_root, check_for_update,
                      prepare_update, remember_update, updated_gui_command)


LOGGER = logging.getLogger("gui")


STATE_ROOT = DEFAULT_STATE_ROOT
LAST_CONFIG = STATE_ROOT / "last_config.json"
GUI_ZERO_DISABLE_FIELDS = DISABLEABLE_ADDRESS_FIELDS | {
    "audio_play_address", "fast_boot_address",
}
TELEMETRY_INSTRUCTION_CADENCE = 1_000_000
TELEMETRY_SCREENSHOT_CADENCE = 5_000_000
TELEMETRY_SCREENSHOT_CAP = 32


def frame_repaint_needed(
        cache: tuple[object, bytes, int, int, int, int] | None,
        emulator: object, frame: bytes, frame_width: int, frame_height: int,
        canvas_width: int, canvas_height: int) -> bool:
    """Avoid rebuilding Pillow/Tk objects for an immutable displayed frame."""
    return (cache is None or cache[0] is not emulator or cache[1] is not frame
            or cache[2:] != (frame_width, frame_height, canvas_width, canvas_height))


KEYS = {
    "메뉴": 0, "▲": 1, "취소": 2, "통화": 3, "◀": 4,
    "OK": 5, "▶": 6, "종료": 7, "볼륨-": 8, "▼": 9,
    "볼륨+": 10, "1": 11, "2": 12, "3": 13, "4": 14, "5": 15,
    "6": 16, "7": 17, "8": 18, "9": 19, "*": 20, "0": 21, "#": 22,
}
LAYOUT = (
    ("메뉴", 0, 1), ("취소", 0, 3),
    ("볼륨+", 1, 0), ("▲", 1, 2),
    ("볼륨-", 2, 0), ("◀", 2, 1), ("OK", 2, 2), ("▶", 2, 3),
    ("▼", 3, 2), ("통화", 4, 1), ("종료", 4, 3),
    ("1", 5, 1), ("2", 5, 2), ("3", 5, 3),
    ("4", 6, 1), ("5", 6, 2), ("6", 6, 3),
    ("7", 7, 1), ("8", 7, 2), ("9", 7, 3),
    ("*", 8, 1), ("0", 8, 2), ("#", 8, 3),
)

UI_LANGUAGE_CHOICES = ("auto", "ko", "en")
UI_TEXT = {
    "ko": {
        "window_title": "MSM5XXX Emulator",
        "ready": "준비", "detecting": "자동 탐지 중", "settings": "설정",
        "capture": "캡처", "restarting": "재부팅 중", "boot_settings": "부팅 설정",
        "ui_language": "UI 언어", "choose_file": "파일 선택…",
        "choose_firmware": "펌웨어 파일 선택", "apply": "적용 (필요 시 재부팅)",
        "save_failed": "저장 실패", "settings_error": "설정 오류",
        "settings_save_error": "설정 저장 오류",
    },
    "en": {
        "window_title": "MSM5XXX Emulator",
        "ready": "Ready", "detecting": "Detecting automatically", "settings": "Settings",
        "capture": "Capture", "restarting": "Restarting", "boot_settings": "Boot Settings",
        "ui_language": "UI Language", "choose_file": "Choose File…",
        "choose_firmware": "Choose Firmware", "apply": "Apply (restart if needed)",
        "save_failed": "Save Failed", "settings_error": "Settings Error",
        "settings_save_error": "Settings Save Error",
    },
}
KEY_TEXT = {
    "ko": {},
    "en": {"메뉴": "Menu", "취소": "Cancel", "통화": "Call", "종료": "End",
           "볼륨-": "Vol-", "볼륨+": "Vol+"},
}
SETTINGS_ENGLISH = {
    "기본": "Basic", "메모리": "Memory", "화면 버퍼": "Display Buffer",
    "하드웨어": "Hardware", "함수": "Functions", "부팅 HLE": "Boot HLE",
    "저장": "Storage", "펌웨어": "Firmware", "모델": "Model", "칩셋": "Chipset",
    "화면 너비": "Screen Width", "화면 높이": "Screen Height",
    "Board revision 이름": "Board Revision Name", "이미지 오프셋": "Image Offset",
    "로드 주소": "Load Address", "Flash 크기": "Flash Size", "RAM 시작 주소": "RAM Base",
    "RAM 크기": "RAM Size", "RAM image 오프셋": "RAM Image Offset",
    "RAM image 크기 (0=끔)": "RAM Image Size (0=off)", "진입점 오프셋": "Entry Offset",
    "Framebuffer 주소 (빈 값=끔)": "Framebuffer Address (empty=off)",
    "Row flush 함수": "Row Flush Function", "Rect flush 함수": "Rect Flush Function",
    "Board revision 레지스터": "Board Revision Register", "Board revision 값": "Board Revision Value",
    "키 레지스터": "Key Register", "키 active-low": "Key Active-Low",
    "Audio play 함수": "Audio Play Function", "Fast boot 함수": "Fast Boot Function",
    "Delay 함수": "Delay Function", "Busy delay 함수": "Busy Delay Function",
    "CRC16 함수": "CRC16 Function", "NAND bad-block 함수": "NAND Bad-Block Function",
    "NAND read 함수": "NAND Read Function", "NAND write 함수": "NAND Write Function",
    "REX idle 함수": "REX Idle Function", "REX tick 함수": "REX Tick Function",
    "REX tick 밀리초": "REX Tick Milliseconds", "Board ADC 함수": "Board ADC Function",
    "Board ADC 값": "Board ADC Value", "Flash ID 함수": "Flash ID Function",
    "Flash ID 값": "Flash ID Value", "DMD download 함수": "DMD Download Function",
    "NOR probe 함수": "NOR Probe Function", "보조 NOR 주소 (0=끔)": "Secondary NOR Address (0=off)",
    "보조 NOR 크기": "Secondary NOR Size", "보조 NOR image": "Secondary NOR Image",
    "보조 NOR state": "Secondary NOR State", "보조 NOR read 함수": "Secondary NOR Read Function",
    "보조 NOR write 함수": "Secondary NOR Write Function",
    "Legacy EFS page read 함수": "Legacy EFS Page Read Function", "NAND 사용": "Enable NAND",
    "NAND data 크기": "NAND Data Size", "NAND page 크기": "NAND Page Size",
    "NAND spare 크기": "NAND Spare Size", "NAND block당 pages": "NAND Pages per Block",
}


def normalize_ui_language(value: object) -> str:
    return value if isinstance(value, str) and value in UI_LANGUAGE_CHOICES else "auto"


def system_ui_language(locale_name: str | None = None) -> str:
    if locale_name is None:
        locale_name = os.environ.get("LC_ALL") or next(
            (os.environ[name] for name in ("LC_MESSAGES", "LANGUAGE", "LANG")
             if os.environ.get(name)), None
        )
    if locale_name is None:
        try:
            category = getattr(locale, "LC_MESSAGES", locale.LC_CTYPE)
            locale_name = locale.getlocale(category)[0] or locale.getlocale()[0]
        except ValueError:
            locale_name = None
    normalized = (locale_name or "").lower()
    return "ko" if normalized.startswith("ko") or "korean" in normalized else "en"


def resolve_ui_language(preference: object, locale_name: str | None = None) -> str:
    preference = normalize_ui_language(preference)
    return system_ui_language(locale_name) if preference == "auto" else preference


def runtime_status_text(latest: dict[str, object], ui_language: str) -> str:
    english = ui_language == "en"
    parts = [
        f"{'Run' if english else '실행'} {latest['instructions']:,}",
        f"PC {latest.get('pc', '?')}",
        f"LCD {int(latest.get('lcd_writes', 0)):,}",
        f"frame {latest.get('frame_sequence', 0)}",
    ]
    audio_requests = int(latest.get("audio_play_requests", 0))
    audio_backend = str(latest.get("audio_backend", ""))
    if audio_requests:
        parts.append(f"{'Audio' if english else '오디오'} {audio_requests}")
    elif audio_backend in ("disabled", "render-only"):
        parts.append("Audio unavailable" if english else "오디오 재생기 없음")
    if latest.get("audio_error"):
        parts.append(f"{'Audio error' if english else '오디오 오류'}: {latest['audio_error']}")
    if latest.get("input_error"):
        parts.append(f"{'Input error' if english else '입력 오류'}: {latest['input_error']}")
    return "\n".join(parts)

def merge_settings_overrides(current: dict[str, object], edited: set[str],
                             parsed: dict[str, object],
                             firmware_changed: bool) -> dict[str, object]:
    """Keep prior manual values for one firmware; a new dump starts clean."""
    merged = {} if firmware_changed else dict(current)
    for name in edited:
        value = parsed[name]
        if value is None and name in GUI_ZERO_DISABLE_FIELDS:
            merged[name] = 0
        elif value is None:
            merged.pop(name, None)
        else:
            merged[name] = value
    return merged


def can_apply_live_framebuffer_format(edited: set[str], firmware_changed: bool,
                                      framebuffer_address: int | None,
                                      framebuffer_format: str,
                                      worker_active: bool = True) -> bool:
    """Allow the colour-map-only setting to update a running framebuffer."""
    return (worker_active and not firmware_changed and edited == {"framebuffer_format"}
            and framebuffer_address is not None
            and framebuffer_format != "none")


def firmware_telemetry(config: object) -> dict[str, object]:
    """Return identity safe to put in a shared user log."""
    identity = config.firmware_identity()  # type: ignore[attr-defined]
    digest = identity.get("sha256") if isinstance(identity, dict) else identity
    return {
        "basename": Path(config.path).name,  # type: ignore[attr-defined]
        "bytes": config.file_size,  # type: ignore[attr-defined]
        "sha256": digest,
    }


def _frame_metrics(frame: bytes, previous_frame: bytes, previous_hash: str,
                   previous_nonblack: int) -> tuple[str, int]:
    """Reuse metrics for the immutable frame returned between publishes."""
    if frame is previous_frame:
        return previous_hash, previous_nonblack
    return hashlib.sha256(frame).hexdigest(), visible_pixels(frame)


def _counter(state: dict[str, object], name: str) -> int:
    value = state.get(name, 0)
    return value if isinstance(value, int) else 0


def _mapping(state: dict[str, object], name: str) -> dict[str, object]:
    value = state.get(name)
    return dict(value) if isinstance(value, dict) else {}


def _phase_state(state: dict[str, object]) -> dict[str, object]:
    """Supply boot-probe's small evidence vocabulary, even on host faults."""
    return {
        "fault": state.get("fault"),
        "frame_sequence": _counter(state, "frame_sequence"),
        "firmware_frame_sequence": _counter(state, "firmware_frame_sequence"),
        "rex_ticks": _counter(state, "rex_ticks"),
        "secondary_flash_reads": _counter(state, "secondary_flash_reads"),
        "secondary_flash_writes": _counter(state, "secondary_flash_writes"),
        "secondary_flash_changed_pages": _counter(
            state, "secondary_flash_changed_pages"
        ),
        "secondary_flash_telemetry": _mapping(state, "secondary_flash_telemetry"),
        "nand_reads": _counter(state, "nand_reads"),
        "nand_writes": _counter(state, "nand_writes"),
        "lcd_writes": _counter(state, "lcd_writes"),
        "control_sink": state.get("control_sink"),
    }


def telemetry_transition(state: dict[str, object], nonblack: int, frame_hash: str,
                         reset_hash: str, previous_hash: str, saw_splash: bool,
                         last_phase: str | None, last_event: str | None,
                         last_instructions: int) -> tuple[str, str, bool, bool]:
    """Return phase/event and whether this state merits one diagnostic line."""
    phase_state = _phase_state(state)
    phase = boot_phase(phase_state, nonblack)
    event, saw_splash = boot_event(
        phase_state, nonblack, frame_hash, reset_hash, previous_hash, saw_splash,
    )
    due = _counter(state, "instructions") >= (
        last_instructions + TELEMETRY_INSTRUCTION_CADENCE
    )
    emit = (phase != last_phase or event != last_event
            or bool(state.get("fault")) or due)
    return phase, event, saw_splash, emit


def telemetry_artifact_due(*, transitioned: bool, terminal: bool,
                            instructions: int,
                            last_screenshot_instructions: int) -> bool:
    """Keep 1M checkpoints in the session log without writing artifact files."""
    return (transitioned or terminal or instructions >= (
        last_screenshot_instructions + TELEMETRY_SCREENSHOT_CADENCE
    ))


def runtime_telemetry(config: object, state: dict[str, object], *, generation: int,
                      phase: str, event: str, width: int, height: int,
                      frame: bytes, nonblack: int,
                      screenshot: str | None = None) -> dict[str, object]:
    """Keep periodic GUI evidence compact and free of local firmware paths."""
    registers = _mapping(state, "registers")
    payload: dict[str, object] = {
        "generation": generation,
        "firmware": firmware_telemetry(config),
        "model": config.model,  # type: ignore[attr-defined]
        "chipset": config.chipset,  # type: ignore[attr-defined]
        "dump_status": config.dump_status,  # type: ignore[attr-defined]
        "instructions": _counter(state, "instructions"),
        "pc": state.get("pc", registers.get("pc")),
        "lr": state.get("lr", registers.get("lr")),
        "cpsr": registers.get("cpsr"),
        "phase": phase,
        "event": event,
        "frame": {
            "width": width,
            "height": height,
            "sha256": hashlib.sha256(frame).hexdigest(),
            "nonblack_pixels": nonblack,
            "sequence": _counter(state, "frame_sequence"),
            "firmware_sequence": _counter(state, "firmware_frame_sequence"),
        },
        "lcd": {
            "writes": _counter(state, "lcd_writes"),
            "protocol": state.get("lcd_protocol"),
            "frame_protocol": state.get("lcd_frame_protocol"),
        },
        "rex": {
            "idle_entries": _counter(state, "rex_idle_entries"),
            "ticks": _counter(state, "rex_ticks"),
            "elapsed_ms": _counter(state, "rex_elapsed_ms"),
            "irq_deliveries": _counter(state, "rex_irq_deliveries"),
        },
        "nor": {
            "primary": _mapping(state, "primary_flash_telemetry"),
            "secondary_reads": _counter(state, "secondary_flash_reads"),
            "secondary_writes": _counter(state, "secondary_flash_writes"),
            "secondary_changed_pages": _counter(
                state, "secondary_flash_changed_pages"
            ),
            "secondary": _mapping(state, "secondary_flash_telemetry"),
        },
        "eeprom": {
            "capacity": _counter(state, "eeprom_capacity"),
            "reads": _counter(state, "eeprom_reads"),
            "read_bytes": _counter(state, "eeprom_read_bytes"),
            "writes": _counter(state, "eeprom_writes"),
            "write_bytes": _counter(state, "eeprom_write_bytes"),
            "changed_bytes": _counter(state, "eeprom_changed_bytes"),
            "loaded_from_state": bool(state.get("eeprom_loaded_from_state")),
            "error": state.get("eeprom_error"),
        },
        "nand": {
            "reads": _counter(state, "nand_reads"),
            "writes": _counter(state, "nand_writes"),
            "bad_block_probes": _counter(state, "nand_bad_block_probes"),
        },
        "control_sink": state.get("control_sink"),
        "last_unmapped": _mapping(state, "last_unmapped"),
        "unmapped_accesses": state.get("unmapped_accesses", []),
        "dynamic_page_first_accesses": state.get("dynamic_page_first_accesses", []),
        "fault": state.get("fault"),
        "fault_context": _mapping(state, "fault_context"),
    }
    if screenshot is not None:
        payload["screenshot"] = screenshot
    return payload


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


def hydrate_host_checkpoint(state: dict[str, object]) -> dict[str, object]:
    """Promote pre-call checkpoint counters into outer host-fault telemetry."""
    hydrated = dict(state)
    counters = _mapping(hydrated, "counters")
    display = _mapping(hydrated, "display")
    storage = _mapping(counters, "storage")

    def promote(target: str, source: dict[str, object], name: str = "") -> None:
        value = source.get(name or target)
        if isinstance(value, int) and (not isinstance(hydrated.get(target), int)
                                       or hydrated.get(target) == 0):
            hydrated[target] = value

    for name in ("lcd_writes", "rex_idle_entries", "rex_ticks", "rex_elapsed_ms"):
        promote(name, counters)
    for name in ("frame_sequence", "firmware_frame_sequence"):
        promote(name, display)
    for target, source in (
            ("eeprom_reads", "eeprom_reads"),
            ("eeprom_writes", "eeprom_writes"),
            ("eeprom_changed_bytes", "eeprom_changed_bytes"),
            ("secondary_flash_reads", "secondary_nor_reads"),
            ("secondary_flash_writes", "secondary_nor_writes"),
            ("secondary_flash_changed_pages", "secondary_nor_changed_pages"),
            ("nand_reads", "nand_reads"),
            ("nand_writes", "nand_writes"),
    ):
        promote(target, storage, source)
    return hydrated


def save_telemetry_frame(config: object, *, generation: int,
                         instructions: int, phase: str, capture: int,
                         width: int, height: int, frame: bytes) -> str | None:
    """Save one immutable display snapshot beside current session log."""
    try:
        directory = _diagnostic_directory()
        directory.mkdir(parents=True, exist_ok=True)
        stem = (
            f"frame-{_diagnostic_session_token()}"
            f"-{_safe_log_name(Path(config.path).stem)}"  # type: ignore[attr-defined]
            f"-g{generation}-i{instructions}-c{capture:02d}"
            f"-{_safe_log_name(phase)}"
        )
        image = Image.frombytes("RGB", (width, height), frame)
        for suffix in range(10_000):
            target = directory / (
                f"{stem}.png" if suffix == 0 else f"{stem}-{suffix}.png"
            )
            try:
                with target.open("xb") as output:
                    image.save(output, format="PNG")
                return target.name
            except FileExistsError:
                continue
            except (OSError, RuntimeError, ValueError):
                try:
                    target.unlink()
                except OSError:
                    pass
                raise
        raise OSError("diagnostic screenshot filename space exhausted")
    except (OSError, RuntimeError, ValueError) as error:
        LOGGER.warning("diagnostic screenshot failed generation=%d firmware=%s error=%s",
                       generation, Path(config.path).name, type(error).__name__)  # type: ignore[attr-defined]
        return None


def _compact_telemetry(payload: dict[str, object]) -> dict[str, object]:
    """Keep one-million-instruction session lines useful but small."""
    return {
        name: payload[name] for name in (
            "generation", "firmware", "model", "chipset", "dump_status",
            "instructions", "pc", "lr", "cpsr", "phase", "event", "frame",
            "lcd", "rex", "nor", "eeprom", "nand", "control_sink",
            "last_unmapped", "unmapped_accesses", "dynamic_page_first_accesses",
            "fault",
        ) if name in payload
    }


def emit_telemetry(kind: str, payload: dict[str, object], *, persist: bool = True) -> None:
    session_payload = payload if persist else _compact_telemetry(payload)
    LOGGER.info("telemetry kind=%s payload=%s", kind,
                json.dumps(session_payload, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")))
    if persist:
        record_diagnostic(kind, payload)


class Window:
    def __init__(self, root: tk.Tk, firmware: Path) -> None:
        LOGGER.info("window create firmware=%s build=%s", firmware.name, BUILD_CODENAME)
        self.root = root
        self.root.minsize(360, 640)
        self.firmware = firmware
        self.ui_language_preference = self._load_ui_language()
        self.ui_language = resolve_ui_language(self.ui_language_preference)
        self.overrides = self._load_config()
        self.emulator: GenericMSMEmulator | None = None
        self.worker: threading.Thread | None = None
        self.stop = threading.Event()
        self.generation = 0
        self.closing = False
        self.commands: queue.SimpleQueue[tuple[object, ...]] = queue.SimpleQueue()
        self.states: queue.SimpleQueue[tuple[int, dict[str, object]]] = queue.SimpleQueue()
        self.save_errors: queue.SimpleQueue[str] = queue.SimpleQueue()
        self.update_results: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.update_download_active = False
        self.held: dict[int, set[str]] = {}
        self.keyboard_bits: dict[str, int] = {}
        self.keyboard_sources: set[str] = set()
        self.pending_key_releases: dict[str, str] = {}
        self.photo: ImageTk.PhotoImage | None = None
        self._render_cache: tuple[object, bytes, int, int, int, int] | None = None
        self.status = tk.StringVar(value=self._text("ready"))
        self.model = tk.StringVar(value=self._text("detecting"))
        self._configure_style()
        self._build()
        self._bind_keyboard()
        self._restart()
        self.root.after(50, self._refresh)
        self.root.after(750, self._check_for_update)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _text(self, key: str) -> str:
        return UI_TEXT[self.ui_language][key]

    def _key_text(self, key: str) -> str:
        return KEY_TEXT[self.ui_language].get(key, key)

    def _settings_text(self, text: str) -> str:
        return SETTINGS_ENGLISH.get(text, text) if self.ui_language == "en" else text

    def _apply_ui_language(self) -> None:
        self.root.title(self._text("window_title"))
        for key, button in self.key_buttons.items():
            button.configure(text=self._key_text(key))
        self.settings_button.configure(text=self._text("settings"))
        self.capture_button.configure(text=self._text("capture"))

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Phone.TFrame", background="#242424")
        style.configure("Phone.TLabel", background="#242424", foreground="#eeeeee")
        style.configure("Phone.TButton", padding=(4, 1), width=6, anchor="center")
        style.configure("Tool.Phone.TButton", padding=(4, 1), width=10)
        self.root.configure(background="#1b1b1b")

    def _build(self) -> None:
        outer = ttk.Frame(self.root, style="Phone.TFrame", padding=10)
        outer.pack(fill="both", expand=True, padx=8, pady=8)

        self.screen = tk.Canvas(outer, width=1, height=1, background="black",
                                highlightthickness=0, bd=0)
        self.screen.pack(fill="both", expand=True, pady=(0, 6))

        controls = ttk.Frame(outer, style="Phone.TFrame")
        controls.pack()
        self.key_buttons: dict[str, ttk.Button] = {}
        for label, row, column in LAYOUT:
            button = ttk.Button(controls, text=self._key_text(label),
                                style="Phone.TButton", takefocus=False)
            button.grid(row=row, column=column, padx=2, pady=1)
            self.key_buttons[label] = button
            bit = KEYS[label]
            button.bind("<ButtonPress-1>",
                        lambda _event, b=bit: self._key(b, True, f"mouse:{b}"))
            button.bind("<ButtonRelease-1>",
                        lambda _event, b=bit: self._key(b, False, f"mouse:{b}"))

        tools = ttk.Frame(outer, style="Phone.TFrame")
        tools.pack(pady=(2, 4))
        self.settings_button = ttk.Button(tools, text=self._text("settings"),
                                          command=self._settings,
                                          style="Tool.Phone.TButton")
        self.settings_button.grid(row=0, column=0, padx=2)
        self.capture_button = ttk.Button(tools, text=self._text("capture"),
                                         command=self._save_png,
                                         style="Tool.Phone.TButton")
        self.capture_button.grid(row=0, column=1, padx=2)

        ttk.Separator(outer).pack(fill="x", pady=(4, 3))
        self.model_label = ttk.Label(outer, textvariable=self.model, anchor="w",
                                     justify="left", wraplength=330, style="Phone.TLabel")
        self.model_label.pack(fill="x")
        self.status_label = ttk.Label(outer, textvariable=self.status, anchor="w",
                                      justify="left", wraplength=330, style="Phone.TLabel")
        self.status_label.pack(fill="x")

        def wrap_status(event: tk.Event) -> None:
            length = max(120, event.width - 24)
            self.model_label.configure(wraplength=length)
            self.status_label.configure(wraplength=length)

        outer.bind("<Configure>", wrap_status)
        self._apply_ui_language()

    def _bind_keyboard(self) -> None:
        self.keyboard_mapping = {
            "Up": "▲", "Down": "▼", "Left": "◀", "Right": "▶",
            "Return": "OK", "Escape": "종료",
            "plus": "볼륨+", "KP_Add": "볼륨+",
            "minus": "볼륨-", "KP_Subtract": "볼륨-",
            **{str(number): str(number) for number in range(10)},
            **{f"KP_{number}": str(number) for number in range(10)},
        }
        self.root.bind("<KeyPress>", lambda event: self._keyboard_event(event, True))
        self.root.bind("<KeyRelease>", lambda event: self._keyboard_event(event, False))
        self.root.bind("<FocusOut>", self._release_all)

    def _keyboard_event(self, event: tk.Event, pressed: bool) -> None:
        source = f"key:{event.keycode}"
        if not pressed and source in self.keyboard_bits:
            self._keyboard_release(source, self.keyboard_bits[source])
            return
        label = self.keyboard_mapping.get(str(event.keysym))
        if label is None:
            return
        bit = KEYS[label]
        if pressed:
            self._keyboard_press(source, bit)
        else:
            self._keyboard_release(source, bit)

    def _keyboard_press(self, source: str, bit: int) -> None:
        pending = self.pending_key_releases.pop(source, None)
        if pending is not None:
            self.root.after_cancel(pending)
        self.keyboard_sources.add(source)
        self.keyboard_bits[source] = bit
        self._key(bit, True, source)

    def _keyboard_release(self, source: str, bit: int) -> None:
        pending = self.pending_key_releases.pop(source, None)
        if pending is not None:
            self.root.after_cancel(pending)
        bit = self.keyboard_bits.get(source, bit)

        def confirm() -> None:
            self.pending_key_releases.pop(source, None)
            self._key(bit, False, source)
            self.keyboard_bits.pop(source, None)
            self.keyboard_sources.discard(source)

        # X11 auto-repeat emits Release/Press pairs.  The following Press is
        # already queued before Tk becomes idle, so it cancels this release.
        self.pending_key_releases[source] = self.root.after_idle(confirm)

    def _release_all(self, _event: tk.Event | None = None) -> None:
        for callback in self.pending_key_releases.values():
            self.root.after_cancel(callback)
        self.pending_key_releases.clear()
        for source in tuple(self.keyboard_sources):
            bit = self.keyboard_bits.get(source)
            if bit is not None:
                self._key(bit, False, source)
        self.keyboard_bits.clear()
        self.keyboard_sources.clear()

    def _key(self, bit: int, pressed: bool, source: str = "legacy") -> None:
        sources = self.held.get(bit)
        if pressed:
            if sources is not None and source in sources:
                return
            if sources is None:
                sources = self.held[bit] = set()
            was_pressed = bool(sources)
            sources.add(source)
            if was_pressed:
                return
        else:
            if sources is None or source not in sources:
                return
            sources.remove(source)
            if sources:
                return
            del self.held[bit]
        self.commands.put((bit, pressed))

    def _restart(self) -> None:
        self.generation += 1
        generation = self.generation
        self.stop.set()
        for callback in self.pending_key_releases.values():
            self.root.after_cancel(callback)
        self.pending_key_releases.clear()
        self.keyboard_bits.clear()
        self.keyboard_sources.clear()
        self.commands = queue.SimpleQueue()
        self.held.clear()
        self.emulator = None
        self._render_cache = None
        self.status.set(self._text("restarting"))
        self._start_when_stopped(generation)

    def _check_for_update(self) -> None:
        """Check GitHub outside Tk; ``_refresh`` owns all UI actions."""
        def check() -> None:
            try:
                update = check_for_update(application_root(), STATE_ROOT)
            except UpdateError as error:
                LOGGER.info("update check skipped error=%s", error)
                return
            if update is not None:
                self.update_results.put(("available", update))

        threading.Thread(target=check, daemon=True).start()

    def _offer_update(self, update: UpdateInfo) -> None:
        if self.closing or self.update_download_active:
            return
        try:
            remember_update(STATE_ROOT, update.revision)
        except (OSError, UpdateError) as error:
            LOGGER.info("update prompt state not saved error=%s", error)
        if not messagebox.askyesno(
                "업데이트",
                f"GitHub 최신 commit {update.revision[:12]}를 찾았습니다.\n"
                "내려받아 새 창으로 실행할까요?",
                parent=self.root):
            return
        self.update_download_active = True
        self.status.set("업데이트 내려받는 중")

        def download() -> None:
            try:
                self.update_results.put(("ready", prepare_update(update, STATE_ROOT)))
            except (OSError, UpdateError) as error:
                self.update_results.put(("error", error))

        threading.Thread(target=download, daemon=True).start()

    def _launch_update(self, root: Path) -> None:
        try:
            command = updated_gui_command(root, self.firmware)
        except UpdateError as error:
            self.status.set(f"업데이트 준비 실패: {error}")
            self.update_download_active = False
            return
        self._close()
        try:
            subprocess.Popen(command, cwd=root)
        except OSError as error:
            LOGGER.error("updated GUI launch failed error=%s", error)

    def _start_when_stopped(self, generation: int) -> None:
        if self.closing or generation != self.generation:
            return
        if self.worker is not None and self.worker.is_alive():
            self.root.after(25, self._start_when_stopped, generation)
            return
        self._show_save_errors()
        self.stop = threading.Event()
        stop = self.stop
        commands = self.commands
        firmware = self.firmware
        overrides = dict(self.overrides)
        self.worker = threading.Thread(
            target=self._run,
            args=(generation, stop, commands, firmware, overrides),
            daemon=False,
        )
        self.worker.start()

    def _run(self, generation: int, stop: threading.Event,
             commands: queue.SimpleQueue[tuple[object, ...]], firmware: Path,
             overrides: dict[str, object]) -> None:
        emulator: GenericMSMEmulator | None = None
        config = None
        captures = 0
        terminal = False
        try:
            config = detect(firmware, argparse.Namespace(**overrides))
            worker_boot = {
                "generation": generation,
                "firmware": firmware_telemetry(config),
                "model": config.model,
                "chipset": config.chipset,
                "chipset_confidence": config.chipset_confidence,
                "screen": {"width": config.width, "height": config.height},
                "dump_status": config.dump_status,
            }
            emit_telemetry("firmware_identity", worker_boot)
            emulator = GenericMSMEmulator(config)
            if generation == self.generation:
                self.emulator = emulator
            self.states.put((generation, {
                "model": f"{config.model} · {config.chipset}/{config.chipset_confidence} · "
                         f"{config.width}×{config.height} · {config.dump_status}",
            }))
            last_publish = 0.0
            _width, _height, initial_frame = emulator.display_snapshot()
            reset_hash = hashlib.sha256(initial_frame).hexdigest()
            previous_frame_hash = reset_hash
            previous_frame = initial_frame
            previous_nonblack = visible_pixels(initial_frame)
            saw_splash = False
            last_phase: str | None = None
            last_event: str | None = None
            last_telemetry_instructions = 0
            last_screenshot_instructions = 0
            while not stop.is_set():
                while True:
                    try:
                        command = commands.get_nowait()
                    except queue.Empty:
                        break
                    if len(command) == 2 and isinstance(command[0], int):
                        bit, pressed = command
                        emulator.set_key(bit, bool(pressed))
                    elif command[0] == "framebuffer-format" and len(command) == 2:
                        framebuffer_format = str(command[1])
                        emulator.set_framebuffer_format(framebuffer_format)
                        LOGGER.info("live framebuffer format=%s generation=%d",
                                    framebuffer_format, generation)
                state = emulator.run(25_000)
                frame_width, frame_height, frame = emulator.display_snapshot()
                frame_hash, nonblack = _frame_metrics(
                    frame, previous_frame, previous_frame_hash, previous_nonblack
                )
                phase, event, saw_splash, telemetry_due = telemetry_transition(
                    state, nonblack, frame_hash, reset_hash, previous_frame_hash,
                    saw_splash, last_phase, last_event, last_telemetry_instructions,
                )
                terminal = bool(state.get("fault"))
                instructions = _counter(state, "instructions")
                transitioned = phase != last_phase or event != last_event
                periodic_screenshot_due = instructions >= (
                    last_screenshot_instructions + TELEMETRY_SCREENSHOT_CADENCE
                )
                artifact_due = telemetry_artifact_due(
                    transitioned=transitioned, terminal=terminal,
                    instructions=instructions,
                    last_screenshot_instructions=last_screenshot_instructions,
                )
                if telemetry_due:
                    screenshot = None
                    # Reserve one capture for a terminal fault after noisy animation.
                    if (artifact_due and captures < TELEMETRY_SCREENSHOT_CAP
                            and (terminal or captures < TELEMETRY_SCREENSHOT_CAP - 1)):
                        captures += 1
                        screenshot = save_telemetry_frame(
                            config, generation=generation, instructions=instructions,
                            phase=phase, capture=captures,
                            width=frame_width, height=frame_height, frame=frame,
                        )
                    if screenshot is not None or periodic_screenshot_due:
                        last_screenshot_instructions = instructions
                    telemetry = runtime_telemetry(
                        config, state, generation=generation, phase=phase, event=event,
                        width=frame_width, height=frame_height, frame=frame,
                        nonblack=nonblack, screenshot=screenshot,
                    )
                    emit_telemetry(
                        "terminal_state" if terminal else "runtime_checkpoint",
                        telemetry,
                        persist=artifact_due,
                    )
                    last_phase, last_event = phase, event
                    last_telemetry_instructions = instructions
                previous_frame_hash = frame_hash
                previous_frame = frame
                previous_nonblack = nonblack
                now = time.monotonic()
                if state["fault"] or now - last_publish >= 0.1:
                    self.states.put((generation, state))
                    last_publish = now
                if state["fault"]:
                    terminal = True
                    LOGGER.error("worker emulation stopped generation=%d fault=%s",
                                 generation, state["fault"])
                    break
        except HostBackendFault as error:
            terminal = True
            diagnostic = getattr(error, "diagnostic", {})
            state = dict(diagnostic) if isinstance(diagnostic, dict) else {}
            # Host error must not be mistaken for a guest Unicorn fault.
            state.pop("fault", None)
            state = hydrate_host_checkpoint(state)
            registers = _mapping(state, "registers")
            state.setdefault("pc", registers.get("pc"))
            state.setdefault("lr", registers.get("lr"))
            screenshot = None
            if emulator is not None and config is not None:
                try:
                    frame_width, frame_height, frame = emulator.display_snapshot()
                    if captures < TELEMETRY_SCREENSHOT_CAP:
                        captures += 1
                        screenshot = save_telemetry_frame(
                            config, generation=generation,
                            instructions=_counter(state, "instructions"),
                            phase="host-backend-fault", capture=captures,
                            width=frame_width, height=frame_height, frame=frame,
                        )
                    telemetry = runtime_telemetry(
                        config, state, generation=generation,
                        phase="host-backend-fault", event="host-backend-fault",
                        width=frame_width, height=frame_height, frame=frame,
                        nonblack=visible_pixels(frame), screenshot=screenshot,
                    )
                except (OSError, RuntimeError, ValueError) as snapshot_error:
                    LOGGER.warning("host fault snapshot failed generation=%d error=%s",
                                   generation, type(snapshot_error).__name__)
                    telemetry = runtime_telemetry(
                        config, state, generation=generation,
                        phase="host-backend-fault", event="host-backend-fault",
                        width=config.width, height=config.height, frame=b"",
                        nonblack=0,
                    )
            else:
                telemetry = {"generation": generation}
            telemetry["host_backend_fault"] = str(error)
            telemetry["host_checkpoint"] = state
            emit_telemetry("host_backend_fault", telemetry)
            LOGGER.error("worker host backend stopped generation=%d firmware=%s error=%s",
                         generation, (Path(config.path).name if config is not None
                                      else "unknown"), error)
            ui_state = {
                name: state[name] for name in (
                    "instructions", "pc", "lr", "lcd_writes", "frame_sequence",
                    "audio_play_requests", "audio_backend", "audio_error", "input_error",
                ) if name in state
            }
            ui_state["host_backend_fault"] = str(error)
            self.states.put((generation, ui_state))
        except Exception as error:
            terminal = emulator is not None
            record_exception(f"GUI worker generation {generation}", error)
            self.states.put((generation, {"fault": str(error)}))
        finally:
            if emulator is not None:
                repro_bundle = (create_repro_bundle(config, emulator, overrides, generation)
                                if terminal and config is not None else None)
                try:
                    emulator.close()
                except Exception as error:
                    record_exception(f"GUI save generation {generation}", error)
                    self.save_errors.put(str(error))
                    self.states.put((generation, {"fault": f"저장 실패: {error}"}))
                finally:
                    if repro_bundle is not None and config is not None:
                        finish_repro_bundle(
                            repro_bundle, config, emulator, overrides, generation
                        )

    def _refresh(self) -> None:
        self._show_save_errors()
        while True:
            try:
                kind, value = self.update_results.get_nowait()
            except queue.Empty:
                break
            if kind == "available" and isinstance(value, UpdateInfo):
                self._offer_update(value)
            elif kind == "ready" and isinstance(value, Path):
                self._launch_update(value)
                return
            elif kind == "error" and isinstance(value, (OSError, UpdateError)):
                self.status.set(f"업데이트 실패: {value}")
                self.update_download_active = False
        latest: dict[str, object] = {}
        while True:
            try:
                generation, state = self.states.get_nowait()
            except queue.Empty:
                break
            if generation == self.generation:
                latest.update(state)
        if latest:
            if "model" in latest:
                self.model.set(str(latest["model"]))
            if "instructions" in latest:
                self.status.set(runtime_status_text(latest, self.ui_language))
            if latest.get("fault"):
                self.status.set(f"{'Stopped' if self.ui_language == 'en' else '중지'}: {latest['fault']}")
            if latest.get("host_backend_fault"):
                self.status.set(
                    f"{'Host backend stopped' if self.ui_language == 'en' else '호스트 backend 중지'}: "
                    f"{latest['host_backend_fault']}"
                )
        emulator = self.emulator
        if emulator is not None:
            frame_width, frame_height, frame = emulator.display_snapshot()
            width = max(1, self.screen.winfo_width())
            height = max(1, self.screen.winfo_height())
            if frame_repaint_needed(
                    self._render_cache, emulator, frame, frame_width, frame_height,
                    width, height):
                image = Image.frombytes("RGB", (frame_width, frame_height), frame)
                scale = min(width / image.width, height / image.height)
                size = (max(1, int(image.width * scale)),
                        max(1, int(image.height * scale)))
                self.photo = ImageTk.PhotoImage(
                    image.resize(size, Image.Resampling.NEAREST)
                )
                self.screen.delete("all")
                self.screen.create_image(width // 2, height // 2, image=self.photo)
                self._render_cache = (
                    emulator, frame, frame_width, frame_height, width, height
                )
        self.root.after(100, self._refresh)

    def _show_save_errors(self) -> None:
        errors: list[str] = []
        while True:
            try:
                errors.append(self.save_errors.get_nowait())
            except queue.Empty:
                break
        if not errors:
            return
        detail = "\n".join(dict.fromkeys(errors))
        self.status.set(f"{self._text('save_failed')}: {detail}")
        messagebox.showerror(self._text("save_failed"), detail, parent=self.root)

    def _settings(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title(self._text("boot_settings"))
        dialog.transient(self.root)
        detected = self.emulator.config if self.emulator is not None else detect(self.firmware)

        def current(name: str) -> object:
            return self.overrides[name] if name in self.overrides else getattr(detected, name)

        def shown(name: str, *, hexadecimal: bool = False) -> str:
            value = current(name)
            if value is None:
                return ""
            return hex(int(value)) if hexadecimal else str(value)

        values = {
            "firmware": str(self.firmware),
            "model": shown("model"),
            "chipset": shown("chipset"),
            "width": shown("width"),
            "height": shown("height"),
            "framebuffer_address": shown("framebuffer_address", hexadecimal=True),
            "framebuffer_stride": shown("framebuffer_stride", hexadecimal=True),
            "framebuffer_format": shown("framebuffer_format"),
            "framebuffer_flush_address": shown("framebuffer_flush_address",
                                                hexadecimal=True),
            "framebuffer_rect_flush_address": shown(
                "framebuffer_rect_flush_address", hexadecimal=True),
            "board_revision": shown("board_revision"),
            "image_offset": shown("image_offset", hexadecimal=True),
            "load_address": shown("load_address", hexadecimal=True),
            "flash_size": shown("flash_size", hexadecimal=True),
            "secondary_flash_address": shown("secondary_flash_address", hexadecimal=True),
            "secondary_flash_size": shown("secondary_flash_size", hexadecimal=True),
            "secondary_flash_image": shown("secondary_flash_image"),
            "secondary_flash_state": shown("secondary_flash_state"),
            "secondary_flash_read_address": shown("secondary_flash_read_address",
                                                  hexadecimal=True),
            "secondary_flash_write_address": shown("secondary_flash_write_address",
                                                   hexadecimal=True),
            "legacy_efs_page_read_address": shown(
                "legacy_efs_page_read_address", hexadecimal=True),
            "ram_base": shown("ram_base", hexadecimal=True),
            "ram_size": shown("ram_size", hexadecimal=True),
            "ram_image_offset": shown("ram_image_offset", hexadecimal=True),
            "ram_image_size": shown("ram_image_size", hexadecimal=True),
            "entry": shown("entry", hexadecimal=True),
            "board_revision_register": shown("board_revision_register", hexadecimal=True),
            "board_revision_value": shown("board_revision_value", hexadecimal=True),
            "key_register": shown("key_register", hexadecimal=True),
            "key_active_low": "true" if current("key_active_low") else "false",
            "audio_play_address": shown("audio_play_address", hexadecimal=True),
            "fast_boot_address": shown("fast_boot_address", hexadecimal=True),
            "delay_address": shown("delay_address", hexadecimal=True),
            "busy_delay_address": shown("busy_delay_address", hexadecimal=True),
            "crc16_address": shown("crc16_address", hexadecimal=True),
            "rex_idle_address": shown("rex_idle_address", hexadecimal=True),
            "rex_tick_address": shown("rex_tick_address", hexadecimal=True),
            "rex_tick_ms": shown("rex_tick_ms"),
            "board_adc_address": shown("board_adc_address", hexadecimal=True),
            "board_adc_value": shown("board_adc_value", hexadecimal=True),
            "flash_id_address": shown("flash_id_address", hexadecimal=True),
            "flash_id_value": shown("flash_id_value", hexadecimal=True),
            "dmd_download_address": shown("dmd_download_address", hexadecimal=True),
            "primary_flash_probe_address": shown("primary_flash_probe_address",
                                                   hexadecimal=True),
            "nand_bad_block_address": shown("nand_bad_block_address", hexadecimal=True),
            "nand_read_address": shown("nand_read_address", hexadecimal=True),
            "nand_write_address": shown("nand_write_address", hexadecimal=True),
            "flash_state": shown("flash_state"),
            "nand_enabled": "true" if current("nand_enabled") else "false",
            "nand_image": shown("nand_image"),
            "nand_data_size": shown("nand_data_size", hexadecimal=True),
            "nand_page_size": shown("nand_page_size", hexadecimal=True),
            "nand_spare_size": shown("nand_spare_size", hexadecimal=True),
            "nand_pages_per_block": shown("nand_pages_per_block"),
            "nand_bus_width": shown("nand_bus_width"),
        }
        sections = (
            ("기본", (("firmware", "펌웨어"), ("model", "모델"),
                    ("chipset", "칩셋"), ("width", "화면 너비"),
                    ("height", "화면 높이"), ("board_revision", "Board revision 이름"))),
            ("메모리", (("image_offset", "이미지 오프셋"),
                     ("load_address", "로드 주소"), ("flash_size", "Flash 크기"),
                     ("ram_base", "RAM 시작 주소"), ("ram_size", "RAM 크기"),
                     ("ram_image_offset", "RAM image 오프셋"),
                     ("ram_image_size", "RAM image 크기 (0=끔)"),
                     ("entry", "진입점 오프셋"))),
            ("화면 버퍼", (("framebuffer_address", "Framebuffer 주소 (빈 값=끔)"),
                         ("framebuffer_stride", "Framebuffer stride bytes"),
                         ("framebuffer_format", "Framebuffer pixel format"),
                         ("framebuffer_flush_address", "Row flush 함수"),
                         ("framebuffer_rect_flush_address", "Rect flush 함수"))),
            ("하드웨어", (("board_revision_register", "Board revision 레지스터"),
                       ("board_revision_value", "Board revision 값"),
                       ("key_register", "키 레지스터"),
                       ("key_active_low", "키 active-low"),
                       ("audio_play_address", "Audio play 함수"),
                       ("fast_boot_address", "Fast boot 함수"))),
            ("함수", (("delay_address", "Delay 함수"),
                    ("busy_delay_address", "Busy delay 함수"),
                    ("crc16_address", "CRC16 함수"),
                    ("nand_bad_block_address", "NAND bad-block 함수"),
                    ("nand_read_address", "NAND read 함수"),
                    ("nand_write_address", "NAND write 함수"))),
            ("부팅 HLE", (("rex_idle_address", "REX idle 함수"),
                        ("rex_tick_address", "REX tick 함수"),
                        ("rex_tick_ms", "REX tick 밀리초"),
                        ("board_adc_address", "Board ADC 함수"),
                        ("board_adc_value", "Board ADC 값"),
                        ("flash_id_address", "Flash ID 함수"),
                        ("flash_id_value", "Flash ID 값"),
                        ("dmd_download_address", "DMD download 함수"),
                        ("primary_flash_probe_address", "NOR probe 함수"))),
            ("EFS NOR", (("secondary_flash_address", "보조 NOR 주소 (0=끔)"),
                       ("secondary_flash_size", "보조 NOR 크기"),
                       ("secondary_flash_image", "보조 NOR image"),
                       ("secondary_flash_state", "보조 NOR state"),
                       ("secondary_flash_read_address", "보조 NOR read 함수"),
                       ("secondary_flash_write_address", "보조 NOR write 함수"),
                       ("legacy_efs_page_read_address", "Legacy EFS page read 함수"))),
            ("저장", (("flash_state", "Flash state"),
                    ("nand_enabled", "NAND 사용"), ("nand_image", "NAND raw image"),
                    ("nand_data_size", "NAND data 크기"),
                    ("nand_page_size", "NAND page 크기"),
                    ("nand_spare_size", "NAND spare 크기"),
                    ("nand_pages_per_block", "NAND block당 pages"),
                    ("nand_bus_width", "NAND bus bytes"))),
        )
        language_labels = {
            "auto": "자동 (시스템)" if self.ui_language == "ko" else "Auto (System)",
            "ko": "한국어", "en": "English",
        }
        language_choice = tk.StringVar(value=language_labels[self.ui_language_preference])
        language_frame = ttk.Frame(dialog, padding=(10, 10, 10, 0))
        language_frame.pack(fill="x")
        ttk.Label(language_frame, text=self._text("ui_language")).pack(side="left")
        ttk.Combobox(language_frame, textvariable=language_choice,
                     values=tuple(language_labels.values()), state="readonly",
                     width=20).pack(side="right")
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill="both", expand=True, padx=10, pady=(10, 4))
        entries: dict[str, ttk.Entry | ttk.Combobox] = {}

        def choose_firmware() -> None:
            """Replace the editable firmware path with a user-selected image."""
            current_path = Path(entries["firmware"].get()).expanduser()
            initial_dir = (current_path.parent if current_path.parent.is_dir()
                           else self.firmware.parent)
            chosen = filedialog.askopenfilename(
                parent=dialog,
                title=self._text("choose_firmware"),
                initialdir=str(initial_dir),
                filetypes=(
                    ("Firmware images", "*.bin *.dump *.img *.mbn"),
                    ("All files", "*"),
                ),
            )
            if not chosen:
                return
            entry = entries["firmware"]
            entry.delete(0, tk.END)
            entry.insert(0, chosen)

        boolean_fields = {"key_active_low", "nand_enabled"}
        for title, fields in sections:
            page = ttk.Frame(notebook, padding=10)
            page.columnconfigure(1, weight=1)
            notebook.add(page, text=self._settings_text(title))
            for row, (name, label) in enumerate(fields):
                ttk.Label(page, text=self._settings_text(label)).grid(
                    row=row, column=0, sticky="w", pady=2)
                if name in boolean_fields:
                    widget = ttk.Combobox(page, values=("true", "false"),
                                          state="readonly", width=40)
                    widget.set(values[name])
                elif name == "chipset":
                    widget = ttk.Combobox(
                        page,
                        values=("MSM5000", "MSM5100", "MSM5105", "MSM5500", "MSM5xxx"),
                                          state="readonly", width=40)
                    widget.set(values[name])
                elif name == "framebuffer_format":
                    widget = ttk.Combobox(
                        page,
                        values=("none", "rgb565le", "bgr565le", "rgb565be", "bgr565be"),
                        state="readonly", width=40,
                    )
                    widget.set(values[name])
                else:
                    widget = ttk.Entry(page, width=42)
                    widget.insert(0, values[name])
                widget.grid(row=row, column=1, sticky="ew", padx=(10, 0), pady=2)
                entries[name] = widget
                if name == "firmware":
                    ttk.Button(page, text=self._text("choose_file"), command=choose_firmware).grid(
                        row=row, column=2, sticky="e", padx=(8, 0), pady=2)

        def integer(name: str) -> int:
            return int(entries[name].get().strip(), 0)

        def optional_integer(name: str) -> int | None:
            text = entries[name].get().strip()
            return int(text, 0) if text else None

        def boolean(name: str) -> bool:
            text = entries[name].get().strip().lower()
            if text == "true":
                return True
            if text == "false":
                return False
            raise ValueError(f"{name}: true 또는 false만 허용")

        def apply() -> None:
            try:
                ui_language = next((name for name, label in language_labels.items()
                                    if label == language_choice.get()), None)
                if ui_language is None:
                    raise ValueError("UI language selection is invalid")
                firmware = Path(entries["firmware"].get()).expanduser().resolve()
                if not firmware.is_file():
                    raise ValueError("펌웨어 파일 없음")
                nand_image_text = entries["nand_image"].get().strip()
                secondary_image_text = entries["secondary_flash_image"].get().strip()
                secondary_state_text = entries["secondary_flash_state"].get().strip()
                overrides = {
                    "model": entries["model"].get().strip(),
                    "chipset": entries["chipset"].get().strip(),
                    "image_offset": integer("image_offset"),
                    "load_address": integer("load_address"),
                    "flash_size": integer("flash_size"),
                    "secondary_flash_address": optional_integer("secondary_flash_address"),
                    "secondary_flash_size": integer("secondary_flash_size"),
                    "secondary_flash_image": (
                        str(Path(secondary_image_text).expanduser().resolve())
                        if secondary_image_text else None),
                    "secondary_flash_state": (
                        str(Path(secondary_state_text).expanduser().resolve())
                        if secondary_state_text else ""),
                    "secondary_flash_read_address": optional_integer(
                        "secondary_flash_read_address"),
                    "secondary_flash_write_address": optional_integer(
                        "secondary_flash_write_address"),
                    "legacy_efs_page_read_address": optional_integer(
                        "legacy_efs_page_read_address"),
                    "ram_base": integer("ram_base"),
                    "ram_size": integer("ram_size"),
                    "ram_image_offset": integer("ram_image_offset"),
                    "ram_image_size": integer("ram_image_size"),
                    "entry": integer("entry"),
                    "width": integer("width"),
                    "height": integer("height"),
                    "framebuffer_address": optional_integer("framebuffer_address"),
                    "framebuffer_stride": integer("framebuffer_stride"),
                    "framebuffer_format": entries["framebuffer_format"].get().strip(),
                    "framebuffer_flush_address": optional_integer(
                        "framebuffer_flush_address"),
                    "framebuffer_rect_flush_address": optional_integer(
                        "framebuffer_rect_flush_address"),
                    "board_revision": entries["board_revision"].get().strip(),
                    "board_revision_register": optional_integer("board_revision_register"),
                    "board_revision_value": optional_integer("board_revision_value"),
                    "key_register": integer("key_register"),
                    "key_active_low": boolean("key_active_low"),
                    "audio_play_address": optional_integer("audio_play_address"),
                    "fast_boot_address": optional_integer("fast_boot_address"),
                    "delay_address": optional_integer("delay_address"),
                    "busy_delay_address": optional_integer("busy_delay_address"),
                    "crc16_address": optional_integer("crc16_address"),
                    "rex_idle_address": optional_integer("rex_idle_address"),
                    "rex_tick_address": optional_integer("rex_tick_address"),
                    "rex_tick_ms": integer("rex_tick_ms"),
                    "board_adc_address": optional_integer("board_adc_address"),
                    "board_adc_value": integer("board_adc_value"),
                    "flash_id_address": optional_integer("flash_id_address"),
                    "flash_id_value": optional_integer("flash_id_value"),
                    "dmd_download_address": optional_integer("dmd_download_address"),
                    "primary_flash_probe_address": optional_integer(
                        "primary_flash_probe_address"),
                    "nand_bad_block_address": optional_integer("nand_bad_block_address"),
                    "nand_read_address": optional_integer("nand_read_address"),
                    "nand_write_address": optional_integer("nand_write_address"),
                    "flash_state": str(Path(entries["flash_state"].get().strip())
                                       .expanduser().resolve()),
                    "nand_enabled": boolean("nand_enabled"),
                    "nand_image": (str(Path(nand_image_text).expanduser().resolve())
                                   if nand_image_text else None),
                    "nand_data_size": integer("nand_data_size"),
                    "nand_page_size": integer("nand_page_size"),
                    "nand_spare_size": integer("nand_spare_size"),
                    "nand_pages_per_block": integer("nand_pages_per_block"),
                    "nand_bus_width": integer("nand_bus_width"),
                }
                edited = {
                    name for name, widget in entries.items()
                    if name != "firmware"
                    and widget.get().strip() != values[name].strip()
                }
                firmware_changed = firmware != self.firmware.resolve()
                minimal = merge_settings_overrides(
                    self.overrides, edited, overrides, firmware_changed
                )
                effective = detect(firmware, argparse.Namespace(**minimal))
                overrides = {name: getattr(effective, name) for name in overrides}
                if not overrides["model"]:
                    raise ValueError("모델 이름이 비어 있음")
                if overrides["chipset"] not in (
                        "MSM5000", "MSM5100", "MSM5105", "MSM5500", "MSM5xxx"):
                    raise ValueError("지원하지 않는 칩셋")
                if not 32 <= overrides["width"] <= 1024 or not 32 <= overrides["height"] <= 1024:
                    raise ValueError("화면 크기 범위: 32..1024")
                framebuffer_address = overrides["framebuffer_address"]
                framebuffer_triggers = (
                    overrides["framebuffer_flush_address"],
                    overrides["framebuffer_rect_flush_address"],
                )
                if framebuffer_address is None:
                    if any(value is not None for value in framebuffer_triggers):
                        raise ValueError("Framebuffer 주소 없이 flush 함수를 쓸 수 없음")
                    if overrides["framebuffer_format"] != "none":
                        raise ValueError("Framebuffer를 끌 때 pixel format은 none이어야 함")
                else:
                    if overrides["framebuffer_format"] == "none":
                        raise ValueError("Framebuffer pixel format을 선택해야 함")
                    if overrides["framebuffer_stride"] < overrides["width"] * 2:
                        raise ValueError("Framebuffer stride가 한 줄보다 작음")
                file_size = firmware.stat().st_size
                if not 0 <= overrides["image_offset"] < file_size:
                    raise ValueError("이미지 오프셋이 펌웨어 범위를 벗어남")
                available = file_size - overrides["image_offset"]
                if (overrides["flash_size"] <= 0
                        or overrides["flash_size"] > MAX_FLASH_SIZE
                        or overrides["flash_size"] - available > PAGE):
                    raise ValueError("Flash 크기가 펌웨어 범위를 벗어남")
                if overrides["load_address"] + overrides["flash_size"] > 0x100000000:
                    raise ValueError("Flash 매핑이 32-bit 주소 공간을 벗어남")
                if not 0 <= overrides["entry"] < overrides["flash_size"]:
                    raise ValueError("진입점 오프셋이 Flash 범위를 벗어남")
                if min(overrides["ram_base"], overrides["ram_size"]) <= 0:
                    raise ValueError("RAM 시작 주소와 크기는 양수여야 함")
                if overrides["ram_size"] > MAX_RAM_SIZE:
                    raise ValueError("RAM 크기 상한: 128 MiB")
                if overrides["ram_base"] + overrides["ram_size"] > 0x100000000:
                    raise ValueError("RAM 범위가 32-bit 주소 공간을 벗어남")
                flash_start = overrides["load_address"]
                flash_end = flash_start + overrides["flash_size"]
                ram_start = overrides["ram_base"]
                ram_end = ram_start + overrides["ram_size"]
                if max(flash_start, ram_start) < min(flash_end, ram_end):
                    raise ValueError("주 Flash가 RAM과 겹침")
                if framebuffer_address is not None:
                    framebuffer_end = (framebuffer_address
                                       + overrides["framebuffer_stride"]
                                       * overrides["height"])
                    if not ram_start <= framebuffer_address < framebuffer_end <= ram_end:
                        raise ValueError("Framebuffer 범위가 RAM을 벗어남")
                if min(overrides["ram_image_offset"], overrides["ram_image_size"]) < 0:
                    raise ValueError("RAM image 오프셋과 크기는 음수일 수 없음")
                if (overrides["ram_image_size"]
                        and (overrides["ram_image_offset"] + overrides["ram_image_size"]
                             > available)):
                    raise ValueError("RAM image 범위가 펌웨어를 벗어남")
                if overrides["ram_image_size"] > overrides["ram_size"]:
                    raise ValueError("RAM image 크기가 RAM 크기를 초과함")
                address_fields = ("load_address", "key_register",
                                  "board_revision_register", "board_revision_value",
                                  "audio_play_address", "fast_boot_address", "delay_address",
                                  "busy_delay_address", "crc16_address",
                                  "rex_idle_address", "rex_tick_address",
                                  "board_adc_address", "board_adc_value",
                                  "flash_id_address", "flash_id_value",
                                  "dmd_download_address", "primary_flash_probe_address",
                                  "nand_bad_block_address", "nand_read_address",
                                  "nand_write_address", "secondary_flash_address",
                                  "secondary_flash_read_address",
                                  "secondary_flash_write_address",
                                  "legacy_efs_page_read_address",
                                  "framebuffer_address", "framebuffer_flush_address",
                                  "framebuffer_rect_flush_address")
                if any(value is not None and not 0 <= value <= 0xFFFFFFFF
                       for value in (overrides[name] for name in address_fields)):
                    raise ValueError("주소와 레지스터 값 범위: 0..0xFFFFFFFF")
                if not 0 <= overrides["rex_tick_ms"] <= 60_000:
                    raise ValueError("REX tick 밀리초 범위: 0..60000")
                if not entries["flash_state"].get().strip():
                    raise ValueError("Flash state 경로가 비어 있음")
                secondary_address = overrides["secondary_flash_address"]
                if overrides["secondary_flash_size"] < 0:
                    raise ValueError("보조 NOR 크기는 음수일 수 없음")
                effective_secondary_address = (
                    secondary_address if secondary_address is not None
                    else effective.secondary_flash_address
                )
                if effective_secondary_address not in (None, 0):
                    secondary_address = effective_secondary_address
                    secondary_size = overrides["secondary_flash_size"]
                    secondary_end = secondary_address + secondary_size
                    primary_start = overrides["load_address"]
                    primary_end = primary_start + overrides["flash_size"]
                    ram_start = overrides["ram_base"]
                    ram_end = ram_start + overrides["ram_size"]
                    if (not 0 < secondary_size <= MAX_FLASH_SIZE
                            or secondary_end > 0x100000000):
                        raise ValueError("보조 NOR 주소 또는 크기 범위 오류")
                    if max(secondary_address, primary_start) < min(secondary_end, primary_end):
                        raise ValueError("보조 NOR가 주 Flash와 겹침")
                    if max(secondary_address, ram_start) < min(secondary_end, ram_end):
                        raise ValueError("보조 NOR가 RAM과 겹침")
                    if not overrides["secondary_flash_state"]:
                        raise ValueError("보조 NOR state 경로가 비어 있음")
                    if overrides["secondary_flash_image"]:
                        image = Path(overrides["secondary_flash_image"])
                        if not image.is_file():
                            raise ValueError("보조 NOR image 파일 없음")
                        if image.stat().st_size > secondary_size:
                            raise ValueError("보조 NOR image가 설정 크기보다 큼")
                nand_values = (overrides["nand_data_size"], overrides["nand_page_size"],
                               overrides["nand_spare_size"],
                               overrides["nand_pages_per_block"])
                if min(nand_values) <= 0:
                    raise ValueError("NAND 크기와 block geometry는 양수여야 함")
                if overrides["nand_data_size"] > MAX_NAND_DATA_SIZE:
                    raise ValueError("NAND data 크기 상한: 128 MiB")
                if not 256 <= overrides["nand_page_size"] <= 0x4000:
                    raise ValueError("NAND page 크기 범위: 256..16384")
                if not 1 <= overrides["nand_spare_size"] <= 0x1000:
                    raise ValueError("NAND spare 크기 범위: 1..4096")
                if not 1 <= overrides["nand_pages_per_block"] <= 0x1000:
                    raise ValueError("NAND block당 pages 범위: 1..4096")
                if overrides["nand_data_size"] % overrides["nand_page_size"]:
                    raise ValueError("NAND data 크기는 page 크기의 배수여야 함")
                if overrides["nand_bus_width"] not in (1, 2):
                    raise ValueError("NAND bus bytes는 1 또는 2여야 함")
                raw_backing = (overrides["nand_data_size"]
                               // overrides["nand_page_size"]
                               * (overrides["nand_page_size"]
                                  + overrides["nand_spare_size"]))
                if raw_backing > MAX_NAND_BACKING_SIZE:
                    raise ValueError("NAND raw backing 상한: 256 MiB")
                if (overrides["nand_enabled"] and overrides["nand_image"]
                        and not Path(overrides["nand_image"]).is_file()):
                    raise ValueError("NAND raw image 파일 없음")
            except (OSError, ValueError) as error:
                messagebox.showerror(self._text("settings_error"), str(error), parent=dialog)
                return
            live_framebuffer_format = can_apply_live_framebuffer_format(
                edited, firmware_changed, framebuffer_address,
                str(overrides["framebuffer_format"]),
                self.worker is not None and self.worker.is_alive()
                and not self.stop.is_set(),
            ) and self.emulator is not None
            old_firmware, old_overrides = self.firmware, self.overrides
            old_ui_preference, old_ui_language = (
                self.ui_language_preference, self.ui_language
            )
            self.firmware, self.overrides = firmware, minimal
            self.ui_language_preference = ui_language
            self.ui_language = resolve_ui_language(ui_language)
            LOGGER.info("settings applied firmware=%s override_keys=%s",
                        firmware.name, sorted(minimal))
            try:
                self._save_config()
            except OSError as error:
                self.firmware, self.overrides = old_firmware, old_overrides
                self.ui_language_preference, self.ui_language = (
                    old_ui_preference, old_ui_language
                )
                messagebox.showerror(self._text("settings_save_error"), str(error), parent=dialog)
                return
            dialog.destroy()
            language_changed = self.ui_language != old_ui_language
            language_preference_changed = self.ui_language_preference != old_ui_preference
            if language_changed:
                self._apply_ui_language()
            if language_preference_changed and not edited and not firmware_changed:
                return
            if live_framebuffer_format:
                self.commands.put(("framebuffer-format", overrides["framebuffer_format"]))
                self.status.set("Applying framebuffer colour map"
                                if self.ui_language == "en"
                                else "Framebuffer 색상맵 적용 중")
            else:
                self._restart()

        footer = ttk.Frame(dialog, padding=(10, 4, 10, 10))
        footer.pack(fill="x")
        ttk.Button(footer, text=self._text("apply"), command=apply).pack(side="right")

    def _save_png(self) -> None:
        emulator = self.emulator
        if emulator is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".png",
                                            filetypes=(("PNG", "*.png"),))
        if path:
            width, height, frame = emulator.display_snapshot()
            Image.frombytes("RGB", (width, height), frame).save(path)

    def _load_ui_language(self) -> str:
        try:
            data = json.loads(LAST_CONFIG.read_text(encoding="utf-8"))
            return normalize_ui_language(data.get("ui_language"))
        except (AttributeError, OSError, ValueError):
            return "auto"

    def _load_config(self) -> dict[str, object]:
        try:
            data = json.loads(LAST_CONFIG.read_text(encoding="utf-8"))
            profiles = data.get("profiles", {})
            profile = profiles.get(str(self.firmware.resolve()), {})
            if not isinstance(profile, dict):
                return {}
            # Migrate profiles written by older builds that stored every
            # displayed auto value as if the user had overridden it.
            baseline = detect(self.firmware)
            return {
                key: value for key, value in profile.items()
                if hasattr(baseline, key) and value != getattr(baseline, key)
            }
        except (AttributeError, OSError, ValueError):
            return {}

    def _save_config(self) -> None:
        path = LAST_CONFIG
        with exclusive_path_lock(path):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            if not isinstance(data, dict):
                data = {}
            profiles = data.get("profiles")
            if not isinstance(profiles, dict):
                profiles = {}
            profiles[str(self.firmware.resolve())] = self.overrides
            atomic_write_text(
                path,
                json.dumps({"ui_language": self.ui_language_preference, "profiles": profiles},
                           ensure_ascii=False, indent=2) + "\n",
            )
            LOGGER.info("GUI profile saved firmware=%s override_keys=%s",
                        self.firmware.name, sorted(self.overrides))

    def _close(self) -> None:
        if self.closing:
            return
        self.closing = True
        firmware = getattr(self, "firmware", None)
        firmware_name = firmware.name if isinstance(firmware, Path) else "unknown"
        LOGGER.info("window close begin firmware=%s", firmware_name)
        self.generation += 1
        self.stop.set()
        if self.worker and self.worker.is_alive():
            self.worker.join()
        self._show_save_errors()
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        LOGGER.info("window close complete firmware=%s", firmware_name)


def main() -> int:
    session_log = install_runtime_logging("gui")
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", nargs="?", type=Path)
    args = parser.parse_args()
    firmware = args.firmware
    if firmware is None:
        root = tk.Tk()
        root.withdraw()
        chosen = filedialog.askopenfilename(filetypes=(("Firmware", "*.bin"), ("All", "*")))
        root.destroy()
        if not chosen:
            LOGGER.info("firmware selection cancelled log=%s", session_log)
            return 0
        firmware = Path(chosen)
    root = tk.Tk()

    def callback_exception(error_type: type[BaseException], error: BaseException,
                           trace: object) -> None:
        error = error.with_traceback(trace)  # type: ignore[arg-type]
        record_exception("Tk callback exception", error)
        sys.__excepthook__(error_type, error, trace)

    root.report_callback_exception = callback_exception
    window = Window(root, firmware.resolve())
    LOGGER.info("GUI mainloop start firmware=%s log=%s", firmware.name, session_log.name)

    def close_from_signal(_number: int, _frame: object) -> None:
        LOGGER.info("signal received number=%d", _number)
        root.after_idle(window._close)

    signal.signal(signal.SIGINT, close_from_signal)
    signal.signal(signal.SIGTERM, close_from_signal)
    try:
        root.mainloop()
    finally:
        window._close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
