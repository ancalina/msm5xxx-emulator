"""One emulator session for a desktop window: detection, QEMU transport and replay thread.

Settings live in the same file and keys as the existing desktop app (last_config.json)."""
from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path

from ..detection import detect
from .profile import (_clean_saved_model, detect_profile, manual_keymap, merge_settings_overrides,
                      parse_network_start_time)
from ..gui.settings import parse_settings_values, settings_values, validate_settings_values
from ..qemu.transport import Transport
from ..qemu.virtual_cell import virtual_cell_scenario
from ..state_io import atomic_write_text, exclusive_path_lock
from msm5xxx_emulator.detection.registry import device_domain

STATE_ROOT = device_domain('storage.configuration').DEFAULT_STATE_ROOT
LAST_CONFIG = STATE_ROOT / "last_config.json"
DEFAULTS = {"persistent_state": True, "virtual_network": False, "network_host_time": True,
            "network_start_time": "", "experimental_rex": False, "ui_language": "auto"}


def saved_settings() -> dict:
    try:
        data = json.loads(LAST_CONFIG.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def setting(key: str):
    value = saved_settings().get(key, DEFAULTS[key])
    return value if type(value) is type(DEFAULTS[key]) else DEFAULTS[key]


def update_settings(change) -> None:
    """Read-modify-write under the shared lock so other windows' keys survive."""
    with exclusive_path_lock(LAST_CONFIG):
        data = saved_settings()
        change(data)
        LAST_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(LAST_CONFIG, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def save_setting(key: str, value) -> None:
    update_settings(lambda data: data.__setitem__(key, value))


class Session:
    def __init__(self, qemu: Path, firmware: Path) -> None:
        self.qemu, self.firmware = qemu, firmware.resolve()
        self.transport: Transport | None = None
        self.config = None  # last detected config, kept after power off for settings
        self.overrides: dict = {}
        self.prepared = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # Per-firmware hardware overrides
    def profile(self) -> dict:
        profile = (saved_settings().get("profiles") or {}).get(str(self.firmware), {})
        return _clean_saved_model(profile) if isinstance(profile, dict) else {}

    def save_profile(self, overrides: dict) -> None:
        def change(data):
            profiles = data.get("profiles") if isinstance(data.get("profiles"), dict) else {}
            profiles[str(self.firmware)] = _clean_saved_model(overrides)
            data["profiles"] = profiles
        update_settings(change)

    def start(self) -> Transport:
        """Blocking: detect and launch QEMU. Call off the UI thread."""
        if self.prepared is not None:
            config, self.overrides = self.prepared
            self.prepared = None
        else:
            config, self.overrides = detect_profile(self.firmware, self.profile())
        self.config = config
        transport = Transport(
            self.qemu, self.firmware, STATE_ROOT / "qemu-state" if setting("persistent_state") else None,
            setting("experimental_rex"), config=config,
            virtual_cell=virtual_cell_scenario(setting("virtual_network"), host_time=setting("network_host_time"),
                                               start_time=parse_network_start_time(setting("network_start_time"))))
        self._stop = threading.Event()
        self._thread = threading.Thread(target=transport.replay, args=(self._stop,), daemon=True)
        self._thread.start()
        self.transport = transport
        return transport

    def settings_values(self) -> dict[str, str] | None:
        return settings_values(self.firmware, self.config, self.overrides) if self.config is not None else None

    def apply_settings(self, raw: dict[str, str], language: str) -> None:
        """Validate edited hardware values exactly as the existing desktop app does; next start uses them."""
        values = self.settings_values()
        edited = {name for name in raw if raw[name] != values[name].strip()}
        if not edited:
            return
        raw = {**values, **raw, "firmware": str(self.firmware)}
        parsed = parse_settings_values(raw, language)
        minimal = merge_settings_overrides(self.overrides, edited, parsed, False)
        effective = detect(self.firmware, argparse.Namespace(**minimal))
        checked = {name: getattr(effective, name) for name in parsed}
        validate_settings_values(self.firmware, effective, checked, edited, raw["flash_state"], language)
        self.save_profile(minimal)
        self.prepared = (effective, dict(minimal))

    # Manual key mappings (per firmware SHA-256, shared with the existing desktop app)
    def key_event(self, bit: int) -> int | None:
        sha = getattr(self.config, "firmware_sha256", None)
        return manual_keymap(saved_settings(), sha).get(bit) if sha else None

    def save_key_event(self, bit: int, event_code: int | None) -> None:
        sha = getattr(self.config, "firmware_sha256", None)
        if not sha:
            raise ValueError("detection_not_ready")
        def change(data):
            maps = data.get("manual_keymaps") if isinstance(data.get("manual_keymaps"), dict) else {}
            current = manual_keymap({"manual_keymaps": maps}, sha)
            if event_code is None:
                current.pop(bit, None)
            else:
                current[bit] = event_code
            if current:
                maps[sha] = {str(k): v for k, v in sorted(current.items())}
            else:
                maps.pop(sha, None)
            data["manual_keymaps"] = maps
        update_settings(change)

    def key_available(self, bit: int) -> bool:
        return self.transport is not None and (self.key_event(bit) is not None or self.transport.can_set_key(bit))

    def set_key(self, bit: int, pressed: bool) -> bool:
        transport = self.transport
        if transport is None:
            return False
        code = self.key_event(bit)
        return (not pressed or transport.can_set_key(bit, code)) and transport.set_key(bit, pressed, code)

    # Live state
    def frame(self):
        return self.transport.decoder.display_snapshot() if self.transport is not None else None

    def secondary(self):
        return self.transport.decoder.secondary_display_snapshot() if self.transport is not None else None

    def fold_state(self) -> bool | None:
        """None when the firmware has no lid; otherwise True when open."""
        transport = self.transport
        if transport is None or not transport.can_set_fold():
            return None
        return transport.board_status_snapshot["level"] == transport.config.board_status_input.default

    def toggle_fold(self) -> str | None:
        opened = self.fold_state()
        if opened is None:
            return None
        return None if self.transport.set_fold(not opened) else self.transport.decoder.input_error

    def metrics(self) -> dict | None:
        transport = self.transport
        if transport is None:
            return None
        decoder = transport.decoder
        secondary = decoder.secondary_display_snapshot()
        frames = str(decoder.frame_sequence) + (f" + {secondary['sequence']}" if secondary and secondary.get("sequence") else "")
        return {"run": f"{transport.instructions:,}", "pc": f"0x{transport.pc:08X}",
                "lcd": f"{decoder.lcd_writes:,}", "frame": frames,
                "virtual_cell": transport.virtual_cell_status if setting("virtual_network") else None}

    def refresh_network_time(self) -> None:
        transport = self.transport
        if transport is not None and setting("virtual_network"):
            timestamp = None if setting("network_host_time") else parse_network_start_time(setting("network_start_time"))
            transport.update_network_time(timestamp, refresh=True)

    def stop(self):
        """Power off; returns the last frame for the library thumbnail."""
        transport, thread, self.transport = self.transport, self._thread, None
        if transport is None:
            return None
        try:
            last = transport.decoder.display_snapshot()
        except Exception:
            last = None
        self._stop.set()
        transport.interrupt()
        if thread is not None:
            thread.join(timeout=10)
        transport.close()
        return last


def remember_boot(firmware: Path, sha: str | None) -> None:
    """Record the boot in the shared library file; other processes write it too, so reload under the lock."""
    from ..gui.firmware_library import FirmwareLibrary
    path = STATE_ROOT / "firmware_library.json"
    with exclusive_path_lock(path):
        library = FirmwareLibrary(path)
        library.add_file(firmware)
        for entry in library.entries:
            if entry.get("path") == str(firmware):
                entry["last_booted"] = time.time()
                if sha:
                    entry["sha256"] = sha
        library.save()


def save_thumbnail(firmware: Path, width: int, height: int, rgb: bytes) -> None:
    from PIL import Image
    from ..gui.firmware_library import FirmwareLibrary
    path = STATE_ROOT / "firmware_library.json"
    with exclusive_path_lock(path):
        library = FirmwareLibrary(path)
        for entry in library.entries:
            if entry.get("path") == str(firmware) and entry.get("sha256"):
                directory = path.parent / "library-thumbnails"
                directory.mkdir(parents=True, exist_ok=True)
                image = Image.frombytes("RGB", (width, height), rgb)
                image.thumbnail((160, 160), Image.Resampling.NEAREST)
                target = directory / (entry["sha256"] + ".png")
                image.save(target)
                entry["thumbnail"] = str(target)
                library.save()
                return
