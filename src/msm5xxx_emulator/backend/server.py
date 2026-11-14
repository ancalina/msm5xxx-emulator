"""Backend process for the native desktop apps: python -m msm5xxx_emulator.backend [--qemu PATH]

One JSON object per line on stdin and stdout (UTF-8). Request: {"id": n, "method": "...", "params": {...}}.
Reply: {"id": n, "result": ...} or {"id": n, "error": {"code": "...", "message": "..."}}. Requests are
answered in order. Logs go to stderr. The GUI starts one process per emulator window (session.*) and may
use another for the library (library.*, settings.*, ui.*). See PROTOCOL.md for every method."""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import threading
from pathlib import Path

from ..gui.locale import UI_TEXT, display_model_name, resolve_ui_language
from ..gui.settings import BOOLEAN_FIELDS, SETTINGS_SECTIONS
from .profile import KEYS, parse_manual_key_event, parse_network_start_time
from .session import DEFAULTS, STATE_ROOT, Session, remember_boot, save_setting, save_thumbnail, setting

PROTOCOL_VERSION = 1
KEY_TEXT = UI_TEXT["ko"]["_key_text"]
LAYOUT = tuple(tuple(item) for item in UI_TEXT["ko"]["_layout"])
METRIC_TEXT = UI_TEXT["ko"]["_metric_text"]
CHOICES = {"chipset": ["MSM5000", "MSM5100", "MSM5105", "MSM5500", "MSM5xxx"],
           "framebuffer_format": ["none", "rgb565le", "bgr565le", "rgb565be", "bgr565be"],
           **{name: ["true", "false"] for name in BOOLEAN_FIELDS}}


class Failure(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def _language() -> str:
    return resolve_ui_language(setting("ui_language"))


def _rgb(width: int, height: int, data: bytes) -> dict:
    return {"width": width, "height": height, "rgb": base64.b64encode(bytes(data)).decode("ascii")}


class Backend:
    def __init__(self, qemu: Path) -> None:
        self.qemu = qemu
        self.session: Session | None = None
        self._library = None

    # library.*
    @property
    def library(self):
        if self._library is None:
            from ..gui.firmware_library import FirmwareLibrary
            self._library = FirmwareLibrary(STATE_ROOT / "firmware_library.json")
        return self._library

    def library_scan(self) -> dict:
        from ..gui.firmware_library import FirmwareLibrary
        self._library = FirmwareLibrary(STATE_ROOT / "firmware_library.json")  # pick up other windows' changes
        entries = self._library.scan()
        keep = ("path", "name", "model", "chipset", "size", "available", "last_booted", "thumbnail", "sha256")
        return {"folders": list(self._library.folders),
                "entries": [{key: entry.get(key) for key in keep} for entry in entries]}

    def library_add_file(self, path: str) -> None:
        self.library.add_file(Path(path))

    def library_add_folder(self, path: str) -> None:
        self.library.add_folder(Path(path))

    def library_remove_folder(self, path: str) -> None:
        self.library.remove_folder(Path(path))

    def library_remove(self, path: str) -> None:
        self.library.remove(Path(path))

    # settings.* (app-wide; same file and keys as the existing desktop app)
    def settings_get(self) -> dict:
        return {key: setting(key) for key in DEFAULTS}

    def settings_set(self, key: str, value) -> None:
        if key not in DEFAULTS or type(value) is not type(DEFAULTS[key]):
            raise Failure("invalid_setting", key)
        if key == "network_start_time":
            try:
                parse_network_start_time(value)
            except (ValueError, OverflowError, OSError):
                raise Failure("network_time_error", UI_TEXT[_language()]["network_time_error"]) from None
        if key == "ui_language" and value not in ("auto", "ko", "en"):
            raise Failure("invalid_setting", key)
        save_setting(key, value)

    # ui.* (shared data the native apps render with their own widgets)
    def ui_layout(self) -> dict:
        language = _language()
        return {"language": language,
                "keys": [{"label": label, "bit": KEYS[label], "row": row, "column": column,
                          "text": KEY_TEXT[language].get(label, label),
                          "accessible_name": KEY_TEXT["en"].get(label, label)} for label, row, column in LAYOUT],
                "metrics": [{"key": key, "title": title, "description": description}
                            for key, (title, description) in METRIC_TEXT[language].items()],
                "keyboard": {"Up": 1, "Down": 9, "Left": 4, "Right": 6, "Return": 5, "Escape": 7,
                             "plus": 10, "KP_Add": 10, "minus": 8, "KP_Subtract": 8,
                             **{str(n): KEYS[str(n)] for n in range(10)}},
                "key_hold_ms": 150}

    # session.*
    def _session(self) -> Session:
        if self.session is None:
            raise Failure("no_session")
        return self.session

    def session_open(self, firmware: str) -> None:
        if self.session is not None and self.session.transport is not None:
            raise Failure("session_running")
        self.session = Session(self.qemu, Path(firmware))

    def session_start(self) -> dict:
        session = self._session()
        if session.transport is not None:
            raise Failure("session_running")
        transport = session.start()
        config = transport.config
        try:
            remember_boot(session.firmware, config.firmware_sha256)
        except OSError:
            pass
        return {"title": display_model_name(config.model, config.verified_model, _language(), session.firmware.stem),
                "model": config.model, "chipset": config.chipset, "width": config.width, "height": config.height,
                "firmware_sha256": config.firmware_sha256,
                "keys": [bit for bit in KEYS.values() if session.key_available(bit)]}

    def session_stop(self) -> None:
        session = self._session()
        last = session.stop()
        if last and last[2]:
            try:
                save_thumbnail(session.firmware, *last)
            except OSError:
                pass

    def session_frame(self, since: int = -1, secondary_since: int = -1) -> dict:
        """Primary and secondary display; image data only when the sequence changed."""
        transport = self._session().transport
        if transport is None:
            return {"running": False}
        decoder = transport.decoder
        result = {"running": transport.process.poll() is None}
        sequence = int(decoder.frame_sequence)
        result["seq"] = sequence
        if sequence != since:
            width, height, frame = decoder.display_snapshot()
            if frame:
                result.update(_rgb(width, height, frame))
        snapshot = decoder.secondary_display_snapshot()
        if snapshot and snapshot.get("qualified"):
            secondary = {"seq": int(snapshot.get("sequence", 0)), "enabled": snapshot["enabled"],
                         "preview": snapshot.get("encoding") == "unverified-byte-preview"}
            if secondary["seq"] != secondary_since:
                width, height = snapshot["width"], snapshot["height"]
                data = bytes(width * height * 3) if snapshot["enabled"] is False else snapshot["frame"]
                secondary.update(_rgb(width, height, data))
            result["secondary"] = secondary
        return result

    def session_state(self) -> dict:
        session = self._session()
        transport = session.transport
        if transport is None:
            return {"running": False}
        width, height, _ = transport.decoder.display_snapshot()
        metrics = session.metrics()
        return {"running": transport.process.poll() is None, "chipset": transport.config.chipset,
                "width": width, "height": height, "fold": session.fold_state(),
                "virtual_cell": metrics.pop("virtual_cell"), "metrics": metrics,
                "input_error": transport.decoder.input_error or None}

    def session_key(self, bit: int, pressed: bool) -> bool:
        return self._session().set_key(int(bit), bool(pressed))

    def session_fold(self) -> None:
        error = self._session().toggle_fold()
        if error:
            raise Failure("input_error", error)

    def session_network_time(self) -> None:
        self._session().refresh_network_time()

    def session_settings(self) -> dict:
        """Hardware values for the settings pages (labels already in the UI language)."""
        session = self._session()
        values = session.settings_values()
        if values is None:
            raise Failure("detection_not_ready", UI_TEXT[_language()]["detection_not_ready"])
        english = _language() == "en"
        names = UI_TEXT["ko"]["_settings_english"]
        label = (lambda text: names.get(text, text)) if english else (lambda text: text)
        return {"sections": [{"title": label(title), "fields": [
                    {"name": name, "label": label(text), "value": values[name], "choices": CHOICES.get(name)}
                    for name, text in fields if name != "firmware"]} for title, fields in SETTINGS_SECTIONS]}

    def session_apply_settings(self, values: dict) -> None:
        """Validated like the existing desktop app; takes effect at the next session.start."""
        try:
            self._session().apply_settings({str(k): str(v).strip() for k, v in values.items()}, _language())
        except ValueError as error:
            raise Failure("settings_error", str(error)) from None

    def session_key_mapping(self, bit: int) -> int | None:
        return self._session().key_event(int(bit))

    def session_set_key_mapping(self, bit: int, value: str) -> int | None:
        """value: '' clears; decimal, 0x.. or zero-prefixed hex byte. Kept as entered (no detection check)."""
        try:
            code = parse_manual_key_event(value) if value.strip() else None
        except ValueError:
            raise Failure("mapping_invalid", UI_TEXT[_language()]["mapping_invalid"]) from None
        try:
            self._session().save_key_event(int(bit), code)
        except ValueError:
            raise Failure("detection_not_ready", UI_TEXT[_language()]["detection_not_ready"]) from None
        return code

    def hello(self) -> dict:
        return {"protocol": PROTOCOL_VERSION, "language": _language(), "state_root": str(STATE_ROOT)}


METHODS = {name.replace("_", ".", 1): name for name in dir(Backend)
           if not name.startswith("_") and callable(getattr(Backend, name)) and name != "library"}


def serve(backend: Backend, source=sys.stdin, sink=sys.stdout) -> None:
    lock = threading.Lock()
    def reply(message: dict) -> None:
        with lock:
            sink.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
            sink.flush()
    for line in source:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            ident, method, params = request.get("id"), request.get("method"), request.get("params") or {}
        except (ValueError, AttributeError):
            reply({"id": None, "error": {"code": "bad_request", "message": "invalid JSON"}})
            continue
        handler = METHODS.get(method)
        if handler is None or not isinstance(params, dict):
            reply({"id": ident, "error": {"code": "unknown_method", "message": str(method)}})
            continue
        try:
            reply({"id": ident, "result": getattr(backend, handler)(**params)})
        except Failure as error:
            reply({"id": ident, "error": {"code": error.code, "message": str(error)}})
        except TypeError as error:
            reply({"id": ident, "error": {"code": "bad_params", "message": str(error)}})
        except Exception as error:  # report, keep serving
            reply({"id": ident, "error": {"code": "internal", "message": f"{type(error).__name__}: {error}"}})
    if backend.session is not None:
        backend.session.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m msm5xxx_emulator.backend")
    default = Path(__file__).resolve().parents[3] / "bin" / ("qemu-system-arm.exe" if os.name == "nt" else "qemu-system-arm")
    parser.add_argument("--qemu", type=Path, default=Path(os.environ.get("MSM5XXX_QEMU", default)))
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8")
    serve(Backend(args.qemu.resolve()))
    return 0
