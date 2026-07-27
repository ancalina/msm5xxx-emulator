from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from ..detection.firmware import (DEFAULT_STATE_ROOT, DISABLEABLE_ADDRESS_FIELDS,
                                  detect)
from ..state_io import atomic_write_text, exclusive_path_lock

from .locale import (UI_TEXT, normalize_ui_language, resolve_ui_language)
from .settings import (BOOLEAN_FIELDS, SETTINGS_SECTIONS, parse_settings_values,
                       settings_values, validate_settings_values)


LOGGER = logging.getLogger("gui")
LAST_CONFIG = DEFAULT_STATE_ROOT / "last_config.json"


GUI_ZERO_DISABLE_FIELDS = DISABLEABLE_ADDRESS_FIELDS | {
    "audio_play_address", "fast_boot_address",
}


KEYS = {
    "메뉴": 0, "▲": 1, "취소": 2, "통화": 3, "◀": 4,
    "OK": 5, "▶": 6, "종료": 7, "볼륨-": 8, "▼": 9,
    "볼륨+": 10, "1": 11, "2": 12, "3": 13, "4": 14, "5": 15,
    "6": 16, "7": 17, "8": 18, "9": 19, "*": 20, "0": 21, "#": 22,
}


def parse_manual_key_event(text: str) -> int:
    """Parse one opt-in firmware event byte without guessing its base."""
    try:
        value = int(text.strip(), 0)
    except ValueError as error:
        raise ValueError("key event must be 0x00..0xFF or decimal 0..255") from error
    if not 0 <= value <= 0xFF:
        raise ValueError("key event must be 0x00..0xFF or decimal 0..255")
    return value


def manual_keymap(data: object, firmware_sha256: str) -> dict[int, int]:
    """Read one validated SHA-scoped GUI mapping from saved preferences."""
    if not isinstance(data, dict):
        return {}
    mappings = data.get("manual_keymaps")
    raw = mappings.get(firmware_sha256) if isinstance(mappings, dict) else None
    if not isinstance(raw, dict):
        return {}
    valid_bits = set(KEYS.values())
    result: dict[int, int] = {}
    for key, value in raw.items():
        try:
            bit = int(key)
        except (TypeError, ValueError):
            continue
        if (bit in valid_bits and isinstance(value, int)
                and not isinstance(value, bool) and 0 <= value <= 0xFF):
            result[bit] = value
    return result


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


METRIC_TEXT = {
    "ko": {
        "run": ("실행", "지금까지 실행한 guest CPU 명령어 수"),
        "pc": ("PC", "Program Counter: 다음에 실행할 guest 코드 주소"),
        "lcd": ("LCD", "firmware가 LCD port에 기록한 누적 횟수"),
        "frame": ("프레임", "완성된 화면으로 게시한 누적 횟수"),
    },
    "en": {
        "run": ("Run", "Guest CPU instructions executed so far"),
        "pc": ("PC", "Program Counter: guest code address to execute next"),
        "lcd": ("LCD", "Firmware writes observed on LCD ports"),
        "frame": ("Frame", "Completed display frames published"),
    },
}


KEY_TEXT = {
    "ko": {},
    "en": {
        "메뉴": "Menu", "취소": "Cancel", "통화": "Call", "종료": "End",
        "볼륨-": "Vol-", "볼륨+": "Vol+",
    },
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


def settings_apply_mode(edited: set[str], firmware_changed: bool) -> str:
    """Keep harmless UI and clean-firmware changes out of override validation."""
    if not edited:
        return "firmware" if firmware_changed else "language"
    return "overrides"


def can_apply_live_framebuffer_format(edited: set[str], firmware_changed: bool,
                                      framebuffer_address: int | None,
                                      framebuffer_format: str,
                                      worker_active: bool = True) -> bool:
    """Allow the colour-map-only setting to update a running framebuffer."""
    return (worker_active and not firmware_changed and edited == {"framebuffer_format"}
            and framebuffer_address is not None
            and framebuffer_format != "none")


def detect_profile(firmware: Path, profile: dict[str, object]) -> tuple[object, dict[str, object]]:
    """Detect once for normal startup while migrating legacy saved auto values."""
    baseline = detect(firmware)
    overrides = {
        key: value for key, value in profile.items()
        if hasattr(baseline, key) and value != getattr(baseline, key)
    }
    config = (detect(firmware, argparse.Namespace(**overrides))
              if overrides else baseline)
    return config, overrides


class ControlsMixin:
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
        for key, label in self.metric_titles.items():
            label.configure(text=METRIC_TEXT[self.ui_language][key][0])

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
        event_code = self._manual_key_event(bit)
        if pressed and not self._key_supported(bit, event_code):
            return
        if pressed:
            self._keyboard_press(source, bit, event_code)
        else:
            self._keyboard_release(source, bit)

    def _keyboard_press(self, source: str, bit: int,
                        event_code: int | None = None) -> None:
        pending = self.pending_key_releases.pop(source, None)
        if pending is not None:
            self.root.after_cancel(pending)
        self.keyboard_sources.add(source)
        self.keyboard_bits[source] = bit
        self._key(bit, True, source, event_code)

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

    def _key(self, bit: int, pressed: bool, source: str = "legacy",
             event_code: int | None = None) -> None:
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
        self.commands.put(
            (bit, pressed, event_code) if event_code is not None
            else (bit, pressed)
        )

    def _key_supported(self, bit: int, event_code: int | None = None) -> bool:
        emulator = self.emulator
        return emulator is not None and emulator.can_set_key(bit, event_code)

    def _mouse_key_press(self, label: str) -> str:
        bit = KEYS[label]
        event_code = self._manual_key_event(bit)
        if not self._key_supported(bit, event_code):
            self._edit_key_mapping(label)
            return "break"
        self._key(bit, True, f"mouse:{bit}", event_code)
        return "break"

    def _mouse_key_release(self, label: str) -> str:
        bit = KEYS[label]
        self._key(bit, False, f"mouse:{bit}")
        return "break"

    def _firmware_sha256(self) -> str | None:
        emulator = self.emulator
        value = (
            getattr(emulator.config, "firmware_sha256", None)
            if emulator is not None else None
        )
        return value if isinstance(value, str) and value else None

    def _manual_key_event(self, bit: int) -> int | None:
        firmware_sha256 = self._firmware_sha256()
        if firmware_sha256 is None:
            return None
        if getattr(self, "_manual_key_sha256", None) != firmware_sha256:
            try:
                data = json.loads(LAST_CONFIG.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            self._manual_key_events = manual_keymap(data, firmware_sha256)
            self._manual_key_sha256 = firmware_sha256
        return getattr(self, "_manual_key_events", {}).get(bit)

    def _save_manual_key_event(self, bit: int,
                               event_code: int | None) -> None:
        firmware_sha256 = self._firmware_sha256()
        if firmware_sha256 is None:
            raise ValueError("firmware detection is not ready")
        path = LAST_CONFIG
        with exclusive_path_lock(path):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            if not isinstance(data, dict):
                data = {}
            mappings = data.get("manual_keymaps")
            if not isinstance(mappings, dict):
                mappings = {}
            current = manual_keymap(
                {"manual_keymaps": mappings}, firmware_sha256
            )
            if event_code is None:
                current.pop(bit, None)
            else:
                current[bit] = event_code
            if current:
                mappings[firmware_sha256] = {
                    str(key): value for key, value in sorted(current.items())
                }
            else:
                mappings.pop(firmware_sha256, None)
            data["manual_keymaps"] = mappings
            atomic_write_text(
                path, json.dumps(data, ensure_ascii=False, indent=2) + "\n"
            )
        self._manual_key_events = current
        self._manual_key_sha256 = firmware_sha256
        LOGGER.info(
            "manual key mapping firmware_sha256=%s bit=%d event=%s",
            firmware_sha256[:12], bit,
            "reset" if event_code is None else f"0x{event_code:02X}",
        )

    def _edit_key_mapping(self, label: str) -> str:
        bit = KEYS[label]
        if self.emulator is None:
            self.status.set(self._text("detecting"))
            return "break"
        if bit in self.held:
            return "break"
        current = self._manual_key_event(bit)
        prompt = (
            "검출된 matrix event byte 입력 (예: 0x53).\n"
            "펌웨어 event table의 고유 row/column만 사용합니다.\n"
            "빈 값은 수동 매핑 삭제."
            if self.ui_language == "ko" else
            "Enter detected matrix event byte (example: 0x53).\n"
            "Only a unique row/column in firmware event table is used.\n"
            "Leave empty to remove manual mapping."
        )
        value = simpledialog.askstring(
            self._key_text(label), prompt, parent=self.root,
            initialvalue=(f"0x{current:02X}" if current is not None else ""),
        )
        if value is None:
            return "break"
        try:
            event_code = parse_manual_key_event(value) if value.strip() else None
            if (event_code is not None
                    and not self._key_supported(bit, event_code)):
                raise ValueError(
                    f"event 0x{event_code:02X} is absent or duplicated "
                    "in the detected matrix"
                )
            self._save_manual_key_event(bit, event_code)
        except (OSError, ValueError) as error:
            messagebox.showerror(
                self._text("settings_error"), str(error), parent=self.root
            )
        return "break"

    def _settings(self) -> None:
        if self.emulator is None:
            # Detection already runs in the worker.  Running it here freezes Tk
            # for multi-second firmware scans before the dialog can appear.
            self._settings_requested = True
            self.status.set(self._text("detecting"))
            return
        self._settings_requested = False
        dialog = tk.Toplevel(self.root)
        dialog.title(self._text("boot_settings"))
        dialog.transient(self.root)
        detected = self.emulator.config

        values = settings_values(self.firmware, detected, self.overrides)
        language_labels = {
            "auto": "자동 (시스템)" if self.ui_language == "ko" else "Auto (System)",
            "ko": "한국어",
            "en": "English",
        }
        language_choice = tk.StringVar(
            value=language_labels[self.ui_language_preference]
        )
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
                    ("Firmware images", "*.bin *.dump *.img *.mbn *.hex *.hxb"),
                    ("All files", "*"),
                ),
            )
            if not chosen:
                return
            entry = entries["firmware"]
            entry.delete(0, tk.END)
            entry.insert(0, chosen)

        for title, fields in SETTINGS_SECTIONS:
            page = ttk.Frame(notebook, padding=10)
            page.columnconfigure(1, weight=1)
            notebook.add(page, text=self._settings_text(title))
            for row, (name, label) in enumerate(fields):
                ttk.Label(page, text=self._settings_text(label)).grid(
                    row=row, column=0, sticky="w", pady=2
                )
                if name in BOOLEAN_FIELDS:
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
                    ttk.Button(page, text=self._text("choose_file"),
                               command=choose_firmware).grid(
                        row=row, column=2, sticky="e", padx=(8, 0), pady=2)

        def apply() -> None:
            try:
                ui_language = next(
                    (name for name, label in language_labels.items()
                     if label == language_choice.get()),
                    None,
                )
                if ui_language is None:
                    raise ValueError("UI language selection is invalid")
                raw = {name: widget.get().strip() for name, widget in entries.items()}
                firmware = Path(raw["firmware"]).expanduser().resolve()
                if not firmware.is_file():
                    raise ValueError("펌웨어 파일 없음")
                edited = {
                    name for name in entries
                    if name != "firmware" and raw[name] != values[name].strip()
                }
                firmware_changed = firmware != self.firmware.resolve()
                mode = settings_apply_mode(edited, firmware_changed)
                if mode == "language":
                    old_preference, old_language = (
                        self.ui_language_preference, self.ui_language
                    )
                    self.ui_language_preference = ui_language
                    self.ui_language = resolve_ui_language(ui_language)
                    try:
                        self._save_config()
                    except OSError:
                        self.ui_language_preference, self.ui_language = (
                            old_preference, old_language
                        )
                        raise
                    dialog.destroy()
                    if self.ui_language != old_language:
                        self._apply_ui_language()
                    return
                if mode == "firmware":
                    old_firmware, old_overrides = self.firmware, self.overrides
                    old_preference, old_language = (
                        self.ui_language_preference, self.ui_language
                    )
                    self.firmware = firmware
                    try:
                        _config, self.overrides = detect_profile(
                            firmware, self._load_config()
                        )
                    except (OSError, ValueError):
                        self.firmware, self.overrides = old_firmware, old_overrides
                        raise
                    self.ui_language_preference = ui_language
                    self.ui_language = resolve_ui_language(ui_language)
                    try:
                        self._save_config()
                    except OSError:
                        self.firmware, self.overrides = old_firmware, old_overrides
                        self.ui_language_preference, self.ui_language = (
                            old_preference, old_language
                        )
                        raise
                    dialog.destroy()
                    if self.ui_language != old_language:
                        self._apply_ui_language()
                    self._restart()
                    return
                overrides = parse_settings_values(raw)
                minimal = merge_settings_overrides(
                    self.overrides, edited, overrides, firmware_changed
                )
                effective = detect(firmware, argparse.Namespace(**minimal))
                overrides = {name: getattr(effective, name) for name in overrides}
                validate_settings_values(
                    firmware, effective, overrides, edited, raw["flash_state"]
                )
                framebuffer_address = overrides["framebuffer_address"]
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
                messagebox.showerror(self._text("settings_save_error"), str(error),
                                     parent=dialog)
                return
            dialog.destroy()
            language_changed = self.ui_language != old_ui_language
            language_preference_changed = (
                self.ui_language_preference != old_ui_preference
            )
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
            return dict(profile)
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
            manual_keymaps = data.get("manual_keymaps")
            if not isinstance(manual_keymaps, dict):
                manual_keymaps = {}
            atomic_write_text(
                path,
                json.dumps({
                    "ui_language": self.ui_language_preference,
                    "profiles": profiles,
                    "manual_keymaps": manual_keymaps,
                }, ensure_ascii=False, indent=2) + "\n",
            )
            LOGGER.info("GUI profile saved firmware=%s override_keys=%s",
                        self.firmware.name, sorted(self.overrides))
