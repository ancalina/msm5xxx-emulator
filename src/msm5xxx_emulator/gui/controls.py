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


KEYS = UI_TEXT["ko"]["_keys"]


def parse_manual_key_event(text: str) -> int:
    """Parse one opt-in firmware event byte from decimal or log-style hex."""
    value_text = text.strip()
    try:
        # User logs conventionally render event bytes as ``053`` / ``05f``.
        # Keep unprefixed nonzero values decimal, but accept that zero-prefixed
        # firmware notation as hexadecimal.
        base = (
            16 if (len(value_text) > 1 and value_text.startswith("0")
                   and not value_text.lower().startswith(("0x", "0o", "0b")))
            else 0
        )
        value = int(value_text, base)
    except ValueError as error:
        raise ValueError(
            "key event must be 0x00..0xFF, zero-prefixed hex, or decimal 0..255"
        ) from error
    if not 0 <= value <= 0xFF:
        raise ValueError(
            "key event must be 0x00..0xFF, zero-prefixed hex, or decimal 0..255"
        )
    return value


def _log_manual_key_mapping(
        firmware_sha256: str | None, bit: int, event_code: int | None, *,
        accepted: bool, reason: str, mapping_rule: str,
        requested_value: str | None = None,
) -> None:
    """Log one GUI mapping decision without exposing state-file paths."""
    payload = {
        "accepted": accepted,
        "bit": bit,
        "firmware_sha256_prefix": (firmware_sha256 or "unknown")[:12],
        "mapping_source": "manual",
        "mapping_rule": mapping_rule,
        "reason": reason,
        "requested_event": (
            f"0x{event_code:02X}" if event_code is not None else None
        ),
        "requested_source": "manual",
        "requested_value": requested_value,
    }
    LOGGER.info(
        "manual key mapping payload=%s",
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
    )


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


LAYOUT = tuple(tuple(item) for item in UI_TEXT["ko"]["_layout"])


METRIC_TEXT = UI_TEXT["ko"]["_metric_text"]


KEY_TEXT = UI_TEXT["ko"]["_key_text"]


SETTINGS_ENGLISH = UI_TEXT["ko"]["_settings_english"]


def _clean_saved_model(profile: dict[str, object]) -> dict[str, object]:
    """Keep a saved model only when the user explicitly set a nonempty value."""
    result = dict(profile)
    model = result.get("model")
    if (result.get("_model_user_set") is not True
            or not isinstance(model, str) or not model.strip()):
        result.pop("model", None)
        result.pop("_model_user_set", None)
    return result


def merge_settings_overrides(current: dict[str, object], edited: set[str],
                             parsed: dict[str, object],
                             firmware_changed: bool) -> dict[str, object]:
    """Keep prior manual values for one firmware; a new dump starts clean."""
    merged = {} if firmware_changed else _clean_saved_model(current)
    if "model" in edited:
        model = parsed["model"]
        if not isinstance(model, str) or not model.strip():
            raise ValueError(UI_TEXT[resolve_ui_language("auto")]["validation_00"])
        merged["_model_user_set"] = True
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
        if key != "model" and hasattr(baseline, key)
        and value != getattr(baseline, key)
    }
    model = profile.get("model")
    if (profile.get("_model_user_set") is True
            and isinstance(model, str) and model.strip()):
        overrides["model"] = model
        overrides["_model_user_set"] = True
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
        self.settings_button.configure(text=self._text("done_editing" if getattr(self, "editing_input_mapping", False) else "more"))
        self.capture_button.configure(text=self._text("capture"))
        for key, label in self.metric_titles.items():
            label.configure(text=METRIC_TEXT[self.ui_language][key][0])

    def _bind_keyboard(self) -> None:
        by_bit = {bit: label for label, bit in KEYS.items()}
        self.keyboard_mapping = {
            "Up": "▲", "Down": "▼", "Left": "◀", "Right": "▶",
            "Return": "OK", "Escape": by_bit[7],
            "plus": by_bit[10], "KP_Add": by_bit[10],
            "minus": by_bit[8], "KP_Subtract": by_bit[8],
            **{str(number): str(number) for number in range(10)},
            **{f"KP_{number}": str(number) for number in range(10)},
        }
        self.root.bind("<KeyPress>", lambda event: self._keyboard_event(event, True))
        self.root.bind("<KeyRelease>", lambda event: self._keyboard_event(event, False))
        self.root.bind("<FocusOut>", self._release_all)

    def _keyboard_event(self, event: tk.Event, pressed: bool) -> None:
        if getattr(self, "editing_input_mapping", False):
            return
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
        if getattr(self, "editing_input_mapping", False):
            return self._edit_key_mapping(label)
        bit = KEYS[label]
        event_code = self._manual_key_event(bit)
        if not self._key_supported(bit, event_code):
            self._edit_key_mapping(label)
            return "break"
        self._key(bit, True, f"mouse:{bit}", event_code)
        return "break"

    def _mouse_key_release(self, label: str) -> str:
        if getattr(self, "editing_input_mapping", False):
            return "break"
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
            raise ValueError(self._text("detection_not_ready"))
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
        _log_manual_key_mapping(
            firmware_sha256, bit, event_code,
            accepted=True,
            reason=(
                "manual-mapping-deleted" if event_code is None
                else "manual-mapping-saved"
            ),
            mapping_rule=(
                "manual-mapping-delete" if event_code is None
                else "manual-unique-event"
            ),
        )

    def _edit_key_mapping(self, label: str) -> str:
        bit = KEYS[label]
        if self.emulator is None:
            self.status.set(self._text("detecting"))
            return "break"
        if bit in self.held:
            return "break"
        current = self._manual_key_event(bit)
        prompt = self._text("key_prompt")
        value = simpledialog.askstring(
            self._key_text(label), prompt, parent=self.root,
            initialvalue=(f"0x{current:02X}" if current is not None else ""),
        )
        if value is None:
            return "break"
        event_code: int | None = None
        try:
            event_code = parse_manual_key_event(value) if value.strip() else None
            if (event_code is not None
                    and not self._key_supported(bit, event_code)):
                raise ValueError(self._text("mapping_rejected"))
            self._save_manual_key_event(bit, event_code)
        except (OSError, ValueError) as error:
            reason = (
                "invalid-value" if isinstance(error, ValueError)
                else "state-io-error"
            )
            _log_manual_key_mapping(
                self._firmware_sha256(), bit, event_code,
                accepted=False,
                reason=reason,
                mapping_rule=(
                    "manual-event-rejected"
                    if isinstance(error, ValueError)
                    else "manual-state-io-error"
                ),
                requested_value=(
                    f"0x{event_code:02X}"
                    if event_code is not None else "<invalid>"
                ),
            )
            messagebox.showerror(
                self._text("settings_error"),
                self._text("mapping_invalid") if isinstance(error, ValueError) else str(error),
                parent=self.root
            )
        return "break"

    def _settings(self) -> None:
        self._settings_requested = False
        dialog = tk.Toplevel(self.root)
        dialog.title(self._text("settings"))
        dialog.transient(self.root)
        detected = self.emulator.config if self.emulator is not None else getattr(self, "_last_detected_config", None)
        values = (settings_values(self.firmware, detected, self.overrides) if detected is not None
                  else {name: str(self.firmware) if name == "firmware" else ""
                        for _, fields in SETTINGS_SECTIONS for name, _ in fields})
        language_labels = {
            "auto": self._text("auto_system"),
            "ko": self._text("korean"),
            "en": self._text("english_language"),
        }
        language_choice = tk.StringVar(
            value=language_labels[self.ui_language_preference]
        )
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill="both", expand=True, padx=10, pady=(10, 4))
        main_page = ttk.Frame(notebook, padding=10)
        notebook.add(main_page, text=self._text("settings"))
        firmware_frame = ttk.Frame(main_page)
        details = notebook
        if detected is None:
            ttk.Label(main_page, text=self._text("profile_required")).pack(anchor="w")
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
                    (self._text("firmware_file_type"), "*.bin *.dump *.img *.mbn *.hex *.hxb"),
                    (self._text("all_file_types"), "*"),
                ),
            )
            if not chosen:
                return
            entry = entries["firmware"]
            entry.delete(0, tk.END)
            entry.insert(0, chosen)

        for title, fields in SETTINGS_SECTIONS:
            page = ttk.Frame(details, padding=10)
            page.columnconfigure(1, weight=1)
            details.add(page, text=self._settings_text(title))
            for row, (name, label) in enumerate(fields):
                if name == "firmware":
                    continue
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
                if detected is None:
                    widget.configure(state="disabled")
                entries[name] = widget
                if name == "firmware":
                    ttk.Button(page, text=self._text("choose_file"),
                               command=choose_firmware).grid(
                        row=row, column=2, sticky="e", padx=(8, 0), pady=2)

        firmware_entry = ttk.Entry(firmware_frame, width=35)
        firmware_entry.insert(0, values["firmware"])
        entries["firmware"] = firmware_entry
        if hasattr(self, "_settings_main_controls"):
            self._settings_main_controls(main_page)
        language_frame = ttk.Frame(main_page, padding=(0, 10, 0, 0))
        language_frame.pack(fill="x")
        ttk.Label(language_frame, text=self._text("ui_language")).pack(side="left")
        ttk.Combobox(language_frame, textvariable=language_choice,
                     values=tuple(language_labels.values()), state="readonly",
                     width=20).pack(side="right")
        if hasattr(self, "_settings_display_controls"):
            self._settings_display_controls(main_page)

        def apply() -> None:
            try:
                ui_language = next(
                    (name for name, label in language_labels.items()
                     if label == language_choice.get()),
                    None,
                )
                if ui_language is None:
                    raise ValueError(self._text("language_invalid"))
                if detected is None:
                    old_language = self.ui_language
                    self.ui_language_preference = ui_language
                    self.ui_language = resolve_ui_language(ui_language)
                    self._save_config()
                    dialog.destroy()
                    if self.ui_language != old_language:
                        self._apply_ui_language()
                    return
                raw = {name: widget.get().strip() for name, widget in entries.items()}
                firmware = Path(raw["firmware"]).expanduser().resolve()
                if not firmware.is_file():
                    raise ValueError(self._text("missing_firmware"))
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
                        config, self.overrides = detect_profile(
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
                    self._prepared_profile = (config, dict(self.overrides))
                    self._restart()
                    return
                overrides = parse_settings_values(raw, self.ui_language)
                minimal = merge_settings_overrides(
                    self.overrides, edited, overrides, firmware_changed
                )
                effective = detect(firmware, argparse.Namespace(**minimal))
                overrides = {name: getattr(effective, name) for name in overrides}
                validate_settings_values(
                    firmware, effective, overrides, edited, raw["flash_state"], self.ui_language
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
                self.status.set(self._text("framebuffer_applying"))
            else:
                self._prepared_profile = (effective, dict(minimal))
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

    def _load_persistent_state(self) -> bool:
        try:
            data = json.loads(LAST_CONFIG.read_text(encoding="utf-8"))
            return data.get("persistent_state", True) is True
        except (AttributeError, OSError, ValueError):
            return True

    def _load_virtual_network(self, key: str = "virtual_network") -> bool:
        try:
            data = json.loads(LAST_CONFIG.read_text(encoding="utf-8"))
            return data.get(key, key == "network_host_time") is True
        except (AttributeError, OSError, ValueError):
            return key == "network_host_time"

    def _load_network_start_time(self) -> str:
        try:
            value = json.loads(LAST_CONFIG.read_text(encoding="utf-8")).get("network_start_time", "")
            return value if isinstance(value, str) else ""
        except (AttributeError, OSError, ValueError):
            return ""

    def _load_config(self) -> dict[str, object]:
        try:
            data = json.loads(LAST_CONFIG.read_text(encoding="utf-8"))
            profiles = data.get("profiles", {})
            profile = profiles.get(str(self.firmware.resolve()), {})
            if not isinstance(profile, dict):
                return {}
            return _clean_saved_model(profile)
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
            profiles[str(self.firmware.resolve())] = _clean_saved_model(self.overrides)
            manual_keymaps = data.get("manual_keymaps")
            if not isinstance(manual_keymaps, dict):
                manual_keymaps = {}
            settings = {
                "ui_language": self.ui_language_preference,
                "profiles": profiles,
                "manual_keymaps": manual_keymaps,
            }
            for key in ("virtual_network", "network_host_time", "persistent_state"):
                if hasattr(self, key + "_enabled") or key in data:
                    settings[key] = getattr(self, key + "_enabled", data.get(key) is True)
            if hasattr(self, "network_start_time") or "network_start_time" in data:
                settings["network_start_time"] = getattr(self, "network_start_time", data.get("network_start_time", ""))
            atomic_write_text(path, json.dumps(
                settings, ensure_ascii=False, indent=2) + "\n")
            LOGGER.info("GUI profile saved firmware=%s override_keys=%s",
                        self.firmware.name, sorted(self.overrides))
