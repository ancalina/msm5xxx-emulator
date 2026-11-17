"""Per-firmware profile, key mapping and network-time helpers shared by every desktop and mobile front end.

No UI toolkit imports: the native GUIs reach these through the backend process."""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

import msm5xxx_emulator.detection.plan as boot_plan
from ..gui.locale import UI_TEXT, resolve_ui_language
from ..qemu.virtual_cell import virtual_cell_scenario

from ..detection.registry import device_domain

detect = boot_plan.detect
DEFAULT_STATE_ROOT = device_domain('storage.configuration').DEFAULT_STATE_ROOT
LOGGER = logging.getLogger("gui")
KEYS = UI_TEXT["ko"]["_keys"]
GUI_ZERO_DISABLE_FIELDS = boot_plan.DISABLEABLE_ADDRESS_FIELDS | {
    "audio_play_address", "fast_boot_address",
}

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

_detect_memo: dict = {}
_detector_fingerprint_value: str | None = None


def _detector_fingerprint() -> str:
    """Hash of the installed detector source; an update changes it and forces re-detection."""
    global _detector_fingerprint_value
    if _detector_fingerprint_value is None:
        import hashlib
        import msm5xxx_emulator
        root = Path(msm5xxx_emulator.__file__).parent
        digest = hashlib.sha256()
        for path in sorted(root.rglob("*.py")):
            digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
        _detector_fingerprint_value = digest.hexdigest()
    return _detector_fingerprint_value


def detect_cached(firmware: Path):
    """Baseline detect() reused per firmware content and detector version (memory, then the state folder).

    Same rule as the mobile runtimes' detect_cached."""
    import copy
    import hashlib
    import os
    import pickle
    if detect is not boot_plan.detect:  # a substituted detector (tests) must not fill the shared cache
        return detect(firmware)
    firmware = Path(firmware)
    try:
        content = firmware.read_bytes()
    except OSError:
        return detect(firmware)  # let the detector report the unreadable input
    key = (_detector_fingerprint(), hashlib.sha256(content).hexdigest())
    config = _detect_memo.get(key)
    if config is None:
        cache = DEFAULT_STATE_ROOT / "detect-cache" / (key[1] + ".pickle")
        try:
            stored_key, config = pickle.loads(cache.read_bytes())  # file written below in the user's state folder
            if stored_key != key:
                config = None
        except Exception:
            config = None
        if config is None:
            config = detect(firmware)
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                temporary = cache.with_name(cache.name + ".tmp")
                temporary.write_bytes(pickle.dumps((key, config)))
                os.replace(temporary, cache)
            except Exception:
                pass  # unwritable location or unpicklable config: memory cache only
        _detect_memo[key] = config
    config = copy.deepcopy(config)  # callers (Transport) append notes to their config
    if hasattr(config, "path"):
        config.path = type(config.path)(firmware) if config.path is not None else firmware
    return config


def detect_profile(firmware: Path, profile: dict[str, object]) -> tuple[object, dict[str, object]]:
    """Detect once for normal startup while migrating legacy saved auto values."""
    baseline = detect_cached(firmware)
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


def parse_network_start_time(value: str) -> float | None:
    if not value.strip():
        return None
    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M")
    if parsed.strftime("%Y-%m-%d %H:%M") != value:
        raise ValueError("invalid date format")
    try:
        timestamp = parsed.timestamp()
        local = datetime.fromtimestamp(timestamp)
    except (OSError, OverflowError) as error:  # Windows rejects times near the epoch
        raise ValueError("invalid local time") from error
    if local != parsed:
        raise ValueError("invalid local time")
    virtual_cell_scenario(False, start_time=timestamp)
    return timestamp
