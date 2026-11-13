"""Thin JSON boundary around the canonical firmware detector."""

import json
import os
import time
import platform
import signal
import struct
import sys
import threading
from pathlib import Path


_session = None
_session_stop = None
_session_thread = None
_session_error = None
_session_log = None
_original_stderr = None
_log_offset = 0
_log_next = 0
_scanout_sent = {}
_background_paused = False
_PCM_PACKET = struct.Struct("<4sIQQQ")
def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def probe():
    import capstone
    import numpy
    from msm5xxx_emulator.qemu.gdb_remote import Remote
    from msm5xxx_emulator.qemu.transport import Transport
    from msm5xxx_emulator.qemu.decoder import QemuDecoder
    from msm5xxx_emulator.detection import detect

    return _json({
        "capstone": capstone.__version__,
        "detector_entry": callable(detect),
        "gdb_remote": callable(getattr(Remote, "command", None)),
        "numpy": numpy.__version__,
        "python": platform.python_version(),
        "qemu_transport": callable(Transport),
        "schema": 1,
        "qemu_decoder": callable(QemuDecoder),
    })


_detector_fingerprint_value = None
_detect_memo = {}


def _detector_fingerprint():
    """Hash of the installed detector source; an app update changes it and forces re-detection."""
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


def detect_cached(firmware):
    """detect() reused per firmware content and detector version (memory, then a shared cache folder).

    Each selection gets a fresh private copy, so the cache is keyed by content, not path; the
    only path-dependent field of the result is ``path``, which is set to the requested copy."""
    import copy
    import hashlib
    import pickle
    from msm5xxx_emulator.detection import detect
    firmware = Path(firmware)
    try:
        content = firmware.read_bytes()
    except OSError:
        return detect(firmware)  # let the detector report the unreadable input
    key = (_detector_fingerprint(), hashlib.sha256(content).hexdigest())
    config = _detect_memo.get(key)
    if config is None:
        # session/<token>/firmware.bin -> session/../detect-cache, outside any per-copy folder
        cache = firmware.resolve().parent.parent.parent / "detect-cache" / (key[1] + ".pickle")
        try:
            stored_key, config = pickle.loads(cache.read_bytes())  # app-private file written below
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


def detect_profile(firmware_path):
    # The existing JNI entry point accepts absolute paths for ordinary detection.
    # An explicit protocol prefix carries library requests without changing JNI.
    if firmware_path.startswith("library-v1:"):
        return library_describe(firmware_path[len("library-v1:"):])
    config = detect_cached(Path(firmware_path))
    profile = config.diagnostic_config()
    if config.image_kind != "firmware":
        accepted = False
        reject_reason = config.image_kind
    elif config.chipset == "MSM6050":
        accepted = False
        reject_reason = "chipset outside MSM5000/MSM5100/MSM5500 scope"
    else:
        accepted = True
        reject_reason = None
    return _json({
        "accepted": accepted,
        "profile": profile,
        "reject_reason": reject_reason,
        "schema": 1,
    })


def library_describe(request_json):
    from msm5xxx_emulator.gui.firmware_library import FirmwareLibrary, describe_file, source_size_limit
    request = json.loads(request_json)
    if isinstance(request, dict) and set(request) == {"limit_name"} and isinstance(request["limit_name"], str):
        return _json({"limit": source_size_limit(Path(request["limit_name"]))})
    if (not isinstance(request, dict) or set(request) != {"path", "cache", "name"}
            or not all(isinstance(request[k], str) for k in request)):
        raise ValueError("invalid library request")
    library = FirmwareLibrary(Path(request["cache"]))
    result = describe_file(Path(request["path"]), library.cache, name=request["name"])
    library.save()
    return _json(result)


def _apply_settings(firmware, baseline, edits):
    """Apply sparse user edits through the desktop parser and validator."""
    import argparse
    from msm5xxx_emulator.gui.settings import (SETTINGS_SECTIONS, settings_values,
        parse_settings_values, validate_settings_values)
    from msm5xxx_emulator.detection import detect
    from msm5xxx_emulator.detection.plan import DISABLEABLE_ADDRESS_FIELDS
    if not isinstance(edits, dict):
        raise ValueError("invalid settings")
    names = {name for _, fields in SETTINGS_SECTIONS for name, _ in fields} - {"firmware"}
    if set(edits) - names or any(not isinstance(value, str) for value in edits.values()):
        raise ValueError("invalid settings fields")
    if not edits:
        return baseline
    values = settings_values(firmware, baseline, {})
    values.update(edits)
    parsed = parse_settings_values(values)
    overrides = {name: (0 if parsed[name] is None and name in DISABLEABLE_ADDRESS_FIELDS else parsed[name])
                 for name in edits if parsed[name] is not None or name in DISABLEABLE_ADDRESS_FIELDS}
    if "model" in overrides:
        overrides["_model_user_set"] = True
    effective = detect(firmware, argparse.Namespace(**overrides))
    effective_values = {name: getattr(effective, name) for name in parsed}
    validate_settings_values(firmware, effective, effective_values, set(edits), values["flash_state"])
    return effective


def _replay(transport, stop):
    global _session_error
    try:
        transport.replay(stop)
    except Exception as error:
        _session_error = type(error).__name__ + ": " + str(error)


def start_session(request_json):
    global _session, _session_stop, _session_thread, _session_error
    global _scanout_sent, _session_log, _original_stderr, _log_offset, _log_next
    from msm5xxx_emulator.core.constants import HANDSET_KEY_COUNT
    from msm5xxx_emulator.detection import detect
    from msm5xxx_emulator.qemu.virtual_cell import virtual_cell_scenario
    from msm5xxx_emulator.qemu.transport import Transport

    if _session is not None:
        raise RuntimeError("session already running")
    request = json.loads(request_json)
    required = {"experimental_rex", "firmware", "profile", "qemu", "state"}
    if (not isinstance(request, dict) or not required <= request.keys()
            or request.keys() - required - {"virtual_network", "network_host_time", "network_start_time", "session_log", "settings"}):
        raise ValueError("invalid session request")
    virtual_network = request.get("virtual_network", False)
    if type(virtual_network) is not bool:
        raise ValueError("invalid virtual network setting")
    if type(request.get("network_host_time", True)) is not bool:
        raise ValueError("invalid network time setting")
    firmware = Path(request["firmware"])
    qemu = Path(request["qemu"])
    state_value = request["state"]
    state = None if state_value is None else Path(state_value)
    experimental_rex = request["experimental_rex"]
    if type(experimental_rex) is not bool:
        raise ValueError("invalid experimental REX setting")
    expected = request["profile"]
    if not firmware.is_file() or not qemu.is_file():
        raise ValueError("session file unavailable")
    config = detect_cached(firmware)
    if config.diagnostic_config() != expected:
        raise ValueError("selected profile no longer matches firmware")
    config = _apply_settings(firmware, config, request.get("settings", {}))
    if state is not None:
        state.mkdir(parents=True, exist_ok=True)
    _session_log = request.get("session_log")
    _log_offset = 0
    _log_next = 0
    if _session_log and _original_stderr is None:
        _original_stderr = sys.stderr
        sys.stderr = open(_session_log, "a", buffering=1)
    transport = Transport(
        qemu, firmware, state, experimental_rex, config=config,
        audio_stream=True, virtual_cell=virtual_cell_scenario(virtual_network, host_time=request.get("network_host_time", True),
                                          start_time=request.get("network_start_time")),
    )
    input_bits = [
        bit for bit in range(HANDSET_KEY_COUNT)
        if transport.can_set_key(bit)
    ]
    stop = threading.Event()
    thread = threading.Thread(target=_replay, args=(transport, stop),
                              name="msm5xxx-qemu-replay", daemon=True)
    # Continuous LCD replay must not starve short JNI input transitions.
    sys.setswitchinterval(0.001)
    _session = transport
    _session_stop = stop
    _session_thread = thread
    _session_error = None
    _scanout_sent.clear()
    thread.start()
    return _json({
        "height": int(config.height),
        "input_bits": input_bits,
        "model": config.model,
        "persistent_state": state is not None,
        "process_running": transport.process.poll() is None,
        "schema": 1,
        "state_identity": str(config.firmware_sha256),
        "width": int(config.width),
    })


def _require_session():
    if _session is None:
        raise RuntimeError("session is not running")
    if _session_error is not None:
        raise RuntimeError("session replay failed: " + _session_error)
    if _session.process.poll() is not None:
        raise RuntimeError("QEMU session exited")
    return _session


def _scanout_packet(panel, width, height, frame, *, parts=False):
    if not (1 <= width <= 2048 and 1 <= height <= 2048
            and len(frame) == width * height * 3):
        raise RuntimeError("inconsistent display snapshot")
    snapshot = (width, height, frame)
    previous = _scanout_sent.get(panel)
    if previous is not None and snapshot == previous[0]:
        header = struct.pack("<4I", 1, width, height, previous[1])
        return (header, b"") if parts else header
    # Client scanout sequence; firmware progress remains in session_status.
    sequence = ((previous[1] if previous else 0) + 1) & 0xFFFFFFFF
    _scanout_sent[panel] = (snapshot, sequence)
    header = struct.pack("<4I", 1, width, height, sequence)
    # JNI copies each immutable part directly into its Java destination array.
    return (header, frame) if parts else header + frame


def session_frame():
    return _scanout_packet("primary", *_require_session().decoder.display_snapshot())


def session_frame_parts():
    return _scanout_packet("primary", *_require_session().decoder.display_snapshot(),
                           parts=True)


def session_secondary_frame():
    return _secondary_frame_packet(parts=False)


def session_secondary_frame_parts():
    return _secondary_frame_packet(parts=True)


def _secondary_frame_packet(*, parts):
    snapshot = _require_session().decoder.secondary_display_snapshot()
    if snapshot is None or not snapshot["qualified"]:
        _scanout_sent.pop("secondary", None)
        return (b"", b"") if parts else b""
    width, height = snapshot["width"], snapshot["height"]
    frame = (bytes(width * height * 3) if snapshot["enabled"] is False
             else snapshot["frame"])
    return _scanout_packet("secondary", width, height, frame, parts=parts)


def refresh_network_time(request_json):
    from msm5xxx_emulator.qemu.virtual_cell import virtual_cell_scenario
    request = json.loads(request_json)
    if (not isinstance(request, dict) or set(request) != {"host_time", "start_time", "refresh"}
            or type(request["host_time"]) is not bool or type(request["refresh"]) is not bool):
        raise ValueError("invalid network time request")
    virtual_cell_scenario(True, host_time=request["host_time"], start_time=request["start_time"])
    if _session is None or _session.process.poll() is not None:
        raise RuntimeError("session is not running")
    timestamp = request["start_time"] if not request["host_time"] else None
    _session.update_network_time(timestamp, request["refresh"])
    return _json({"schema": 1, "accepted": True})


def session_fold(request_json):
    transport = _require_session()
    request = json.loads(request_json)
    if set(request) != {"open"} or type(request["open"]) is not bool:
        raise ValueError("invalid fold request")
    if not transport.can_set_fold():
        raise ValueError("fold input is not detector-admitted")
    if not transport.set_fold(request["open"]):
        raise RuntimeError("fold input transport rejected transition")
    return _json({"schema": 1, "accepted": True})


def session_status():
    global _log_offset, _log_next
    if _session is None:
        raise RuntimeError("session is not running")
    if _session_log and time.monotonic() >= _log_next:
        _log_next = time.monotonic() + 2
        data = os.pread(_session.stderr.fileno(), 1048576, _log_offset)
        if data:
            with open(_session_log, "ab") as log:
                log.write(data)
            _log_offset += len(data)
    audio_underflow, audio_overflow, audio_epoch = \
        _session.audio_pcm_snapshot()
    secondary = _session.decoder.secondary_display_snapshot()
    fold_supported = _session.can_set_fold()
    return _json({
        "frame_sequence": int(_session.decoder.frame_sequence),
        "virtual_cell_status": str(_session.virtual_cell_status),
        "secondary_available": bool(secondary and secondary["qualified"]),
        "secondary_preview": bool(secondary and secondary["qualified"]
                                  and secondary.get("encoding") == "unverified-byte-preview"),
        "fold_supported": bool(fold_supported),
        "fold_open": bool(fold_supported and _session.board_status_snapshot["level"]
                          == _session.config.board_status_input.default),
        "audio_epoch": int(audio_epoch),
        "audio_overflow_frames": int(audio_overflow),
        "audio_reject_reason": _session.audio_stream_reject_reason or "",
        "audio_status": str(_session.audio_stream_status),
        "audio_underflow_frames": int(audio_underflow),
        "input_host_events": int(_session.input_host_events),
        "input_rejections": int(_session.input_rejections),
        "instructions": int(_session.instructions),
        "lcd_writes": int(_session.decoder.lcd_writes),
        "pc": int(_session.pc),
        "process_running": _session.process.poll() is None,
        "schema": 1,
    })


def session_audio():
    if _session is None:
        raise RuntimeError("session is not running")
    if _session_error is not None or _session.process.poll() is not None:
        return b""
    metadata = getattr(_session.config, "audio_transport", None)
    tone_metadata = getattr(_session.config, "tone_generator", None)
    transport = getattr(_session.decoder, "audio_transport", None)
    accepted_ma2 = (isinstance(metadata, dict)
                    and metadata.get("family") == "ma2"
                    and metadata.get("static_status") == "accepted"
                    and getattr(transport, "family", None) == "ma2"
                    and getattr(transport, "static_status", None) == "accepted")
    native_ma5 = (getattr(_session, "audio_native", False) is True
                  and getattr(_session, "audio_native_ma5_pcm", False) is True
                  and _session.audio_stream_status == "native")
    accepted_tone = (isinstance(tone_metadata, dict)
                     and tone_metadata.get("static_status") == "accepted")
    if (not (accepted_ma2 or native_ma5 or accepted_tone)
            or not _session.audio_stream_enabled
            or _session.audio_stream_status == "rejected"
            or not callable(getattr(_session, "take_native_audio", None))):
        return b""
    raw = _session.take_native_audio(0.02)
    if not isinstance(raw, bytes) or len(raw) != 1796:
        return b""
    magic, schema, epoch, sequence, start_frame = _PCM_PACKET.unpack_from(raw)
    payload_bytes = len(raw) - _PCM_PACKET.size
    payload_frames = payload_bytes // 4
    if (magic != b"M5P2" or schema != 2 or epoch == 0 or sequence == 0
            or payload_bytes == 0 or payload_bytes % 4 != 0
            or start_frame > (1 << 63) - 1 - payload_frames):
        return b""
    return raw


def can_session_key(request_json):
    if _session is None:
        raise RuntimeError("session is not running")
    request = json.loads(request_json)
    if set(request) != {"bit", "event_code"}:
        raise ValueError("invalid input query")
    bit = int(request["bit"])
    event_code = request["event_code"]
    if event_code is not None:
        event_code = int(event_code)
    return _json({
        "accepted": bool(_session.can_set_key(bit, event_code)),
        "schema": 1,
    })


def set_session_key(request_json):
    if _session is None:
        raise RuntimeError("session is not running")
    request = json.loads(request_json)
    if set(request) != {"bit", "event_code", "pressed"}:
        raise ValueError("invalid input request")
    bit = int(request["bit"])
    event_code = request["event_code"]
    if event_code is not None:
        event_code = int(event_code)
    if not _session.can_set_key(bit, event_code):
        raise ValueError("input is not detector-admitted")
    previous_send = getattr(_session, "input_send_completed_ns", 0)
    if not _session.set_key(bit, bool(request["pressed"]), event_code):
        raise RuntimeError("input transport rejected transition")
    completed = getattr(_session, "input_send_completed_ns", 0)
    sent = completed != previous_send
    return _json({
        "accepted": True, "schema": 1, "sent": sent,
        "send_started_ns": getattr(_session, "input_send_started_ns", 0) if sent else 0,
        "send_completed_ns": completed if sent else 0,
        "send_duration_ns": getattr(_session, "input_send_duration_ns", 0) if sent else 0,
    })


def _background_pause(request_json):
    global _background_paused
    request = json.loads(request_json)
    if not isinstance(request, dict) or set(request) != {"paused"} or type(request["paused"]) is not bool:
        raise ValueError("invalid pause request")
    transport = _require_session()
    transport.process.send_signal(signal.SIGSTOP if request["paused"] else signal.SIGCONT)
    _background_paused = request["paused"]
    return _json({"schema": 1, "paused": request["paused"]})


def stop_session():
    global _session, _session_stop, _session_thread, _session_error
    global _scanout_sent, _session_socket, _session_log, _original_stderr, _background_paused
    transport = _session
    stop = _session_stop
    thread = _session_thread
    if transport is None:
        return _json({"schema": 1, "stopped": True})
    if stop is not None:
        stop.set()
    try:
        if _background_paused and transport.process.poll() is None:
            transport.process.send_signal(signal.SIGCONT)
            _background_paused = False
        transport.interrupt()
        if thread is not None:
            thread.join(3)
        transport.close()
    finally:
        _session = None
        _session_stop = None
        _session_thread = None
        _session_error = None
        _scanout_sent.clear()
        _session_socket = None
        if _original_stderr is not None:
            sys.stderr.close()
            sys.stderr = _original_stderr
            _original_stderr = None
        _session_log = None
    return _json({"schema": 1, "stopped": True})
