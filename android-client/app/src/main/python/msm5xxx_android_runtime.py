"""Thin JSON boundary around the canonical firmware detector."""

import json
import platform
import struct
import sys
import threading
from pathlib import Path


_session = None
_session_stop = None
_session_thread = None
_session_error = None
_frame_sequence_sent = None
def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def probe():
    import unicorn
    from gdb_remote import Remote
    from qemu_transport import Transport
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from msm5xxx_emulator.detection.firmware import detect

    engine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    engine.mem_map(0x1000, 0x1000)
    engine.mem_write(0x1000, b"\0\0\0\0")
    del engine
    return _json({
        "detector_entry": callable(detect),
        "gdb_remote": callable(getattr(Remote, "command", None)),
        "python": platform.python_version(),
        "qemu_transport": callable(Transport),
        "schema": 1,
        "unicorn": unicorn.__version__,
        "unicorn_arm": True,
    })


def detect_profile(firmware_path):
    from msm5xxx_emulator.detection.firmware import detect

    config = detect(Path(firmware_path))
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


def _replay(transport, stop):
    global _session_error
    try:
        transport.replay(stop)
    except Exception as error:
        _session_error = type(error).__name__


def start_session(request_json):
    global _session, _session_stop, _session_thread, _session_error
    global _frame_sequence_sent
    from msm5xxx_emulator.core.constants import HANDSET_KEY_COUNT
    from msm5xxx_emulator.detection.firmware import detect
    from qemu_transport import Transport

    if _session is not None:
        raise RuntimeError("session already running")
    request = json.loads(request_json)
    if set(request) != {
            "experimental_rex", "firmware", "profile", "qemu", "state"}:
        raise ValueError("invalid session request")
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
    config = detect(firmware)
    if config.diagnostic_config() != expected:
        raise ValueError("selected profile no longer matches firmware")
    if state is not None:
        state.mkdir(parents=True, exist_ok=True)
    transport = Transport(
        qemu, firmware, state, experimental_rex, config=config,
        qemu_prefix=("/system/bin/nice", "-n", "10"),
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
    _frame_sequence_sent = None
    thread.start()
    return _json({
        "height": int(config.height),
        "input_bits": input_bits,
        "model": str(config.model),
        "persistent_state": state is not None,
        "process_running": transport.process.poll() is None,
        "schema": 1,
        "state_identity": str(config.firmware_sha256),
        "width": int(config.width),
    })


def session_frame():
    global _frame_sequence_sent
    if _session is None:
        raise RuntimeError("session is not running")
    if _session_error is not None:
        raise RuntimeError("session replay failed")
    if _session.process.poll() is not None:
        raise RuntimeError("QEMU session exited")
    decoder = _session.decoder
    with decoder._display_lock:
        width = int(decoder.config.width)
        height = int(decoder.config.height)
        sequence = int(decoder.frame_sequence) & 0xFFFFFFFF
        frame = decoder.display_frame
    header = struct.pack("<4I", 1, width, height, sequence)
    if sequence == _frame_sequence_sent:
        return header
    if len(frame) != width * height * 3:
        raise RuntimeError("inconsistent display snapshot")
    _frame_sequence_sent = sequence
    return header + frame


def session_status():
    if _session is None:
        raise RuntimeError("session is not running")
    return _json({
        "frame_sequence": int(_session.decoder.frame_sequence),
        "input_host_events": int(_session.input_host_events),
        "input_rejections": int(_session.input_rejections),
        "instructions": int(_session.instructions),
        "lcd_writes": int(_session.decoder.lcd_writes),
        "pc": int(_session.pc),
        "process_running": _session.process.poll() is None,
        "schema": 1,
    })


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
    if not _session.set_key(bit, bool(request["pressed"]), event_code):
        raise RuntimeError("input transport rejected transition")
    return _json({"accepted": True, "schema": 1})


def stop_session():
    global _session, _session_stop, _session_thread, _session_error
    global _frame_sequence_sent, _session_socket
    transport = _session
    stop = _session_stop
    thread = _session_thread
    if transport is None:
        return _json({"schema": 1, "stopped": True})
    if stop is not None:
        stop.set()
    try:
        transport.interrupt()
        if thread is not None:
            thread.join(3)
        transport.close()
    finally:
        _session = None
        _session_stop = None
        _session_thread = None
        _session_error = None
        _frame_sequence_sent = None
        _session_socket = None
    return _json({"schema": 1, "stopped": True})
