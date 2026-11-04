"""iOS boundary; share Android's frame/key/status protocol and detector policy.

The packaging script includes msm5xxx_android_runtime.py as a platform-neutral
protocol implementation. Only session construction and the optional numpy probe
are platform specific. No detector logic is duplicated here.
"""
import json
import platform
import struct
import sys
import threading
from pathlib import Path

import msm5xxx_android_runtime as shared
from msm5xxx_android_runtime import (  # noqa: F401: exported native bridge API
    detect_profile, session_frame, session_secondary_frame, session_fold,
    session_status, can_session_key, set_session_key,
)

_PCM_PACKET = struct.Struct("<4sIQQQ")


def _audio_admitted(transport, *, require_native_ma5=False):
    """Match Android's static admission; MA5 may still be pending at startup."""
    metadata = getattr(transport.config, "audio_transport", None)
    tone = getattr(transport.config, "tone_generator", None)
    decoder = getattr(transport.decoder, "audio_transport", None)
    ma2 = (isinstance(metadata, dict) and metadata.get("family") == "ma2"
           and metadata.get("static_status") == "accepted"
           and getattr(decoder, "family", None) == "ma2"
           and getattr(decoder, "static_status", None) == "accepted")
    ma5 = (getattr(transport, "audio_native", False) is True
           and getattr(transport, "audio_native_ma5_pcm", False) is True
           and (not require_native_ma5 or transport.audio_stream_status == "native"))
    tone = isinstance(tone, dict) and tone.get("static_status") == "accepted"
    return bool((ma2 or ma5 or tone) and transport.audio_stream_enabled
                and transport.audio_stream_status != "rejected"
                and callable(getattr(transport, "take_native_audio", None)))


def probe():
    from msm5xxx_emulator.qemu.transport import Transport
    from msm5xxx_emulator.qemu.decoder import QemuDecoder
    return shared._json({"schema": 1, "python": platform.python_version(),
                         "qemu_transport": callable(Transport),
                         "qemu_decoder": callable(QemuDecoder), "numpy": False})


def start_session(request_json):
    from msm5xxx_emulator.core.constants import HANDSET_KEY_COUNT
    from msm5xxx_emulator.detection.firmware import detect
    from msm5xxx_emulator.qemu.transport import Transport, IOSLauncher
    from msm5xxx_emulator.qemu.virtual_cell import virtual_cell_scenario
    if shared._session is not None:
        raise RuntimeError("session already running")
    request = json.loads(request_json)
    if (not isinstance(request, dict)
            or set(request) - {"virtual_network", "network_host_time", "network_start_time"} != {"firmware", "profile", "qemu", "state", "experimental_rex"}
            or type(request["experimental_rex"]) is not bool
            or type(request.get("virtual_network", False)) is not bool):
        raise ValueError("invalid session request")
    if type(request.get("network_host_time", True)) is not bool:
        raise ValueError("invalid network time setting")
    firmware = Path(request["firmware"])
    config = detect(firmware)
    # Apply the same fail-closed admission policy used by Android before starting.
    admission = json.loads(detect_profile(str(firmware)))
    if not admission["accepted"]:
        raise ValueError(admission["reject_reason"])
    if config.diagnostic_config() != request["profile"]:
        raise ValueError("selected profile no longer matches firmware")
    state = None if request["state"] is None else Path(request["state"])
    if state is not None:
        state.mkdir(parents=True, exist_ok=True)
    transport = Transport(
        Path(request["qemu"]), firmware, state, request["experimental_rex"],
        config=config, audio_stream=True, audio_pcm=True,
        virtual_cell=virtual_cell_scenario(request.get("virtual_network", False),
                                           host_time=request.get("network_host_time", True),
                                           start_time=request.get("network_start_time")),
        launcher=IOSLauncher(),
    )
    stop = threading.Event()
    thread = threading.Thread(target=shared._replay, args=(transport, stop),
                              name="msm5xxx-ios-replay", daemon=True)
    sys.setswitchinterval(0.001)
    shared._session = transport
    shared._session_stop = stop
    shared._session_thread = thread
    shared._session_error = None
    shared._scanout_sent.clear()
    thread.start()
    return shared._json({"schema": 1, "width": int(config.width),
                         "height": int(config.height),
                         "input_bits": [bit for bit in range(HANDSET_KEY_COUNT)
                                        if transport.can_set_key(bit)],
                         "process_running": transport.process.poll() is None,
                         "audio_admitted": _audio_admitted(transport)})


def session_audio():
    """Return one admitted native M5P2 packet without blocking the UI queue."""
    transport = shared._session
    if transport is None:
        raise RuntimeError("session is not running")
    if not _audio_admitted(transport, require_native_ma5=True):
        return b""
    if shared._session_error is not None or transport.process.poll() is not None:
        return b""
    raw = transport.take_native_audio(0.0)
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


def stop_session():
    """Keep resources owned if a worker cannot stop; never close beneath replay."""
    transport = shared._session
    if transport is None:
        return shared._json({"schema": 1, "stopped": True})
    if shared._session_stop is not None:
        shared._session_stop.set()
    transport.interrupt()
    thread = shared._session_thread
    if thread is not None:
        thread.join(3)
        if thread.is_alive():
            raise RuntimeError("replay did not stop; relaunch app")
    transport.close()
    shared._session = None
    shared._session_stop = None
    shared._session_thread = None
    shared._session_error = None
    shared._scanout_sent.clear()
    return shared._json({"schema": 1, "stopped": True})
