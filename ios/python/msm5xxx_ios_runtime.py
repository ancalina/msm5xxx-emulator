"""iOS boundary; share Android's frame/key/status protocol and detector policy.

The packaging script includes msm5xxx_android_runtime.py as a platform-neutral
protocol implementation. Only session construction and the optional numpy probe
are platform specific. No detector logic is duplicated here.
"""
import json
import platform
import socket
import struct
import sys
import threading
from pathlib import Path

import msm5xxx_android_runtime as shared
from msm5xxx_android_runtime import (  # noqa: F401: exported native bridge API
    detect_cached, detect_profile, library_describe, session_frame, session_secondary_frame, session_fold,
    session_status, can_session_key, set_session_key,
)

_PCM_PACKET = struct.Struct("<4sIQQQ")
_control = None
_session_spec = None
_display_update_lock = None


class _ControlLauncher:
    """Add a loopback QMP connection to the existing embedded launcher."""

    supports_pass_fds = False

    def __init__(self, launcher):
        self.launcher = launcher
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(30)
        self.connection = None
        self.reader = None
        self.next_id = 0

    def __call__(self, argv, **options):
        host, port = self.listener.getsockname()
        args = list(argv) + ["-chardev", f"socket,id=app-control,host={host},port={port},server=off,nodelay=on",
                             "-mon", "chardev=app-control,mode=control"]
        process = self.launcher(args, **options)
        try:
            self.connection, _ = self.listener.accept()
            self.connection.settimeout(2)
            self.reader = self.connection.makefile("rb")
            if "QMP" not in self._receive():
                raise RuntimeError("monitor greeting missing")
            self.command("qmp_capabilities")
        except Exception:
            process.terminate()
            try:
                process.wait(3)
            except Exception:
                pass
            self.close()
            raise
        finally:
            if self.listener is not None:
                self.listener.close()
                self.listener = None
        return process

    def _receive(self):
        line = self.reader.readline(65537)
        if not line or len(line) > 65536 or not line.endswith(b"\n"):
            raise RuntimeError("invalid monitor response")
        response = json.loads(line)
        if not isinstance(response, dict):
            raise RuntimeError("invalid monitor response")
        return response

    def command(self, name):
        self.next_id += 1
        request = {"execute": name, "id": self.next_id}
        self.connection.sendall((json.dumps(request) + "\n").encode())
        for _ in range(64):
            response = self._receive()
            if response.get("id") == self.next_id:
                if "error" in response or "return" not in response:
                    raise RuntimeError("monitor command failed: " + name)
                return response["return"]
        raise RuntimeError("monitor response limit exceeded")

    def close(self):
        for channel in (self.reader, self.connection, self.listener):
            if channel is not None:
                channel.close()
        self.reader = self.connection = self.listener = None


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


def host_status():
    """Distinguish a rejected selection from an entered native initialization."""
    import _msm5xxx_ios_host as host
    return shared._json({"schema": 1, "used": host.has_started()})


def probe():
    from msm5xxx_emulator.qemu.transport import Transport
    from msm5xxx_emulator.qemu.decoder import QemuDecoder
    return shared._json({"schema": 1, "python": platform.python_version(),
                         "qemu_transport": callable(Transport),
                         "qemu_decoder": callable(QemuDecoder), "numpy": False})


def start_session(request_json):
    global _control, _session_spec, _display_update_lock
    from msm5xxx_emulator.core.constants import HANDSET_KEY_COUNT
    from msm5xxx_emulator.detection import detect
    from msm5xxx_emulator.qemu.transport import Transport, IOSLauncher
    from msm5xxx_emulator.qemu.virtual_cell import virtual_cell_scenario
    if shared._session is not None:
        raise RuntimeError("session already running")
    request = json.loads(request_json)
    if (not isinstance(request, dict)
            or set(request) - {"virtual_network", "network_host_time", "network_start_time", "settings"} != {"firmware", "profile", "qemu", "state", "experimental_rex"}
            or type(request["experimental_rex"]) is not bool
            or type(request.get("virtual_network", False)) is not bool):
        raise ValueError("invalid session request")
    if type(request.get("network_host_time", True)) is not bool:
        raise ValueError("invalid network time setting")
    firmware = Path(request["firmware"])
    config = detect_cached(firmware)
    # Apply the same fail-closed admission policy used by Android before starting.
    admission = json.loads(detect_profile(str(firmware)))
    if not admission["accepted"]:
        raise ValueError(admission["reject_reason"])
    if config.diagnostic_config() != request["profile"]:
        raise ValueError("selected profile no longer matches firmware")
    config = shared._apply_settings(firmware, config, request.get("settings", {}))
    state = None if request["state"] is None else Path(request["state"])
    if state is not None:
        state.mkdir(parents=True, exist_ok=True)
    control = _ControlLauncher(IOSLauncher())
    try:
        transport = Transport(
            Path(request["qemu"]), firmware, state, request["experimental_rex"],
            config=config, audio_stream=True, audio_pcm=True,
            virtual_cell=virtual_cell_scenario(request.get("virtual_network", False),
                                               host_time=request.get("network_host_time", True),
                                               start_time=request.get("network_start_time")),
            launcher=control,
        )
    except Exception:
        control.close()
        raise
    _control = control
    # Serialize display replay with the one decoder setting that can be changed
    # without replacing the machine. Other transport operations remain independent.
    _display_update_lock = threading.RLock()
    replay_batch = getattr(transport, "_replay_batch", None)
    if replay_batch is not None:
        display_lock = _display_update_lock
        def locked_replay_batch(pending, complete):
            with display_lock:
                return replay_batch(pending, complete)
        transport._replay_batch = locked_replay_batch
    _session_spec = {"firmware": str(firmware), "settings": dict(request.get("settings", {})),
                     "persistent_state": state is not None, "experimental_rex": request["experimental_rex"]}
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


def set_session_paused(request_json):
    request = json.loads(request_json)
    if not isinstance(request, dict) or set(request) != {"paused"} or type(request["paused"]) is not bool:
        raise ValueError("invalid pause request")
    if shared._session is None or _control is None or shared._session.process.poll() is not None:
        raise RuntimeError("session is not running")
    _control.command("stop" if request["paused"] else "cont")
    return shared._json({"schema": 1, "paused": request["paused"]})


def refresh_network_time(request_json):
    return shared.refresh_network_time(request_json)


def reset_session(request_json=None):
    if shared._session is None or _control is None or shared._session.process.poll() is not None:
        raise RuntimeError("session is not running")
    if request_json is not None:
        request = json.loads(request_json)
        if request.get("enabled") and shared._session.virtual_cell_status == "configured":
            shared.refresh_network_time(json.dumps({"host_time": request["host_time"],
                                                    "start_time": request["start_time"],
                                                    "refresh": False}))
    _control.command("system_reset")
    return shared._json({"schema": 1, "reset": True})



def _settings_plan(request_json):
    from msm5xxx_emulator.detection import detect
    if shared._session is None or _control is None or _session_spec is None:
        raise RuntimeError("session is not running")
    if shared._session.process.poll() is not None or shared._session_error is not None:
        raise RuntimeError("session is not running")
    request = json.loads(request_json)
    if (not isinstance(request, dict)
            or set(request) != {"settings", "persistent_state", "experimental_rex"}
            or not isinstance(request["settings"], dict)
            or type(request["persistent_state"]) is not bool
            or type(request["experimental_rex"]) is not bool):
        raise ValueError("invalid settings request")
    firmware = Path(_session_spec["firmware"])
    candidate = shared._apply_settings(firmware, detect_cached(firmware), request["settings"])
    active = _session_spec["settings"]
    edits = {key for key in active.keys() | request["settings"].keys()
             if active.get(key) != request["settings"].get(key)}
    same_options = (request["persistent_state"] == _session_spec["persistent_state"]
                    and request["experimental_rex"] == _session_spec["experimental_rex"])
    current = shared._session.config
    live_format = (edits <= {"framebuffer_format"} and same_options
                   and getattr(current, "framebuffer_address", None) is not None
                   and getattr(candidate, "framebuffer_address", None) == current.framebuffer_address
                   and getattr(candidate, "framebuffer_stride", None) == current.framebuffer_stride
                   and getattr(candidate, "width", None) == current.width
                   and getattr(candidate, "height", None) == current.height
                   and getattr(candidate, "framebuffer_format", "none") != "none")
    unchanged = not edits and same_options
    return request, candidate, "reset" if unchanged or live_format else "reopen"


def prepare_session_settings(request_json):
    """Validate before disturbing a live session and classify its reset path."""
    _, _, action = _settings_plan(request_json)
    return shared._json({"schema": 1, "action": action})


def apply_reset_settings(request_json):
    """Apply a decoder-only edit and reset the existing machine."""
    request, candidate, action = _settings_plan(request_json)
    if action != "reset":
        raise ValueError("settings require a new session")
    if _display_update_lock is None:
        raise RuntimeError("display synchronization is unavailable")
    decoder = shared._session.decoder
    previous = decoder.config.framebuffer_format
    new_format = candidate.framebuffer_format
    with _display_update_lock:
        try:
            if new_format != previous:
                decoder.set_framebuffer_format(new_format)
            reset_session()
        except Exception:
            if decoder.config.framebuffer_format != previous:
                decoder.set_framebuffer_format(previous)
            raise
    _session_spec["settings"] = dict(request["settings"])
    shared._scanout_sent.clear()
    return shared._json({"schema": 1, "applied": True})

def stop_session():
    """Keep resources owned if a worker cannot stop; never close beneath replay."""
    global _control, _session_spec, _display_update_lock
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
    if _control is not None:
        _control.close()
        _control = None
    shared._session = None
    shared._session_stop = None
    shared._session_thread = None
    shared._session_error = None
    shared._scanout_sent.clear()
    _session_spec = None
    _display_update_lock = None
    return shared._json({"schema": 1, "stopped": True})
