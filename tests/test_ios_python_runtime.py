"""Host-independent iOS protocol lifecycle tests; never starts QEMU."""
import importlib.util
import json
from pathlib import Path
import sys
import struct
import socket
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IOSRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.shared = load_module("msm5xxx_android_runtime",
                                  ROOT / "android/app/src/main/python/msm5xxx_android_runtime.py")
        self.modules = patch.dict(sys.modules, {"msm5xxx_android_runtime": self.shared})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.runtime = load_module("msm5xxx_ios_runtime", ROOT / "ios/python/msm5xxx_ios_runtime.py")

    def test_start_rejects_malformed_settings_before_detection(self):
        base = {"firmware": "x", "profile": {}, "qemu": "q", "state": None, "experimental_rex": False}
        for request in ({**base, "virtual_network": "yes"}, {**base, "unknown": True},
                        {k: v for k, v in base.items() if k != "state"}):
            with self.subTest(request=request), self.assertRaisesRegex(ValueError, "invalid session request"):
                self.runtime.start_session(__import__("json").dumps(request))

    def test_audio_admission_matches_supported_transports(self):
        def transport(metadata=None, decoder=None, tone=None, *, native=False,
                      ma5=False, status="pending", enabled=True):
            return SimpleNamespace(
                config=SimpleNamespace(audio_transport=metadata, tone_generator=tone),
                decoder=SimpleNamespace(audio_transport=decoder),
                audio_native=native, audio_native_ma5_pcm=ma5,
                audio_stream_status=status, audio_stream_enabled=enabled,
                take_native_audio=lambda timeout: b"")

        ma2 = {"family": "ma2", "static_status": "accepted"}
        decoder = SimpleNamespace(family="ma2", static_status="accepted")
        cases = [
            (transport(ma2, decoder), True),
            (transport(ma2, SimpleNamespace(family="ma2", static_status="rejected")), False),
            (transport({**ma2, "static_status": "rejected"}, decoder), False),
            (transport(tone={"static_status": "accepted"}), True),
            (transport(tone={"static_status": "rejected"}), False),
            (transport(native=True, ma5=True), True),
            (transport(native=True, ma5=False), False),
            (transport(ma2, decoder, enabled=False), False),
            (transport(ma2, decoder, status="rejected"), False),
            (transport(), False),
        ]
        for session, expected in cases:
            with self.subTest(session=session):
                self.assertEqual(self.runtime._audio_admitted(session), expected)
        pending = transport(native=True, ma5=True)
        self.assertFalse(self.runtime._audio_admitted(pending, require_native_ma5=True))
        pending.audio_stream_status = "native"
        self.assertTrue(self.runtime._audio_admitted(pending, require_native_ma5=True))

    def test_admitted_audio_is_nonblocking_and_validated(self):
        packet = struct.pack("<4sIQQQ", b"M5P2", 2, 3, 4, 5) + bytes(1764)
        take = Mock(return_value=packet)
        self.shared._session = SimpleNamespace(
            config=SimpleNamespace(audio_transport=None, tone_generator={"static_status": "accepted"}),
            decoder=SimpleNamespace(audio_transport=None), audio_native=False,
            audio_native_ma5_pcm=False, audio_stream_status="native",
            audio_stream_enabled=True, take_native_audio=take,
            process=SimpleNamespace(poll=lambda: None))
        self.assertEqual(self.runtime.session_audio(), packet)
        take.assert_called_once_with(0.0)
        take.return_value = b"invalid"
        self.assertEqual(self.runtime.session_audio(), b"")

    def test_ma2_and_native_ma5_deliver_pcm(self):
        packet = struct.pack("<4sIQQQ", b"M5P2", 2, 1, 1, 0) + b"\x01\x00\x02\x00" * 441
        ma2 = {"family": "ma2", "static_status": "accepted"}
        for family in ("ma2", "ma5"):
            take = Mock(return_value=packet)
            self.shared._session = SimpleNamespace(
                config=SimpleNamespace(audio_transport=ma2 if family == "ma2" else None,
                                       tone_generator=None),
                decoder=SimpleNamespace(audio_transport=SimpleNamespace(
                    family="ma2", static_status="accepted") if family == "ma2" else None),
                audio_native=family == "ma5", audio_native_ma5_pcm=family == "ma5",
                audio_stream_status="native", audio_stream_enabled=True,
                take_native_audio=take, process=SimpleNamespace(poll=lambda: None))
            with self.subTest(family=family):
                self.assertEqual(self.runtime.session_audio(), packet)
                take.assert_called_once_with(0.0)

    def test_start_enables_stream_and_reports_admitted_ma2(self):
        metadata = {"family": "ma2", "static_status": "accepted"}
        profile = {"audio_transport": metadata}
        config = SimpleNamespace(width=176, height=220, tone_generator=None,
                                 diagnostic_config=lambda: profile)
        transport = SimpleNamespace(
            config=SimpleNamespace(audio_transport=metadata, tone_generator=None),
            decoder=SimpleNamespace(audio_transport=SimpleNamespace(
                family="ma2", static_status="accepted")),
            audio_native=False, audio_native_ma5_pcm=False,
            audio_stream_status="pending", audio_stream_enabled=True,
            take_native_audio=lambda timeout: b"", can_set_key=lambda bit: False,
            process=SimpleNamespace(poll=lambda: None))
        request = {"firmware": "synthetic", "profile": profile, "qemu": "q",
                   "state": None, "experimental_rex": False, "virtual_network": True,
                   "network_host_time": True, "network_start_time": 1037837100}
        self.runtime.detect_profile = lambda _: json.dumps({"accepted": True})
        with patch("msm5xxx_emulator.detection.firmware.detect", return_value=config), \
             patch("msm5xxx_emulator.qemu.transport.Transport", return_value=transport) as factory, \
             patch("msm5xxx_emulator.qemu.transport.IOSLauncher"), \
             patch.object(self.runtime.threading, "Thread"):
            result = json.loads(self.runtime.start_session(json.dumps(request)))
        self.assertTrue(result["audio_admitted"])
        self.assertTrue(factory.call_args.kwargs["audio_stream"])
        self.assertTrue(factory.call_args.kwargs["audio_pcm"])
        from msm5xxx_emulator.qemu.virtual_cell import virtual_cell_scenario
        self.assertEqual(factory.call_args.kwargs["virtual_cell"],
                         virtual_cell_scenario(True, host_time=True, start_time=1037837100))
        self.runtime._control.close()

    def test_pause_monitor_handshake_and_commands(self):
        seen = []
        reader = []
        process = Mock()

        def launch(argv, **kwargs):
            spec = argv[argv.index("-chardev") + 1]
            port = int(spec.split("port=")[1].split(",")[0])
            def serve():
                with socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
                    peer.sendall(b'{"QMP":{}}\n')
                    with peer.makefile("rb") as stream:
                        for _ in range(3):
                            request = json.loads(stream.readline())
                            seen.append(request["execute"])
                            peer.sendall((json.dumps({"event": "STATUS"}) + "\n" +
                                          json.dumps({"return": {}, "id": request["id"]}) + "\n").encode())
            thread = threading.Thread(target=serve)
            reader.append(thread); thread.start()
            return process

        control = self.runtime._ControlLauncher(launch)
        self.addCleanup(control.close)
        self.assertIs(control(["qemu"]), process)
        self.shared._session = SimpleNamespace(process=SimpleNamespace(poll=lambda: None))
        self.runtime._control = control
        self.assertTrue(json.loads(self.runtime.set_session_paused('{"paused":true}'))["paused"])
        self.assertFalse(json.loads(self.runtime.set_session_paused('{"paused":false}'))["paused"])
        reader[0].join(2)
        self.assertFalse(reader[0].is_alive())
        self.assertEqual(seen, ["qmp_capabilities", "stop", "cont"])
        for invalid in ('{}', '{"paused":1}', '{"paused":true,"extra":0}'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.runtime.set_session_paused(invalid)

    def test_stop_retains_resources_when_replay_still_alive(self):
        transport = self.shared._session = Mock()
        thread = self.shared._session_thread = Mock()
        thread.is_alive.return_value = True
        stop = self.shared._session_stop = Mock()
        with self.assertRaisesRegex(RuntimeError, "replay did not stop"):
            self.runtime.stop_session()
        stop.set.assert_called_once()
        transport.interrupt.assert_called_once()
        transport.close.assert_not_called()
        self.assertIs(self.shared._session, transport)

    def test_stop_closes_after_replay_finishes(self):
        transport = self.shared._session = Mock()
        thread = self.shared._session_thread = Mock()
        thread.is_alive.return_value = False
        self.shared._session_stop = Mock()
        self.shared._scanout_sent["primary"] = object()
        self.assertIn('"stopped":true', self.runtime.stop_session())
        thread.join.assert_called_once_with(3)
        transport.close.assert_called_once()
        self.assertIsNone(self.shared._session)
        self.assertEqual(self.shared._scanout_sent, {})

    def test_stop_retains_session_if_native_quit_times_out(self):
        transport = self.shared._session = Mock()
        transport.interrupt.side_effect = TimeoutError("native thread stuck")
        with self.assertRaises(TimeoutError):
            self.runtime.stop_session()
        transport.close.assert_not_called()
        self.assertIs(self.shared._session, transport)

    def test_repeated_stop_is_idempotent(self):
        self.assertIn('"stopped":true', self.runtime.stop_session())
        self.assertIn('"stopped":true', self.runtime.stop_session())
