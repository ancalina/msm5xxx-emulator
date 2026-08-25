"""QEMU MA2 sideband-to-PCM check."""
from __future__ import annotations

from pathlib import Path
from collections import deque
import importlib.util
import json
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.devices.audio import AudioMixin
from msm5xxx_emulator.devices.audio_lle import AudioTransport


EXPERIMENT = Path(__file__).parents[1] / "experiments/qemu-tcg"
sys.path.insert(0, str(EXPERIMENT))
from qemu_transport import (  # noqa: E402
    AUDIO_PACKET_BYTES, AUDIO_SOCKET_SEND_BUFFER,
    AUDIO_PCM_TELEMETRY, AUDIO_REJECT_TELEMETRY, AUDIO_STATUS,
    AUDIO_STATUS_NATIVE, AUDIO_STATUS_OVERFLOW, AUDIO_STATUS_REJECTED,
    AUDIO_STATUS_RESET, AUDIO_TIMING_TELEMETRY,
    AUDIO_WRITE, LCD_WRITE, TELEMETRY, Transport,
    bounded_audio_socket_pair, qemu_audio_sites,
)

ANDROID_RUNTIME = (
    Path(__file__).parents[1]
    / "android-client/app/src/main/python/msm5xxx_android_runtime.py"
)


class QEMUAudioTransportTests(unittest.TestCase):
    @staticmethod
    def native_transport() -> Transport:
        transport = object.__new__(Transport)
        transport.decoder = SimpleNamespace()
        transport.audio_stream_enabled = True
        transport.audio_stream_status = "native"
        transport.audio_stream_reject_reason = None
        transport.audio_stream_dropped = 0
        transport.audio_pcm_underflow_frames = 0
        transport.audio_pcm_overflow_frames = 0
        transport.audio_pcm_epoch = 0
        transport.audio_timing_late_events = 0
        transport.audio_timing_collapsed_events = 0
        transport.audio_timing_max_lateness_ns = 0
        transport.audio_reject_witness = None
        transport.audio_native = True
        transport.audio_stream_seen = False
        transport.audio_stream_order = 0
        transport._audio_lock = threading.RLock()
        transport._audio_ready = threading.Condition(transport._audio_lock)
        transport.native_audio_packets = deque(maxlen=4)
        transport.native_audio_epoch = 0
        transport.native_audio_sequence = 0
        transport.native_audio_end_frame = 0
        transport.native_audio_reset_epoch = 0
        return transport

    @staticmethod
    def pcm_packet(epoch: int, sequence: int, start_frame: int) -> bytes:
        return struct.pack("<4sIQQQ", b"M5P2", 2, epoch, sequence,
                           start_frame) + bytes(441 * 4)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux socket bound")
    def test_audio_socket_pair_bounds_qemu_sender(self) -> None:
        host, qemu = bounded_audio_socket_pair()
        try:
            self.assertEqual(AUDIO_SOCKET_SEND_BUFFER, 4096)
            self.assertLessEqual(
                qemu.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF), 8192
            )
            qemu.setblocking(False)
            accepted = 0
            packet = bytes(AUDIO_PACKET_BYTES)
            while True:
                try:
                    written = qemu.send(packet)
                except BlockingIOError:
                    break
                self.assertGreater(written, 0)
                accepted += written
            self.assertLessEqual(accepted, AUDIO_PACKET_BYTES * 2)
        finally:
            host.close()
            qemu.close()

    def test_qemu_audio_sites_are_canonical_and_fail_closed(self) -> None:
        metadata = {
            "family": "ma2", "base": 0x02080000,
            "data_offset": 2,
            "sites": {
                "read_0": [0x10],
                "read_2": [0x14],
                "write_2": [0x102, 0x100],
                "write_0": [0x12],
            },
        }
        self.assertEqual(
            qemu_audio_sites(metadata), "r2/14;w0/12;w2/100;w2/102"
        )
        ma5 = {
            "family": "ma5", "base": 0x02840000,
            "data_offset": 2,
            "aperture_write_sites": {
                "write_0": [
                    0x582, 0x58A, 0x10566, 0x1056E, 0x37CAE2,
                ],
                "write_2": [
                    0x586, 0x58E, 0x1056A, 0x10572,
                    0x37CB1E, 0x37CB48, 0x37CB74,
                ],
            },
        }
        self.assertEqual(
            qemu_audio_sites(ma5),
            "w0/582;w0/58a;w0/10566;w0/1056e;w0/37cae2;"
            "w2/586;w2/58e;w2/1056a;w2/10572;w2/37cb1e;"
            "w2/37cb48;w2/37cb74",
        )
        opaque = {
            "family": "opaque", "grammar": "command-status-data-v1",
            "base": 0x02880000, "data_offset": 2,
            "begin": 0x406, "end": 0x43C,
            "sites": {
                "read_0": [0x416], "read_2": [0x43A],
                "write_0": [0x406], "write_2": [0x42A],
            },
        }
        self.assertEqual(
            qemu_audio_sites(opaque), "r0/416;r2/43a;w0/406;w2/42a"
        )
        self.assertIsNone(qemu_audio_sites({
            **opaque,
            "sites": {**opaque["sites"], "read_2": [0x438]},
        }))
        for invalid in (
            {**ma5, "base": 0x0283FFFE},
            {**ma5, "base": 0x02BFFFFE},
            {**ma5, "base": 0x02C00001},
            {**ma5, "data_offset": 4},
        ):
            self.assertIsNone(qemu_audio_sites(invalid))
        self.assertIsNone(qemu_audio_sites({
            **ma5, "base": 0x02C00000, "data_offset": 4,
            "aperture_write_sites": {
                "write_0": [0x100], "write_4": [0x102],
            },
        }))
        self.assertIsNone(qemu_audio_sites({
            **ma5,
            "aperture_write_sites": {
                **ma5["aperture_write_sites"],
                "read_2": [0x37CB00],
            },
        }))
        self.assertIsNone(qemu_audio_sites({
            **ma5,
            "aperture_write_sites": {
                **ma5["aperture_write_sites"],
                "write_2": ma5["aperture_write_sites"]["write_2"][:-1],
            },
        }))
        invalid = (
            {**metadata, "sites": {"write_2": [0x100]}},
            {**metadata, "sites": {"write_0": [0x100]}},
            {**metadata, "sites": {
                "write_0": [0x100], "write_2": [0x101],
            }},
            {**metadata, "sites": {
                "write_0": [0x100], "write_2": [0x100],
            }},
            {**metadata, "sites": {
                "write_0": [0x100], "write_2": [0x100000000],
            }},
            {**metadata, "sites": {
                "write_0": [0x100], "write_3": [0x102],
                "write_2": [0x104],
            }},
            {**metadata, "base": 0x02000000},
            {**metadata, "family": "ma2", "data_offset": 4},
            {**metadata, "family": "ma5", "data_offset": 1},
            {**metadata, "family": "ma5", "data_offset": 2},
            {**metadata, "base": 0x02200000},
            {**metadata, "base": 0x021FFFFF},
            {**metadata, "base": 0x027FFFFE},
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(qemu_audio_sites(value))
        overflow = {
            "family": "ma2", "base": 0x02080000,
            "data_offset": 2,
            "sites": {
                "write_0": [0x100],
                "write_2": list(range(0x200, 0x200 + 64 * 2, 2)),
            },
        }
        self.assertIsNone(qemu_audio_sites(overflow))
        source = (EXPERIMENT / "qemu_transport.py").read_text(
            encoding="utf-8"
        )
        audio_block = source[source.index("audio = self.config.audio_transport"):]
        audio_block = audio_block[:audio_block.index("        rex_fields =")]
        sites_gate = audio_block.index("if audio_sites is not None:")
        self.assertGreater(audio_block.index("audio-aperture=", sites_gate),
                           sites_gate)
        self.assertGreater(audio_block.index("self.audio_stream_enabled = True",
                                             sites_gate), sites_gate)
        self.assertIn('"qemu-audio-adapter-unsupported"', audio_block)
        self.assertIn('"qemu-audio-detector-"', audio_block)
        self.assertIn('machine += ",audio-pcm=off"', audio_block)
        self.assertIn("if audio_stream and audio_pcm:", source)
        self.assertIn("self.config, approximate_audio=False", source)
        self.assertIn("bounded_audio_socket_pair()", source)
        self.assertIn('"pass_fds": (audio_qemu_socket.fileno(),)', source)
        self.assertIn("AUDIO_PACKET_BYTES - len(pending)", source)
        java = (Path(__file__).parents[1]
                / "android-client/app/src/main/java/org/msm5xxx/emulator/"
                "MainActivity.java").read_text(encoding="utf-8")
        self.assertIn("new ArrayBlockingQueue<>(4)", java)
        self.assertIn("audioSink.start(opened);", java)
        self.assertIn('"msm5xxx-audio-input"', java)
        self.assertIn("byte[] pcm = source.audio()", java)
        self.assertIn("if (pcm.length == 0) {", java)
        self.assertIn("Thread.sleep(1);", java)
        session_loop = java[java.index("while (generation == sessionGeneration)"):
                            java.index("        } catch (IOException", java.index(
                                "while (generation == sessionGeneration)"))]
        self.assertIn('"native".equals(status.audioStatus)', session_loop)
        self.assertIn('"rejected".equals(status.audioStatus)', session_loop)
        self.assertIn("audioSink.start(opened);", session_loop)
        self.assertIn("audioSink.close();", session_loop)
        self.assertNotIn("audioSink.start(opened);",
                         java[:java.index("while (generation == sessionGeneration)")])
        self.assertNotIn("opened.audio()", session_loop)
        self.assertIn("pending.remainingCapacity() > 0", java)
        self.assertIn("if (!pending.offer(packet))", java)
        self.assertNotIn("audioDeadline", java)
        self.assertNotIn("offeredEpoch", java)
        offer = java[java.index("        void offer(byte[] pcm)"):
                     java.index("        private void run()")]
        self.assertNotIn("pending.clear();", offer)
        self.assertIn("data.length != PACKET_BYTES", java)
        self.assertIn("private volatile AudioTrack activeTrack", java)
        self.assertIn("if (track == null) {\n                            track = createTrack()", java)
        self.assertIn("track.pause();\n                            track.flush();", java)
        self.assertIn("android.os.Process.THREAD_PRIORITY_AUDIO", java)
        self.assertIn("private static final int PREBUFFER_MILLIS = 60", java)
        self.assertIn("private static final int BUFFER_MILLIS = 80", java)
        self.assertIn("track.getUnderrunCount()", java)
        self.assertIn('"M5P2 ingress gapMs="', java)
        self.assertIn("cadenceLogs < 8", java)
        self.assertIn("underrunLogs < 8", java)
        self.assertIn("long spanStartFrame = -1", java)
        self.assertIn('"AudioTrack span epoch="', java)
        self.assertIn('" elapsedNanos="', java)
        create_track = java[java.index("private static AudioTrack createTrack()"):
                            java.index("        void disable()")]
        self.assertNotIn("track.play()", create_track)
        self.assertIn("* PREBUFFER_MILLIS / 1000", java)
        self.assertIn("pauseTrack(track);", java)
        self.assertIn("input.interrupt();", java)
        self.assertIn("worker.interrupt();", java)
        self.assertIn("worker.isAlive() || (input != null && input.isAlive())", java)
        self.assertNotIn("while (!closed && !disabled", java)
        self.assertNotIn("pending.clear();\n            pending.offer", java)
        bridge = (Path(__file__).parents[1]
                  / "android-client/app/src/main/java/org/msm5xxx/emulator/"
                  "BackendBridge.java").read_text(encoding="utf-8")
        self.assertIn("private static PythonSession activeSession", bridge)
        self.assertIn("static synchronized Session open", bridge)
        self.assertIn("if (activeSession != this)", bridge)
        runtime_java = (Path(__file__).parents[1]
                        / "android-client/app/src/main/java/org/msm5xxx/emulator/"
                        "PythonRuntime.java").read_text(encoding="utf-8")
        self.assertIn("new ReentrantLock(true)", runtime_java)
        self.assertIn("static byte[] audio()", runtime_java)
        self.assertNotIn("static synchronized byte[] audio()", runtime_java)
        self.assertEqual(runtime_java.count("AUDIO_GATE.lock();"), 3)
        self.assertEqual(runtime_java.count("AUDIO_GATE.unlock();"), 3)
        self.assertIn("static synchronized String key(", runtime_java)
        self.assertIn("static synchronized String canKey(", runtime_java)
        korean = (Path(__file__).parents[1]
                  / "android-client/app/src/main/res/values-ko/strings.xml"
                  ).read_text(encoding="utf-8")
        self.assertIn("u%2$d/o%3$d/e%4$d/l%5$d", korean)
        self.assertIn('"coreaudio,id=msm5xxx"', source)
        self.assertIn('"out.buffer-length=40000"', source)
        replay = source[source.index("    def replay("):
                        source.index("    def _queue_native_audio(")]
        self.assertIn('name="msm5xxx-qemu-audio-replay"', replay)
        android_runtime = ANDROID_RUNTIME.read_text(encoding="utf-8")
        self.assertNotIn('qemu_prefix=("/system/bin/nice"', android_runtime)
        self.assertIn("icount_shift=10", android_runtime)
        self.assertIn('f"shift={icount_shift},align=on,sleep=on"', source)
        machine = (EXPERIMENT / "msm5xxx-poc.c").read_text(encoding="utf-8")
        synth_header = (EXPERIMENT / "msm5xxx-audio-synth.h").read_text(
            encoding="utf-8")
        self.assertIn("MSM5XXX_AUDIO_TARGET_FRAMES", machine)
        self.assertIn("MSM5XXX_AUDIO_SAMPLE_RATE * 80u / 1000u",
                      synth_header)

    def test_m5p2_fragment_sequence_epoch_and_bound(self) -> None:
        transport = self.native_transport()
        transport.input_socket, input_peer = socket.socketpair()
        transport.lcd_socket, lcd_peer = socket.socketpair()
        transport.audio_socket, audio_peer = socket.socketpair()
        transport.process = SimpleNamespace(poll=lambda: None)
        stop = threading.Event()
        worker = threading.Thread(target=transport.replay, args=(stop,))
        packet = self.pcm_packet(1, 1, 0)
        try:
            worker.start()
            audio_peer.sendall(packet[:17])
            audio_peer.sendall(packet[17:777])
            audio_peer.sendall(packet[777:])
            self.assertEqual(transport.take_native_audio(1.0), packet)
        finally:
            stop.set()
            worker.join(1)
            for stream in (transport.input_socket, input_peer,
                           transport.lcd_socket, lcd_peer,
                           transport.audio_socket, audio_peer):
                stream.close()
        self.assertFalse(worker.is_alive())

        transport = self.native_transport()
        first = self.pcm_packet(1, 1, 0)
        second = self.pcm_packet(1, 2, 441)
        resync = self.pcm_packet(2, 1, 50_000)
        transport._queue_native_audio(first)
        transport._queue_native_audio(second)
        self.assertEqual(len(transport.native_audio_packets), 2)
        transport._queue_native_audio(resync)
        self.assertEqual(list(transport.native_audio_packets), [resync])
        transport._queue_native_audio(self.pcm_packet(2, 3, 50_441))
        self.assertEqual(transport.audio_stream_status, "rejected")
        self.assertEqual(transport.audio_stream_reject_reason,
                         "qemu-audio-pcm-sequence")
        self.assertEqual(list(transport.native_audio_packets), [])
        self.assertEqual(transport.take_native_audio(), b"")
        self.assertEqual(transport.native_audio_packets.maxlen, 4)

        transport = self.native_transport()
        transport.native_audio_epoch = 1
        transport.native_audio_sequence = 9
        transport.native_audio_end_frame = 10_000
        transport.native_audio_reset_epoch = 2
        newer = self.pcm_packet(3, 1, 50_000)
        transport._queue_native_audio(newer)
        self.assertEqual(transport.take_native_audio(), newer)
        self.assertEqual(transport.native_audio_reset_epoch, 0)

    def test_m5p2_delivery_does_not_wait_for_lcd_decode(self) -> None:
        transport = self.native_transport()
        transport.input_socket, input_peer = socket.socketpair()
        transport.lcd_socket, lcd_peer = socket.socketpair()
        transport.audio_socket, audio_peer = socket.socketpair()
        transport.process = SimpleNamespace(poll=lambda: None)
        lcd_entered = threading.Event()
        lcd_release = threading.Event()

        def block_lcd(*_args) -> None:
            lcd_entered.set()
            lcd_release.wait(1)

        transport.decoder = SimpleNamespace(
            uc=None, input_error=None, _lcd_write=block_lcd,
        )
        stop = threading.Event()
        worker = threading.Thread(target=transport.replay, args=(stop,))
        lcd_write = bytearray(16)
        lcd_write[0] = LCD_WRITE
        packet = self.pcm_packet(1, 1, 0)
        try:
            worker.start()
            lcd_peer.sendall(lcd_write)
            self.assertTrue(lcd_entered.wait(1))
            audio_peer.sendall(packet)
            self.assertEqual(transport.take_native_audio(0.2), packet)
        finally:
            lcd_release.set()
            stop.set()
            worker.join(1)
            for stream in (transport.input_socket, input_peer,
                           transport.lcd_socket, lcd_peer,
                           transport.audio_socket, audio_peer):
                stream.close()
        self.assertFalse(worker.is_alive())

    def test_qemu_path_never_calls_python_renderer(self) -> None:
        closed = []
        decoder = SimpleNamespace(
            _lcd_page_flush_current=lambda: None,
            _flush_indexed_frame=lambda: None,
            _flush_audio_transport_renderer=lambda: self.fail(
                "native audio must not call Python renderer"
            ),
            audio_player=SimpleNamespace(close=lambda: closed.append(True)),
        )
        transport = self.native_transport()
        transport.decoder = decoder
        transport.audio_native = False
        transport.audio_stream_status = "pending"
        telemetry = bytearray(16)
        telemetry[0] = TELEMETRY
        transport._replay_record(telemetry)
        status = bytearray(16)
        status[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_NATIVE))
        transport._replay_record(status)
        transport._replay_record(telemetry)
        self.assertTrue(transport.audio_native)
        self.assertEqual(transport.audio_stream_status, "native")
        self.assertEqual(closed, [True])
        self.assertIsNone(decoder.audio_player)
        pcm_telemetry = bytearray(16)
        pcm_telemetry[0] = AUDIO_PCM_TELEMETRY
        struct.pack_into("<III", pcm_telemetry, 4, 441, 882, 3)
        transport._replay_record(pcm_telemetry)
        self.assertEqual(
            transport.audio_pcm_snapshot(),
            (441, 882, 3),
        )
        timing_telemetry = bytearray(16)
        timing_telemetry[0] = AUDIO_TIMING_TELEMETRY
        struct.pack_into("<III", timing_telemetry, 4, 4, 2, 3_000_000)
        transport._replay_record(timing_telemetry)
        self.assertEqual(
            transport.audio_timing_snapshot(),
            (4, 2, 3_000_000),
        )

    def test_reset_flushes_old_epoch_and_restarts_write_order(self) -> None:
        owner = AudioMixin()
        owner.audio_transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100]}, "block_write_offsets": [],
        })
        transport = self.native_transport()
        transport.decoder = owner
        transport.audio_stream_enabled = True
        transport.audio_stream_seen = True
        transport.audio_stream_order = 7
        transport.audio_stream_dropped = 3
        transport.audio_pcm_underflow_frames = 441
        transport.audio_pcm_overflow_frames = 882
        transport.audio_pcm_epoch = 1
        transport.audio_timing_late_events = 4
        transport.audio_timing_collapsed_events = 2
        transport.audio_timing_max_lateness_ns = 3_000_000
        transport._queue_native_audio(self.pcm_packet(1, 1, 0))

        reset = bytearray(16)
        reset[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_RESET))
        struct.pack_into("<Q", reset, 4, 2)
        transport._replay_record(reset)

        self.assertEqual(transport.audio_stream_status, "native")
        self.assertTrue(transport.audio_native)
        self.assertEqual(transport.audio_stream_reject_reason, None)
        self.assertEqual((transport.audio_stream_seen,
                          transport.audio_stream_order,
                          transport.audio_stream_dropped),
                         (False, 0, 0))
        self.assertEqual(transport.audio_pcm_snapshot(), (0, 0, 0))
        self.assertEqual(transport.audio_timing_snapshot(), (0, 0, 0))
        self.assertEqual(list(transport.native_audio_packets), [])

        transport._queue_native_audio(self.pcm_packet(1, 2, 441))
        self.assertEqual(transport.audio_stream_status, "native")
        self.assertEqual(list(transport.native_audio_packets), [])
        fresh = self.pcm_packet(2, 1, 50_000)
        transport._queue_native_audio(fresh)
        self.assertEqual(transport.take_native_audio(), fresh)

        write = bytearray(16)
        write[0:2] = bytes((AUDIO_WRITE, 1))
        struct.pack_into("<III", write, 4, 0x100, 0x0F00, 1)
        transport._replay_record(write)
        self.assertEqual(transport.audio_stream_order, 1)
        self.assertEqual(owner.audio_transport.counts["raw-writes"], 1)

        raced = self.native_transport()
        raced.decoder = SimpleNamespace()
        raced.audio_stream_enabled = True
        raced._queue_native_audio(self.pcm_packet(1, 1, 0))
        first = self.pcm_packet(3, 1, 50_000)
        raced._queue_native_audio(first)
        raced._replay_record(reset)
        raced._queue_native_audio(self.pcm_packet(2, 1, 50_000))
        self.assertEqual(list(raced.native_audio_packets), [first])
        latest_reset = bytearray(reset)
        struct.pack_into("<Q", latest_reset, 4, 3)
        raced._replay_record(latest_reset)
        raced._replay_record(latest_reset)
        second = self.pcm_packet(3, 2, 50_441)
        raced._queue_native_audio(second)
        self.assertEqual(list(raced.native_audio_packets), [first, second])
        self.assertEqual(raced.audio_stream_status, "native")

        recovered = self.native_transport()
        recovered._reject_audio_stream("qemu-audio-order-gap")
        recovered._replay_record(reset)
        recovered._queue_native_audio(fresh)
        self.assertEqual(recovered.take_native_audio(), fresh)
        self.assertEqual(recovered.audio_stream_status, "native")
        self.assertIsNone(recovered.audio_stream_reject_reason)

    def test_android_audio_only_exposes_accepted_ma2_pcm(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "msm5xxx_android_audio_test", ANDROID_RUNTIME
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        packet = struct.pack("<4sIQQQ", b"M5P2", 2, 1, 1, 0) \
            + b"\x01\0\x02\0" * 441
        metadata = {"family": "ma2", "static_status": "accepted"}
        transport = SimpleNamespace(
            family="ma2", static_status="accepted",
            renderer_status="submitted", renderer_reject_reason=None,
        )
        process = SimpleNamespace(poll=lambda: None)
        audio_timeouts = []

        def take_native_audio(timeout=0.0):
            audio_timeouts.append(timeout)
            return packet

        runtime._session = SimpleNamespace(
            config=SimpleNamespace(audio_transport=metadata),
            decoder=SimpleNamespace(
                audio_transport=transport,
                frame_sequence=7,
                lcd_writes=9,
            ),
            take_native_audio=take_native_audio,
            audio_pcm_snapshot=lambda: (441, 882, 3),
            audio_stream_reject_reason=None,
            audio_stream_enabled=True,
            audio_stream_status="active",
            input_host_events=4,
            input_rejections=5,
            instructions=6,
            pc=8,
            process=process,
        )
        try:
            status = json.loads(runtime.session_status())
            self.assertEqual(
                (status["audio_underflow_frames"],
                 status["audio_overflow_frames"], status["audio_epoch"],
                 status["audio_status"], status["audio_reject_reason"]),
                (441, 882, 3, "active", ""),
            )
            self.assertEqual(runtime.session_audio(), packet)
            self.assertEqual(audio_timeouts, [0.02])
            metadata["family"] = "ma5"
            self.assertEqual(runtime.session_audio(), b"")
            metadata["family"] = "ma2"
            runtime._session.audio_stream_status = "rejected"
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.audio_stream_status = "active"
            runtime._session.take_native_audio = lambda _timeout=0.0: b"bad"
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.take_native_audio = \
                lambda _timeout=0.0: packet[:32]
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.take_native_audio = lambda _timeout=0.0: packet
            transport.family = "ma5"
            self.assertEqual(runtime.session_audio(), b"")
            transport.family = "ma2"
            overflow = struct.pack(
                "<4sIQQQ", b"M5P2", 2, 1, 1, (1 << 63) - 1
            ) + packet[32:]
            runtime._session.take_native_audio = \
                lambda _timeout=0.0: overflow
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.take_native_audio = lambda _timeout=0.0: packet
            runtime._session_error = "RuntimeError"
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session_error = None
            process.poll = lambda: 1
            self.assertEqual(runtime.session_audio(), b"")
        finally:
            runtime._session = None
            runtime._session_error = None

    def test_overflow_is_terminal(self) -> None:
        owner = AudioMixin()
        owner.audio_transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100]}, "block_write_offsets": [],
        })
        transport = object.__new__(Transport)
        transport.decoder = owner
        transport.audio_stream_enabled = True
        transport.audio_stream_seen = False
        transport.audio_stream_order = 0
        transport.audio_stream_status = "pending"
        transport.audio_stream_reject_reason = None
        transport.audio_stream_dropped = 0
        transport._audio_lock = threading.RLock()
        transport._audio_ready = threading.Condition(transport._audio_lock)
        transport.native_audio_packets = deque(maxlen=4)

        write = bytearray(16)
        write[0:2] = bytes((AUDIO_WRITE, 1))
        struct.pack_into("<III", write, 4, 0x100, 0x0F00, 1)
        transport._replay_record(write)
        overflow = bytearray(16)
        overflow[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_OVERFLOW))
        struct.pack_into("<III", overflow, 4, 1, 1, 0)
        transport._replay_record(overflow)
        write[8:16] = struct.pack("<II", 0, 2)
        transport._replay_record(write)

        self.assertEqual(owner.audio_transport.counts["raw-writes"], 1)
        self.assertEqual(transport.audio_stream_status, "rejected")
        self.assertEqual(
            transport.audio_stream_reject_reason, "qemu-audio-overflow"
        )
        self.assertEqual(transport.audio_stream_dropped, 1)
        self.assertEqual(
            owner.audio_transport.counts["ma2-render-submission-rejections"],
            1,
        )

        transport.audio_stream_status = "active"
        witness = bytearray(16)
        witness[0:2] = bytes((AUDIO_REJECT_TELEMETRY, 0x5A))
        struct.pack_into("<III", witness, 4, 0x00123456, 8,
                         2 | 0xAB << 8 | 1 << 16 | 3 << 24)
        transport._replay_record(witness)
        rejected = bytearray(16)
        rejected[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_REJECTED))
        struct.pack_into("<II", rejected, 4, 9, 2)
        struct.pack_into("<I", rejected, 12, 5)
        transport._replay_record(rejected)
        self.assertEqual(transport.audio_stream_status, "rejected")
        self.assertEqual(
            transport.audio_stream_reject_reason,
            "qemu-audio-core-rejected:0x00000005:order=8:"
            "pc=0x00123456:port=2:value=0xab:page=1:index=0x03:control=0x5a",
        )


if __name__ == "__main__":
    unittest.main()
