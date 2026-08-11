"""QEMU MA2 sideband-to-PCM check."""
from __future__ import annotations

from pathlib import Path
import importlib.util
import struct
import sys
import time
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.devices.audio import AudioMixin
from msm5xxx_emulator.devices.audio_lle import AudioTransport
from msm5xxx_emulator.e170_gm_audio import ApproximateSmafPlayer


EXPERIMENT = Path(__file__).parents[1] / "experiments/qemu-tcg"
sys.path.insert(0, str(EXPERIMENT))
from qemu_transport import (  # noqa: E402
    AUDIO_STATUS, AUDIO_STATUS_OVERFLOW, AUDIO_WRITE, TELEMETRY, Transport,
)

ANDROID_RUNTIME = (
    Path(__file__).parents[1]
    / "android-client/app/src/main/python/msm5xxx_android_runtime.py"
)


class QEMUAudioTransportTests(unittest.TestCase):
    def test_android_audio_only_exposes_accepted_ma2_pcm(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "msm5xxx_android_audio_test", ANDROID_RUNTIME
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        packet = struct.pack("<4sIQQ", b"M5P1", 1, 1, 0) \
            + b"\x01\0\x02\0"
        player = SimpleNamespace(take_latest_pcm=lambda: packet)
        metadata = {"family": "ma2", "static_status": "accepted"}
        transport = SimpleNamespace(
            family="ma2", static_status="accepted",
            renderer_status="submitted", renderer_reject_reason=None,
        )
        process = SimpleNamespace(poll=lambda: None)
        runtime._session = SimpleNamespace(
            config=SimpleNamespace(audio_transport=metadata),
            decoder=SimpleNamespace(
                audio_transport=transport,
                audio_player=player,
            ),
            audio_stream_enabled=True,
            audio_stream_status="active",
            process=process,
        )
        try:
            self.assertEqual(runtime.session_audio(), packet)
            metadata["family"] = "ma5"
            self.assertEqual(runtime.session_audio(), b"")
            metadata["family"] = "ma2"
            runtime._session.audio_stream_status = "rejected"
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.audio_stream_status = "active"
            player.take_latest_pcm = lambda: b"bad"
            self.assertEqual(runtime.session_audio(), b"")
            player.take_latest_pcm = lambda: packet[:24]
            self.assertEqual(runtime.session_audio(), b"")
            player.take_latest_pcm = lambda: packet
            transport.family = "ma5"
            self.assertEqual(runtime.session_audio(), b"")
            transport.family = "ma2"
            runtime._session_error = "RuntimeError"
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session_error = None
            process.poll = lambda: 1
            self.assertEqual(runtime.session_audio(), b"")
        finally:
            runtime._session = None
            runtime._session_error = None

    def test_ma2_sideband_renders_pcm_and_rejects_order_gap(self) -> None:
        owner = AudioMixin()
        owner.audio_transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100], "write_2": [0x102]},
            "block_write_offsets": [],
        })
        owner.audio_player = ApproximateSmafPlayer()
        owner.audio_player.set_muted(True)
        owner.fault = None
        owner._lcd_page_flush_current = lambda: None
        owner._flush_indexed_frame = lambda: None
        transport = object.__new__(Transport)
        transport.decoder = owner
        transport.audio_stream_enabled = True
        transport.audio_stream_seen = False
        transport.audio_stream_order = 0
        transport.audio_stream_status = "pending"
        transport.audio_stream_reject_reason = None
        transport.audio_stream_dropped = 0

        order = 0

        def write(port: int, value: int) -> None:
            nonlocal order
            order += 1
            record = bytearray(16)
            record[0:2] = bytes((AUDIO_WRITE, 1))
            struct.pack_into(
                "<III", record, 4,
                0x100 if port == 0 else 0x102,
                port | value << 8, order,
            )
            transport._replay_record(record)

        try:
            for port, value in (
                (0, 0x0F), (2, 1), (0, 2), (2, 0x22),
                (0, 0x0F), (2, 0), (0, 0),
                *((2, value) for value in bytes.fromhex("00fff000000101")),
                (0, 0x0F), (2, 1), (0, 1), (2, 0), (0, 1), (2, 1),
            ):
                write(port, value)
            telemetry = bytearray(16)
            telemetry[0] = TELEMETRY
            transport._replay_record(telemetry)
            deadline = time.monotonic() + 2
            while owner.audio_player.last_pcm is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIsNotNone(owner.audio_player.last_pcm)
            self.assertTrue(owner.audio_player.last_pcm.any())
            self.assertEqual(owner.audio_transport.renderer_status, "submitted")
            owner.audio_player.muted = False
            pcm = owner.audio_player.take_latest_pcm()
            self.assertGreater(len(pcm), 24)
            self.assertEqual(
                struct.unpack_from("<4sIQQ", pcm),
                (b"M5P1", 1, 1, 0),
            )
            self.assertEqual((len(pcm) - 24) % 4, 0)
            self.assertEqual(owner.audio_player.take_latest_pcm(), b"")
            owner.audio_player.muted = True
            raw_writes = owner.audio_transport.counts["raw-writes"]

            order += 2
            gap = bytearray(16)
            gap[0:2] = bytes((AUDIO_WRITE, 1))
            struct.pack_into("<III", gap, 4, 0x100, 0, order)
            transport._replay_record(gap)
            self.assertEqual(transport.audio_stream_status, "rejected")
            self.assertEqual(
                transport.audio_stream_reject_reason, "qemu-audio-order-gap"
            )
            self.assertEqual(owner.audio_transport.counts["raw-writes"], raw_writes)
        finally:
            owner.audio_player.close()

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


if __name__ == "__main__":
    unittest.main()
