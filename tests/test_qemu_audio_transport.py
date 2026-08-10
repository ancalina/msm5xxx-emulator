"""QEMU MA2 sideband-to-PCM check."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import time
import unittest

from msm5xxx_emulator.devices.audio import AudioMixin
from msm5xxx_emulator.devices.audio_lle import AudioTransport
from msm5xxx_emulator.e170_gm_audio import ApproximateSmafPlayer


EXPERIMENT = Path(__file__).parents[1] / "experiments/qemu-tcg"
sys.path.insert(0, str(EXPERIMENT))
from qemu_transport import (  # noqa: E402
    AUDIO_STATUS, AUDIO_STATUS_OVERFLOW, AUDIO_WRITE, TELEMETRY, Transport,
)


class QEMUAudioTransportTests(unittest.TestCase):
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
