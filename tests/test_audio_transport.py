"""Yamaha transport detector and write-stream checks."""
from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.audio import _marker_families
from msm5xxx_emulator.detection.audio import find_audio_transport
from msm5xxx_emulator.core.lifecycle import ApproximateSmafPlayer as LifecycleAudioPlayer
from msm5xxx_emulator.devices.audio import AudioMixin
from msm5xxx_emulator.devices.audio_lle import AudioTransport
from msm5xxx_emulator.e170_gm_audio import ApproximateSmafPlayer
from msm5xxx_emulator.e170_gm_audio import _Ma2SnapshotDecoder
from msm5xxx_emulator.sf2_renderer import render_notes


def _access(image: bytearray, offset: int, base: int,
            port: int, kind: str) -> None:
    immediate, shift = next(
        (immediate, shift)
        for immediate in range(1, 256)
        for shift in range(1, 32)
        if immediate << shift == base
    )
    setup = (0x2000 | immediate, shift << 6)
    opcode = 0x7000 if kind == "write" else 0x7800
    struct.pack_into("<3H", image, offset, *setup, opcode | port << 6 | 1)


class AudioTransportTests(unittest.TestCase):
    def test_lifecycle_uses_packaged_audio_player(self) -> None:
        self.assertIs(LifecycleAudioPlayer, ApproximateSmafPlayer)

    def test_marker_scan_keeps_chunk_boundary_matches(self) -> None:
        image = bytearray(b"\xff" * 128)
        image[62:71] = b"Ma2main.c"
        with patch("msm5xxx_emulator.detection.audio._MARKER_CHUNK", 64):
            self.assertEqual(_marker_families(bytes(image)), ["ma2"])

    def test_unaccepted_transport_skips_hot_path_pc_read(self) -> None:
        class Registers:
            def reg_read(self, register: int) -> int:
                raise AssertionError("unaccepted transport must not read PC")

        owner = AudioMixin()
        owner.audio_transport = AudioTransport(None)
        self.assertFalse(
            owner._audio_transport_owns_write(
                Registers(), 0x02000000, 1
            )
        )

    def test_static_classes_require_complete_unique_grammar(self) -> None:
        ma2 = bytearray(b"\xff" * 0x800)
        ma2[0x700:0x709] = b"Ma2main.c"
        for offset, port, kind in (
            (0x20, 0, "write"), (0x40, 2, "write"),
            (0x60, 1, "write"), (0x80, 0, "write"),
            (0xA0, 2, "write"), (0xC0, 1, "write"),
            (0xE0, 0, "write"), (0x100, 2, "read"),
        ):
            _access(ma2, offset, 0x02080000, port, kind)
        detected = find_audio_transport(bytes(ma2))
        self.assertEqual(
            (detected["family"], detected["grammar"], detected["base"],
             detected["data_offset"]),
            ("ma2", "ma2-command-v1", 0x02080000, 2),
        )
        _access(ma2, 0x120, 0x02880000, 0, "write")
        self.assertEqual(
            find_audio_transport(bytes(ma2))["static_status"], "accepted"
        )

        ma5 = bytearray(b"\xff" * 0x800)
        ma5[0x700:0x707] = b"MA5_SMW"
        for offset, port, kind in (
            (0x20, 0, "write"), (0x40, 0, "read"),
            (0x60, 4, "write"), (0x80, 4, "write"),
            (0xA0, 4, "read"),
        ):
            _access(ma5, offset, 0x02C00000, port, kind)
        detected = find_audio_transport(bytes(ma5))
        self.assertEqual(
            (detected["family"], detected["grammar"], detected["base"],
             detected["data_offset"]),
            ("ma5", "indexed-rw-v1", 0x02C00000, 4),
        )
        ma5[0x710:0x719] = b"Ma2main.c"
        self.assertEqual(
            find_audio_transport(bytes(ma5))["reject_reason"],
            "marker-ambiguous",
        )

    def test_ma3_marker_stays_fail_closed_without_decoder(self) -> None:
        ma3 = bytearray(b"\xff" * 0x800)
        ma3[0x700:0x707] = b"MA3_SMW"
        for offset, port, kind in (
            (0x20, 0, "write"), (0x40, 0, "read"),
            (0x60, 4, "write"), (0x80, 4, "write"),
            (0xA0, 4, "read"),
        ):
            _access(ma3, offset, 0x02C00000, port, kind)
        detected = find_audio_transport(bytes(ma3))
        self.assertEqual(
            (detected["family"], detected["grammar"],
             detected["static_status"], detected["reject_reason"]),
            ("ma3", None, "rejected", "protocol-unsupported"),
        )

    def test_ma2_stream_keeps_sticky_register_and_fifo_indexes(self) -> None:
        transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100], "write_2": [0x102]},
            "block_write_offsets": [],
        })
        for pc, port, value in (
            (0x100, 0, 0x0F), (0x102, 2, 1),
            (0x100, 0, 0x22), (0x102, 2, 0x18),
            (0x102, 2, 0x19),
        ):
            self.assertTrue(
                transport.write(pc, 0x02080000 + port, 1, value)
            )
        writes = [
            event for event in transport.recent
            if event["kind"] == "ma2-register-write"
        ]
        self.assertEqual(
            [(event["address"], event["value"]) for event in writes],
            [(0x122, 0x18), (0x122, 0x19)],
        )
        for pc, port, value in (
            (0x100, 0, 0x0F), (0x102, 2, 0),
            (0x100, 0, 2), (0x102, 2, 0xAA),
            (0x102, 2, 0xBB),
        ):
            self.assertTrue(
                transport.write(pc, 0x02080000 + port, 1, value)
            )
        fifo = [
            event for event in transport.recent
            if event["kind"] == "ma2-fifo-write"
        ]
        self.assertEqual(
            [(event["fifo_kind"], event["value"]) for event in fifo],
            [("fm-2", 0xAA), ("fm-2", 0xBB)],
        )
        self.assertFalse(transport.write(0x104, 0x02080000, 1, 0))

    def test_ma2_snapshot_is_chunk_drained_and_not_replayed(self) -> None:
        transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100], "write_2": [0x102]},
            "block_write_offsets": [],
        })

        def write_index(index: int, value: int) -> None:
            self.assertTrue(transport.write(0x100, 0x02080000, 1, index))
            self.assertTrue(transport.write(0x102, 0x02080002, 1, value))

        write_index(0x0F, 1)
        write_index(2, 0x22)
        write_index(0x0F, 0)
        self.assertTrue(transport.write(0x100, 0x02080000, 1, 0))
        for value in bytes.fromhex("00fff000000101"):
            self.assertTrue(transport.write(0x102, 0x02080002, 1, value))
        write_index(0x0F, 1)
        write_index(1, 0)
        write_index(1, 1)

        snapshots = transport.drain_renderer_snapshots()
        self.assertEqual(len(snapshots), 1)
        snapshot = snapshots[0]
        self.assertEqual(transport.drain_renderer_snapshots(), ())
        decoder = _Ma2SnapshotDecoder()
        notes = decoder.decode(snapshot)
        self.assertEqual(
            [(note.tick, note.ch, note.note, note.span) for note in notes],
            [(0, 0, 37, 1)],
        )
        self.assertEqual(decoder.decode(snapshot), [])

        class Player:
            def __init__(self) -> None:
                self.snapshots = []

            last_submit_error = None

            def play_ma2_snapshots(
                    self, value: tuple[dict[str, object], ...]) -> bool:
                self.snapshots.extend(value)
                return True

        write_index(1, 0)
        write_index(1, 1)
        owner = AudioMixin()
        owner.audio_transport = transport
        owner.audio_player = Player()
        owner.fault = None
        owner._flush_audio_transport_renderer()
        self.assertEqual(len(owner.audio_player.snapshots), 1)
        self.assertEqual(transport.renderer_status, "submitted")

    def test_ma2_snapshot_survives_timebase_change_in_same_chunk(self) -> None:
        transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100], "write_2": [0x102]},
            "block_write_offsets": [],
        })

        def write(index: int, value: int) -> None:
            transport.write(0x100, 0x02080000, 1, index)
            transport.write(0x102, 0x02080002, 1, value)

        write(0x0F, 1)
        write(2, 0x22)
        write(0x0F, 0)
        transport.write(0x100, 0x02080000, 1, 0)
        for value in bytes.fromhex("00fff000000101"):
            transport.write(0x102, 0x02080002, 1, value)
        write(0x0F, 1)
        write(1, 0)
        write(1, 1)
        write(2, 0x23)

        snapshots = transport.drain_renderer_snapshots()
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["timebase"], 0x22)
        self.assertEqual(
            [(note.note, note.span)
             for note in _Ma2SnapshotDecoder().decode(snapshots[0])],
            [(37, 1)],
        )

    def test_ma2_player_rejects_malformed_and_stays_closed(self) -> None:
        player = ApproximateSmafPlayer()
        try:
            self.assertIsNotNone(player._soundfont)
            self.assertTrue(all(
                (0, program) in player._soundfont.presets
                for program in range(128)
            ))
            notes = _Ma2SnapshotDecoder().decode({
                "kind": "ma2-fifo-snapshot",
                "epoch": 0,
                "sequence": 1,
                "timebase": 0x22,
                "fifos": (bytes.fromhex("00fff000000101"), b"", b"", b""),
            })
            pcm = render_notes(
                player._soundfont, notes, sample_rate=8000, max_seconds=1.0
            )
            self.assertTrue((pcm != 0).any())
            self.assertFalse(player.play_ma2_snapshot({
                "kind": "ma2-fifo-snapshot",
                "epoch": 0,
                "sequence": 1,
                "timebase": 0x88,
                "fifos": (b"",) * 4,
            }))
            self.assertEqual(player.last_submit_error, "ma2-snapshot-invalid")
        finally:
            player.close()
        self.assertFalse(player._thread.is_alive())
        self.assertFalse(player.play_ma2_snapshot({
            "kind": "ma2-fifo-snapshot",
            "epoch": 0,
            "sequence": 1,
            "timebase": 0x22,
            "fifos": (b"",) * 4,
        }))
        self.assertEqual(player.last_submit_error, "audio-player-closed")

    def test_ma5_fifo_decodes_register_write_without_readback(self) -> None:
        transport = AudioTransport({
            "family": "ma5", "grammar": "indexed-rw-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02C00000, "data_offset": 4,
            "sites": {"write_0": [0x100], "write_4": [0x200, 0x220]},
            "block_write_offsets": [0x220],
        })
        self.assertTrue(transport.write(0x100, 0x02C00000, 1, 1))
        for value in (0x80, 0x83, 0xC0):
            self.assertTrue(transport.write(0x220, 0x02C00004, 1, value))
        self.assertEqual(transport.ma5_fifo.state, 0)
        self.assertEqual(transport.ma5_registers[3], 0x40)
        self.assertEqual(
            transport.counts["ma5-register-write"], 1
        )
        self.assertEqual(transport.counts["raw-reads"], 0)


if __name__ == "__main__":
    unittest.main()
