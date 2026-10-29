"""Yamaha transport detector and write-stream checks."""
from __future__ import annotations

import struct
import threading
import time
import unittest
from unittest.mock import patch

import numpy as np

from msm5xxx_emulator.detection.audio import (
    _marker_families, _synthesized_base_accesses,
)
from msm5xxx_emulator.detection.audio import find_audio_transport, find_ma5_readback_candidate
from msm5xxx_emulator.detection.arm import thumb_bl_target
from msm5xxx_emulator.detection.memory_layout import find_linker_layout
from msm5xxx_emulator.core.lifecycle import ApproximateSmafPlayer as LifecycleAudioPlayer
from msm5xxx_emulator.devices.audio import AudioMixin
from msm5xxx_emulator.devices.audio_lle import AudioTransport
from msm5xxx_emulator.audio.player import ApproximateSmafPlayer
from msm5xxx_emulator.audio.player import _Ma2SnapshotDecoder
from msm5xxx_emulator.audio.sf2 import render_notes


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


def _thumb_bl(source: int, target: int) -> bytes:
    displacement = (target - source - 4) & 0x7FFFFF
    return struct.pack(
        "<2H",
        0xF000 | displacement >> 12 & 0x7FF,
        0xF800 | displacement >> 1 & 0x7FF,
    )


def _ma5_readback_image(relocation: int = 0) -> bytes:
    # Original instruction fixture, relocated as a linked producer graph.
    spans = (
        (0x25ad08, 0x100, '90b5c0270024e443381cfff73bf9002811db0006000e60280cd10137d02ff3d3d027381cfff72ef9002804db0006000e3c2803d0201c90bc08bc18470137e02fefd30020f7e7'),
        (0x259f8c, 0x200, 'f0b5071c294809260068f6018019817801318170032001f0cff901f049fc041c002805da00f084fe201cf0bc08bc18478025802f02d22f43381c13e0fc097806400e01239b039f4204d201f0a9fb2c43201c07e001f0a4fb6006400e01f0a0fbb80b28430006000e01f09afb802001f097fb402001f0cafb071c002802da00f057fe11e0412001f097f901f0b1fb071c064800688119887801380006000e887002d1802001f088f9381cbee7880c0101'),
        (0x25b344, 0x400, '0a4a80b511680923db01c9180f7808701168c9184978012901d14006400e00f0c5f9381c80bc08bc18470000880c0101'),
        (0x25b798, 0x500, 'f0b50f4d041c00262e80fff7b5ff071c28880c4b013028802888984209dd0420c0432e80fff796ff0420c043f0bc08bc18475af6a9fc2740e7d00020f6e70000941c4e01dc050000'),
        (0x25b83c, 0x600, 'b0b50e4c00252580fff764ff071c20880b4b013020802088984209dd0420c0432580fff745ff0420c043b0bc08bc18475af658fc7808e7d30020f6e7941c4e01dc050000'),
        (0x25b6f0, 0x700, '80b5071cf8f5f2fd04490020486015204005077080bc08bc18470000941c4e01'),
        (0x25b710, 0x720, '00b5f8f5e3fd04490120486015204005007808bc18470000941c4e01'),
        (0x25b72c, 0x73c, '80b5071cf8f5d4fd04490020486015204005877080bc08bc18470000941c4e01'),
        (0x25b74c, 0x75c, 'b0b5041c0f1c0ed0f8f5c2fd0020074915256d05486004e020780134a870f8f5b7fd013ff8d2b0bc08bc1847941c4e01'),
        (0x25b77c, 0x78c, '00b5f8f5adfd04490120486015204005807808bc18470000941c4e01'),
    )
    addresses = {original: target + relocation for original, target, _ in spans}
    addresses.update({0x542DC: 0x1800 + relocation,
                      0x25ACBC: 0x1802 + relocation,
                      0x25B6EC: 0x1804 + relocation,
                      0xB6120: 0x1806 + relocation})
    image = bytearray(b"\xff" * (0x2000 + relocation))
    for original, target, encoded in spans:
        target += relocation
        code = bytearray.fromhex(encoded)
        for offset in range(0, len(code) - 3, 2):
            destination = thumb_bl_target(code, offset)
            if destination is not None:
                code[offset:offset + 4] = _thumb_bl(
                    target + offset, addresses[original + destination])
        image[target:target + len(code)] = code
    return bytes(image)


def _ma5_literal_readback_image(relocation: int = 0) -> bytes:
    spans = (
        (0x138a10, 0x100, '90b5c0270024e443381cfff735f9002811db0006000e60280cd10137d02ff3d3d027381cfff728f9002804db0006000e3c2803d0201c90bc08bc18470137e02fefd30020f7e7'),
        (0x137c88, 0x200, 'f0b5071c294809260068f6018019817801318170032001f0d7f901f0a1fa041c002805da00f08afe201cf0bc08bc18478025802f02d22f43381c13e0fc097806400e01239b039f4204d201f017fa2c43201c07e001f012fa6006400e01f00efab80b28430006000e01f008fa802001f005fa402001f03afa071c002802da00f05dfe11e0412001f09ff901f00dfa071c064800688119887801380006000e887002d1802001f090f9381cbee7d0128201'),
        (0x139050, 0x400, '0a4a80b511680923db01c9180f7808701168c9184978012901d14006400e00f020f8381c80bc08bc18470000d0128201'),
        (0x139174, 0x500, '90b5041c0027fff7afffff231a339f4208dd0420c043fff781ff0420c04390bc08bc184701372040edd00020f7e7'),
        (0x1391e8, 0x600, '80b50027fff776ff084b9f4208dd0420c043fff749ff0420c04380bc08bc184701374008eed30020f7e7000028230000'),
        (0x1390b2, 0x702, '084b80b41f680121002f064a00d1117011700021196009218905087080bc70470000b86db601327d8201'),
        (0x1390dc, 0x72c, '074a012013680749002b03d10870087008700870087010600920800500787047b86db601327d8201'),
        (0x139104, 0x754, '074b80b41f680121002f064a00d111701170002119600449087080bc70470000b86db601327d820180004002'),
        (0x139130, 0x780, '074a012013680749002b03d10870087008700870087010600348007870470000b86db601327d820180004002'),
        (0x13915c, 0x7ac, '002906d0034a02e00378013013700139fad2704780004002'),
    )
    addresses = {original: target + relocation for original, target, _ in spans}
    addresses.update({0x139090: 0x1800 + relocation, 0x1389C4: 0x1802 + relocation})
    image = bytearray(b"\xff" * (0x2000 + relocation))
    for original, target, encoded in spans:
        target += relocation
        code = bytearray.fromhex(encoded)
        for offset in range(0, len(code) - 3, 2):
            destination = thumb_bl_target(code, offset)
            if destination is not None:
                code[offset:offset + 4] = _thumb_bl(
                    target + offset, addresses[original + destination])
        image[target:target + len(code)] = code
    image[0x1800 + relocation:0x1802 + relocation] = b"\x70\x47"
    return bytes(image)


def _sequence_image(shift: int = 0) -> tuple[bytearray, dict[str, int]]:
    spans = {
        'timer': (0xb00, (156,),
            'fcb51c1c0126f6430328079d07dc012d05dc012c03dc01278740fb0803d0301cfcbc08bc1847214bdb681e1c3e4002d00220c043f4e7061c5006400ea2006d002a43022e16da9b0712d1522400ab1c7082245c708023194300ab99705421d970822119715871802010439871072114e0002015e00121012c00d000210906090e572400ab1c7082245c7098700a43101c8023184300abd8700421684604f0aaf9024bd9683943d960bae7'),
        'timer-stop': (0xbb0, (70,),
            '98b5021c0020871e022a03dc01219140cb0803d0381c98bc08bc18470b4f0c1cfb689c4302d00020c043f4e75940f960022af0d1582000ab187082205870802098700321684604f07df9e4e7'),
        'sequence': (0x100, (76,),
            '9cb501228240930804d00120c0439cbc08bc1847104f7b6a1c1c144002d00220c043f4e71a437a62002812d15e2000ab187082205870c8114006400e98704806400ed870842018710521684604f052f9dde70020dbe7'),
        'sender': (0x200, (8, 16, 36, 54, 72, 88, 104),
            'f0b5071c0e1c022002f0a1fdb5090de002f082fe041c002800da11e0402403e03878013702f0a5fd013cf9d2013defd2b506ad0e14d002f06ffe041c00280dda0b4840682030007902f081fd201cf0bc08bc18473878013702f08bfd013df9d2034840682030007902f071fd0020eee7'),
        'init': (0x400, (2, 8, 14, 20, 26, 32),
            '042001f012fe002001f021fe052001f00cfe0e2001f01bfe062001f006fe3f2001f015fe'),
        'alternate-init': (0x45e, (2, 8, 14, 20, 26, 32),
            '042001f0e3fd002001f0f2fd052001f0ddfd0e2001f0ecfd062001f0d7fd3e2001f0e6fd'),
        'reset': (0x43c, (2, 8, 12, 18),
            '042001f0f4fd802001f003fe83f67efb002001f0fefd'),
        'empty': (0x8ee, (4, 14, 26, 38, 50, 62, 78, 94, 120, 130, 142, 154, 166, 178, 188, 198),
            'f0b50027fff7a8ff800800d30127fff7a3ff800801d302200743fff79dff800801d304200743fff797ff800801d308200743fff791ff800801d310200743fff78bff022318402024002800d02743fff783ff022318404025002800d02f43fff77bff022318408026002800d03743002f34d0ff2f2ed00027fff76eff800800d30127fff769ff800801d302200743fff763ff800801d304200743fff75dff800801d308200743fff757ff800801d310200743fff751ff800800d32743fff74cff800800d32f43fff747ff800800d33743ff2f03d10120f0bc08bc18470020fae7'),
        'ready': (0xa00, (14, 24, 36, 48, 60, 72, 84, 94),
            'f0b5224c00204025802620700027fff71aff400800d30127fff715ff400801d302200743fff70fff400801d304200743fff709ff400801d308200743fff703ff400801d310200743fff7fdfe400801d320200743fff7f7fe400800d32f43fff7f2fe400800d337432078013020700006000e642805dd00202070c043f0bc08bc1847ff2fc2d10020f8e7'),
        'wrapper': (0x600, (8, 24, 44, 60),
            '4121c90400b5087081f689fd08bc18474120c00480b5077881f681fd381c80bc08bc18474121c90400b5887081f677fd08bc18474120c00480b5877881f66ffd381c80bc08bc1847'),
    }
    image = bytearray(b"\xff" * (0xe00 + shift))
    targets = {
        "timer": [0x200], "timer-stop": [0x200],
        "sequence": [0x200],
        "sender": [0x600, 0xa00, 0x624, 0xa00, 0x600, 0x624, 0x600],
        "init": [0x600, 0x624] * 3,
        "alternate-init": [0x600, 0x624] * 3,
        "reset": [0x600, 0x624, 0x800, 0x624],
        "empty": [0x610] * 16, "ready": [0x610] * 8,
        "wrapper": [0x800] * 4,
    }
    for role, (offset, calls, hex_code) in spans.items():
        code = bytes.fromhex(hex_code)
        start = offset + shift
        image[start:start + len(code)] = code
        for call, target in zip(calls, targets[role]):
            image[start + call:start + call + 4] = _thumb_bl(start + call, target + shift)
    image[0x49a + shift:0x4b0 + shift] = image[0x43c + shift:0x452 + shift]
    for call, target in zip((2, 8, 12, 18), targets["reset"]):
        start = 0x49a + shift + call
        image[start:start + 4] = _thumb_bl(start, target + shift)
    image[0x800 + shift:0x802 + shift] = b"\x70\x47"
    struct.pack_into("<I", image, 0x200 + shift + 112, 0x1000100)
    struct.pack_into("<I", image, 0x100 + shift + 88, 0x1000200)
    struct.pack_into("<I", image, 0xbac + shift, 0x1000200)
    struct.pack_into("<I", image, 0xbfc + shift, 0x1000200)
    struct.pack_into("<I", image, 0xa00 + shift + 140, 0x1000300)
    return image, {role: offset + shift for role, (offset, _, _) in spans.items()}


def _sequence_clear_image(shift: int = 0) -> tuple[bytearray, dict[str, int]]:
    image, roles = _sequence_image(shift)
    clear = 0xd00 + shift
    code = bytes.fromhex(
        "90b5042001f0f3fe282001f002ff83f67dfc002001f0fdfe03211448fff740f9"
        "124f0020163f21227968520189180873796889184873002441007b680130c918"
        "89184c820428f7db78682030007901f0cefe78682030c4717868203044707868"
        "2030047090bc08bc00201847")
    image[clear:clear + 108] = code
    for offset, target in zip((4, 10, 14, 20, 28, 78),
                              (roles["wrapper"], roles["wrapper"] + 0x24,
                               0x800 + shift, roles["wrapper"] + 0x24,
                               roles["sender"], roles["wrapper"])):
        image[clear + offset:clear + offset + 4] = _thumb_bl(clear + offset, target)
    payload = 0x1000116
    struct.pack_into("<I", image, clear + 108, payload)
    source = len(image)
    image.extend(b"\xff" * 0x200)
    table = 0x300 + shift
    struct.pack_into("<5I", image, table, source, 0x1000000, 0x200,
                     0x1000200, 0x1000)
    image[source + 0x116:source + 0x119] = b"\x60\x82\x84"
    return image, {**roles, "clear": clear, "copy": table, "payload_rom": source + 0x116}


class AudioTransportTests(unittest.TestCase):
    def test_optional_clear_contract_relocated_and_byte_dependencies(self):
        for shift in (0, 0x2000):
            image, roles = _sequence_clear_image(shift)
            found = find_audio_transport(bytes(image))
            self.assertEqual(found["static_status"], "accepted")
            self.assertEqual(found["control_clear_status"], "accepted")
            self.assertIsNone(found["control_clear_reject_reason"])
            self.assertEqual(found["control_clear_producer"], roles["clear"])
            self.assertEqual(found["control_clear_payload"], 0x1000116)
            self.assertEqual(found["ram_dependencies"][-3:],
                             [[0x1000116 + i, 1] for i in range(3)])
            self.assertIn([roles["payload_rom"], 3], found["nor_dependencies"])
            self.assertIn([roles["copy"], 20], found["nor_dependencies"])

    def test_optional_clear_failures_preserve_existing_sequence(self):
        image, roles = _sequence_clear_image()
        mutations = {}
        for offset in (4, 10, 14, 20, 28, 78):
            bad = bytearray(image)
            site = roles["clear"] + offset
            bad[site:site + 4] = _thumb_bl(site, roles["timer"])
            mutations[f"other-in-image-target-{offset}"] = bad
            bad = bytearray(image)
            bad[site:site + 4] = b"\xc0\x46" * 2
            mutations[f"erased-bl-{offset}"] = bad
        for offset in (8, 18, 24):
            bad = bytearray(image)
            bad[roles["clear"] + offset] ^= 1
            mutations[f"opcode-{offset}"] = bad
        bad = bytearray(image)
        struct.pack_into("<I", bad, roles["clear"] + 108, 0x1000117)
        mutations["wrong-shared-state"] = bad
        bad = bytearray(image)
        bad[roles["payload_rom"] + 2] ^= 1
        mutations["wrong-payload"] = bad
        for field, value in ((0, len(image)), (8, 0x118), (12, 0x1000300)):
            bad = bytearray(image)
            struct.pack_into("<I", bad, roles["copy"] + field, value)
            mutations[f"invalid-copy-{field}"] = bad
        bad = bytearray(image)
        # Two valid covering copies are ambiguous, even if one payload matches.
        struct.pack_into("<5I", bad, 0x2a0, roles["payload_rom"] - 0x11a,
                         0x1000000, 0x200, 0x1000200, 0x1000)
        mutations["ambiguous-covering-copy"] = bad
        bad = bytearray(image)
        duplicate = 0xc20
        bad[duplicate:duplicate + 112] = image[roles["clear"]:roles["clear"] + 112]
        for offset, target in zip((4, 10, 14, 20, 28, 78),
                                  (0x600, 0x624, 0x800, 0x624, 0x200, 0x600)):
            bad[duplicate + offset:duplicate + offset + 4] = _thumb_bl(duplicate + offset, target)
        mutations["duplicate-clear"] = bad
        mutations["truncated-clear-literal"] = image[:roles["clear"] + 110]
        absent, _ = _sequence_image()
        mutations["absent-clear"] = absent
        for label, bad in mutations.items():
            with self.subTest(label=label):
                found = find_audio_transport(bytes(bad))
                self.assertEqual(found["static_status"], "accepted")
                self.assertEqual(found["grammar"], "repeated-bit-sequence-v1")
                self.assertEqual(found["control_clear_status"], "unavailable")
                self.assertTrue(found["control_clear_reject_reason"])
                self.assertNotIn("control_clear_producer", found)
                self.assertNotIn("control_clear_payload", found)
                self.assertEqual(found["ram_dependencies"],
                                 [[0x1000100, 8], [0x1000200, 40], [0x1000300, 1]])

    def test_optional_clear_copy_selection_preserves_default(self):
        image, roles = _sequence_clear_image()
        struct.pack_into("<5I", image, 0x2a0, 0x100, 0x13feffc, 0x34,
                         0x13ff030, 0x978)
        default = find_linker_layout(bytes(image))
        self.assertEqual(default.table_offset, 0x2a0)
        self.assertEqual(default.data_target, 0x13feffc)
        selected = find_linker_layout(bytes(image), required_span=(0x1000116, 3))
        self.assertEqual(selected.table_offset, roles["copy"])
        self.assertEqual(find_audio_transport(bytes(image))["control_clear_status"], "accepted")
        for span in ([], (), (1,), (1, 2, 3), (True, 3), (-1, 3),
                     (0x1000116, 0), (0xffffffff, 3), (0x1000200, 1)):
            with self.subTest(span=span):
                self.assertIsNone(find_linker_layout(bytes(image), required_span=span))
        duplicate = bytearray(image)
        duplicate[0x2c0:0x2d4] = image[roles["copy"]:roles["copy"] + 20]
        self.assertIsNone(find_linker_layout(bytes(duplicate), required_span=(0x1000116, 3)))
        self.assertEqual(find_audio_transport(bytes(duplicate))["static_status"], "accepted")
        self.assertEqual(find_audio_transport(bytes(duplicate))["control_clear_status"], "unavailable")

    def test_sequence_class_requires_same_image_producer_reset_and_consumers(self):
        for shift in (0, 0x2000):
            image, roles = _sequence_image(shift)
            detected = find_audio_transport(bytes(image))
            self.assertEqual(detected["grammar"], "repeated-bit-sequence-v1")
            self.assertEqual(detected["static_status"], "accepted")
            self.assertEqual(detected["begin"], roles["wrapper"] + 6)
            self.assertEqual(detected["sequence_producer"], roles["sequence"])
            self.assertEqual(detected["timer_producer"], roles["timer"])
            self.assertEqual(detected["timer_stop_producer"], roles["timer-stop"])
            self.assertIn([roles["ready"] + 140, 4], detected["nor_dependencies"])
            self.assertEqual(detected["ram_dependencies"],
                             [[0x1000100, 8], [0x1000200, 40], [0x1000300, 1]])
            for role, literal in (("timer", 172), ("timer-stop", 76)):
                bad = bytearray(image)
                struct.pack_into("<I", bad, roles[role] + literal, 0x1000300)
                self.assertNotEqual(find_audio_transport(bytes(bad))["static_status"], "accepted")
            self.assertTrue(detected["requires_runtime_reset"])
            self.assertEqual(detected["renderer_status"], "unavailable")
            for role in roles:
                with self.subTest(shift=shift, damaged=role):
                    bad = bytearray(image)
                    bad[roles[role]] ^= 1
                    self.assertNotEqual(find_audio_transport(bytes(bad))["static_status"], "accepted")
            for site in (roles["timer"] + 156, roles["timer-stop"] + 70,
                         roles["sequence"] + 76, roles["sender"] + 16,
                         roles["ready"] + 14, roles["empty"] + 4,
                         roles["init"] + 2, 0x49a + shift + 12):
                bad = bytearray(image)
                bad[site:site + 4] = _thumb_bl(site, 0xb00 + shift)
                self.assertNotEqual(find_audio_transport(bytes(bad))["static_status"], "accepted")
            bad = bytearray(image)
            bad[0x800 + shift] ^= 1
            self.assertNotEqual(find_audio_transport(bytes(bad))["static_status"], "accepted")
            bad = bytearray(image)
            duplicate = 0xd00 + shift
            bad[duplicate:duplicate + 86] = image[roles["sequence"]:roles["sequence"] + 86]
            bad[duplicate + 76:duplicate + 80] = _thumb_bl(duplicate + 76, roles["sender"])
            self.assertNotEqual(find_audio_transport(bytes(bad))["static_status"], "accepted")
            self.assertNotEqual(find_audio_transport(bytes(image[:roles["ready"] + 136]))["static_status"], "accepted")

    def test_sequence_literal_owners_require_word_alignment(self):
        image, _ = _sequence_image(2)
        self.assertNotEqual(find_audio_transport(bytes(image))["static_status"], "accepted")

    def test_sequence_metadata_integrates_with_firmware_detector(self):
        import tempfile
        from pathlib import Path
        from msm5xxx_emulator.detection.firmware import detect
        image, _ = _sequence_image()
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / "protocol.bin"
            firmware.write_bytes(image)
            config = detect(firmware)
        self.assertEqual(config.audio_transport["static_status"], "accepted")
        self.assertEqual(config.audio_transport["grammar"], "repeated-bit-sequence-v1")
        self.assertEqual(config.audio_transport["block_write_offsets"], [])

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
        _access(ma5, 0x500, 0x02C00000, 0, "write")
        _access(ma5, 0x520, 0x02C00000, 4, "write")
        detected = find_audio_transport(bytes(ma5))
        self.assertEqual(
            (detected["family"], detected["grammar"], detected["base"],
             detected["data_offset"]),
            ("ma5", "indexed-rw-v1", 0x02C00000, 4),
        )
        self.assertEqual(detected["aperture_write_sites"], {
                "write_0": [0x24, 0x504],
                "write_4": [0x64, 0x84, 0x524],
        })
        ma5[0x710:0x719] = b"Ma2main.c"
        self.assertEqual(
            find_audio_transport(bytes(ma5))["reject_reason"],
            "marker-ambiguous",
        )

    def test_experimental_ma5_readback_requires_closed_relocated_graph(self) -> None:
        for relocation in (0, 0x100, 0x1000):
            with self.subTest(relocation=relocation):
                image = _ma5_readback_image(relocation)
                profile = find_ma5_readback_candidate(image)
                self.assertEqual(profile["static_status"], "candidate")
                self.assertEqual((profile["base"], profile["data_offset"]),
                                 (0x02A00000, 2))
                for target in (0x1800, 0x1802, 0x1804, 0x1806):
                    self.assertIn([target + relocation, 2], profile["nor_dependencies"])
                self.assertEqual(profile["ram_dependencies"],
                                 [[0x1010C88, 4], [0x14E1C94, 8]])
                self.assertEqual(profile["sites"], {
                    "write_0": [0x712 + relocation],
                    "read_0": [0x730 + relocation],
                    "write_2": [0x74E + relocation, 0x778 + relocation],
                    "read_2": [0x79C + relocation],
                })
                detected = find_audio_transport(image)
                self.assertEqual(detected["static_status"], "candidate")
                self.assertEqual(detected["protocol_status"], "temporary-evidence-gated")
                self.assertEqual(detected["base"], 0x02A00000)
        image = _ma5_readback_image()
        for offset in (0x116, 0x22A, 0x412, 0x730, 0x778, 0x71C):
            with self.subTest(mutation=hex(offset)):
                changed = bytearray(image)
                changed[offset] ^= 1
                self.assertEqual(find_ma5_readback_candidate(bytes(changed))["static_status"],
                                 "rejected")
        changed = bytearray(image)
        changed[0x10A:0x10E] = _thumb_bl(0x10A, 0x204)
        self.assertEqual(find_ma5_readback_candidate(bytes(changed))["static_status"], "rejected")
        rebased = bytearray(image)
        for offset in (0x70E, 0x72C, 0x74A, 0x76C, 0x798):
            rebased[offset] = 0x14
        self.assertEqual(find_ma5_readback_candidate(bytes(rebased))["base"], 0x02800000)
        duplicate = bytearray(image + _ma5_readback_image())
        second = _ma5_readback_image(len(image))
        duplicate[len(image):] = second[len(image):]
        self.assertEqual(find_ma5_readback_candidate(bytes(duplicate))["reject_reason"],
                         "structural-ambiguous")

    def test_ma5_literal_data_class_keeps_exact_roles_and_bounds(self) -> None:
        for relocation in (0, 0x100, 0x1000):
            with self.subTest(relocation=relocation):
                image = _ma5_literal_readback_image(relocation)
                profile = find_ma5_readback_candidate(image)
                self.assertEqual(profile["static_status"], "candidate")
                self.assertEqual((profile["base"], profile["data_offset"]),
                                 (0x02400000, 128))
                self.assertEqual(profile["sites"], {
                    "write_0": [0x71C + relocation],
                    "read_0": [0x748 + relocation],
                    "write_128": [0x76C + relocation, 0x7B8 + relocation],
                    "read_128": [0x79A + relocation],
                })
                self.assertEqual(profile["ram_dependencies"],
                                 [[0x18212D0, 4], [0x1B66DB8, 4], [0x1827D32, 1]])
                self.assertNotIn("poll_state", profile["structural_evidence"])
                self.assertIn([0x1800 + relocation, 2], profile["nor_dependencies"])
                detected = find_audio_transport(image)
                self.assertEqual(detected["static_status"], "candidate")
                self.assertEqual(detected["protocol_status"], "temporary-evidence-gated")
        image = _ma5_literal_readback_image()
        for offset in (0x116, 0x506, 0x60A, 0x71C, 0x748, 0x76C,
                       0x7B8, 0x703, 0x724, 0x77C, 0x1800):
            with self.subTest(mutation=hex(offset)):
                changed = bytearray(image)
                changed[offset] ^= 1
                self.assertEqual(find_ma5_readback_candidate(bytes(changed))["static_status"],
                                 "rejected")
        for end in (0x1800, 0x7C2, 0x410):
            self.assertEqual(find_ma5_readback_candidate(image[:end])["static_status"], "rejected")
        changed = bytearray(image)
        for offset in (0x77C, 0x7A8, 0x7C0):
            struct.pack_into("<I", changed, offset, 0x02400004)
        self.assertEqual(find_ma5_readback_candidate(bytes(changed))["static_status"], "rejected")
        # Consistent physical rebase preserves the protocol and data delta.
        changed = bytearray(image)
        changed[0x718] = changed[0x744] = 10
        for offset in (0x77C, 0x7A8, 0x7C0):
            struct.pack_into("<I", changed, offset, 0x02800080)
        self.assertEqual(find_ma5_readback_candidate(bytes(changed))["base"], 0x02800000)
        combined = bytearray(image + _ma5_readback_image())
        second = _ma5_readback_image(len(image))
        combined[len(image):] = second[len(image):]
        self.assertEqual(find_ma5_readback_candidate(bytes(combined))["reject_reason"],
                         "structural-ambiguous")

    def test_synthesized_base_stops_at_register_overwrite(self) -> None:
        image = bytearray(b"\xff" * 0x80)
        _access(image, 0x20, 0x02400000, 0, "write")
        for instruction, expected in (
            (0x4800, [0x24]),  # LDR r0, [PC] replaces the MMIO base.
            (0x4A00, [0x24, 0x28]),  # LDR r2, [PC] preserves r0.
            (0x7800, [0x24, 0x26]),  # LDRB r0, [r0] uses then replaces it.
        ):
            with self.subTest(instruction=hex(instruction)):
                struct.pack_into("<2H", image, 0x26, instruction, 0x7001)
                self.assertEqual(
                    [site["offset"] for site in
                     _synthesized_base_accesses(bytes(image))],
                    expected,
                )

    def test_repeated_status_requires_closed_accumulator_and_keeps_native_fallback(self) -> None:
        for immediate in (0x41, 0x49):
            with self.subTest(base=immediate << 19):
                image = bytearray(b"\xff" * 0x800)
                for entry, prefix in (
                    (0x400, "4121c90400b50870"),
                    (0x410, "4120c00480b50778"),
                    (0x424, "4121c90400b58870"),
                    (0x434, "4120c00480b58778"),
                ):
                    code = bytearray.fromhex(prefix)
                    code[0] = immediate
                    image[entry:entry + 8] = code
                    image[entry + 8:entry + 12] = _thumb_bl(entry + 8, 0x700)
                first = 0x10E
                struct.pack_into("<H", image, first - 14, 0xB5F0)
                image[first - 10:first] = bytes.fromhex("00204025802620700027")
                for offset, tail in zip(
                    (0, 0xA, 0x16, 0x22, 0x2E, 0x3A, 0x46, 0x50),
                    ("400800d30127", "400801d302200743",
                     "400801d304200743", "400801d308200743",
                     "400801d310200743", "400801d320200743",
                     "400800d32f43", "400800d33743"),
                ):
                    call = first + offset
                    image[call:call + 4] = _thumb_bl(call, 0x410)
                    image[call + 4:call + 4 + len(bytes.fromhex(tail))] = bytes.fromhex(tail)
                struct.pack_into("<H", image, first + 0x74, 0x2FFF)
                detected = find_audio_transport(bytes(image))
                self.assertEqual(detected["grammar"], "repeated-bit-status-v1")
                self.assertEqual(detected["reject_reason"], "protocol-unsupported")
                self.assertEqual(detected["candidates"][0]["base"], immediate << 19)
                self.assertEqual(detected["candidates"][0]["status_consumers"], [0x100])
                self.assertEqual(detected["candidates"][0]["status_mask"], 1)
                self.assertEqual(detected["candidates"][0]["consecutive_samples"], 8)
                self.assertNotEqual(detected["static_status"], "accepted")
                self.assertFalse(AudioTransport(detected).write(0x406, immediate << 19, 1, 2))
                image[first + 0xA + 8] = 4  # Duplicate accumulator bit; not eight samples.
                self.assertEqual(find_audio_transport(bytes(image))["reject_reason"], "marker-none")
                image[first + 0xA + 8] = 2
                struct.pack_into("<H", image, first + 0x50 + 4, 0x0848)
                self.assertEqual(find_audio_transport(bytes(image))["reject_reason"], "marker-none")

    def test_markerless_command_status_shape_requires_closed_callers(self) -> None:
        image = bytearray(b"\xff" * 0x900)
        write_0, read_0, write_2, read_2 = 0x400, 0x410, 0x424, 0x434
        delay = 0x700
        wrappers = (
            (write_0, "5121c90400b50870", "08bc1847"),
            (read_0, "5120c00480b50778", "381c80bc08bc1847"),
            (write_2, "5121c90400b58870", "08bc1847"),
            (read_2, "5120c00480b58778", "381c80bc08bc1847"),
        )
        for entry, prefix, suffix in wrappers:
            image[entry:entry + 8] = bytes.fromhex(prefix)
            image[entry + 8:entry + 12] = _thumb_bl(entry + 8, delay)
            image[entry + 12:entry + 12 + len(bytes.fromhex(suffix))] = (
                bytes.fromhex(suffix)
            )
        image[0x780:0x784] = b"MMMD"
        for command in range(7):
            caller = 0x40 + command * 8
            struct.pack_into("<H", image, caller, 0x2000 | command)
            image[caller + 2:caller + 6] = _thumb_bl(caller + 2, write_0)
        for caller, target in zip((0x100, 0x110, 0x120),
                                  (read_0, write_2, read_2)):
            image[caller:caller + 4] = _thumb_bl(caller, target)

        detected = find_audio_transport(bytes(image))
        self.assertEqual(
            (detected["family"], detected["grammar"], detected["base"],
             detected["data_offset"], detected["begin"], detected["end"]),
            ("opaque", "command-status-data-v1", 0x02880000, 2,
             0x406, 0x43C),
        )
        self.assertEqual(detected["sites"], {
            "read_0": [0x416], "read_2": [0x43A],
            "write_0": [0x406], "write_2": [0x42A],
        })

        image[read_2 + 8:read_2 + 12] = _thumb_bl(read_2 + 8, delay + 0x20)
        self.assertEqual(
            find_audio_transport(bytes(image))["reject_reason"], "marker-none"
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

    def test_ma2_running_fifo_refill_emits_incremental_snapshot(self) -> None:
        transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100], "write_2": [0x102]},
            "block_write_offsets": [],
        })

        def write(index: int, value: int) -> None:
            self.assertTrue(transport.write(0x100, 0x02080000, 1, index))
            self.assertTrue(transport.write(0x102, 0x02080002, 1, value))

        write(0x0F, 1)
        write(2, 0x22)
        write(0x0F, 0)
        self.assertTrue(transport.write(0x100, 0x02080000, 1, 0))
        for value in bytes.fromhex("00fff000000101"):
            self.assertTrue(transport.write(0x102, 0x02080002, 1, value))
        write(0x0F, 1)
        write(1, 1)

        first = transport.drain_renderer_snapshots()
        self.assertEqual(len(first), 1)
        write(0x0F, 0)
        self.assertTrue(transport.write(0x100, 0x02080000, 1, 0))
        for value in bytes.fromhex("640201"):
            self.assertTrue(transport.write(0x102, 0x02080002, 1, value))
        second = transport.drain_renderer_snapshots()

        self.assertEqual(len(second), 1)
        decoder = _Ma2SnapshotDecoder()
        self.assertEqual(
            [(note.tick, note.note) for note in decoder.decode(first[0])],
            [(0, 37)],
        )
        self.assertEqual(
            [(note.tick, note.note) for note in decoder.decode(second[0])],
            [(100, 38)],
        )
        self.assertEqual(transport.drain_renderer_snapshots(), ())

    def test_ma2_batch_renders_one_same_epoch_timeline(self) -> None:
        first = bytes.fromhex("00fff000000101")
        second = bytes.fromhex("00fff000000101640201")
        snapshots = tuple(
            {
                "kind": "ma2-fifo-snapshot",
                "epoch": 0,
                "sequence": sequence,
                "timebase": 0x22,
                "fifos": (fifo, b"", b"", b""),
            }
            for sequence, fifo in enumerate((first, second), 1)
        )
        player = ApproximateSmafPlayer()
        player.backend = "render-only"
        player.set_muted(True)
        try:
            with patch(
                    "msm5xxx_emulator.audio.player.render_notes",
                    wraps=render_notes) as renderer:
                self.assertTrue(player.play_ma2_snapshots(snapshots))
                deadline = time.monotonic() + 2
                while player.last_pcm is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertIsNotNone(player.last_pcm)
                self.assertEqual(renderer.call_count, 1)
                notes = renderer.call_args.args[1]
                self.assertEqual(
                    [(note.tick, note.note) for note in notes],
                    [(0, 37), (100, 38)],
                )
        finally:
            player.close()

    def test_ma2_pcm_revisions_keep_the_complete_timeline(self) -> None:
        fifos = (
            bytes.fromhex("00fff000000101"),
            bytes.fromhex("00fff000000101640201"),
        )
        snapshots = tuple({
            "kind": "ma2-fifo-snapshot",
            "epoch": 0,
            "sequence": sequence,
            "timebase": 0x22,
            "fifos": (fifo, b"", b"", b""),
        } for sequence, fifo in enumerate(fifos, 1))
        player = ApproximateSmafPlayer()
        player.backend = "desktop-test"
        try:
            with (patch.object(player, "_play_pcm") as playback,
                  patch(
                      "msm5xxx_emulator.audio.player.render_notes",
                      wraps=render_notes) as renderer):
                self.assertTrue(player.play_ma2_snapshot(snapshots[0]))
                # Timeline publication precedes desktop playback; wait for both.
                deadline = time.monotonic() + 2
                while ((player._pcm_sequence < 1 or playback.call_count < 1)
                       and time.monotonic() < deadline):
                    time.sleep(0.01)
                first = player.take_latest_pcm()

                self.assertTrue(player.play_ma2_snapshot(snapshots[1]))
                deadline = time.monotonic() + 2
                while ((player._pcm_sequence < 2 or playback.call_count < 2)
                       and time.monotonic() < deadline):
                    time.sleep(0.01)
                second = player.take_latest_pcm()

                self.assertEqual(renderer.call_count, 4)
                self.assertEqual(
                    [(note.tick, note.note)
                     for note in renderer.call_args_list[2].args[1]],
                    [(0, 37), (100, 38)],
                )
                self.assertEqual(
                    [(note.tick, note.note)
                     for note in renderer.call_args_list[3].args[1]],
                    [(100, 38)],
                )
                self.assertEqual(playback.call_count, 2)
                self.assertEqual(
                    struct.unpack_from("<4sIQQ", first),
                    (b"M5P1", 1, 1, 0),
                )
                self.assertEqual(
                    struct.unpack_from("<4sIQQ", second),
                    (b"M5P1", 1, 2, 0),
                )
                self.assertGreater(len(second), len(first))

                self.assertTrue(player.play_ma2_snapshot(snapshots[0]))
                time.sleep(0.05)
                self.assertEqual(player._pcm_sequence, 2)

                epoch_change = {**snapshots[1], "epoch": 1, "sequence": 3}
                self.assertFalse(player.play_ma2_snapshot(epoch_change))
                self.assertTrue(player._ma2_timeline_rejected)
                self.assertEqual(player._pcm_sequence, 2)
                self.assertFalse(player.play_ma2_snapshot(epoch_change))
                self.assertEqual(
                    player.last_submit_error,
                    "ma2-epoch-change-unsupported",
                )
        finally:
            player.close()

    def test_mmf_does_not_drop_or_publish_the_ma2_timeline(self) -> None:
        blocked = threading.Event()
        release = threading.Event()
        first_mmf = b"MMMD-first"
        second_mmf = b"MMMD-second"

        def render_mmf(data: bytes):
            if data == first_mmf:
                blocked.set()
                self.assertTrue(release.wait(1))
            return np.zeros((1, 2), dtype="<i2"), {}

        snapshot = {
            "kind": "ma2-fifo-snapshot",
            "epoch": 0,
            "sequence": 1,
            "timebase": 0x22,
            "fifos": (bytes.fromhex("00fff000000101"), b"", b"", b""),
        }
        player = ApproximateSmafPlayer()
        player.backend = "render-only"
        player._soundfont = object()
        try:
            with (patch.object(player, "render_now", side_effect=render_mmf),
                  patch.object(player, "_play_pcm"),
                  patch(
                      "msm5xxx_emulator.audio.player.render_notes",
                      return_value=np.ones((2, 2), dtype="<i2"),
                  ) as renderer):
                player.play_mmf(first_mmf)
                self.assertTrue(blocked.wait(1))
                self.assertTrue(player.play_ma2_snapshot(snapshot))
                player.play_mmf(second_mmf)
                release.set()
                deadline = time.monotonic() + 2
                while (player.last_mmf != second_mmf
                       or renderer.call_count != 1) \
                        and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(renderer.call_count, 1)
                self.assertEqual(player._pcm_sequence, 1)
                self.assertEqual(
                    struct.unpack_from("<4sIQQ", player.take_latest_pcm()),
                    (b"M5P1", 1, 1, 0),
                )
        finally:
            release.set()
            player.close()

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

    def test_player_uses_macos_native_audio_fallback(self) -> None:
        with patch(
                "msm5xxx_emulator.audio.player.shutil.which",
                side_effect=lambda name: "/usr/bin/afplay"
                if name == "afplay" else None):
            player = ApproximateSmafPlayer()
        try:
            self.assertEqual(player.backend, "SMAF PCM / afplay")
        finally:
            player.close()

    def test_player_uses_linux_native_audio_fallback(self) -> None:
        with patch(
                "msm5xxx_emulator.audio.player.shutil.which",
                side_effect=lambda name: "/usr/bin/aplay"
                if name == "aplay" else None):
            player = ApproximateSmafPlayer()
        try:
            self.assertEqual(player.backend, "SMAF PCM / aplay")
        finally:
            player.close()

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
