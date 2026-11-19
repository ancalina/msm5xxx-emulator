"""Synthetic checks for linked byte-port MA3 readback recognition."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.audio.rules.linked_readback import (
    _leaf,
    find_linked_ma3_readback,
)
from msm5xxx_emulator.detection.devices.audio.selection import (
    boot_transport_selection,
    register_transport_eligible,
)
from msm5xxx_emulator.detection.devices.audio.transport_projection import (
    qemu_audio_sites,
)


def _code(*words: int) -> bytes:
    return struct.pack("<" + "H" * len(words), *words)


def _bl(source: int, target: int) -> tuple[int, int]:
    displacement = target - (source + 4)
    if displacement & 1 or not -(1 << 22) <= displacement < (1 << 22):
        raise ValueError("Thumb BL target out of range")
    imm = displacement & 0x7FFFFF
    first = 0xF000 | (imm >> 12 & 0x7FF)
    second = 0xF800 | (imm >> 1 & 0x7FF)
    return first, second


def _put_bl(image: bytearray, source: int, target: int) -> None:
    struct.pack_into("<HH", image, source, *_bl(source, target))


def _base_setup() -> tuple[int, ...]:
    # MOVS r1,#0xb0; LSLS r1,r1,#18 => 0x02c00000.
    return (0x21B0, 0x0489)


def _leaf(kind: str, offset: int = 0, tail: tuple[int, ...] = ()) -> bytes:
    access = (0x7008 if kind == "write" else 0x7808) + (offset << 6)
    return _code(*_base_setup(), *tail, access, 0x4770)


def _synthetic_profile_image() -> bytes:
    image = bytearray(b"\xc0\x46" * 0x500)
    verifier = 0x100
    reader = 0x200
    poller_a, poller_b = 0x400, 0x480
    write_0, write_2, read_2, status = 0x600, 0x620, 0x640, 0x660
    # Exact three-range verifier grammar with linked calls at all three loops.
    code = [0x46C0] * 45
    def put(off: int, word: int) -> None:
        code[off // 2] = word

    for off, word in ((0, 0x2490), (2, 0x2700), (4, 0x43FD), (6, 0x19E0), (8, 0x2102),
                      (14, 0x0600 | 24 << 6), (16, 0x0800 | 24 << 6), (18, 0x2860),
                      (22, 0x3701), (24, 0x2F10), (28, 0x24A0), (30, 0x2700),
                      (32, 0x19E0), (34, 0x2102), (40, 0x0600 | 24 << 6),
                      (42, 0x0800 | 24 << 6), (44, 0x283C), (48, 0x3701),
                      (50, 0x2F10), (54, 0x24FF), (56, 0x344B), (58, 0x2700),
                      (60, 0x19E0), (62, 0x2102), (68, 0x0600 | 24 << 6),
                      (70, 0x0800 | 24 << 6), (72, 0x2840), (84, 0x3701),
                      (86, 0x2F08)):
        put(off, word)
    # Branch offsets are encoded by the verifier recognizer as well as decoded
    # by the source scan; assign them from their required destinations.
    def branch(at: int, condition: int, destination: int) -> int:
        delta = destination - (at + 4)
        if delta & 1 or not -256 <= delta <= 254:
            raise ValueError("short branch out of range")
        return 0xD000 | condition << 8 | (delta // 2 & 0xFF)

    put(20, branch(verifier + 20, 1, verifier + 76))
    put(26, branch(verifier + 26, 3, verifier + 6))
    put(46, branch(verifier + 46, 1, verifier + 76))
    put(52, branch(verifier + 52, 3, verifier + 32))
    put(74, branch(verifier + 74, 0, verifier + 84))
    put(88, branch(verifier + 88, 3, verifier + 60))
    struct.pack_into("<" + "H" * len(code), image, verifier, *code)
    reader_code = [0xB5F8, 0x1C07, 0x1C0D, 0x2003] + [0x46C0] * (0xC8 // 2 - 4)
    reader_code[0x0C // 2] = 0x2F80
    reader_code[0x14 // 2] = 0x2301
    reader_code[0x16 // 2] = 0x039B
    reader_code[0x18 // 2] = 0x429F
    struct.pack_into("<" + "H" * len(reader_code), image, reader, *reader_code)
    for source, target in ((verifier + 10, reader), (verifier + 36, reader), (verifier + 64, reader)):
        _put_bl(image, source, target)
    for source, target in ((reader + 8, write_0), (reader + 0x20, poller_a),
                           (reader + 0x30, poller_b), (reader + 0x84, write_2),
                           (reader + 0xC4, read_2), (poller_a, status), (poller_b, status)):
        _put_bl(image, source, target)
    for entry, code_bytes in ((write_0, _leaf("write")), (write_2, _leaf("write", 2)),
                              (read_2, _leaf("read", 2)), (status, _leaf("read"))):
        image[entry:entry + len(code_bytes)] = code_bytes
    return bytes(image)


class LinkedReadbackLeafTests(unittest.TestCase):
    def test_byte_writer_and_unsigned_reader_are_closed(self) -> None:
        image = bytearray(0x80)
        image[0x20:0x20 + len(_leaf("write"))] = _leaf("write")
        image[0x30:0x30 + len(_leaf("read", 2))] = _leaf("read", 2)
        writer = _leaf_facts(bytes(image), 0x20)
        reader = _leaf_facts(bytes(image), 0x30)
        self.assertEqual((writer["kind"], writer["address"]), ("write", 0x02C00000))
        self.assertEqual((reader["kind"], reader["address"]), ("read", 0x02C00002))
        self.assertEqual(writer["site"], 0x24)
        self.assertEqual(reader["site"], 0x34)

    def test_writer_must_forward_argument_and_reader_must_return_loaded_byte(self) -> None:
        self.assertIsNone(_leaf_facts(_leaf("write", tail=(0x2000,)), 0))
        overwritten = _code(*_base_setup(), 0x7808, 0x2000, 0x4770)
        self.assertIsNone(_leaf_facts(overwritten, 0))

    def test_byte_width_unconditional_thumb16_and_no_calls_are_required(self) -> None:
        halfword = _code(*_base_setup(), 0x8848, 0x4770)
        conditional = _code(0xD000, *_base_setup(), 0x7808, 0x4770)
        thumb2 = _code(0xF240, 0x01B0, 0x0489, 0x7808, 0x4770)
        called = _code(*_base_setup(), 0xF000, 0xF800, 0x7808, 0x4770)
        for image in (halfword, conditional, thumb2, called):
            self.assertIsNone(_leaf_facts(image, 0))


class LinkedReadbackRecognitionTests(unittest.TestCase):
    def test_three_range_verifier_links_four_byte_accessors(self) -> None:
        image = _synthetic_profile_image()
        profile = find_linked_ma3_readback(image)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["source_class"], "linked-byte-port-readback-v1")
        self.assertEqual(profile["base"], 0x02C00000)
        self.assertEqual(profile["register_readback"], [[0x90, 0xA0, 0x60], [0xA0, 0xB0, 0x3C], [0x14A, 0x152, 0x40]])
        self.assertEqual(profile["sites"], {"write_0": [0x604], "write_2": [0x624], "read_2": [0x644], "read_0": [0x664]})

    def test_linkage_and_accessor_mutations_fail_closed(self) -> None:
        image = bytearray(_synthetic_profile_image())
        # Repoint one register reader accessor call at a distinct helper.
        _put_bl(image, 0x200 + 0x84, 0x300)
        self.assertIsNone(find_linked_ma3_readback(bytes(image)))
        image = bytearray(_synthetic_profile_image())
        # Make the byte-data leaf a halfword read.
        struct.pack_into("<H", image, 0x640 + 4, 0x8848)
        self.assertIsNone(find_linked_ma3_readback(bytes(image)))


def _leaf_facts(image: bytes, entry: int):
    from msm5xxx_emulator.detection.devices.audio.rules.linked_readback import _leaf as leaf

    return leaf(image, entry)


class LinkedReadbackProjectionTests(unittest.TestCase):
    def test_linked_profile_is_admitted_and_projected(self) -> None:
        profile = {
            "family": "ma3", "grammar": "ma3-readback-v1", "static_status": "accepted",
            "source_class": "linked-byte-port-readback-v1", "base": 0x02C00000,
            "data_offset": 2, "verifier_entry": 0x100, "register_reader": 0x200,
            "register_readback": [[0x90, 0xA0, 0x60], [0xA0, 0xB0, 0x3C], [0x14A, 0x152, 0x40]],
            "sites": {"write_0": [0x210], "write_2": [0x220], "read_2": [0x230], "read_0": [0x240]},
            "nor_dependencies": [(0x100, 0x90), (0x200, 0xC8)],
            "ram_dependencies": [(0x01000100, 1)],
        }
        config = SimpleNamespace(
            load_address=0, flash_size=0x00400000,
            ram_base=0x01000000, ram_size=0x00800000,
        )
        self.assertTrue(register_transport_eligible(profile, config, False, False))
        projected = qemu_audio_sites(profile)
        self.assertEqual(projected, "r0/240;r2/230;w0/210;w2/220")
        selection = boot_transport_selection(
            b"", profile, config, ma3_indexed_ram_profile=False,
            upper_nor_present=False, experimental_audio_refill=False,
        )
        self.assertEqual(selection["branch"], "register")
        self.assertIn("audio-aperture=2c00000:2:ma3", selection["properties"])
        self.assertIn("audio-sites=" + projected, selection["properties"])

    def test_linked_profile_rejects_unmapped_source_dependencies(self) -> None:
        profile = {
            "family": "ma3", "grammar": "ma3-readback-v1", "static_status": "accepted",
            "source_class": "linked-byte-port-readback-v1", "base": 0x02C00000,
            "data_offset": 2, "verifier_entry": 0x100, "register_reader": 0x200,
            "register_readback": [[0x90, 0xA0, 0x60], [0xA0, 0xB0, 0x3C], [0x14A, 0x152, 0x40]],
            "sites": {"write_0": [0x210], "write_2": [0x220], "read_2": [0x230], "read_0": [0x240]},
            "nor_dependencies": [(0x100, 0x90), (0x200, 0xC8)],
            "ram_dependencies": [(0x01000100, 1)],
        }
        bad_nor = SimpleNamespace(load_address=0, flash_size=0x100, ram_base=0x01000000, ram_size=0x00800000)
        bad_ram = SimpleNamespace(load_address=0, flash_size=0x00400000, ram_base=0x01200000, ram_size=0x00100000)
        self.assertFalse(register_transport_eligible(profile, bad_nor, False, False))
        self.assertFalse(register_transport_eligible(profile, bad_ram, False, False))
        self.assertFalse(register_transport_eligible(profile, SimpleNamespace(**{**vars(bad_nor), "flash_size": 0x00400000}), False, True))


if __name__ == "__main__":
    unittest.main()
