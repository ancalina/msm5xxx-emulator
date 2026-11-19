"""Synthetic relocatable Thumb contracts for shifted MA2 audio ports."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.audio.rules.shifted_ma2 import find_shifted_ma2
from msm5xxx_emulator.detection.devices.audio.selection import ma2_eligible
from msm5xxx_emulator.detection.devices.audio.transport_projection import qemu_audio_sites


def _put16(image: bytearray, at: int, value: int) -> None:
    struct.pack_into("<H", image, at, value)


def _literal(image: bytearray, at: int, register: int, pool: int, value: int) -> None:
    pc = (at + 4) & ~3
    displacement = pool - pc
    if displacement < 0 or displacement > 1020 or displacement & 3:
        raise ValueError("synthetic literal is out of range")
    _put16(image, at, 0x4800 | register << 8 | displacement >> 2)
    struct.pack_into("<I", image, pool, value)


def _base(image: bytearray, at: int, register: int, immediate: int = 0xA0) -> None:
    # MOVS Rd,#imm followed by LSLS Rd,Rd,#18 forms the shifted bus base.
    _put16(image, at, 0x2000 | register << 8 | immediate)
    _put16(image, at + 2, 18 << 6 | register << 3 | register)


def _bl(image: bytearray, at: int, target: int) -> None:
    displacement = target - at - 4
    if displacement & 1 or not -(1 << 22) <= displacement < (1 << 22):
        raise ValueError("synthetic call is out of range")
    encoded = displacement & 0x7FFFFF
    _put16(image, at, 0xF000 | (encoded >> 12 & 0x7FF))
    _put16(image, at + 2, 0xF800 | (encoded >> 1 & 0x7FF))


def _program(relocation: int = 0) -> dict[str, object]:
    """Emit the linked routines and independent literal pools at a chosen base."""
    reader = relocation + 0x500
    pair, block, bank = reader - 0x84, reader - 0x4C, reader + 0x1C
    restore = bank + 0xFA
    save = restore - 0x10
    call_restore = restore + 6
    state, port = 0x01012000, 0x02800000
    image = bytearray(relocation + 0x1000)

    # Required instruction positions describe the page/register writer.
    pair_words = {0: 0xB5B0, 2: 0x1C04, 4: 0x1C0D, 0xA: 0x1C07,
                  0xC: 0x0620, 0xE: 0x0E00, 0x16: 0x7048,
                  0x18: 0x7120, 0x1E: 0x71A5, 0x20: 0x2F00,
                  0x22: 0xD101, 0x2C: 0xBCB0, 0x2E: 0xBC08,
                  0x30: 0x4718}
    block_words = {0: 0xB5F0, 2: 0x1C07, 4: 0x1C0C, 6: 0x1C15,
                   0xC: 0x1C06, 0x10: 0x7047, 0x16: 0x7107,
                   0x1C: 0x2700, 0x1E: 0xE009, 0x20: 0x7820,
                   0x22: 0x3401, 0x28: 0x7188, 0x2E: 0x3701,
                   0x30: 0x043F, 0x32: 0x0C3F, 0x34: 0x42AF,
                   0x36: 0xDBF3, 0x38: 0x2E00, 0x3A: 0xD101,
                   0x40: 0xBCF0, 0x42: 0xBC08, 0x44: 0x4718}
    bank_words = {0: 0xB580, 2: 0x07C7, 4: 0x0FFF, 6: 0x1C39,
                  8: 0x200F, 0x10: 0x7007, 0x12: 0xBC80,
                  0x14: 0xBC08, 0x16: 0x4718}
    for entry, words in ((pair, pair_words), (block, block_words), (bank, bank_words)):
        for offset, word in words.items():
            _put16(image, entry + offset, word)
    for offset, word in ((0, 0xB580), (8, 0x7048), (0xA, 0x7138)):
        _put16(image, reader + offset, word)

    # Each literal load gets its own pool word, while aliases carry one state value.
    pool = relocation + 0x800
    literal_sites = ((pair + 0x10, 1, state), (block + 0xE, 0, state),
                     (reader + 2, 1, state), (bank + 0xE, 0, state),
                     (save, 1, state), (restore + 2, 7, state))
    for at, register, value in literal_sites:
        _literal(image, at, register, pool, value)
        pool += 4

    # The shifted bus base is independently constructed at each consumer.
    for at, register in ((pair + 0x12, 4), (block + 0x12, 0),
                         (block + 0x24, 1), (reader + 4, 7),
                         (restore + 0xC, 1)):
        _base(image, at, register)

    # Calls form the page selector, lock/delay, writer, reader, and restore graph.
    stubs = {relocation + 0x700: 0x4770, relocation + 0x704: 0x4770,
             relocation + 0x708: 0x4770, relocation + 0x70C: 0x4770}
    for at, word in stubs.items():
        _put16(image, at, word)
    lock, unlock, write_delay, read_delay = tuple(stubs)
    for at, target in ((pair + 6, lock), (pair + 0x24, unlock),
                       (pair + 0x1A, write_delay), (pair + 0x28, read_delay),
                       (block + 8, lock), (block + 0x3C, unlock),
                       (block + 0x18, write_delay), (block + 0x2A, write_delay),
                       (reader + 0xC, read_delay), (bank + 0xA, pair),
                       (call_restore, bank)):
        _bl(image, at, target)

    # Save four state bytes, call the page selector, then restore the index.
    for offset, word in ((2, 0x7808), (4, 0x7088), (6, 0x7848),
                         (8, 0x70C8), (0xA, 0x4770)):
        _put16(image, save + offset, word)
    for offset, word in ((0, 0xB580), (4, 0x78B8), (0xA, 0x78F8),
                         (0x10, 0x7078), (0x12, 0x7878), (0x14, 0x7108),
                         (0x16, 0xBC80), (0x18, 0xBC08), (0x1A, 0x4718)):
        _put16(image, restore + offset, word)

    # Return a byte from port +6, followed by the complete Thumb return sequence.
    for offset, word in enumerate((0x79B8, 0xBC80, 0xBC08, 0x4718)):
        _put16(image, reader + 0x10 + offset * 2, word)

    return {"image": image, "reader": reader, "pair": pair, "block": block,
            "bank": bank, "restore": restore, "save": save, "state": state,
            "port": port, "pool": relocation + 0x800}


class ShiftedMa2SyntheticTests(unittest.TestCase):
    def test_relocated_program_links_and_projects_audio_sites(self) -> None:
        config = SimpleNamespace(load_address=0, flash_size=0x00400000,
                                 ram_base=0x01000000, ram_size=0x00800000,
                                 ma2_silent_boot_address=None)
        for relocation in (0x100, 0x300):
            with self.subTest(relocation=relocation):
                program = _program(relocation)
                profile = find_shifted_ma2(bytes(program["image"]))
                self.assertIsNotNone(profile)
                self.assertEqual(profile["base"], program["port"] + 4)
                self.assertEqual(profile["page_selector"], program["bank"])
                self.assertEqual(profile["register_writer"], program["pair"])
                self.assertEqual(profile["fifo_writer"], program["block"])
                self.assertEqual(profile["register_reader"], program["reader"])
                self.assertEqual(profile["index_restore"], program["restore"])
                self.assertTrue(ma2_eligible(profile, config))
                self.assertEqual(qemu_audio_sites(profile),
                                 f"r2/{program['reader'] + 0x10:x};"
                                 f"w0/{program['pair'] + 0x18:x};"
                                 f"w0/{program['block'] + 0x16:x};"
                                 f"w0/{program['reader'] + 0xA:x};"
                                 f"w0/{program['restore'] + 0x14:x};"
                                 f"w2/{program['pair'] + 0x1E:x};"
                                 f"w2/{program['block'] + 0x28:x}")

    def test_broken_page_fifo_alias_save_restore_port_and_delay_links_reject(self) -> None:
        corruptions = (
            ("page-selector call", lambda p: _bl(p["image"], p["bank"] + 0xA, p["bank"] + 0x16)),
            ("FIFO backedge", lambda p: _put16(p["image"], p["block"] + 0x36, 0xDBF2)),
            ("state literal alias", lambda p: struct.pack_into(
                "<I", p["image"], p["pool"] + 4, p["state"] + 4)),
            ("saved index store", lambda p: _put16(
                p["image"], p["save"] + 6, 0x7048)),
            ("restore selector call", lambda p: _bl(
                p["image"], p["restore"] + 6, p["bank"] + 0x16)),
            ("data port", lambda p: _base(p["image"], p["reader"] + 4, 7, 0xA8)),
            ("delay call", lambda p: _bl(p["image"], p["pair"] + 0x1A, p["bank"])),
        )
        for label, corrupt in corruptions:
            with self.subTest(link=label):
                program = _program(0x100)
                corrupt(program)
                self.assertIsNone(find_shifted_ma2(bytes(program["image"])))

    def test_state_must_be_in_configured_ram_and_code_must_fit_nor(self) -> None:
        config = SimpleNamespace(load_address=0, flash_size=0x00400000,
                                 ram_base=0x01000000, ram_size=0x00800000,
                                 ma2_silent_boot_address=None)
        program = _program()
        profile = find_shifted_ma2(bytes(program["image"]))
        self.assertIsNotNone(profile)
        outside_ram = SimpleNamespace(load_address=0, flash_size=0x00400000,
                                      ram_base=0x01020000, ram_size=0x00800000,
                                      ma2_silent_boot_address=None)
        self.assertFalse(ma2_eligible(profile, outside_ram))
        outside_nor = SimpleNamespace(load_address=0, flash_size=0x500,
                                      ram_base=0x01000000, ram_size=0x00800000,
                                      ma2_silent_boot_address=None)
        self.assertFalse(ma2_eligible(profile, outside_nor))


if __name__ == "__main__":
    unittest.main()
