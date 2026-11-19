"""Synthetic table-driven halfword keypad scanner evidence."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from nor_fixtures import copy_consumer_fixture
from test_startup_entry import reset_entry_fixture
from msm5xxx_emulator.detection.devices.input.event_projection import (
    _matrix_input_position,
)
from msm5xxx_emulator.detection.devices.input.startup_copy import (
    reset_linked_input_copy,
)
from msm5xxx_emulator.detection.devices.input.table_rows import (
    find_table_row_scanners,
    table_row_property,
)
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import (
    matrix_input_command,
)
from msm5xxx_emulator.detection.registry import device_domain

HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


def _put16(image: bytearray, address: int, value: int) -> None:
    struct.pack_into("<H", image, address, value)


def _put32(image: bytearray, address: int, value: int) -> None:
    struct.pack_into("<I", image, address, value)


def _bl(image: bytearray, site: int, target: int) -> None:
    delta = target - site - 4
    _put16(image, site, 0xF000 | ((delta >> 12) & 0x7FF))
    _put16(image, site + 2, 0xF800 | ((delta >> 1) & 0x7FF))


def _literal(image: bytearray, site: int, register: int, pool: int,
             value: int) -> None:
    delta = pool - ((site + 4) & ~3)
    assert 0 <= delta < 1024 and delta % 4 == 0
    _put16(image, site, 0x4800 | (register << 8) | (delta // 4))
    _put32(image, pool, value)


def _branch(image: bytearray, site: int, condition: int, target: int) -> None:
    delta = (target - site - 4) // 2
    assert -128 <= delta <= 127
    _put16(image, site, 0xD000 | (condition << 8) | (delta & 0xFF))


def _arm_branch(image: bytearray, site: int, target: int) -> None:
    delta = target - site - 8
    assert delta % 4 == 0 and -(1 << 25) <= delta < (1 << 25)
    _put32(image, site, 0xEA000000 | ((delta >> 2) & 0xFFFFFF))


def _image(row_register: int = 5, ram_base: int = 0x01000000, *,
           sense: int = 0x600, presence: int = 0x580,
           presence_pool: int = 0x914, held_presence: bool = False,
           clear: int = 0xC00, clear_pool: int = 0xC80,
           row_pool: int = 0x900) -> bytearray:
    image = bytearray(0x5000)
    start = sense - 42
    end = sense + 72
    descriptor = ram_base + 0x100
    preserve = 0xFFFFFF80
    row_mask = preserve ^ 0xFFFFFFFF
    table = ram_base + 0x300
    events_at = 0x1800
    lock, unlock = 0xA00, 0xA20

    # The row fixture is reached through a reset vector and a source-proven
    # copy consumer. A separate linker tuple keeps the scanner's source bytes
    # available to its local grammar checks.
    consumer, row = copy_consumer_fixture()
    image[0x100:len(consumer)] = consumer[0x100:]
    _put32(image, 0x80, ram_base + 0x1000)
    struct.pack_into("<5I", image, row.table,
                     0x1000, ram_base, 0x1000, ram_base + 0x1000, 0x40)
    image[:0x100] = reset_entry_fixture()[:0x100]
    _put32(image, 0x80, ram_base + 0x1000)

    # The direct row scan, including reset of its seven-row counter.
    _put16(image, start - 6, 0x2000 | (row_register << 8))
    _bl(image, start - 4, lock)
    words = {
        4: 0x8B91, 6: 0x4019, 12: 0x5A9A, 16: 0x439A,
        18: 0x4311, 22: 0x8391, 24: 0x8B91, 26: 0x6912,
        28: 0x8011, 30: 0x2800,
    }
    for offset, value in words.items():
        _put16(image, start + offset, value)
    _literal(image, start, 2, row_pool, descriptor)
    _literal(image, start + 2, 3, row_pool + 4, preserve)
    _literal(image, start + 8, 3, row_pool + 8, table)
    _put16(image, start + 10, 0x0042 | row_register << 3)
    _literal(image, start + 14, 3, row_pool + 12, preserve)
    _literal(image, start + 20, 2, row_pool + 16, descriptor)
    _branch(image, start + 32, 1, sense - 4)
    _bl(image, start + 34, unlock)
    _literal(image, sense - 4, 0, row_pool + 20, descriptor)
    _put16(image, sense - 2, 0x6B40)
    for offset, value in ((0, 0x8800), (2, 0x0700),
                          (4, 0x0F00), (6, 0x280F)):
        _put16(image, sense + offset, value)

    _put16(image, end, 0x3001 | row_register << 8)
    _put16(image, end + 2, 0x0600 | row_register << 3 | row_register)
    _put16(image, end + 4, 0x0E00 | row_register << 3 | row_register)
    _put16(image, end + 6, 0x2807 | row_register << 8)
    _branch(image, end + 8, 11, start - 4)
    _bl(image, end + 10, clear)

    # Presence/no-key scan and its linkage to the same clear helper.
    if held_presence:
        _put16(image, presence - 12, 0xB510)  # Preserve the held descriptor register.
        _literal(image, presence - 10, 4, presence_pool, descriptor)
        _bl(image, presence - 8, clear)
        pointer_register = 4
    else:
        _bl(image, presence - 8, clear)
        _literal(image, presence - 4, 0, presence_pool, descriptor)
        pointer_register = 0
    for offset, value in ((-2, 0x6B40), (0, 0x8800), (2, 0x0700),
                          (4, 0x0F00), (6, 0x280F)):
        if offset == -2:
            value = 0x6B40 | pointer_register << 3
        _put16(image, presence + offset, value)
    _branch(image, presence + 8, 0, end + 0x20)

    # Literal-derived column lookup and event table append loop.
    decode = sense + 10
    decode_words = {
        0: 0x0702, 2: 0x0F12, 4: 0x9203, 6: 0x2000,
        8: 0x2101, 10: 0x9A03, 12: 0x4081, 14: 0x4391,
        18: 0x00C1, 22: 0x1A09, 26: 0x1889,
        28: 0x5C0B | row_register << 6, 42: 0x548B,
        48: 0x3001, 50: 0x0600, 52: 0x0E00, 54: 0x2804,
    }
    for offset, value in decode_words.items():
        _put16(image, decode + offset, value)
    _branch(image, sense + 8, 0, end)
    _branch(image, decode + 16, 0, decode + 44)
    _literal(image, decode + 20, 2, row_pool + 24, events_at + 0x40)
    _put16(image, decode + 24, 0x3A40)
    _branch(image, decode + 56, 11, decode + 8)

    # Source copy layout translates the descriptor and table into relocated RAM.
    descriptor_rom = 0x1100
    rows_rom = 0x1300
    _put32(image, descriptor_rom + 0x10, 0x03000724)
    _put32(image, descriptor_rom + 0x34, 0x0300072C)
    struct.pack_into("<7H", image, rows_rom,
                     *(row_mask ^ (1 << bit) for bit in range(7)))
    image[events_at:events_at + 28] = bytes(range(1, 17)) + b"123456789*0#"

    # The clear helper shares descriptor, mask and lock ownership with the scan.
    _put16(image, clear, 0xB500)
    _bl(image, clear + 2, lock)
    _literal(image, clear + 6, 1, clear_pool, descriptor)
    _literal(image, clear + 8, 3, clear_pool + 4, preserve)
    for offset, value in ((10, 0x8B8A), (12, 0x401A), (14, 0x838A),
                          (16, 0x8B8A), (18, 0x6909), (20, 0x800A),
                          (22, 0x2800), (30, 0xBC08), (32, 0x4718)):
        _put16(image, clear + offset, value)
    _branch(image, clear + 24, 1, clear + 30)
    _bl(image, clear + 26, unlock)
    return image


class TableRowScannerTests(unittest.TestCase):
    def test_table_scan_with_both_row_registers_and_relocated_ram(self):
        for row_register, ram_base in ((5, 0x01000000), (6, 0x01200000)):
            with self.subTest(row_register=row_register, ram_base=hex(ram_base)):
                image = _image(row_register, ram_base)
                profiles = find_table_row_scanners(image)
                self.assertEqual(len(profiles), 1)
                profile = profiles[0]
                self.assertEqual(profile["row_select_mask"], 0x7F)
                self.assertEqual(profile["row_select_bits"], list(range(7)))
                self.assertEqual(profile["descriptor"], ram_base + 0x100)
                self.assertEqual(profile["event_codes"],
                                 list(bytes(range(1, 17)) + b"123456789*0#"))

    def test_property_requires_all_source_bytes_inside_flash(self):
        image = _image()
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=0x5000)
        prop, profile = table_row_property(image, config)
        self.assertEqual(prop, "matrix-halfword=1000100:580:600:7f")
        self.assertIsNotNone(profile)
        config.flash_size = 0x1000
        self.assertEqual(table_row_property(image, config), (None, None))

    def test_property_rejects_orphan_layout_and_incomplete_copy_ranges(self):
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=0x5000)
        orphan = _image()
        _put32(orphan, 0, 0)
        self.assertEqual(len(find_table_row_scanners(orphan)), 1)
        self.assertEqual(table_row_property(orphan, config), (None, None))

        image = _image()
        config.flash_size = 0x1800
        self.assertEqual(table_row_property(image, config), (None, None))
        config.flash_size = len(image)
        config.ram_size = 0x800
        self.assertEqual(table_row_property(image, config), (None, None))

    def test_reset_linked_copy_follows_secondary_branch_root(self):
        image = _image()
        # The vector enters a short ARM trampoline that branches to the real
        # stack/copy reset root at 0x40.
        _arm_branch(image, 0, 0x20)
        _arm_branch(image, 0x20, 0x28)
        _arm_branch(image, 0x28, 0x40)
        proof = reset_linked_input_copy(
            image, ((0x01000100, 0x38), (0x01000300, 14)),
            ram_base=0x01000000, ram_size=0x00800000,
            flash_size=len(image))
        self.assertIsNotNone(proof)
        self.assertEqual((proof.target, proof.size),
                         (0x01000000, 0x1000))
        self.assertIn((0x20, 4), proof.evidence)
        self.assertIn((0x28, 4), proof.evidence)

    def test_numeric_event_projection_and_release_command(self):
        image = _image()
        profile = find_table_row_scanners(image)[0]
        owner = SimpleNamespace(matrix_input_profile=profile)
        position = _matrix_input_position(owner, 11, None)
        self.assertEqual(position, (ord("1"), 2, 2))
        self.assertEqual(matrix_input_command(profile, position, True),
                         bytes((HOST_INPUT, 1, 2, 11)))
        self.assertEqual(matrix_input_command(profile, None, False),
                         bytes((HOST_INPUT, 0, 0, 0)))

    def test_property_preserves_an_existing_status_descriptor_owner(self):
        image = _image()
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=len(image))
        self.assertEqual(table_row_property(image, config,
                         status_descriptor_claimed=True), (None, None))

    def test_property_checks_linked_callees_against_flash_extent(self):
        for sites in ((0x5D2, 0xC02), (0x5F8, 0xC1A)):
            with self.subTest(sites=sites):
                image = _image()
                for site in sites:
                    _bl(image, site, 0x4800)
                self.assertEqual(len(find_table_row_scanners(image)), 1)
                config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                         ram_size=0x00800000, flash_size=0x4000)
                self.assertEqual(table_row_property(image, config), (None, None))

    def test_property_bounds_clear_helper_literal_pools(self):
        image = _image(clear=0x3C00, clear_pool=0x4000)
        profiles = find_table_row_scanners(image)
        self.assertEqual(len(profiles), 1)
        self.assertIn((0x4000, 4), profiles[0]["dependencies"])
        self.assertIn((0x4004, 4), profiles[0]["dependencies"])
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x00800000, flash_size=0x4000)
        self.assertEqual(table_row_property(image, config), (None, None))

    def test_property_bounds_presence_descriptor_literal_pool(self):
        # Move the scan near the flash end so the literal remains in Thumb reach.
        sense, presence, pool = 0x2C00, 0x2B80, 0x2F74
        for held_register in (False, True):
            with self.subTest(held_register=held_register):
                image = _image(sense=sense, presence=presence,
                               presence_pool=pool,
                               held_presence=held_register,
                               row_pool=0x2E00)
                profiles = find_table_row_scanners(image)
                self.assertEqual(len(profiles), 1)
                self.assertIn((pool, 4), profiles[0]["dependencies"])
                config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                         ram_size=0x00800000,
                                         flash_size=pool)
                self.assertEqual(table_row_property(image, config), (None, None))

    def test_rejects_wiring_descriptor_lookup_linkage_and_event_mutations(self):
        mutations = {
            "row wiring": lambda image: _put16(image, 0x1300, 0x7F),
            "descriptor MMIO": lambda image: _put32(image, 0x1110, 0x03000720),
            "lookup arithmetic": lambda image: _put16(image, 0x622, 0x3A41),
            "BL linkage": lambda image: _put16(image, 0x5D2, 0x2000),
            "column branch": lambda image: _put16(image, 0x608, 0xD000),
            "duplicate numeric event": lambda image: image.__setitem__(
                0x180F, ord("1")),
            "copy source outside image": lambda image: _put32(
                image, 0x200, 0x3004),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                image = _image()
                mutate(image)
                self.assertEqual(find_table_row_scanners(image), [])


if __name__ == "__main__":
    unittest.main()
