"""Independent relocation rows require either order proof or commuting effects."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.startup_entry import startup_load_operations
from msm5xxx_emulator.detection.startup_facts import proven_startup_rows


def two_copies(*, dependent_source=False, overlapping_targets=False):
    image = bytearray(0x3000)
    words, literals, fixups = [], [], []

    def emit(word):
        words.append(word)

    def literal(register, address):
        index = len(words)
        fixups.append((index, register, len(literals)))
        literals.append(address)
        emit(0)

    # Code consumes the higher-address row first. Table order differs from
    # execution order, which is harmless only when the rows are independent.
    for table in (0x400, 0x300):
        literal(0, table + 4)
        emit(0x6800)                 # LDR r0,[r0]: destination
        literal(1, table + 8)
        emit(0x6809)                 # LDR r1,[r1]: byte count
        emit(0x1842)                 # ADDS r2,r0,r1: exclusive bound
        literal(3, table)
        emit(0x681D)                 # LDR r5,[r3]: source
        literal(3, table + 4)
        emit(0x681C)                 # LDR r4,[r3]: destination cursor
        compare = len(words)
        emit(0x4294)                 # CMP r4,r2
        emit(0xD300)                 # BLO to body, over the exit branch
        exit_branch = len(words)
        emit(0)
        emit(0x6828)                 # LDR r0,[r5]
        emit(0x6020)                 # STR r0,[r4]
        emit(0x3404)
        emit(0x3504)
        back = len(words)
        emit(0xE000 | ((compare - back - 2) & 0x7FF))
        words[exit_branch] = 0xE000 | ((len(words) - exit_branch - 2) & 0x7FF)
    emit(0x4770)
    for index, register, slot in fixups:
        pc = 0x100 + index * 2
        displacement = 0x200 + slot * 4 - ((pc + 4) & ~3)
        words[index] = 0x4800 | register << 8 | displacement // 4
    struct.pack_into('<' + 'H' * len(words), image, 0x100, *words)
    struct.pack_into('<' + 'I' * len(literals), image, 0x200, *literals)
    struct.pack_into('<3I', image, 0x400, 0x500, 0x1000, 4)
    struct.pack_into('<3I', image, 0x300,
                     0x1000 if dependent_source else 0x600,
                     0x1000 if overlapping_targets else 0x2000, 4)
    image[0x500:0x504] = b'abcd'
    image[0x600:0x604] = b'efgh'
    image[0x1000:0x1004] = b'old!'
    return FirmwareFacts(bytes(image))


class StartupProjectionTests(unittest.TestCase):
    def rows(self, facts):
        rows = proven_startup_rows(
            facts, CodeAddress(0x100, 'thumb'),
            target_ranges=((0x1000, 0x3000),))
        self.assertEqual(len(rows), 2)
        self.assertEqual(tuple(row.table for row, _ in rows), (0x300, 0x400))
        return rows

    def test_reversed_table_order_is_harmless_for_independent_rows(self):
        facts = two_copies()
        view = facts.after_loads(startup_load_operations(self.rows(facts))).view
        self.assertEqual(view.read(0x1000, 4, phase='post-copy'), b'abcd')
        self.assertEqual(view.read(0x2000, 4, phase='post-copy'), b'efgh')

    def test_a_copy_reading_another_rows_destination_needs_execution_order(self):
        facts = two_copies(dependent_source=True)
        with self.assertRaisesRegex(ValueError, 'execution order'):
            startup_load_operations(self.rows(facts))

    def test_overlapping_destinations_need_execution_order(self):
        facts = two_copies(overlapping_targets=True)
        with self.assertRaisesRegex(ValueError, 'execution order'):
            startup_load_operations(self.rows(facts))


if __name__ == '__main__':
    unittest.main()
