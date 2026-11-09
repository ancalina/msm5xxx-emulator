"""Independently assembled contact, event and display guard examples."""
import struct
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for, fact_scope, bind_facts
from msm5xxx_emulator.detection.image_view import ImageView
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.devices.board_contact.rules import (
    contact_semantics, indirect_scanner_at,
)


def contact_image(mask=2, *, entry=0x100, flag=0x01003000, port=0x03000728,
                  panel=0x02000000):
    image = bytearray(b'\xff' * 0x1000)
    pools = {}

    def words(at, *values):
        struct.pack_into('<' + 'H' * len(values), image, at, *values)

    def literal(at, register, value):
        block = at & ~0xff
        pool = pools.get(block, block + 0xe0)
        assert 0 <= pool - ((at + 4) & ~3) <= 1020
        words(at, 0x4800 | register << 8 | ((pool - ((at + 4) & ~3)) // 4))
        struct.pack_into('<I', image, pool, value)
        pools[block] = pool + 4

    def jump(at, target, condition=0xe000):
        words(at, condition | (((target - at - 4) // 2) & (0x7ff if condition == 0xe000 else 255)))

    def call(at, target):
        delta = target - at - 4
        words(at, 0xf000 | ((delta >> 12) & 2047), 0xf800 | ((delta >> 1) & 2047))

    # Descriptor load, saved frame, halfword GPIO pointer/read and one-bit test.
    literal(entry, 0, 0x01002000)
    words(entry + 2, 0xb590, 0x6a40, 0x8800, 0x2300 | mask, 0x4018)
    literal(entry + 12, 4, flag)
    words(entry + 14, 0x2800)
    jump(entry + 16, entry + 28, 0xd000)
    words(entry + 18, 0x2100, 0x7021, 0x275f)
    jump(entry + 24, entry + 34)
    words(entry + 28, 0x2101, 0x7021, 0x2760)
    words(entry + 34, 0x1c38)
    call(entry + 36, 0x600)
    words(entry + 40, 0xbc90, 0xbc08, 0x4718)

    # The event consumer reads the same flag.
    literal(0x600, 0, flag)
    words(0x602, 0x7800, 0x4770)
    # Nonzero flag returns with its entry frame restored; zero calls the writer.
    words(0x700, 0xb510)
    literal(0x702, 0, flag)
    words(0x704, 0x7800, 0x2800)
    jump(0x708, 0x70e, 0xd000)
    jump(0x70a, 0x720)
    call(0x70e, 0x800)
    jump(0x712, 0x720)
    words(0x720, 0xbc10, 0xbc08, 0x4718)
    literal(0x800, 2, panel)
    words(0x802, 0x8010, 0x8051, 0x4770)
    return image, dict(entry=entry, flag=flag, port=port)


def boot_contact_image():
    image, data = contact_image(flag=0x01002030)
    # ARM reset owns a manually linked Thumb copy routine and its concrete SP.
    struct.pack_into('<I', image, 0, 0xea00000e)
    struct.pack_into('<7I', image, 0x40, 0xe321f0d3, 0xe59fd034,
                     0xe59f4034, 0xe3140001, 0x159fe030, 0x059fe030, 0xe12fff14)
    struct.pack_into('<H', image, 0x5c, 0x4778)
    struct.pack_into('<I', image, 0x60, 0xeafffffe)
    struct.pack_into('<4I', image, 0x80, 0x01008000, 0x301, 0x5d, 0x60)
    # A bounded forward word-copy consumer; only the table supplies addresses.
    code = [0, 0x6800, 0, 0x6809, 0x1842, 0, 0x681d, 0, 0x681c,
            0x4294, 0xd300, 0xe004, 0x6828, 0x6020, 0x3404, 0x3504,
            0xe7f7, 0x4770]
    literals = ((0, 0, 0x3c4), (2, 1, 0x3c8), (5, 3, 0x3c0), (7, 3, 0x3c4))
    for slot, (index, register, value) in enumerate(literals):
        site, pool = 0x300 + index * 2, 0x380 + slot * 4
        code[index] = 0x4800 | register << 8 | ((pool - ((site + 4) & ~3)) // 4)
        struct.pack_into('<I', image, pool, value)
    struct.pack_into('<' + 'H' * len(code), image, 0x300, *code)
    struct.pack_into('<3I', image, 0x3c0, 0x400, 0x01002000, 0x40)
    struct.pack_into('<I', image, 0x424, data['port'])
    def call(at, target):
        delta = target - at - 4
        struct.pack_into('<2H', image, at, 0xf000 | ((delta >> 12) & 2047),
                         0xf800 | ((delta >> 1) & 2047))
    struct.pack_into('<H', image, 0x900, 0xb500)
    call(0x902, data['entry'])
    struct.pack_into('<H', image, 0x906, 0xbd00)
    struct.pack_into('<6H', image, 0xa00, 0x2201, 0x9200, 0x2219,
                     0x2319, 0x1c20, 0x4935)
    struct.pack_into('<I', image, 0xae0, 0x901)
    call(0xa0c, 0xb00)
    struct.pack_into('<H', image, 0xb00, 0x4770)
    return image, data


class ContactSemanticsTests(unittest.TestCase):
    def prove(self, image, data):
        return contact_semantics(facts_for(bytes(image)), CodeAddress(data['entry']),
                                 0x01002000, data['port'])

    def test_reset_copy_periodic_owner_and_contact_are_joined_without_mocks(self):
        image, data = boot_contact_image()
        self.assertEqual(indirect_scanner_at(bytes(image), data['entry']),
                         (BoardStatusInput(data['port'], 2, 2), ''))
        for pc, value in ((0x31c, 0x3408), (0x84, 0), (0xa04, 0x2218),
                          (0x424, 0x03000729)):
            with self.subTest(pc=hex(pc)):
                changed = image.copy()
                struct.pack_into('<I' if pc in (0x84, 0x424) else '<H', changed, pc, value)
                self.assertIsNone(indirect_scanner_at(bytes(changed), data['entry'])[0])

    def test_postcopy_pointer_overrides_a_captured_ram_tail_and_rejects_a_source_hole(self):
        image, data = boot_contact_image()
        image = bytes(image)
        captured = ImageView.sparse(((0, image),
                                     (0x01002024, struct.pack('<I', 0x03000724))))
        with fact_scope():
            bind_facts(image, captured)
            self.assertEqual(indirect_scanner_at(image, data['entry'])[0],
                             BoardStatusInput(data['port'], 2, 2))
        incomplete = ImageView.sparse(((0, image[:0x424]), (0x428, image[0x428:])))
        with fact_scope():
            bind_facts(image, incomplete)
            self.assertIsNone(indirect_scanner_at(image, data['entry'])[0])

    def test_domain_plan_claims_only_the_proven_input_bit(self):
        from msm5xxx_emulator.detection.registry import device_domain
        image, data = boot_contact_image()
        owner = BoardStatusInput(data['port'], 2, 2)
        domain = device_domain('board_contact')
        resolution = domain.machine_plan(bytes(image), SimpleNamespace(board_status_input=owner))
        self.assertEqual(dict(resolution.plan.properties), {'board-status-input': '3000728:2:2'})
        self.assertEqual(len(resolution.plan.claims), 1)
        claim = resolution.plan.claims[0]
        self.assertEqual((claim.kind, claim.start, claim.end, claim.mask),
                         ('gpio', data['port'], data['port'] + 2, 2))
        wrong = BoardStatusInput(data['port'], 2, 0)
        self.assertEqual(domain.machine_plan(bytes(image),
                         SimpleNamespace(board_status_input=wrong)).plan.capabilities, ())

    def test_independent_relocated_data_and_mask(self):
        for entry, flag, port, mask in ((0x100, 0x01003000, 0x03000728, 2),
                                       (0x182, 0x01008000, 0x03000674, 0x80)):
            image, data = contact_image(mask, entry=entry, flag=flag, port=port)
            proof = self.prove(image, data)
            self.assertIsNotNone(proof)
            self.assertEqual((proof.address, proof.mask, proof.state), (port, mask, flag))

    def test_wrong_polarity_field_events_or_consumer_rejects(self):
        image, data = contact_image()
        for pc, value in ((0x112, 0x2101), (0x11c, 0x2100), (0x120, 0x275f),
                          (0x602, 0x7840), (0x702, 0x2000), (0x708, 0xd100),
                          (0x720, 0xb002), (0x724, 0x4700), (0x804, 0x8091)):
            with self.subTest(pc=hex(pc)):
                changed = image.copy()
                struct.pack_into('<H', changed, pc, value)
                self.assertIsNone(self.prove(changed, data))

    def test_unused_saved_register_can_be_discarded_with_the_same_sp_delta(self):
        image, data = contact_image()
        struct.pack_into('<H', image, 0x720, 0xb001)
        self.assertIsNotNone(self.prove(image, data))

    def test_multi_bit_guard_and_non_panel_writer_reject(self):
        image, data = contact_image(mask=3)
        self.assertIsNone(self.prove(image, data))
        image, data = contact_image(panel=0x03000720)
        self.assertIsNone(self.prove(image, data))


if __name__ == '__main__':
    unittest.main()
