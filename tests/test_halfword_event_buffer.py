"""Independent Thumb queue fixtures for computed-row event handoff."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.devices.input.halfword_event_buffer import (
    prove_halfword_event_buffer,
)
from msm5xxx_emulator.detection.devices.input.halfword_jump_rows import (
    _contact_event_code,
)


def _put(image, site, word):
    struct.pack_into('<H', image, site, word)


def _branch(site, target, condition=None):
    delta = (target - site - 4) // 2
    return (0xe000 | (delta & 0x7ff) if condition is None else
            0xd000 | condition << 8 | (delta & 0xff))


def _queue_image(*, intervening=(), reverse_compare=False, guard=11):
    image = bytearray(0x400)
    # Numeric event R6 appends at SP+4+old R4; R4 becomes byte(R4+1).
    numeric = (0x5c8e, 0x1c60, 0x0600, 0x0e00,
               0x1c21, 0x1c04, 0xab01, 0x545e)
    for index, word in enumerate(numeric):
        _put(image, 0x100 + 2 * index, word)
    # A separate low event occupies element zero and sets count to one.
    _put(image, 0x17e, 0x2800)  # CMP R0,#0 feeds the low-contact gate.
    _put(image, 0x180, _branch(0x180, 0x1e0, 1))
    for site, word in ((0x182, 0x205a), (0x184, 0xab00),
                       (0x186, 0x7118), (0x188, 0x2401)):
        _put(image, site, word)
    _put(image, 0x18a, _branch(0x18a, 0x240))
    # Enter the same queue consumer through an index<count test.
    _put(image, 0x240, 0x2500)  # MOVS R5,#0
    pc = 0x242
    for word in intervening:
        _put(image, pc, word)
        pc += 2
    _put(image, pc, _branch(pc, 0x280))
    _put(image, 0x260, 0xab01)  # ADD R3,SP,#4
    _put(image, 0x262, 0x5d5e)  # LDRB R6,[R3,R5]
    _put(image, 0x264, 0x4770)  # BX LR
    _put(image, 0x280, 0x42ac if reverse_compare else 0x42a5)
    _put(image, 0x282, _branch(0x282, 0x260, guard))
    _put(image, 0x284, 0x4770)
    return image


def _prove(image, *, event_sink=0x10e):
    image = bytes(image)
    contact = _contact_event_code(image, 0x180, with_metadata=True)
    if contact is None:
        return None
    return prove_halfword_event_buffer(image, event_load=0x100,
        event_sink=event_sink, event_register=a.ARM_REG_R6,
        event_codes=list(range(24)), event_code=contact[0], handoff=contact[2])


class HalfwordEventBufferTests(unittest.TestCase):
    def test_numeric_and_auxiliary_bytes_share_the_counted_queue(self):
        proof = _prove(_queue_image())
        self.assertIsNotNone(proof)
        self.assertEqual(proof['buffer_offset'], 4)
        self.assertEqual(proof['count_register'], 4)
        self.assertEqual(proof['numeric_store'], 0x10e)
        self.assertEqual(proof['sideband_store'], 0x186)
        self.assertEqual(proof['consumer_read'], 0x262)
        self.assertEqual(proof['consumer_event_register'], 6)

    def test_later_index_write_cannot_select_another_queue_element(self):
        self.assertIsNone(_prove(_queue_image(intervening=(0x2502,))))

    def test_count_guard_has_the_source_index_count_operand_order(self):
        self.assertIsNone(_prove(_queue_image(reverse_compare=True)))
        self.assertIsNone(_prove(_queue_image(guard=10)))

    def test_frame_count_and_buffer_survive_the_selected_consumer_path(self):
        for instruction in (0xb081, 0x2400, 0x7018, 0xbf08):
            with self.subTest(instruction=instruction):
                self.assertIsNone(_prove(_queue_image(intervening=(instruction,))))

    def test_numeric_store_and_auxiliary_store_use_the_same_stack_slot(self):
        for site, word in ((0x10c, 0xab02), (0x186, 0x7218),
                           (0x10a, 0x1c05), (0x188, 0x2400)):
            with self.subTest(site=site, word=word):
                image = _queue_image()
                _put(image, site, word)
                self.assertIsNone(_prove(image))

    def test_terminal_instruction_cannot_replace_the_auxiliary_count(self):
        image = _queue_image()
        _put(image, 0x240, 0x2400)  # MOVS R4,#0 destroys the incoming count.
        _put(image, 0x242, 0x2500)
        _put(image, 0x244, _branch(0x244, 0x280))
        self.assertIsNone(_prove(image))

    def test_predication_cannot_skip_the_sideband_store_or_numeric_increment(self):
        auxiliary = _queue_image()
        auxiliary[0x184:0x18c] = auxiliary[0x182:0x18a]
        _put(auxiliary, 0x182, 0xbf08)  # IT EQ before the event definition.
        _put(auxiliary, 0x18c, _branch(0x18c, 0x240))
        self.assertIsNone(_prove(auxiliary))

        numeric = _queue_image()
        numeric[0x104:0x112] = numeric[0x102:0x110]
        _put(numeric, 0x102, 0xbf08)  # IT EQ before the count increment.
        self.assertIsNone(_prove(numeric, event_sink=0x110))

    def test_sideband_exit_must_be_feasible_and_keep_the_stored_byte(self):
        paths = (
            # R4 is one: CMP #0 makes the following EQ exit impossible.
            (0x2c00, _branch(0x18c, 0x240, 0), 0x4770),
            # MOVS #0 replaces CMP's flags: the following NE cannot fire.
            (0x2c00, 0x2200, _branch(0x18e, 0x240, 1), 0x4770),
        )
        paths += tuple((0x2c00, _branch(0x18c, 0x240, condition), 0x4770)
                       for condition in (3, 4, 6, 11, 13))
        for words in paths:
            image = _queue_image()
            for index, word in enumerate(words):
                _put(image, 0x18a + 2 * index, word)
            with self.subTest(words=words):
                self.assertIsNone(_prove(image))
        for store in (0x700a, 0x800a):  # Unknown R1 may alias SP+4.
            image = _queue_image()
            _put(image, 0x188, store)
            _put(image, 0x18a, 0x2401)
            _put(image, 0x18c, _branch(0x18c, 0x240))
            with self.subTest(store=store):
                self.assertIsNone(_prove(image))

    def test_numeric_append_register_roles_cannot_alias(self):
        mutations = (
            # Updating R4 before the index copy loses the old count.
            ((0x102, 0x1c64), (0x104, 0x0624), (0x106, 0x0e24),
             (0x10a, 0x1c24)),
            # The index copy would overwrite the new increment in R1.
            ((0x102, 0x1c61), (0x104, 0x0609), (0x106, 0x0e09),
             (0x10a, 0x1c0c)),
            # The increment would replace the loaded event in R6.
            ((0x102, 0x1c66), (0x104, 0x0636), (0x106, 0x0e36),
             (0x10a, 0x1c34)),
            # Forming the base must not replace count, index, or event.
            ((0x10c, 0xac01), (0x10e, 0x5466)),
            ((0x10c, 0xa901), (0x10e, 0x544e)),
            ((0x10c, 0xae01), (0x10e, 0x5476)),
        )
        for changes in mutations:
            image = _queue_image()
            for site, word in changes:
                _put(image, site, word)
            with self.subTest(changes=changes):
                self.assertIsNone(_prove(image))

    def test_increment_temporary_can_be_reused_after_updating_the_count(self):
        image = _queue_image()
        for site, word in ((0x102, 0x1c63), (0x104, 0x061b),
                           (0x106, 0x0e1b), (0x10a, 0x1c1c)):
            _put(image, site, word)
        proof = _prove(image)
        self.assertIsNotNone(proof)
        self.assertEqual(proof['count_register'], 4)

    def test_backward_route_cannot_hide_an_index_clobber(self):
        image = _queue_image()
        _put(image, 0x240, _branch(0x240, 0x2a0))
        _put(image, 0x2a0, 0x2500)
        _put(image, 0x2a2, _branch(0x2a2, 0x250))
        _put(image, 0x250, 0x2502)
        _put(image, 0x252, _branch(0x252, 0x280))
        self.assertIsNone(_prove(image))

    def test_consumer_route_cannot_take_a_known_false_branch(self):
        for compare, condition in ((0x2c00, 0), (0x2200, 1)):
            image = _queue_image()
            _put(image, 0x242, compare)
            _put(image, 0x244, _branch(0x244, 0x280, condition))
            _put(image, 0x246, 0x4770)
            with self.subTest(compare=compare, condition=condition):
                self.assertIsNone(_prove(image))

    def test_sideband_return_or_indirect_call_cannot_fall_through(self):
        for instruction in (0x4770, 0x4790):
            image = _queue_image()
            _put(image, 0x188, instruction)
            _put(image, 0x18a, 0x2401)
            _put(image, 0x18c, _branch(0x18c, 0x240))
            with self.subTest(instruction=instruction):
                self.assertIsNone(_prove(image))

    def test_consumer_observation_requires_the_proven_thumb_width(self):
        image = _queue_image()
        _put(image, 0x262, 0xf813)  # LDRB.W R6,[R3,R5] is four bytes.
        _put(image, 0x264, 0x6005)
        self.assertIsNone(_prove(image))

    def test_low_contact_path_inherits_the_gate_compare_flags(self):
        image = _queue_image()
        words = {0x182: _branch(0x182, 0x190, 1), 0x184: 0x4770,
                 0x190: 0x205a, 0x192: 0xab00, 0x194: 0x7118,
                 0x196: 0x2401, 0x198: _branch(0x198, 0x240)}
        for site, word in words.items():
            _put(image, site, word)
        self.assertIsNone(_prove(image))

    def test_consumer_inherits_the_sideband_exit_flags(self):
        image = _queue_image()
        _put(image, 0x240, _branch(0x240, 0x278, 0))
        _put(image, 0x242, 0x4770)
        _put(image, 0x278, 0x2500)
        _put(image, 0x27a, _branch(0x27a, 0x280))
        self.assertIsNone(_prove(image))

    def test_consecutive_conditions_cannot_take_conflicting_flag_edges(self):
        consumer = _queue_image()
        for site, word in ((0x240, 0x7810), (0x242, 0x2801),
                           (0x244, _branch(0x244, 0x270, 0)), (0x246, 0x4770),
                           (0x270, _branch(0x270, 0x278, 1)), (0x272, 0x4770),
                           (0x278, 0x2500), (0x27a, _branch(0x27a, 0x280))):
            _put(consumer, site, word)
        self.assertIsNone(_prove(consumer))

        contact = _queue_image()
        for site, word in ((0x182, 0x7808), (0x184, 0x2801),
                           (0x186, _branch(0x186, 0x190, 0)), (0x188, 0x4770),
                           (0x190, _branch(0x190, 0x1a0, 1)), (0x192, 0x4770),
                           (0x1a0, 0x205a), (0x1a2, 0xab00), (0x1a4, 0x7118),
                           (0x1a6, 0x2401), (0x1a8, _branch(0x1a8, 0x240))):
            _put(contact, site, word)
        self.assertIsNone(_prove(contact))


if __name__ == '__main__':
    unittest.main()
