"""Generated source snippets exercise the A80 timer proof fail-closed."""
import struct
import unittest
from capstone import arm as a

from msm5xxx_emulator.detection.devices.rex.a80_timer import (
    _callback,
    _registration,
    _setter_slot,
    _timer_init,
    _typed_irq_access_contract,
    _wrapper_loads_slot,
    find_a80_timer,
)
from msm5xxx_emulator.detection.devices.rex.a80_timer_setup import (
    _channel_linear_path,
    _channel_reload_values,
    _counter_contract,
    _ordered_channel_updates,
    _state_load_matches_ram,
    _symbolic_step_matches,
)
from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue, facts_for


def _ldr_literal(address, pool):
    base = (address + 4) & ~3
    displacement = pool - base
    if displacement < 0 or displacement & 3 or displacement > 1020:
        raise ValueError('literal outside Thumb LDR range')
    return 0x4900 | (displacement >> 2)


def _bl(address, target):
    displacement = target - (address + 4)
    if displacement & 1 or not -(1 << 22) <= displacement < (1 << 22):
        raise ValueError('call outside Thumb BL range')
    encoded = displacement & 0x7FFFFF
    return (0xF000 | (encoded >> 12 & 0x7FF),
            0xF800 | (encoded >> 1 & 0x7FF))


def _synthetic_initializer(*, arm_address=0x030007A0, arm_value=2,
                           timer_index=0x25):
    image = bytearray(0x180)
    struct.pack_into('<H', image, 0x40, 0xB580)  # push {r7,lr}
    struct.pack_into('<H', image, 0x50, _ldr_literal(0x50, 0x80))
    struct.pack_into('<HH', image, 0x52, 0x2000 | arm_value, 0x7008)
    struct.pack_into('<H', image, 0x56, _ldr_literal(0x56, 0x84))
    struct.pack_into('<H', image, 0x58, 0x2000 | timer_index)
    struct.pack_into('<HH', image, 0x5A, *_bl(0x5A, 0x120))
    struct.pack_into('<II', image, 0x80, arm_address, 0x181)
    return bytes(image)


def _synthetic_registrar(*, row_size=0x1C, callback_offset=0x14):
    image = bytearray(0x180)
    struct.pack_into('<H', image, 0x100, 0x2000 | row_size)
    struct.pack_into('<H', image, 0x102, _ldr_literal(0x102, 0x160))
    struct.pack_into('<HHH', image, 0x104, 0x4368, 0x1840,
                     0x6000 | ((callback_offset // 4) << 6) | 4)
    struct.pack_into('<I', image, 0x160, 0x14004F20)
    return bytes(image)


def _synthetic_callback(*, five=5, ten=10):
    image = bytearray(0x180)
    words = [0x4900, 0xB5B0, 0x2400 | five, 0x2828, 0xD100,
             0x2400 | ten]
    for index in range(5):
        words.extend(_bl(0x10C + index * 4, 0x140))
    words.append(0xBDB0)
    struct.pack_into('<' + 'H' * len(words), image, 0x100, *words)
    return bytes(image)


def _synthetic_setter(*, branch_target=0x10A, clobber=None):
    image = bytearray(0x180)
    # ldr r2, =table; cmp r0,#0; bne second; str r1,[r2,#1c]; bx lr;
    # str r1,[r2,#20]; bx lr
    if clobber is None:
        struct.pack_into('<HHHHHHH', image, 0x100, 0x4A07, 0x2800,
                         0xD100 | ((branch_target - 0x108) // 2),
                         0x61D1, 0x4770, 0x6211, 0x4770)
    else:
        changed_register = {'r0': 0x2000, 'r1': 0x2100}[clobber]
        target = 0x10E
        struct.pack_into('<HHHHHHHHH', image, 0x100, 0x4A07,
                         changed_register, 0x2800,
                         0xD100 | ((target - 0x10A) // 2),
                         0x61D1, 0x4770, 0x0000, 0x6211, 0x4770)
    struct.pack_into('<I', image, 0x120, 0x1411B250)
    return bytes(image)


def _synthetic_irq_wrapper(*, slot=0x1411B26C):
    image = bytearray(0x180)
    # ldr r3,[pc,#0x18]; ldr r3,[r3]; tst r3,#1; bx r3
    struct.pack_into('<IIII', image, 0x100, 0xE59F3018, 0xE5933000,
                     0xE3130001, 0xE12FFF13)
    struct.pack_into('<I', image, 0x120, slot)
    return bytes(image)


class A80TimerSourceTests(unittest.TestCase):
    def test_initializer_proves_arm_and_registration_arguments(self):
        found = _timer_init(_synthetic_initializer())
        self.assertIsNotNone(found)
        self.assertEqual(found[1], 0x180)
        self.assertEqual(found[2], 0x120)

    def test_initializer_rejects_changed_arm_literal(self):
        self.assertIsNone(_timer_init(_synthetic_initializer(arm_address=0x030007A4)))

    def test_initializer_rejects_changed_registration_index(self):
        self.assertIsNone(_timer_init(_synthetic_initializer(timer_index=0x24)))

    def test_registration_requires_row_stride_and_callback_field(self):
        self.assertEqual(_registration(_synthetic_registrar(), 0x100)[0],
                         0x14004F20)
        self.assertIsNone(_registration(_synthetic_registrar(row_size=0x18),
                                        0x100))
        self.assertIsNone(_registration(_synthetic_registrar(
            callback_offset=0x10), 0x100))

    def test_callback_requires_both_timer_intervals_and_calls(self):
        self.assertIsNotNone(_callback(_synthetic_callback(), 0x100))
        self.assertIsNone(_callback(_synthetic_callback(five=4), 0x100))
        self.assertIsNone(_callback(_synthetic_callback(ten=9), 0x100))

    def test_public_finder_declines_empty_or_unlinked_source(self):
        config = type('Config', (), {'ram_base': 0x14000000,
                                     'ram_size': 0x800000})()
        self.assertIsNone(find_a80_timer(b'', config))
        self.assertIsNone(find_a80_timer(_synthetic_initializer(), config))

    def test_channel_setup_requires_complete_ordered_masks_and_reloads(self):
        valid = (('ands', 0xDF, 0x100, 0x102), ('ands', 0xEF, 0x104, 0x106),
                 ('orrs', 2, 0x108, 0x10A), ('orrs', 1, 0x10C, 0x10E))
        self.assertEqual(_ordered_channel_updates(valid), valid)
        reordered = (valid[0], ('orrs', 2, 0x104, 0x106),
                     ('ands', 0xEF, 0x108, 0x10A), valid[3])
        self.assertIsNone(_ordered_channel_updates(reordered))
        self.assertIsNone(_ordered_channel_updates((valid[0], valid[1], valid[2])))
        wrong_op = (('orrs', 0xDF, 0x100, 0x102), *valid[1:])
        self.assertIsNone(_ordered_channel_updates(wrong_op))
        reloads = ((0x030007B4, 0x80, 0x120), (0x030007B0, 0x80, 0x122))
        self.assertTrue(_channel_reload_values(reloads))
        self.assertFalse(_channel_reload_values((reloads[0], (0x030007B0, 0x40, 0x122))))

    def test_channel_path_rejects_conditional_or_clobber_edge(self):
        addresses = set(range(0x100, 0x110, 2))
        edges = {(CodeAddress(at, 'thumb'), CodeAddress(at + 2, 'thumb'))
                 for at in range(0x100, 0x10E, 2)}
        self.assertTrue(_channel_linear_path(edges, addresses, 0x100, 0x10E))
        # A branch or an intervening clobber breaks the proven fallthrough.
        edges.remove((CodeAddress(0x106, 'thumb'), CodeAddress(0x108, 'thumb')))
        self.assertFalse(_channel_linear_path(edges, addresses, 0x100, 0x10E))

    def test_shared_use_def_facts_reject_a_clobbered_mask_register(self):
        # MOVS r3,#0xdf; MOVS r3,#1; ANDS r0,r3. A stale linear value
        # would incorrectly keep the first mask across the second write.
        image = bytearray(0x110)
        struct.pack_into('<HHHHH', image, 0x100,
                         0xB501, 0x23DF, 0x2301, 0x4018, 0x4770)
        facts = facts_for(bytes(image))
        function = facts.function(CodeAddress(0x100, 'thumb'), budget=32)
        value = facts.register_value(function, CodeAddress(0x106, 'thumb'), a.ARM_REG_R3)
        self.assertEqual((value.kind, value.value), ('const', 1))

    def test_symbolic_transform_chain_rejects_a_wrong_source_load(self):
        source = SymbolicValue('load', operands=(SymbolicValue.const(0x14001000),),
                               width=4, site=CodeAddress(0x100, 'thumb'))
        other = SymbolicValue('load', operands=(SymbolicValue.const(0x14002000),),
                              width=4, site=CodeAddress(0x104, 'thumb'))
        first = SymbolicValue('op', 'and', (SymbolicValue.const(0xDF), source))
        second = SymbolicValue('op', 'and', (SymbolicValue.const(0xEF), first))
        wrong = SymbolicValue('op', 'and', (SymbolicValue.const(0xEF),
                                            SymbolicValue('op', 'and',
                                                (SymbolicValue.const(0xDF), other))))
        self.assertTrue(_state_load_matches_ram(source, 0x14000000, 0x20000))
        self.assertFalse(_state_load_matches_ram(other, 0x14000000, 0x2000))
        self.assertTrue(_symbolic_step_matches(second, 'and', 0xEF, first))
        self.assertFalse(_symbolic_step_matches(wrong, 'and', 0xEF, first))

    def test_counter_contract_rejects_width_or_conversion_mutations(self):
        byte_reads = ((0x03000740, 1),) * 3
        self.assertTrue(_counter_contract(byte_reads, 100, 0x3C1, 0x782, True))
        self.assertFalse(_counter_contract(((0x03000740, 2),) * 3,
                                           100, 0x3C1, 0x782, True))
        self.assertFalse(_counter_contract(byte_reads, 99, 0x3C1, 0x782, True))
        self.assertFalse(_counter_contract(byte_reads, 100, 0x3C1, 0x782, False))

    def test_irq_access_contract_requires_typed_status_and_enable_lanes(self):
        accesses = {
            ('read', 0x03000A80, 4), ('read', 0x03000A84, 1),
            ('write', 0x03000A80, 4), ('write', 0x03000A84, 1),
            ('write', 0x03000A94, 4), ('write', 0x03000A98, 1),
        }
        self.assertTrue(_typed_irq_access_contract(accesses))
        self.assertFalse(_typed_irq_access_contract(accesses - {('read', 0x03000A84, 1)}))
        self.assertFalse(_typed_irq_access_contract(
            (accesses - {('write', 0x03000A98, 1)}) | {('write', 0x03000A98, 4)}))

    def test_setter_selects_the_store_reached_by_selector_branch(self):
        image = _synthetic_setter()
        self.assertEqual(_setter_slot(image, 0x100, 0)[0], 0x1411B26C)
        self.assertEqual(_setter_slot(image, 0x100, 1)[0], 0x1411B270)
        self.assertIsNone(_setter_slot(image, 0x100, 2))
        self.assertIsNone(_setter_slot(_synthetic_setter(branch_target=0x108),
                                       0x100, 0))
        self.assertIsNone(_setter_slot(_synthetic_setter(clobber='r0'),
                                       0x100, 0))
        self.assertIsNone(_setter_slot(_synthetic_setter(clobber='r1'),
                                       0x100, 0))

    def test_wrapper_requires_a_live_slot_dereference_and_indirect_branch(self):
        self.assertIsNotNone(_wrapper_loads_slot(
            _synthetic_irq_wrapper(), 0x100, 0x1411B26C))
        self.assertIsNone(_wrapper_loads_slot(
            _synthetic_irq_wrapper(slot=0x1411B270), 0x100, 0x1411B26C))
        image = bytearray(_synthetic_irq_wrapper())
        struct.pack_into('<I', image, 0x104, 0xE1A03000)  # clobber the slot load
        self.assertIsNone(_wrapper_loads_slot(bytes(image), 0x100, 0x1411B26C))


if __name__ == '__main__':
    unittest.main()
