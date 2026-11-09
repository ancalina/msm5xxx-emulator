"""Independent complete Thumb/descriptor tests for the dual-descriptor protocol."""
import struct
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.capabilities import MachinePlan
from msm5xxx_emulator.detection.facts import bind_facts, fact_scope
from msm5xxx_emulator.detection.image_view import ImageView
from msm5xxx_emulator.detection.devices.dmd.dual import _CALL_LAYOUTS, _EVENTS, _LITERAL_ROLES, _PORTS, capability, find_dmd5000_profile, qemu_dual_property as qemu_property


def _lit(site, register, pool):
    base = (site + 4) & ~3
    delta = pool - base
    assert 0 <= delta <= 1020 and not delta & 3
    return 0x4800 | (register << 8) | (delta >> 2)


def _bl(at, target):
    delta = target - at - 4
    encoded = delta & 0x7fffff
    return struct.pack('<HH', 0xf000 | ((encoded >> 12) & 0x7ff),
                       0xf800 | ((encoded >> 1) & 0x7ff))


def _strb(rt, rn, offset):
    assert offset % 1 == 0 and offset <= 31
    return 0x7000 | (offset << 6) | (rn << 3) | rt


def _strh(rt, rn, offset):
    assert offset % 2 == 0 and offset <= 62
    return 0x8000 | ((offset // 2) << 6) | (rn << 3) | rt


def _ldrh(rt, rn, offset):
    assert offset % 2 == 0 and offset <= 62
    return 0x8800 | ((offset // 2) << 6) | (rn << 3) | rt


def _image(*, short=False, wrong_port=None, wrong_count=False,
           missing_call=False, wrong_read=False, wrong_nested=False,
           descriptor_choice=False, wrong_mode_source=False, bypass_descriptor=False,
           descriptor=0x5000, payloads=(0x1000, 0x3000)):
    entry, caller = 0x100, 0x500
    completion, read_base = 0x01000000, 0x03000760
    body_size, offsets = _CALL_LAYOUTS[1 if short else 0]
    image = bytearray(max(0x7000, descriptor + 0x10, payloads[1] + 0x2000))
    words = [0] * (body_size // 2 + 3)
    words[0] = 0xB5F0
    struct.pack_into('<' + 'H' * len(words), image, entry, *words)
    pool = entry + 0x200
    pool_values = []
    def load(site, reg, value):
        idx = len(pool_values)
        address = pool + 4 * idx
        struct.pack_into('<H', image, entry + site,
                         _lit(entry + site, reg, address))
        pool_values.append(value)
    roles = {'completion': completion, 'descriptor0': descriptor,
             'descriptor1': descriptor + 8, 'descriptor_end': descriptor + 16}
    rolespecs = (*_LITERAL_ROLES, (374 if short else 380, 1, 'descriptor_end'))
    for off, reg, role in rolespecs:
        value = roles.get(role, role)
        load(off, reg, value)
    # Event-specific bases and immediate values are ordinary source operations.
    for off, reg, value in ((0x50, 2, 0x03000050), (0x56, 2, 0x03000050),
                            (0x70, 2, 0x03000050), (0x76, 2, 0x03000050),
                            (0xF8, 7, read_base), (0xBA, 7, read_base),
                            (0xDE, 7, read_base), (0x11E, 7, read_base),
                            (0x146, 7, read_base)):
        load(off, reg, value)
    # Direct event instructions at the exact source PCs checked by native code.
    instructions = {
        0x18: 0x2000, 0x1A: _strb(0, 1, 12),
        0x2E: 0x2000, 0x32: _strh(0, 1, 12),
        0x52: _strh(0, 2, 0), 0x58: _strh(0, 2, 0),
        0x72: _strh(0, 2, 0), 0x78: _strh(0, 2, 0),
        0x88: 0x2001, 0x8A: _strb(0, 1, 12),
        0x96: 0x200E, 0x98: _strb(0, 7, 8),
        0x9A: 0x2000, 0x9C: _strb(0, 7, 12),
        0xF4: 0x2000, 0xFA: _strb(0, 7, 12),
        0x15C: 0x2000, 0x160: _strb(0, 7, 8),
        0xBC: _ldrh(0, 7, 8), 0xE0: _ldrh(0, 7, 8),
        0x120: _ldrh(0, 7, 12), 0x148: _ldrh(0, 7, 12),
    }
    if wrong_port is not None:
        instructions[0x1A] = _strb(0, 1, wrong_port)
    if wrong_read:
        instructions[0x120] = _ldrh(0, 7, 8)
    if descriptor_choice:
        # An opaque helper result chooses between two independently loaded rows.
        instructions.update({0x24: 0x2800, 0x26: 0xD001, 0x2A: 0xE000,
                             0x2E: _ldrh(0, 3, 6 if wrong_mode_source else 4)})
        if bypass_descriptor:
            instructions[0x24] = 0xE003  # Enter after both descriptor loads.
    for off, word in instructions.items():
        struct.pack_into('<H', image, entry + off, word)
    targets = []
    for index, off in enumerate(offsets):
        target = (0x800 if off in (28, 56, 160, 256) else
                  0x900 if off in (52, 130) else
                  0x600 if off == 14 else
                  0x610 if off == 144 else 0xA00 + index * 0x10)
        targets.append(target)
        if missing_call and off == 160:
            continue
        image[entry + off:entry + off + 4] = _bl(entry + off, target)
    # Ensure a normal closed return after the final layout-specific event/call.
    struct.pack_into('<H', image, entry + body_size - 2, 0xBDF0)
    for i, value in enumerate(pool_values):
        struct.pack_into('<I', image, pool + 4 * i, value)
    # One unique caller with a short linked setup sequence.
    image[caller:caller + 4] = _bl(caller, 0x700)
    image[caller + 4:caller + 8] = _bl(caller + 4, 0x710)
    image[caller + 8:caller + 12] = _bl(caller + 8, entry)
    struct.pack_into('<H', image, caller - 2, 0xB500)
    struct.pack_into('<H', image, caller + 12, 0xBD00)
    for target in set(targets):
        if target == 0x800:
            # The linked board-status helper loads 0x03000750 and reads +12.
            struct.pack_into('<HHH', image, target, _lit(target, 0, target + 0x20),
                             0x7B00, 0x4770)  # ldrb r0,[r0,#12]
            struct.pack_into('<I', image, target + 0x20, 0x03000750)
        elif target == 0x900:
            struct.pack_into('<H', image, target, 0xB500)
            for relative, leaf in ((10, 0x600), (38, 0x610),
                                   (42, 0x600), (62, 0x610)):
                if wrong_nested and relative == 38:
                    continue
                image[target + relative:target + relative + 4] = _bl(target + relative, leaf)
            struct.pack_into('<H', image, target + 66, 0xBD00)
        else:
            struct.pack_into('<H', image, target, 0x4770)
    struct.pack_into('<IHHIHH', image, descriptor,
                     payloads[0], 0, 0x1000, payloads[1], 0, 0x1000)
    if wrong_count:
        struct.pack_into('<H', image, descriptor + 6, 0x0FFE)
    return bytes(image), (entry, descriptor, payloads, completion)


class DmdDualProtocolTests(unittest.TestCase):
    def test_dual_descriptors_bind_source_footprint_without_payload_hashes(self):
        image, (entry, descriptor, payloads, completion) = _image()
        profile = find_dmd5000_profile(image)
        self.assertEqual(profile, {'completion': completion, 'entry': entry,
                                   'descriptors': (descriptor, descriptor + 8),
                                   'payloads': payloads, 'pairs': 0x800})
        changed = bytearray(image)
        changed[payloads[0]:payloads[0] + 16] = bytes(range(16))
        self.assertEqual(find_dmd5000_profile(bytes(changed)), profile)

    def test_alternate_closed_layout_and_helper_linkage(self):
        image, _ = _image(short=True)
        self.assertIsNotNone(find_dmd5000_profile(image))
        self.assertIsNone(find_dmd5000_profile(_image(wrong_nested=True)[0]))

    def test_descriptor_modes_remain_proved_across_a_pointer_join(self):
        self.assertIsNotNone(find_dmd5000_profile(_image(descriptor_choice=True)[0]))
        for options in ({'wrong_mode_source': True}, {'bypass_descriptor': True}):
            with self.subTest(options=options):
                self.assertIsNone(find_dmd5000_profile(
                    _image(descriptor_choice=True, **options)[0]))

    def test_footprint_rejects_wrong_port_count_call_and_readback(self):
        for options in ({'wrong_port': 8}, {'wrong_count': True},
                        {'missing_call': True}, {'wrong_read': True}):
            with self.subTest(options=options):
                self.assertIsNone(find_dmd5000_profile(_image(**options)[0]))

    def test_native_wire_alignment_and_sparse_payload_coverage(self):
        for options in ({'descriptor': 0x5002},
                        {'descriptor': 0x6000, 'payloads': (0x1001, 0x3002)}):
            self.assertIsNone(find_dmd5000_profile(_image(**options)[0]))

        image, _ = _image()
        segments = ((0x100, 0x284), (0x300, 0x400), (0x500, 0x50E),
                    (0x600, 0x612), (0x700, 0x702), (0x710, 0x712),
                    (0x800, 0x824), (0x900, 0x944), (0xA00, 0xAA0),
                    (0x5000, 0x5010))
        sparse = ImageView.sparse((begin, image[begin:end])
                                  for begin, end in segments)
        with fact_scope():
            bind_facts(image, sparse)
            self.assertIsNone(find_dmd5000_profile(image))

    def test_plan_claims_all_native_windows_and_property_owner_conflicts(self):
        image, _ = _image()
        profile = find_dmd5000_profile(image)
        cap = capability(profile)
        plan = MachinePlan((cap,), cap.properties, cap.claims, cap.evidence)
        self.assertEqual(len(plan.claims), 5)
        loaded = image + bytes(0x1000)
        config = SimpleNamespace(load_address=0, image_offset=0, entry=0,
            flash_size=len(loaded), ram_base=0x01000000, ram_size=0x100000,
            image_kind='firmware', ram_bootstrap_profile=None,
            missing_overlays=(), ram_image_size=0, board_status_input=None,
            key_register=None, uart_console=None)
        property_value, reason = qemu_property(image, loaded, config)
        self.assertIsNone(reason)
        self.assertEqual(property_value,
                         'dmd5000-program=100:5000:1000:5008:3000:800')
        config.key_register = _PORTS[1]
        self.assertEqual(qemu_property(image, loaded, config),
                         (None, 'dmd5000-input-owner-conflict'))
        config.key_register = None
        self.assertEqual(qemu_property(image, loaded, config, input_profile='bad'),
                         (None, 'dmd5000-input-owner-unclosed'))
        self.assertEqual(qemu_property(image, loaded, config, uart_windows=((None, 1),)),
                         (None, 'dmd5000-input-owner-conflict'))
        self.assertEqual(qemu_property(image, loaded, config, layout_claimed=True),
                         (None, 'dmd5000-loaded-source-or-memory-owner-unclosed'))


if __name__ == '__main__':
    unittest.main()
