"""Synthetic instruction graphs for the watchdog grammar (no firmware snippets)."""
import struct
import unittest

from msm5xxx_emulator.detection import watchdog as detector
from corpus import firmware_path


def fixture(shift=0, register=0x03000700, mask=1):
    data = bytearray(0x1800 + shift)
    service, task, dog = 0x100 + shift, 0x500 + shift, 0x1000 + shift

    def half(at, value):
        struct.pack_into('<H', data, at, value)

    def literal(at, reg, value):
        # Each literal is reachable by the Thumb PC-relative unsigned imm8.
        local = ((at + 4) & ~3) + 0x200
        while any(data[local:local + 4]):
            local += 4
        half(at, 0x4800 | reg << 8 | ((local - ((at + 4) & ~3)) // 4))
        struct.pack_into('<I', data, local, value)

    def bl(at, target):
        delta = target - at - 4
        struct.pack_into('<HH', data, at,
                         0xF000 | ((delta >> 12) & 0x7FF),
                         0xF800 | ((delta >> 1) & 0x7FF))

    # An independently assembled graph, with no firmware bytes or addresses.
    for off, op in detector._SERVICE.items():
        half(service + off, op)
    half(service + 0x1E, 0x2200 | mask)
    service_values = {0: 0x01002000, 0xE: 0x01003000,
                      0x18: 0xFFFF ^ mask, 0x1A: register,
                      0x36: 0xFFFF ^ mask}
    for off, reg in detector._SERVICE_LITERALS.items():
        literal(service + off, reg, service_values[off])
    for off in detector._SERVICE_CALLS:
        bl(service + off, 0x1100 + shift + (0 if off in (0xA, 0x30) else 4))
    for off, op in detector._TASK.items():
        half(task + off, op)
    task_values = {8: 0x01004000, 0x14: 0x01005000, 0x36: 0x01006000,
                   0x40: 10, 0x48: 0x01007000, 0x4A: 0xFF,
                   0x54: dog, 0x56: 100, 0x60: 0x01007000,
                   0x62: 0xFF00, 0x70: 100}
    for off, reg in detector._TASK_LITERALS.items():
        literal(task + off, reg, task_values[off])
    for off in detector._TASK_CALLS:
        target = service if off == 0x1C else 0x1120 + shift
        if off == 0x16:
            target = 0xE00 + shift
        bl(task + off, target)
    for off, op in detector._WAIT.items():
        half(0xE00 + shift + off, op)
    bl(0xE08 + shift, 0x1140 + shift)
    bl(0xE0E + shift, 0x1144 + shift)
    data[dog:dog + 6] = b'dog.c\0'
    return data, service, task


class WatchdogTests(unittest.TestCase):
    def test_relocated_contract_and_mask_from_code(self):
        for shift, port, mask in ((0, 0x03000700, 1),
                                  (0x100, 0x03000600, 2)):
            data, service, task = fixture(shift, port, mask)
            profile, reason = detector.find_watchdog_profile(bytes(data))
            self.assertIsNotNone(profile, reason)
            self.assertEqual((profile['register'], profile['mask']), (port, mask))
            self.assertEqual(profile['service_address'], service)
            self.assertEqual(profile['task_address'], task)
            self.assertEqual(profile['timeout_ms'], 30000)

    def test_control_flow_and_rmw_mutations_reject(self):
        data, service, task = fixture()
        # Every fixed instruction participates in the admitted ownership graph.
        for base, offsets in ((service, detector._SERVICE), (task, detector._TASK),
                              (0xE00, detector._WAIT)):
            for offset in offsets:
                changed = bytearray(data)
                changed[base + offset] ^= 1
                with self.subTest(base=base, offset=offset):
                    self.assertIsNone(detector.find_watchdog_profile(bytes(changed))[0])
        for offset in (0xA, 0x2C, 0x30, 0x44):
            changed = bytearray(data)
            changed[service + offset] ^= 1
            self.assertIsNone(detector.find_watchdog_profile(bytes(changed))[0])

    def test_invalid_mask_port_marker_and_literal_reject(self):
        for port, mask in ((0x01001000, 1), (0x03000700, 3), (0x03000700, 0)):
            data, _, _ = fixture(register=port, mask=mask)
            self.assertIsNone(detector.find_watchdog_profile(bytes(data))[0])
        data, service, task = fixture()
        data[0x1000] = ord('x')
        self.assertIsNone(detector.find_watchdog_profile(bytes(data))[0])
        data, _, _ = fixture()
        op = struct.unpack_from('<H', data, service + 0x36)[0]
        pool = ((service + 0x3A) & ~3) + (op & 255) * 4
        struct.pack_into('<I', data, pool, 0xFFFD)
        self.assertIsNone(detector.find_watchdog_profile(bytes(data))[0])
        for end in (service + 0x4D, task + 0x81, 0x1005):
            self.assertIsNone(detector.find_watchdog_profile(bytes(data[:end]))[0])

    def test_unowned_pulse_and_duplicate_owner_reject(self):
        data, _, task = fixture()
        data[task] = 0
        self.assertEqual(detector.find_watchdog_profile(bytes(data))[1],
                         'watchdog-periodic-owner-unclosed')
        first, _, _ = fixture()
        second, _, _ = fixture(0x1800)
        # A second self-contained graph retains absolute file offsets and BLs.
        first.extend(bytes(len(second) - len(first)))
        first[0x1800:] = second[0x1800:]
        self.assertEqual(detector.find_watchdog_profile(bytes(first))[1],
                         'watchdog-owner-ambiguous')

    def test_actual_watchdog_structure(self):
        profile, reason = detector.find_watchdog_profile(
            firmware_path('SPH-X7700.bin').read_bytes())
        self.assertIsNotNone(profile, reason)
        self.assertEqual((profile['register'], profile['mask']), (0x03000700, 1))
        self.assertEqual(profile['service_address'], 0x950A0)
        self.assertEqual(profile['task_address'], 0x951B8)


if __name__ == '__main__':
    unittest.main()
