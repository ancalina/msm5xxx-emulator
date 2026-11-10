import struct
import unittest

from msm5xxx_emulator.detection.registry import device_domain
find_gpio_pmic_profile = device_domain('external_bus.gpio_pmic').find_gpio_pmic_profile


def _h(word):
    return struct.pack('<H', word & 0xffff)


def _bl(at, target):
    delta = target - (at + 4)
    encoded = delta & 0x7fffff
    return struct.pack('<HH', 0xf000 | ((encoded >> 12) & 0x7ff),
                       0xf800 | ((encoded >> 1) & 0x7ff))


def _branch_back(at, target, condition=5):
    delta = (target - (at + 4)) >> 1
    return _h(0xd000 | (condition << 8) | (delta & 0xff))


def _literal_load(at, register, pool):
    base = (at + 4) & ~3
    offset = pool - base
    assert offset >= 0 and offset % 4 == 0 and offset <= 1020
    return _h(0x4800 | (register << 8) | (offset // 4))


def _irq_routines(image, entry):
    # MRS, change the interrupt mask, MSR the new control field, restore CPSR.
    struct.pack_into('<2H', image, entry, 0x4778, 0x0000)  # Thumb interworking entry
    disable = (0xe10f0000, 0xe38010c0, 0xe121f001, 0xe121f000, 0xe12fff1e)
    enable = (0xe10f0000, 0xe3c010c0, 0xe121f001, 0xe121f000, 0xe12fff1e)
    struct.pack_into('<5I', image, entry + 4, *disable)
    second = entry + 0x18
    struct.pack_into('<2H', image, second, 0x4778, 0x0000)
    struct.pack_into('<5I', image, second + 4, *enable)


def _function(image, start, kind, irq, table):
    code = bytearray()
    if kind == 'write':
        code += _h(0xb5f8)                    # preserve the serial routine's ABI
        code += _h(0x1c0e)                    # r6 = r1
        code += _h(0x0640)                    # shift command to the high byte
        code += _h(0x0e04)                    # command in r4
    else:
        code += _h(0xb5f8)
        code += _h(0x0040) + _h(0x2101) + _h(0x4308)  # (reg << 1) | read
        code += _h(0x0604) + _h(0x0e24)
    pool = start + 0x100
    code += _literal_load(start + len(code), 0, pool)
    code += _literal_load(start + len(code), 1, pool + 4)
    code += _h(0x6802) + _h(0x6011)  # read shadow/table pointer and write the port
    code += _h(0x680b) + _h(0x600b)  # shadow read/modify/write path
    code += _h(0x6882 if kind == 'write' else 0x6842)  # direction or input table entry
    if kind == 'read':
        code += _h(0x6882) + _h(0x6011)    # direction register, then MMIO write
    # A paired save/restore call route brackets each GPIO transition.
    for _ in range(6):
        code += _bl(start + len(code), irq)
        code += _bl(start + len(code), irq + 0x18)
    code += _h(0x2506)               # six command bits
    loop6 = start + len(code)
    code += _h(0x025b) + _h(0x3d01)  # data GPIO9, decrement bit count
    code += _branch_back(start + len(code), loop6)
    code += _h(0x2407)               # eight data bits
    loop7 = start + len(code)
    code += _h(0x029b) + _h(0x3c01)  # clock GPIO10, decrement bit count
    code += _branch_back(start + len(code), loop7)
    if kind == 'read':
        code += _h(0x6840) + _h(0x6800) + _h(0x0580)  # sample GPIO9 input
    code += _h(0xbd00)                  # return through the saved PC
    code += bytes(pool - start - len(code))
    code += struct.pack('<II', table, 0x147ff000)
    image[start:start + len(code)] = code


def _synthetic_image():
    image = bytearray(0x1200)
    irq = 0x200
    _irq_routines(image, irq)
    table = 0x300
    struct.pack_into('<3I', image, table, 0x030006e8, 0x03000720, 0x030006f4)
    writer, reader, poll, init = 0x400, 0x600, 0x800, 0xa00
    _function(image, writer, 'write', irq, table)
    _function(image, reader, 'read', irq, table)
    code = bytearray(_h(0xb510))
    code += _bl(poll + len(code), reader)
    code += _bl(poll + len(code), irq)  # expected-value helper
    code += _h(0x06e1) + _h(0x0ec9) + _h(0x4281)
    code += _branch_back(poll + len(code), poll + 2, condition=1)
    code += _bl(poll + len(code), writer)
    code += _h(0xbd10)
    image[poll:poll + len(code)] = code
    code = bytearray(_h(0xb580))
    for _ in range(7):
        code += _bl(init + len(code), writer)
    for _ in range(3):
        code += _bl(init + len(code), poll)
    code += _h(0xbc80) + _h(0xbc08) + _h(0x4718)
    image[init:init + len(code)] = code
    return bytes(image), writer, reader


class GpioPmicDetectionTests(unittest.TestCase):
    def test_closed_serial_readback_contract(self):
        image, writer, reader = _synthetic_image()
        profile, reason = find_gpio_pmic_profile(image)
        self.assertEqual(reason, '')
        self.assertEqual(profile['kind'], 'gpio-serial-register-readback-v1')
        self.assertEqual(profile['register_count'], 64)
        self.assertTrue(profile['write_readback'])
        roles = {item['role'] for item in profile['evidence']}
        self.assertTrue({'writer', 'reader', 'gpio-port-table', 'readback-poll', 'initializer'} <= roles)
        self.assertIn({'role': 'writer-literal', 'span': [writer + 0x100, 4]},
                      profile['extra_spans'])
        self.assertIn({'role': 'reader-literal', 'span': [reader + 0x100, 4]},
                      profile['extra_spans'])

    def test_rejects_missing_serial_table_and_read_path(self):
        image, _, _ = _synthetic_image()
        changed = bytearray(image)
        struct.pack_into('<I', changed, 0x300 + 4, 0x03000724)
        profile, reason = find_gpio_pmic_profile(bytes(changed))
        self.assertIsNone(profile)
        self.assertEqual(reason, 'serial-writer-not-closed')

    def test_rejects_unrelated_or_truncated_images(self):
        for image, expected in ((b'\x00' * 80, 'image-too-small'),
                                (b'\x00' * 0x1000, 'serial-writer-not-closed')):
            with self.subTest(expected=expected):
                profile, reason = find_gpio_pmic_profile(image)
                self.assertIsNone(profile)
                self.assertEqual(reason, expected)


if __name__ == '__main__':
    unittest.main()
