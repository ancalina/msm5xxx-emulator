"""Focused private detector checks; never runs a guest."""
from pathlib import Path
import struct
import unittest

import os
from msm5xxx_emulator.detection import ma5_gpio_irq as candidate
from msm5xxx_emulator.detection.audio import find_ma5_readback_candidate
ROOT = Path(os.environ.get('MSM5XXX_TEST_FIRMWARE_ROOT',
                           Path(__file__).resolve().parents[2] / 'firmwares'))
FIRMWARE = ROOT / 'KTFT_X3500_verX3p56.73.0_riffdump_clean.bin'

class NewParentClass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIRMWARE.is_file():
            raise unittest.SkipTest('firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT')
        cls.image = FIRMWARE.read_bytes()

    def test_finite_variants_and_roles(self):
        for role, entry, size in [('parent_register', 0x484868, 134), ('soc_dispatch', 0x484648, 392), ('exception_register', 0x45299C, 14), ('chip_isr', 0x561CB8, 88), ('install_direct', 0x3D5C90, 56)]:
            span = candidate._span(self.image, entry, role)
            self.assertEqual(span['size'], size)
            # Every fixed instruction byte participates in exact class recognition.
            encoded, calls, literals, pins = next(row for row in candidate._SPANS[role] if len(bytes.fromhex(row[0])) == size)
            normalized = set(literals) | set(pins)
            normalized.update(x for o in calls for x in range(o, o + 4))
            image = bytearray(self.image)
            for offset in set(range(size)) - normalized:
                image[entry + offset] ^= 0x80
                with self.assertRaises(candidate._Reject, msg=(role, offset)):
                    candidate._span(image, entry, role)
                image[entry + offset] ^= 0x80
        exception = candidate._span(self.image, 0x45299C, 'exception_register')
        self.assertEqual(exception['literals'][0], 0x010F1FD0)
        self.assertEqual((struct.unpack_from('<H', self.image, exception['entry'] + 6)[0] >> 6 & 31) * 4, 0x1C)

    def test_boot_consumed_descriptor_and_mutations(self):
        rows, dependencies = candidate._boot_copy(self.image)
        self.assertEqual(rows, [(0x3D000C, 0x8EA0C8, 0x01000000, 0x18148, 0x01800000)])
        self.assertIn([0x3D000C, 12], dependencies)
        self.assertNotIn([0x3D000C, 20], dependencies)
        image = bytearray(self.image)
        for address in (0, 0x36C8, 0x36CC, 0x36E0, 0x36E4, 0x36E8, 0x36EC, 0x36F0, 0x3710, 0x3718, 0x372C, 0x373C, 0x3A5C, 0xB32, 0xB38, 0xB3C, 0xB42, 0xB44, 0xB2C, 0xB9C, 0xBA0, 0xBA4, 0x3D000C, 0x3D0010, 0x3D0014):
            image[address] ^= 1
            self.assertEqual(candidate._boot_copy(image)[0], [], hex(address))
            image[address] ^= 1
        original = image[0x3D0004:0x3D0008]
        struct.pack_into('<I', image, 0x3D0004, 0x01200000)
        self.assertEqual(candidate._boot_copy(image)[0], [])
        image[0x3D0004:0x3D0008] = original
        # Unconsumed trailing metadata does not change the proven copy/clear class.
        for address in (0x3D0018, 0x3D001C):
            image[address] ^= 1
            self.assertEqual(candidate._boot_copy(image)[0], rows)
            image[address] ^= 1

    def test_new_spans_relocate_with_literal_and_adr_dependencies(self):
        from test_audio_transport import _thumb_bl
        image = bytearray(self.image)
        for role, original in [('parent_register', 0x484868), ('soc_dispatch', 0x484648), ('exception_register', 0x45299C), ('chip_isr', 0x561CB8), ('install_direct', 0x3D5C90), ('boot_copy', 0xAD8)]:
            span = candidate._span(self.image, original, role)
            entry = original + 0x2000
            code = bytearray(self.image[original:original+span['size']])
            pool = (entry + len(code) + 3) & ~3
            for offset, target in span['calls'].items():
                code[offset:offset+4] = _thumb_bl(entry + offset, target)
            for offset, value in span['literals'].items():
                base = (entry + offset + 4) & ~3
                if offset in span['pins']:
                    end = self.image.index(0, value) + 1
                    text = self.image[value:end]
                    code[offset] = (pool - base) // 4
                    image[pool:pool+len(text)] = text
                    pool = (pool + len(text) + 3) & ~3
                else:
                    code[offset] = (pool - base) // 4
                    struct.pack_into('<I', image, pool, value)
                    pool += 4
            image[entry:entry+len(code)] = code
            self.assertEqual(candidate._span(image, entry, role)['size'], span['size'])

    def test_partition_and_partial_overlap(self):
        layouts = candidate._layouts(self.image)
        self.assertIn((0x3D000C, 0x8EA0C8, 0x01000000, 0x18148, 0x017FE000), layouts)
        for address in (0x017FF304, 0x017FFFFC):
            with self.assertRaises(candidate._Reject):
                candidate._mapping(layouts, address, 4)
        image = bytearray(self.image)
        struct.pack_into('<5I', image, 0x1937C, 0x19390, 0x01018000, 0x54, 0x01018054, 0x12B0)
        partial = candidate._layouts(image)
        self.assertFalse(any(row[0] == 0x3D000C for row in partial))
        with self.assertRaises(candidate._Reject):
            candidate._mapping(partial, 0x010030A8, 28, data=True)
        struct.pack_into('<5I', image, 0x1937C, 0x19390, 0x017FD000, 0x54, 0x017FD054, 0x12B0)
        self.assertEqual(candidate._layouts(image)[-1][-1], 0x017FD000)

    def test_original_static_graph_and_mutations(self):
        audio = find_ma5_readback_candidate(self.image)
        def detect(image):
            return candidate.find_ma5_gpio_irq_candidate(image, audio)
        baseline = detect(self.image)
        self.assertEqual(baseline['status'], 'candidate', baseline)
        self.assertFalse(baseline['runtime_admitted'])
        self.assertEqual(baseline['gpio']['pin'], 22)
        self.assertEqual(baseline['parent']['exception_callback_slot'], 0x010F1FEC)
        self.assertEqual(baseline['installation']['profile'], 'direct-install-no-flag-v1')
        self.assertEqual(baseline['installation']['trigger_argument'], 0)
        self.assertIsNone(baseline['installation']['installed_flag'])
        self.assertIsNone(baseline['installation']['installed_value'])
        self.assertTrue(any(row['callsite'] == 0x561CBA and not row['callee_body_verified'] for row in baseline['aux_calls']))
        self.assertIn([0x1937C, 20], baseline['nor_dependencies'])
        self.assertIn([0x3D000C, 12], baseline['nor_dependencies'])
        self.assertNotIn([0x3D000C, 20], baseline['nor_dependencies'])
        image = bytearray(self.image)
        # Every new call rejects invalid encoding, every fixed byte checked separately above.
        for role, entry in [('parent_register', 0x484868), ('soc_dispatch', 0x484648), ('chip_isr', 0x561CB8), ('install_direct', 0x3D5C90)]:
            span = candidate._span(image, entry, role)
            for offset in span['calls']:
                original = image[entry+offset:entry+offset+4]
                image[entry+offset:entry+offset+4] = bytes(4)
                with self.assertRaises(candidate._Reject):
                    candidate._span(image, entry, role)
                image[entry+offset:entry+offset+4] = original
        # Mutations in graph/descriptor/read-consumer operands cannot become candidates.
        for address in (0x3ED220, 0x48482E, 0x4529A2, 0x8ED178, 0x8ED188, 0x8ED1C9, 0x3D5CB4, 0x3D5CBC):
            image[address] ^= 1
            result = detect(image)
            self.assertEqual(result['status'], 'rejected', (hex(address), result))
            image[address] ^= 1

if __name__ == '__main__':
    unittest.main()
