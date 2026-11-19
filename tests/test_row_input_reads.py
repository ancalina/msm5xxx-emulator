"""Unknown input permissions are exact, read-only halfword observations."""
import struct
import unittest

from capstone import arm as a
from msm5xxx_emulator.detection.devices.input.row_execution import _Bits, _row_outputs


class RowInputReadTests(unittest.TestCase):
    def prove(self, *, read=0x880a, pointer=0x0300072c,
              permissions=((0x22, 0x0300072c),), capture=True,
              pointer_clobber=False):
        image = bytearray(0x200)
        # LDR R1,[R6,#0x34]; LDRH R2,[R1]; CMP; BEQ; NOP;
        # LDRB R0,[R3,R4]. Both unknown-input paths retain the table address.
        words = (0x2100 if pointer_clobber else 0x6b71,
                 read, 0x2a00, 0xd000, 0x46c0, 0x5d18)
        struct.pack_into('<6H', image, 0x20, *words)
        struct.pack_into('<I', image, 0xb4, pointer)
        initial = {a.ARM_REG_R6: _Bits.constant(0x01002000),
                   a.ARM_REG_R3: _Bits.constant(0x100),
                   a.ARM_REG_R4: _Bits.constant(1)}
        return _row_outputs(bytes(image), 0x20, 0x2a, initial,
            0x01002000, 0x80, capture_load=capture,
            unknown_halfword_inputs=permissions)

    def test_unknown_halfword_preserves_all_reaching_table_addresses(self):
        result = self.prove()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 0x101)
        self.assertIn((0x22, 2), result[1])
        self.assertNotIn((0x0300072c, 2), result[1])

    def test_permission_cannot_cover_another_site_address_or_pointer(self):
        for options in ({'permissions': ((0x24, 0x0300072c),)},
                        {'pointer': 0x0300066c}, {'pointer_clobber': True},
                        {'permissions': ((0x22, 0x0300072d),)}):
            with self.subTest(options=options):
                self.assertIsNone(self.prove(**options))

    def test_byte_word_store_and_row_drive_proofs_gain_no_permission(self):
        for read in (0x780a, 0x680a, 0x800a):
            with self.subTest(read=read):
                self.assertIsNone(self.prove(read=read))
        self.assertIsNone(self.prove(capture=False))
        self.assertIsNone(self.prove(permissions=()))


if __name__ == '__main__':
    unittest.main()
