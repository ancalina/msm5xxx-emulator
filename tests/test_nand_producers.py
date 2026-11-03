"""Synthetic instruction and aperture evidence for middle NAND producers."""
import struct
import unittest
from msm5xxx_emulator.detection.low_port_nand import find_middle_nand_producers


class NandProducerTests(unittest.TestCase):
    def test_requires_two_resets_three_operations_and_ports(self):
        image = bytearray(256)
        reset = bytes.fromhex('ff200d21490508707047')
        image[0:10] = image[20:30] = reset
        for at, code in ((40, '0d204005'), (50, '19210905'), (60, '0320c005')):
            image[at:at + 4] = bytes.fromhex(code)
        for at, port in ((80, 0x01800000), (84, 0x01900000), (88, 0x01a00000)):
            struct.pack_into('<I', image, at, port)
        self.assertTrue(find_middle_nand_producers(bytes(image)))
        self.assertFalse(find_middle_nand_producers(b"\0" + bytes(image)))
        for at in (0, 20, 40, 50, 60, 80, 84, 88):
            changed = bytearray(image); changed[at] ^= 1
            self.assertFalse(find_middle_nand_producers(bytes(changed)))

    def test_single_reset_ready_and_ambiguous_code(self):
        import hashlib
        from unittest.mock import patch
        image = bytearray(256)
        image[:10] = bytes.fromhex('ff200d21490508707047')
        image[10:22] = bytes.fromhex('0348406801888909fcd37047')
        image[40:44] = bytes.fromhex('0d204005')
        image[50:54] = bytes.fromhex('0320c005')
        for at, port in ((80, 0x01800000), (84, 0x01900000), (88, 0x01a00000)):
            struct.pack_into('<I', image, at, port)
        self.assertTrue(find_middle_nand_producers(bytes(image)))
        image[10:22] = bytes.fromhex('0348406a0188090bfcd37047')
        self.assertFalse(find_middle_nand_producers(bytes(image)))
        digest = hashlib.sha256(image[:64]).hexdigest()
        with patch('msm5xxx_emulator.detection.low_port_nand._KNOWN_DRIVER_BODY', digest):
            self.assertTrue(find_middle_nand_producers(bytes(image)))
            image[30] ^= 1
            self.assertFalse(find_middle_nand_producers(bytes(image)))
