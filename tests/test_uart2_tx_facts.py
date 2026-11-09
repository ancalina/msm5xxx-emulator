"""Independent synthetic UART byte transmitter and ownership tests."""
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.uart2_tx import (
    DATA, PULSE, STATUS, find_uart2_tx_ready_pc, transmit_proofs, uart2_tx_property,
)


def transmitter(entry=0x80):
    image = bytearray(entry + 0x60)
    def word(at, value):
        struct.pack_into('<H', image, at, value)
    def call(at, target):
        delta = target - at - 4
        struct.pack_into('<2H', image, at,
                         0xF000 | ((delta >> 12) & 0x7FF),
                         0xF800 | ((delta >> 1) & 0x7FF))
    def literal(at, register, pool):
        word(at, 0x4800 | (register << 8) | ((pool - ((at + 4) & ~3)) // 4))
    # A distinct register allocation and flag producer from the old matcher:
    # extract bit zero into N and branch MI to the transmit path.
    literal(entry, 4, entry + 0x40)
    for offset, opcode in ((2, 0x7822), (4, 0x07D2), (6, 0xD403),
                           (8, 0x2301), (12, 0x702B),
                           (16, 0x2300), (20, 0x702B),
                           (24, 0x7030), (26, 0x4770)):
        word(entry + offset, opcode)
    literal(entry + 10, 5, entry + 0x44)
    literal(entry + 18, 5, entry + 0x44)
    literal(entry + 22, 6, entry + 0x48)
    word(entry + 14, 0xE000 | (((entry - (entry + 14) - 4) // 2) & 0x7FF))
    struct.pack_into('<3I', image, entry + 0x40, STATUS, PULSE, DATA)
    word(0, 0xB500)
    call(2, 0x40)
    call(6, entry)
    word(10, 0xBD00)
    word(0x40, 0x4770)
    return bytes(image)


class UARTTransmitFactsTests(unittest.TestCase):
    def test_relocated_register_and_flag_variants_have_same_device_parameters(self):
        for entry in (0x80, 0x180, 0x280):
            with self.subTest(entry=entry):
                image = transmitter(entry)
                self.assertEqual(find_uart2_tx_ready_pc(image), entry + 2)
                proof, = transmit_proofs(image)
                self.assertEqual((proof.entry.address, proof.write.address), (entry, entry + 24))

    def test_hardware_and_control_flow_mutations_do_not_borrow_readiness(self):
        for offset, value in ((0x82, 0x8822),  # halfword status
                              (0x84, 0x0792),  # tests a different bit
                              (0x86, 0xD503),  # ready bit selects retry
                              (0x88, 0x2300),  # no asserted wait pulse
                              (0x90, 0x2301),  # no pulse clear
                              (0x98, 0x8030),  # halfword data
                              (0x98, 0x7031)):  # wrong transmit argument
            with self.subTest(offset=offset, value=value):
                image = bytearray(transmitter())
                struct.pack_into('<H', image, offset, value)
                self.assertIsNone(find_uart2_tx_ready_pc(bytes(image)))

    def test_unreferenced_code_and_wrong_ports_are_not_device_evidence(self):
        image = bytearray(transmitter())
        image[6:10] = bytes(4)
        self.assertIsNone(find_uart2_tx_ready_pc(bytes(image)))
        for offset in (0xC0, 0xC4, 0xC8):
            image = bytearray(transmitter())
            value, = struct.unpack_from('<I', image, offset)
            struct.pack_into('<I', image, offset, value + 4)
            self.assertIsNone(find_uart2_tx_ready_pc(bytes(image)))

    def test_property_requires_independent_wait_and_loaded_source_binding(self):
        image = transmitter()
        ready = dict(signature='thumb-uart-csr-sr-rx-empty-v1',
                     status_address=0x030007B4, mask=8, pulse_address=PULSE, entries=[0x40])
        config = SimpleNamespace(image_kind='firmware', flash_size=len(image),
                                 load_address=0, image_offset=0, entry=0,
                                 uart_console=None, ready_poll=ready)
        # Isolate the compatibility projection; transmitter proof remains real.
        with patch('msm5xxx_emulator.detection.devices.ready_poll.find_ready_poll_profile', return_value=ready):
            self.assertEqual(uart2_tx_property(image, image, config), 'uart2-tx-ready=82')
            self.assertIsNone(uart2_tx_property(image, image, config, claimed=True))
            changed = bytearray(image)
            struct.pack_into('<I', changed, 0xC0, STATUS + 4)
            self.assertIsNone(uart2_tx_property(image, bytes(changed), config))
            config.ready_poll = {**ready, 'entries': [0x42]}
            self.assertIsNone(uart2_tx_property(image, image, config))

    def test_transmit_on_only_one_caller_branch_does_not_close_driver_link(self):
        image = bytearray(transmitter())
        # After the wait, either return directly or send a byte. The transmit
        # call no longer lies on every normal continuation of this owner.
        struct.pack_into('<2H', image, 6, 0x2B00, 0xD103)
        delta = 0x80 - 10 - 4
        struct.pack_into('<2H', image, 10,
                         0xF000 | ((delta >> 12) & 0x7FF),
                         0xF800 | ((delta >> 1) & 0x7FF))
        struct.pack_into('<H', image, 14, 0xBD00)
        struct.pack_into('<H', image, 18, 0xBD00)
        image = bytes(image)
        ready = dict(signature='thumb-uart-csr-sr-rx-empty-v1',
                     status_address=0x030007B4, mask=8, pulse_address=PULSE, entries=[0x40])
        config = SimpleNamespace(image_kind='firmware', flash_size=len(image),
                                 load_address=0, image_offset=0, entry=0,
                                 uart_console=None, ready_poll=ready)
        self.assertEqual(find_uart2_tx_ready_pc(image), 0x82)
        with patch('msm5xxx_emulator.detection.devices.ready_poll.find_ready_poll_profile', return_value=ready):
            self.assertIsNone(uart2_tx_property(image, image, config))


if __name__ == '__main__':
    unittest.main()
