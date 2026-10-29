"""Explicit software cell scenario; no firmware or guest execution."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import msm5xxx_emulator

from msm5xxx_emulator.qemu.virtual_cell import virtual_cell_scenario


class VirtualCellModesTests(unittest.TestCase):
    def test_default_off_and_strict_boolean(self):
        self.assertIsNone(virtual_cell_scenario())
        self.assertIsNone(virtual_cell_scenario(False))
        for value in (0, 1, None, 'virtual', {}):
            with self.subTest(value=value), self.assertRaises(TypeError):
                virtual_cell_scenario(value)

    def test_explicit_scenario_contract_and_fresh_message_list(self):
        first, second = virtual_cell_scenario(True), virtual_cell_scenario(True)
        self.assertEqual(set(first), {
            'pilot_phase', 'raw_energy', 'virtual_delay_ns', 'decoder_init_delay_ns',
            'sync_message_hex', 'paging_messages_hex', 'sid', 'nid', 'channel',
            'tx_init_delay_ns', 'tx_frame_period_ns', 'access_response_probe',
            'access_assignment_code', 'traffic_decoder_probe', 'traffic_frame_hex', 'allow_receive_only'})
        self.assertIsNot(first, second)
        self.assertIsNot(first['paging_messages_hex'], second['paging_messages_hex'])
        for name in ('pilot_phase', 'raw_energy', 'virtual_delay_ns', 'decoder_init_delay_ns',
                     'sid', 'nid', 'channel', 'tx_init_delay_ns', 'tx_frame_period_ns',
                     'access_assignment_code'):
            self.assertIs(type(first[name]), int)
        for name in ('access_response_probe', 'traffic_decoder_probe', 'allow_receive_only'):
            self.assertIs(first[name], True)
        self.assertEqual(first['traffic_frame_hex'], 'auto')
        self.assertIs(type(first['sync_message_hex']), str)
        self.assertIs(type(first['paging_messages_hex']), list)
        self.assertTrue(all(type(x) is str for x in first['paging_messages_hex']))
        self.assertEqual(len(bytes.fromhex(first['sync_message_hex'])), 26)
        messages = [bytes.fromhex(x) for x in first['paging_messages_hex']]
        self.assertEqual([len(x) for x in messages], [33, 19, 9, 9])
        self.assertEqual([x[0] for x in messages], [33, 19, 9, 9])
        self.assertEqual([x[1] for x in messages], [1, 2, 3, 4])
        first['paging_messages_hex'][0] = 'changed'
        first['paging_messages_hex'].append('changed')
        first['sid'] = -1
        self.assertEqual(virtual_cell_scenario(True), second)

    def test_receive_only_opt_in_does_not_hide_invalid_requests(self):
        source = Path(msm5xxx_emulator.__file__).resolve().parents[2]
        from msm5xxx_emulator.qemu.transport import qemu_virtual_cell_property
        config = SimpleNamespace(load_address=1, image_offset=0)
        for value in (0, 1, None, 'true', {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                qemu_virtual_cell_property(b'', config,
                    dict(virtual_cell_scenario(True), allow_receive_only=value))
        for change in ({'tx_frame_period_ns': False}, {'traffic_frame_hex': 'auto '},
                       {'access_assignment_code': 129}, {'sync_message_hex': '00'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                qemu_virtual_cell_property(b'', config,
                    dict(virtual_cell_scenario(True), **change))

    def test_existing_validator_checks_payload_before_unsupported_map(self):
        source = Path(msm5xxx_emulator.__file__).resolve().parents[2]
        from msm5xxx_emulator.qemu.transport import qemu_virtual_cell_property
        self.assertEqual(qemu_virtual_cell_property(
            b'', SimpleNamespace(load_address=1, image_offset=0), virtual_cell_scenario(True)),
            (None, 'primary-map-unsupported'))


if __name__ == '__main__':
    unittest.main()
