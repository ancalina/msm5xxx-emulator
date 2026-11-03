"""Explicit software cell scenario; no firmware or guest execution."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import msm5xxx_emulator

from msm5xxx_emulator.qemu.virtual_cell import (
    _leap_seconds, _long_code_state, host_sync_message_hex, sync_message_hex, virtual_cell_scenario)


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


class SyncMessageTimeTests(unittest.TestCase):
    @staticmethod
    def fields(message):
        bits = bin(int(message, 16))[2:].zfill(len(message) * 4)
        def take(first, width):
            return int(bits[first:first + width], 2)
        return {"lc": take(72, 42), "sys_time": take(114, 36), "lp_sec": take(150, 8),
                "ltm_off": take(158, 6), "daylt": take(164, 1), "sid": take(32, 15),
                "channel": take(167, 11)}

    def test_epoch_reproduces_original_template(self):
        self.assertEqual(sync_message_hex(0), "1a010303115dfffe00000000000040000000000000076374e349")

    def test_long_code_jump_matches_register_stepping(self):
        state = 1
        for steps in range(200):
            self.assertEqual(_long_code_state(steps), state)
            state <<= 1
            if state >> 42:
                state ^= 0x40A8E6F04EF

    def test_host_time_fields_and_crc(self):
        from msm5xxx_emulator.qemu.transport import qemu_virtual_cell_property
        now = 1793600000.0  # 2026-11-02 12:53:20 UTC
        message = host_sync_message_hex(now)
        values = self.fields(message)
        gps = now - 315964800 + 18
        self.assertEqual(values["sys_time"], int(gps / 0.08))
        self.assertEqual(values["lp_sec"], 18)
        self.assertEqual(values["lc"], _long_code_state(values["sys_time"] * 98304))
        self.assertEqual((values["sid"], values["channel"]), (2222, 29))
        # The transport accepts only packets with a valid CRC30 residue.
        config = SimpleNamespace(load_address=1, image_offset=0)
        self.assertEqual(qemu_virtual_cell_property(
            b"", config, virtual_cell_scenario(True, host_time=True, now=now)), (None, "primary-map-unsupported"))

    def test_local_offset_is_signed_half_hours(self):
        values = self.fields(sync_message_hex(1, 18, -16, 1))
        self.assertEqual((values["ltm_off"], values["daylt"]), (0x30, 1))
        with self.assertRaises(ValueError):
            sync_message_hex(1, ltm_off=32)

    def test_default_time_is_fixed_and_deterministic(self):
        values = self.fields(virtual_cell_scenario(True)["sync_message_hex"])
        utc = 1217462400  # 2008-07-31 00:00 UTC = 09:00 at +9 h
        self.assertEqual(values["sys_time"], int((utc - 315964800 + 14) / 0.08))
        self.assertEqual((values["lp_sec"], values["ltm_off"], values["daylt"]), (14, 18, 0))

    def test_leap_seconds_follow_announced_date(self):
        self.assertEqual(_leap_seconds(1217462400), 14)   # 2008
        self.assertEqual(_leap_seconds(1230768000), 15)   # 2009-01-01
        self.assertEqual(_leap_seconds(1793600000), 18)   # 2026
