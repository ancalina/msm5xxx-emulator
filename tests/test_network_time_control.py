import json
import threading
import unittest
from unittest.mock import Mock, patch

from msm5xxx_emulator.qemu.network_control import NetworkMonitor, replace_sync_time
from msm5xxx_emulator.qemu.virtual_cell import host_sync_message_hex, _crc30


class NetworkTimeControlTests(unittest.TestCase):
    def test_replace_clock_preserves_network_fields_and_crc(self):
        before = int(host_sync_message_hex(1037837100), 16)
        after = int(replace_sync_time(f'{before:052x}', 1700000000), 16)
        mask = (1 << 30) - 1
        for start, width in ((72, 42), (114, 36), (150, 8), (158, 6), (164, 1)):
            mask |= ((1 << width) - 1) << (208 - start - width)
        self.assertEqual(before & ~mask, after & ~mask)
        self.assertNotEqual(before & mask, after & mask)
        self.assertEqual(after & ((1 << 30) - 1), _crc30(after >> 30, 178))

    def test_update_sets_sync_and_restores_service(self):
        monitor = object.__new__(NetworkMonitor)
        monitor.lock = threading.Lock()
        source = '10:20:30:' + host_sync_message_hex(1037837100)
        monitor._command = Mock(side_effect=[source, {}, {}, {}])
        with patch('msm5xxx_emulator.qemu.network_control.time.sleep'):
            monitor.update(1700000000, refresh=True)
        calls = monitor._command.call_args_list
        self.assertEqual([c.args[0] for c in calls], ['qom-get', 'qom-set', 'qom-set', 'qom-set'])
        self.assertTrue(calls[1].args[1]['value'].startswith('10:20:30:'))
        self.assertEqual([c.args[1]['value'] for c in calls[2:]], ['off', 'on'])

    def test_service_restored_when_wait_fails(self):
        monitor = object.__new__(NetworkMonitor)
        monitor.lock = threading.Lock()
        monitor._command = Mock(side_effect=['10:20:30:' + host_sync_message_hex(), {}, {}, {}])
        with patch('msm5xxx_emulator.qemu.network_control.time.sleep', side_effect=RuntimeError('interrupted')):
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                monitor.update(refresh=True)
        self.assertEqual(monitor._command.call_args.args[1]['value'], 'on')
