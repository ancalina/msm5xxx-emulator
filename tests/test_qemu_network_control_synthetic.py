"""Exercise virtual-service and sync properties without loading firmware."""
import os
from pathlib import Path
import subprocess
import unittest

from msm5xxx_emulator.qemu.network_control import NetworkMonitor
from msm5xxx_emulator.qemu.virtual_cell import host_sync_message_hex


@unittest.skipUnless(os.environ.get('MSM5XXX_TEST_QEMU'), 'native QEMU unavailable')
class SyntheticNetworkControlTests(unittest.TestCase):
    def test_sync_update_and_service_pulse(self):
        monitor = NetworkMonitor()
        process = subprocess.Popen([
            os.environ['MSM5XXX_TEST_QEMU'], '-M', 'msm5xxx-poc', '-cpu', 'ti925t',
            '-S', '-display', 'none', '-serial', 'none', '-monitor', 'none',
            *monitor.arguments(),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            monitor.connect()
            def get(name): return monitor._command('qom-get', {'path': '/machine', 'property': name})
            def put(name, value): return monitor._command('qom-set', {'path': '/machine', 'property': name, 'value': value})
            put('search2-virtual', '2:4:6:8:a:c:e:10:80:f4240:1fc28:fa00')
            source = '2:4:6:' + host_sync_message_hex(1037837100)
            put('decoder-sync-source', source)
            monitor.update(1700000000, refresh=False)
            self.assertNotEqual(get('decoder-sync-source'), source)
            put('virtual-service', 'off')
            self.assertEqual(get('virtual-service'), 'off')
            self.assertEqual(get('legacy-search').split(':')[1], '0')
            put('virtual-service', 'on')
            self.assertEqual(get('virtual-service'), 'on')
            self.assertEqual(get('legacy-search').split(':')[1], 'fa00')
            monitor._command('quit')
            process.wait(timeout=10)
        finally:
            monitor.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
