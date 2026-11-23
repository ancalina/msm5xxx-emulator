"""Exercise W18 partition isolation and its persistent command semantics."""
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


@unittest.skipUnless(os.environ.get('MSM5XXX_W18_QEMU'), 'native W18 QEMU not supplied')
class BootW18NativeTests(unittest.TestCase):
    def test_partitioned_query_lock_program_and_erase(self):
        with tempfile.TemporaryDirectory(prefix='w18-') as directory:
            root = Path(directory)
            flash = root / 'flash.raw'
            image = bytearray(b'\xff' * 0x800000)
            image[0:2] = b'\x34\x12'
            image[0x2000:0x2002] = b'\x00\x00'
            flash.write_bytes(image)
            qtest, qmp = root / 'qtest', root / 'qmp'
            with (root / 'qemu.log').open('w') as log:
                process = subprocess.Popen([
                    'taskset', '-c', '4', os.environ['MSM5XXX_W18_QEMU'],
                    '-M', 'msm5xxx-poc,standalone-boot-events=on,boot-w18=on,boot-legacy-clock=on,boot-legacy-map=on',
                    '-m', '32M', '-nographic', '-S', '-monitor', 'none', '-serial', 'none',
                    '-drive', f'file={flash},if=pflash,format=raw,unit=0',
                    '-qtest', f'unix:{qtest},server=on,wait=off',
                    '-qmp', f'unix:{qmp},server=on,wait=off',
                ], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                def connect(path):
                    for _ in range(200):
                        try:
                            sock = socket.socket(socket.AF_UNIX)
                            sock.connect(str(path))
                            sock.settimeout(15)
                            return sock
                        except OSError:
                            sock.close()
                            if process.poll() is not None:
                                self.fail('QEMU exited during W18 setup')
                            time.sleep(.05)
                    self.fail('QEMU W18 socket not created')
                q = connect(qtest)
                monitor = connect(qmp)
                mon = monitor.makefile('rwb', buffering=0)
                mon.readline()
                mon.write(b'{"execute":"qmp_capabilities"}\n')
                json.loads(mon.readline())
                channel = q.makefile('rwb', buffering=0)
                def command(text):
                    channel.write((text + '\n').encode())
                    response = channel.readline().decode().split()
                    self.assertEqual(response[0], 'OK', response)
                    return int(response[1], 0) if len(response) > 1 else None
                def write(address, value):
                    command(f'writew 0x{address:x} 0x{value:x}')
                def check(address, expected):
                    self.assertEqual(command(f'readw 0x{address:x}'), expected)
                try:
                    check(0, 0x1234)
                    write(0x600000, 0x98)
                    check(0x600020, ord('Q'))
                    check(0x600058, 2)
                    check(0x600062, 126)
                    check(0, 0x1234)
                    write(0x680000, 0x90)
                    check(0x680000, 0x89)
                    check(0x680002, 0x8865)
                    check(0x680004, 1)
                    check(0x600020, ord('Q'))
                    write(0x600000, 0xff)
                    write(0x600000, 0x40)
                    write(0x600000, 0x1234)
                    check(0x600000, 0x92)
                    write(0x600000, 0x50)
                    write(0x600000, 0x60)
                    write(0x600000, 0xd0)
                    write(0x600000, 0x40)
                    write(0x600000, 0x1234)
                    check(0x600000, 0x80)
                    write(0x600000, 0xff)
                    check(0x600000, 0x1234)
                    write(0x600000, 0x40)
                    write(0x600000, 0xffff)
                    check(0x600000, 0x90)
                    write(0x600000, 0x50)
                    write(0x600000, 0x20)
                    write(0x600000, 0xd0)
                    check(0x600000, 0x80)
                    write(0x600000, 0xff)
                    check(0x600000, 0xffff)
                    check(0, 0x1234)
                    write(0, 0x60)
                    write(0, 0xd0)
                    write(0, 0x20)
                    write(0, 0xd0)
                    write(0, 0xff)
                    check(0, 0xffff)
                    check(0x2000, 0)
                    write(0x600001b0, 0x20)
                    check(0x600001b0, 0x20)
                    write(0x482007b6, 0x55aa)
                    check(0x482007b6, 0x55aa)
                    command('writel 0x80000c98 0x200000')
                    tick = command('readl 0x88004008')
                    command(f'writel 0x880040c4 0x{(tick + 4) & 0xffffffff:x}')
                    self.assertEqual(command('readl 0x880040c0'), 1)
                    mon.write(b'{"execute":"cont"}\n')
                    while 'return' not in json.loads(mon.readline()):
                        pass
                    time.sleep(.05)
                    mon.write(b'{"execute":"stop"}\n')
                    while 'return' not in json.loads(mon.readline()):
                        pass
                    self.assertEqual(command('readl 0x80000c84') & 0x200000, 0x200000)
                    command('writel 0x80000c84 0x200000')
                    self.assertEqual(command('readl 0x80000c84') & 0x200000, 0)
                finally:
                    mon.write(b'{"execute":"quit"}\n')
                    process.wait(timeout=15)
                    channel.close()
                    mon.close()
                    q.close()
                    monitor.close()
