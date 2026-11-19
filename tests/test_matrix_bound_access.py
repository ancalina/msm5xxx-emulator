"""Synthetic guest word accesses outside source-owned keypad read sites."""
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest

from msm5xxx_emulator.qemu.gdb_remote import Remote


@unittest.skipUnless(os.environ.get("MSM5XXX_TEST_QEMU"), "native QEMU not selected")
class MatrixBackingAccessTests(unittest.TestCase):
    def test_foreign_arm_word_accesses_preserve_gpio_backing(self):
        cases = [
            ("", 0x0300066c),
            (",matrix-halfword-wires=1001000:300:302:3000660:20:3000668:1f", 0x0300066c),
            (",matrix-halfword-wires=1001000:300:302:3000660:20:3000668:1f"
             ",experimental-boot-contact=300066c:304:4:1", 0x0300066c),
            (",matrix-encoded-ports=1001000:300:302:304", 0x0300072c),
            (",matrix-encoded-ports=1001000:300:302:304", 0x03000728),
        ]
        for properties, address in cases:
            with self.subTest(properties=properties, address=hex(address)):
                self._execute(properties, address)

    def _execute(self, properties, address):
        image = bytearray(0x400)
        words = {0: 0xea00000e, 0x10: 0xea00007a, 0x200: 0xeafffffe,
                 0x40: 0xe59f0038, 0x44: 0xe59f1038,
                 0x48: 0xe5801000, 0x4c: 0xe5902000,
                 0x50: 0xe59f3030, 0x54: 0xe5832000, 0x58: 0xeafffffe,
                 0x80: address, 0x84: 0x44332211, 0x88: 0x01000000}
        for position, value in words.items():
            struct.pack_into("<I", image, position, value)
        with tempfile.TemporaryDirectory(prefix="matrix-backing-") as directory:
            root = Path(directory)
            program = root / "program.bin"
            program.write_bytes(image)
            gdb_path = root / "gdb.sock"
            arguments = [os.environ["MSM5XXX_TEST_QEMU"], "-M",
                "msm5xxx-poc,input-chardev=input,memory-profile=800000:1000000:1007ffc" + properties,
                "-cpu", "ti925t", "-m", "8M", "-S", "-display", "none",
                "-serial", "none", "-monitor", "none",
                "-chardev", "null,id=input",
                "-device", f"loader,file={program},addr=0,force-raw=on",
                "-gdb", f"unix:{gdb_path},server=on,wait=off"]
            process = subprocess.Popen(arguments, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE)
            connection = None
            try:
                deadline = time.monotonic() + 30
                while not gdb_path.exists():
                    if process.poll() is not None:
                        self.fail(process.stderr.read().decode(errors="replace"))
                    if time.monotonic() > deadline:
                        self.fail("QEMU debug socket did not appear")
                    time.sleep(0.02)
                connection = socket.socket(socket.AF_UNIX)
                connection.settimeout(30)
                connection.connect(str(gdb_path))
                remote = Remote(connection)
                remote.command("qSupported:qXfer:features:read+")
                registers = remote.register_map()
                remote.breakpoint(0x58, True)
                remote.breakpoint(0x200, True)
                remote.continue_execution()
                stopped = int.from_bytes(bytes.fromhex(remote.command(
                    f"p{registers['pc']:x}")), "little")
                self.assertEqual(stopped, 0x58, "foreign word access took data abort")
                self.assertEqual(remote.command("m1000000,4"), "11223344")
            finally:
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                if process.stderr is not None:
                    process.stderr.close()
