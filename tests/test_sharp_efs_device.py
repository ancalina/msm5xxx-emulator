"""Optional real-TCG PCR regression (MSM5XXX_TEST_QEMU selects the binary).

Run it through a resource-limited wrapper on shared machines. The injected
instructions are synthetic STRH/LDRH, and no firmware fixture is needed.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest

from msm5xxx_emulator.qemu.gdb_remote import Remote


@unittest.skipUnless(os.environ.get("MSM5XXX_TEST_QEMU"), "native QEMU not selected")
class SharpPCRDeviceTests(unittest.TestCase):
    def test_pcr_command_contract_and_legacy_default(self):
        native = Path(os.environ["MSM5XXX_TEST_QEMU"]).resolve()
        with tempfile.TemporaryDirectory(prefix="sharp-pcr-device-") as directory:
            root = Path(directory)
            backing = root / "flash.raw"
            backing.write_bytes(b"\xff" * 0x200000)

            def session(action, sharp=True):
                machine = (
                    "memory-profile=800000:1000000:1007ffc,"
                    "sharp-primary-nv=600000:200000:10000:b0:b1,sharp-nv-status-mirror=on"
                    if sharp
                    else "memory-profile=600000:1000000:1007ffc,"
                    "intel-adjacent-nv16=600000:200000:10000:b0:b1"
                )
                with socket.socket() as listener, (root / "qemu.log").open("ab") as log:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    listener.settimeout(15)
                    process = subprocess.Popen(
                        [
                            str(native),
                            "-machine",
                            "msm5xxx-poc," + machine,
                            "-cpu",
                            "ti925t",
                            "-m",
                            "8M",
                            "-display",
                            "none",
                            "-serial",
                            "none",
                            "-monitor",
                            "none",
                            "-drive",
                            f"file={backing},if=pflash,format=raw,unit=0",
                            "-S",
                            "-chardev",
                            "socket,id=gdb,host=127.0.0.1,port="
                            f"{listener.getsockname()[1]},server=off",
                            "-gdb",
                            "chardev:gdb",
                        ],
                        stdout=log,
                        stderr=log,
                    )
                    connection = None
                    try:
                        connection, _ = listener.accept()
                        connection.settimeout(15)
                        remote = Remote(connection)
                        remote.command("qSupported:qXfer:features:read+")
                        registers = remote.register_map()
                        code = 0x01000000
                        remote.write_memory(code, struct.pack("<2H", 0x8001, 0x8802))
                        remote.write_register(registers["cpsr"], 0xF3)

                        def write(address, value):
                            remote.write_register(registers["r0"], address)
                            remote.write_register(registers["r1"], value)
                            remote.write_register(registers["pc"], code)
                            remote.step()

                        def read(address):
                            remote.write_register(registers["r0"], address)
                            remote.write_register(registers["pc"], code + 2)
                            remote.step()
                            return int.from_bytes(
                                bytes.fromhex(remote.command(f'p{registers["r2"]:x}')),
                                "little",
                            )

                        action(write, read)
                    finally:
                        if connection is not None:
                            connection.close()
                        process.terminate()
                        process.wait(timeout=30)

            def enabled(write, read):
                write(0x600000, 0x90)
                self.assertEqual(read(0x60000C), 0x100)  # Bottom partition reset.
                write(0x600000, 0xFF)
                write(0x600800, 0x60)
                write(0x600802, 0x04)  # Different address must not configure.
                write(0x600000, 0x90)
                self.assertEqual(read(0x60000C), 0x100)
                write(0x600000, 0xFF)
                for address, expected in ((0x600800, 0x400), (0x600200, 0x100)):
                    write(address, 0x60)
                    write(address, 0x04)
                    write(0x600000, 0x90)
                    self.assertEqual(read(0x60000C), expected)
                    self.assertEqual(read(0x600000), 0xB0)
                    self.assertEqual(read(0x600002), 0xB1)
                    write(0x600000, 0xFF)
                    self.assertEqual(read(0x60000C), 0xFFFF)
                # A locked program reports the same protection error on both lanes.
                write(0x600100, 0x40)
                write(0x600100, 0x1234)
                self.assertEqual(read(0x600100) & 0x9292, 0x9292)
                write(0x600100, 0x50)
                write(0x600100, 0xFF)
                write(0x600100, 0x60)
                write(0x600100, 0xD0)
                write(0x600100, 0x40)
                write(0x600100, 0x1234)
                self.assertEqual(read(0x600100) & 0x8080, 0x8080)
                write(0x600100, 0xFF)
                self.assertEqual(read(0x600100), 0x1234)
                write(0x600000, 0x90)
                self.assertEqual(read(0x60000C), 0x100)
                write(0x600000, 0xFF)

            session(enabled)
            self.assertEqual(backing.read_bytes()[0x100:0x102], b"\x34\x12")

            def reload_and_erase(write, read):
                self.assertEqual(read(0x600100), 0x1234)
                write(0x600000, 0x60)
                write(0x600000, 0xD0)
                write(0x600000, 0x20)
                write(0x600000, 0xD0)
                write(0x600000, 0xFF)
                self.assertEqual(read(0x600100), 0xFFFF)

            session(reload_and_erase)

            def legacy(write, read):
                write(0x600800, 0x60)
                write(0x600800, 0x04)
                write(0x600000, 0x90)
                self.assertEqual(read(0x60000C), 0)
                write(0x600000, 0xFF)

            session(legacy, sharp=False)
