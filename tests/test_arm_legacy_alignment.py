"""Optional CPU checks with independently constructed ARM and Thumb programs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest

from msm5xxx_emulator.qemu.gdb_remote import Remote


@unittest.skipUnless(os.environ.get('MSM5XXX_TEST_QEMU'), 'native QEMU not selected')
class LegacyAlignmentTests(unittest.TestCase):
    def _execute(self, thumb=False, alignment=False, big_endian=False, cpu='ti925t'):
        image = bytearray(0x400)
        def word(at, value):
            struct.pack_into('<I', image, at, value)
        word(0, 0xEA00000E)  # branch to the control-register setup
        word(0x10, 0xEA00007A)  # data abort branches to 0x200
        word(0x200, 0xEAFFFFFE)
        setup = [0xEE113F10, 0xE3C33082]  # MRC; clear A and B
        if alignment:
            setup.append(0xE3833002)
        if big_endian:
            setup.append(0xE3833080)
        setup += [0xEE013F10]
        pc = 0x40
        for value in setup:
            word(pc, value)
            pc += 4
        if thumb:
            word(pc, 0xE59F0000 | (0x80 - pc - 8))
            word(pc + 4, 0xE12FFF10)
            word(0x80, 0x101)
        else:
            word(pc, 0xEA000000 | ((0x100 - pc - 8) // 4))
        pc, pool = 0x100, 0x300
        def emit(value):
            nonlocal pc
            struct.pack_into('<H' if thumb else '<I', image, pc, value)
            pc += 2 if thumb else 4
        def literal(reg, value):
            nonlocal pool
            if thumb:
                emit(0x4800 | reg << 8 | ((pool - ((pc + 4) & ~3)) // 4))
            else:
                emit(0xE59F0000 | reg << 12 | (pool - pc - 8))
            word(pool, value)
            pool += 4
        for offset in range(4):
            literal(0, 0x01000000 + offset)
            emit(0x6801 if thumb else 0xE5901000)
            literal(2, 0x01000100 + offset * 4)
            emit(0x6011 if thumb else 0xE5821000)
        for offset in range(4):
            literal(0, 0x01000200 + offset * 16 + offset)
            literal(1, 0xA1B2C3D4)
            emit(0x6001 if thumb else 0xE5801000)
        done = pc
        emit(0xE7FE if thumb else 0xEAFFFFFE)
        if thumb and big_endian:
            for at in range(0x100, (pc + 3) & ~3, 4):
                image[at:at+4] = image[at+2:at+4] + image[at:at+2]
        with tempfile.TemporaryDirectory(prefix='arm-alignment-') as directory:
            root = Path(directory)
            program = root / 'program.bin'
            program.write_bytes(image)
            data = root / 'data.bin'
            data.write_bytes(struct.pack('<II', 0x44332211, 0x88776655) + bytes(0x3F8))
            gdb_path, qmp_path = root / 'gdb.sock', root / 'qmp.sock'
            args = [os.environ['MSM5XXX_TEST_QEMU'], '-M', 'msm5xxx-poc',
                    '-cpu', cpu, '-m', '32M', '-S', '-display', 'none',
                    '-serial', 'none', '-monitor', 'none',
                    '-device', f'loader,file={program},addr=0,force-raw=on',
                    '-device', f'loader,file={data},addr=0x01000000,force-raw=on',
                    '-gdb', f'unix:{gdb_path},server=on,wait=off',
                    '-qmp', f'unix:{qmp_path},server=on,wait=off']
            process = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE)
            gdb = qmp = None
            try:
                deadline = time.monotonic() + 30
                while not gdb_path.exists() or not qmp_path.exists():
                    if process.poll() is not None:
                        self.fail(process.stderr.read().decode(errors='replace'))
                    if time.monotonic() > deadline:
                        self.fail('QEMU control sockets did not appear')
                    time.sleep(0.02)
                qmp = socket.socket(socket.AF_UNIX)
                qmp.connect(str(qmp_path))
                reader = qmp.makefile('r')
                json.loads(reader.readline())
                qmp.sendall(b'{"execute":"qmp_capabilities"}\n')
                while 'return' not in json.loads(reader.readline()):
                    pass
                gdb = socket.socket(socket.AF_UNIX)
                gdb.settimeout(30)
                gdb.connect(str(gdb_path))
                remote = Remote(gdb)
                remote.command('qSupported:qXfer:features:read+')
                registers = remote.register_map()
                remote.breakpoint(done, True)
                remote.breakpoint(0x200, True)
                remote.continue_execution()
                stopped = int.from_bytes(bytes.fromhex(remote.command(
                    f'p{registers["pc"]:x}')), 'little')
                loaded = bytes.fromhex(remote.command('m1000100,10'))
                stored = bytes.fromhex(remote.command('m1000200,40'))
                return stopped, done, loaded, stored
            finally:
                try:
                    if gdb is not None:
                        try:
                            remote.command('D')
                        except (OSError, RuntimeError):
                            pass
                    if qmp is not None:
                        qmp.settimeout(30)
                        qmp.sendall(b'{"execute":"quit"}\n')
                        while True:
                            line = reader.readline()
                            if not line or 'return' in json.loads(line):
                                break
                finally:
                    if gdb is not None:
                        gdb.close()
                    if qmp is not None:
                        reader.close()
                        qmp.close()
                    if process.poll() is None:
                        try:
                            process.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            process.wait(timeout=180)
                process.stderr.close()

    def test_word_load_rotation_and_store_alignment(self):
        for cpu in ('ti925t', 'arm926'):
            for thumb in (False, True):
                for big_endian in (False, True):
                    with self.subTest(cpu=cpu, thumb=thumb, big_endian=big_endian):
                        pc, done, loads, stores = self._execute(
                            thumb=thumb, big_endian=big_endian, cpu=cpu)
                        self.assertEqual(pc, done)
                        self.assertEqual(struct.unpack('<4I', loads),
                                         (0x44332211, 0x11443322,
                                          0x22114433, 0x33221144))
                        for offset in range(4):
                            self.assertEqual(stores[offset*16:offset*16+8],
                                             bytes.fromhex('d4c3b2a100000000'))

    def test_explicit_alignment_check_still_aborts(self):
        for cpu in ('ti925t', 'arm926'):
            for thumb in (False, True):
                with self.subTest(cpu=cpu, thumb=thumb):
                    pc, _done, _loads, stores = self._execute(
                        thumb=thumb, alignment=True, cpu=cpu)
                    self.assertEqual(pc, 0x200)
                    self.assertEqual(stores, bytes(64))
