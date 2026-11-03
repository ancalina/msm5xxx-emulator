"""Exercise CDMA time continuity and the decoded FIFO across message boundaries."""
import ctypes
from pathlib import Path
import subprocess
import tempfile
import unittest


class SyncClockNativeTests(unittest.TestCase):
    def test_stream(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        def crc(bits):
            value = (1 << 30) - 1
            for bit in bits:
                feedback = (value >> 29 ^ bit) & 1
                value = ((value << 1) ^ (0x6030b9c7 if feedback else 0)) & 0x3fffffff
            return value ^ 0x3fffffff
        def put(bits, start, width, value):
            bits[start:start + width] = [(value >> (width - 1 - n)) & 1 for n in range(width)]
        def step(s):
            return ((s << 1) ^ (0x40a8e6f04ef if s & (1 << 41) else 0)) & ((1 << 42)-1)
        def logical(packet, part):
            payload = packet[part*93:(part+1)*93]
            payload += [0] * (93-len(payload))
            bits = []
            for j in range(3): bits += [int(part == 0 and j == 0)] + payload[j*31:j*31+31]
            return bytes(sum(bits[i+j] << (7-j) for j in range(8)) for i in range(0,96,8))
        with tempfile.TemporaryDirectory() as directory:
            lib = Path(directory)/'core.so'
            subprocess.run(['cc','-std=c11','-shared','-fPIC','-I',str(native),
                            str(native/'msm5xxx-search2.c'),'-o',str(lib)],check=True)
            fn = ctypes.CDLL(str(lib)).msm5xxx_sync_clock_frame
            fn.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint,
                           ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint16)]
            fn.restype = ctypes.c_bool
            template = (ctypes.c_uint8*26)(26,1)
            frames=[]; state=1
            for j in range(5):
                bits = [0]*208; put(bits,0,8,26); put(bits,8,8,1)
                put(bits,72,42,state); put(bits,114,36,j*3); put(bits,178,30,crc(bits[:178]))
                for part in range(3): frames.append(logical(bits,part))
                for _ in range(3*98304): state=step(state)
            for frame, current in enumerate(frames):
                out = (ctypes.c_uint16*8)()
                self.assertTrue(fn(template,26,frame,0,out))
                previous = frames[frame-1] if frame else bytes(12)
                expected = previous[3:] + current[:3]
                actual = bytes(v for word in out[:6] for v in (word&255,word>>8))
                self.assertEqual(actual,expected,frame)
                self.assertEqual(list(out[6:]),[0,0])
            self.assertFalse(fn(template,25,0,0,(ctypes.c_uint16*8)()))
            self.assertFalse(fn(template,26,0,1<<36,(ctypes.c_uint16*8)()))
