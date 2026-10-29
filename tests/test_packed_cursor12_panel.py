import unittest
from msm5xxx_emulator.devices.display.packed_cursor12_panel import (
    PackedCursor12Panel, find_packed_cursor12_port, _PRODUCER, _HEADER, _THUMB_PRODUCER, _THUMB_DELAYS)


class PackedCursor12Tests(unittest.TestCase):
    port = 0x02000000

    def row(self, panel, y, payload=None):
        for command, value in ((3, 0), (5, y)):
            panel.write(self.port, 2, command)
            panel.write(self.port + 2, 2, value)
        panel.write(self.port, 2, 11)
        for value in ([255] * 192 if payload is None else payload):
            panel.write(self.port + 2, 2, value)

    def raster(self, panel, value=255):
        for y in range(160):
            self.row(panel, y, [value] * 192)
        panel.write(self.port, 2, 3)

    def test_complete_and_update(self):
        p = PackedCursor12Panel(self.port)
        self.raster(p)
        self.assertTrue(p.qualified)
        self.assertEqual(p.frame, bytes([255]) * (128 * 160 * 3))
        # The closing command already started the next row header.
        p.write(self.port + 2, 2, 0)
        p.write(self.port, 2, 5)
        p.write(self.port + 2, 2, 7)
        p.write(self.port, 2, 11)
        for v in [0x12, 0x34, 0x56] * 64:
            p.write(self.port + 2, 2, v)
        before = p.frame
        p.write(self.port, 2, 3)
        self.assertEqual(p.frame[7*384:8*384], bytes([17,34,51,68,85,102]) * 64)
        self.assertEqual(p.frame[:7*384], before[:7*384])
        self.assertEqual(p.frame[8*384:], before[8*384:])
        self.assertEqual(p.sequence, 2)
        self.assertIsNone(p.snapshot()['enabled'])

    def test_black_valid(self):
        p = PackedCursor12Panel(self.port)
        self.raster(p, 0)
        self.assertTrue(p.qualified)
        self.assertEqual(p.frame, bytes(128*160*3))

    def test_incomplete_and_malformed(self):
        for payload in ([1]*191, [1]*193, [1]*191+[256]):
            p = PackedCursor12Panel(self.port)
            self.row(p, 0, payload)
            p.write(self.port, 2, 3)
            self.assertFalse(p.qualified)
            self.assertEqual(p.sequence, 0)
        p = PackedCursor12Panel(self.port)
        self.row(p, 1)
        p.write(self.port, 2, 3)
        self.assertEqual(p.rejection, 'unordered-initial-raster')
        for address, size, value in ((self.port+2,1,0), (self.port+2,2,256),
                                     (self.port+2,2,True), (0x02800002,2,0)):
            p = PackedCursor12Panel(self.port)
            p.write(self.port,2,3)
            p.write(address,size,value)
            self.assertFalse(p.qualified)
            self.assertIsNotNone(p.rejection)
        for x, y in ((1,0),(0,160)):
            p = PackedCursor12Panel(self.port)
            for a,v in ((self.port,3),(self.port+2,x),(self.port,5),(self.port+2,y)):
                p.write(a,2,v)
            self.assertIsNotNone(p.rejection)

    def test_reset_and_foreign_revoke_preserve_frame(self):
        for event in ((self.port,2,0),(self.port+2,1,0)):
            p = PackedCursor12Panel(self.port)
            self.raster(p)
            frame = p.frame
            p.write(*event)
            self.assertFalse(p.qualified)
            self.assertEqual(p.frame,frame)
            self.raster(p,0)
            self.assertTrue(p.qualified)
            self.assertEqual(p.frame,bytes(128*160*3))

    def test_flush_foreign_and_control(self):
        p = PackedCursor12Panel(self.port)
        for y in range(160):
            self.row(p,y)
        p.flush()
        self.assertTrue(p.qualified)
        sequence = p.sequence
        p.flush()
        self.assertEqual(p.sequence,sequence)
        p.write(0x02800002,2,0)
        self.assertTrue(p.qualified)
        p.write(self.port,2,0x2b)
        p.write(self.port+2,2,1)
        self.assertTrue(p.qualified)
        p.write(self.port,2,3)
        p.write(0x02800002,2,0)
        self.assertTrue(p.qualified)
        # A flush cannot make a subsequent excess sample valid.
        p.write(self.port+2,2,1)
        self.assertFalse(p.qualified)
        extra = PackedCursor12Panel(self.port)
        for y in range(160):
            self.row(extra,y)
        extra.flush()
        self.assertTrue(extra.qualified)
        frame = extra.frame
        extra.write(self.port+2,2,1)
        self.assertFalse(extra.qualified)
        self.assertEqual(extra.frame,frame)
        q = PackedCursor12Panel(self.port)
        self.row(q,0,[1]*191)
        q.flush()
        self.assertFalse(q.qualified)
        self.assertEqual(q.sequence,0)

    def test_verified_reinit_stages_whole_replacement(self):
        for pairs in (PackedCursor12Panel._SETUP,
                      PackedCursor12Panel._PREFIX + PackedCursor12Panel._SETUP[:9] + PackedCursor12Panel._SETUP):
            p = PackedCursor12Panel(self.port)
            for y in range(160):
                self.row(p,y)
            p.flush()
            original = p.frame
            for command, value in pairs:
                for address, word in ((self.port,command),(self.port+2,value)):
                    p.write(address,2,word)
                    p.flush()
                    self.assertTrue(p.qualified)
                    self.assertEqual(p.frame,original)
                    self.assertEqual(p.observation,'provisional-last-complete-image')
                    p.write(0x02800002,2,0)
                    self.assertTrue(p.qualified)
            for y in range(160):
                self.row(p,y,[0]*192)
                p.flush()
                self.assertTrue(p.qualified)
                if y < 159:
                    self.assertEqual(p.frame,original)
                    self.assertEqual(p.sequence,1)
            self.assertEqual(p.frame,bytes(128*160*3))
            self.assertEqual(p.sequence,2)
            self.assertEqual(p.observation,'complete-raster')

    def test_setup_near_miss_revokes_immediately(self):
        events = [(a, v) for c, value in PackedCursor12Panel._SETUP
                  for a,v in ((self.port,c),(self.port+2,value))]
        for bad_index in range(len(events)):
            p = PackedCursor12Panel(self.port)
            for y in range(160):
                self.row(p,y)
            p.flush()
            original = p.frame
            for index, (address, value) in enumerate(events):
                p.write(address,2,value ^ 0x80 if index == bad_index else value)
                if index == bad_index:
                    self.assertFalse(p.qualified)
                    self.assertIsNotNone(p.rejection)
                    self.assertEqual(p.frame,original)
                    break
        p = PackedCursor12Panel(self.port)
        for y in range(160):
            self.row(p,y)
        p.flush()
        p.write(self.port,2,0)
        self.assertFalse(p.qualified)

    def test_thumb_relocation_and_boundaries(self):
        def image_at(at, target):
            image = bytearray(at + len(_THUMB_PRODUCER))
            image[at:] = _THUMB_PRODUCER
            for offset in _THUMB_DELAYS:
                displacement = (target - (at + offset + 4)) & ((1 << 23) - 1)
                first = 0xF000 | (displacement >> 12)
                second = 0xF800 | (displacement >> 1 & 0x7FF)
                image[at+offset:at+offset+4] = first.to_bytes(2,'little') + second.to_bytes(2,'little')
            return image
        for at,target in ((0,0x800),(0x202,0x100),(0x1000,0x4000)):
            image = image_at(at,target)
            self.assertEqual(find_packed_cursor12_port(bytes(image))[0],self.port)
            # Register, transport, headers, pack operations, both bounds/backedges.
            for offset in (2,4,6,8,0x36,0x40,0x48,0x50,0x56,0x5e,
                           0x74,0x78,0x8c,0xac,0xae,0xc2,0xc4,0xe2):
                bad = image[:];bad[at+offset] ^= 1
                self.assertIsNone(find_packed_cursor12_port(bytes(bad))[0])
            bad=image[:];bad[at+_THUMB_DELAYS[0]+2] ^= 1
            self.assertIsNone(find_packed_cursor12_port(bytes(bad))[0])
            bad=image[:];bad[at+_THUMB_DELAYS[0]+1] = 0
            self.assertIsNone(find_packed_cursor12_port(bytes(bad))[0])
        image = image_at(0,0x800)
        self.assertIsNone(find_packed_cursor12_port(b'X'+bytes(image))[0])
        self.assertIsNone(find_packed_cursor12_port(bytes(image)+bytes(image))[0])
        # Distinct valid compiler variants are also ambiguous, never preferred.
        arm = bytearray(0x240);at=0x180
        arm[at:at+60]=_PRODUCER
        arm[at-0x160:at-0x15c]=bytes.fromhex('80b7a0e3')
        arm[at-0x124:at-0x118]=bytes.fromhex('0b70a0e30580a0e30390a0e3')
        arm[at-0x114:at-0x110]=bytes.fromhex('0fe0a0e3')
        arm[at-0x4c:at-0x30]=_HEADER
        arm[at+60:at+76]=bytes.fromhex('010080e2400bc0e3800050e3e7ffffba')
        self.assertIsNone(find_packed_cursor12_port(bytes(arm)+bytes(image))[0])

    def test_signature_binding_and_aliases(self):
        image = bytearray(0x240)
        at = 0x180
        image[at:at+60] = _PRODUCER
        image[at-0x160:at-0x15c] = bytes.fromhex('80b7a0e3')
        image[at-0x124:at-0x118] = bytes.fromhex('0b70a0e30580a0e30390a0e3')
        image[at-0x114:at-0x110] = bytes.fromhex('0fe0a0e3')
        image[at-0x4c:at-0x30] = _HEADER
        image[at+60:at+76] = bytes.fromhex('010080e2400bc0e3800050e3e7ffffba')
        self.assertEqual(find_packed_cursor12_port(bytes(image))[0],self.port)
        for offset in (at,at-0x160,at-0x124,at-0x120,at-0x11c,at-0x114,at-0x4c,at+0x44,at+0x48):
            bad = image[:];bad[offset] ^= 1
            self.assertIsNone(find_packed_cursor12_port(bytes(bad))[0])
        self.assertIsNone(find_packed_cursor12_port(bytes(image)+bytes(image))[0])
        self.assertIsNone(find_packed_cursor12_port(b'X'+bytes(image))[0])
        # Alias must contain the producer and bindings together, not just its bytes.
        self.assertIsNone(find_packed_cursor12_port(_PRODUCER)[0])

if __name__ == '__main__':
    unittest.main()
