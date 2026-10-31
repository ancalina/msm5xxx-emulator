"""Window grammar, retained prefix coverage and byte-exact direct raster admission."""
import unittest
from msm5xxx_emulator.devices.display.legacy_panel import LegacyPanel

class LegacyPanelTests(unittest.TestCase):
 def byte_window(self,p,mode,x0,x1,y0,y1):
  for v in (7,mode,0x31,x0,x1,0x21,y0,y1):p.write(p.port,1,v)
 def column_window(self,p,y0,y1):
  p.write(p.port,2,0x75)
  for v in (y0,y1):p.write(p.port+4,2,v)
  p.write(p.port,2,0x15)
  for v in (140,0,11,1):p.write(p.port+4,2,v)
  p.write(p.port,2,0x5c)
 def test_byte_mode_axis_order_and_coverage(self):
  p=LegacyPanel('byte31');self.byte_window(p,0xd,0,127,0,127)
  for _ in range(128*128-1):p.write(p.port+4,1,255)
  self.assertFalse(p.qualified)
  p.write(p.port+4,1,255);self.assertTrue(p.qualified)
  self.byte_window(p,0x2d,0,1,0,1)
  for v in (0xe0,0x1c,3,0):p.write(p.port+4,1,v)
  self.assertEqual(p.frame[:6],b'\xff\x00\x00\x00\x00\xff')
  self.assertEqual(p.frame[128*3:128*3+6],b'\x00\xff\x00\x00\x00\x00')
  before=p.sequence;self.byte_window(p,0x99,0,127,0,127)
  p.write(p.port+4,1,0);self.assertEqual(p.sequence,before)
 def test_column_prefix_does_not_claim_declared_unwritten_rows(self):
  p=LegacyPanel('column16');self.column_window(p,0,127)
  for _ in range(128*14):p.write(p.port+4,2,0xf800)
  self.assertEqual(p.coverage,128*14);self.assertFalse(p.qualified)
  self.column_window(p,14,159)
  for _ in range(128*146-1):p.write(p.port+4,2,0x7e0)
  self.assertFalse(p.qualified)
  p.write(p.port+4,2,0x7e0);self.assertTrue(p.qualified)
  self.assertEqual(p.frame[:3],b'\xff\x00\x00')
  self.assertEqual(p.frame[128*14*3:128*14*3+3],b'\x00\xff\x00')
 def test_byte565_boot_requires_setup_and_one_complete_little_endian_frame(self):
  p=LegacyPanel('byte565_boot');cmd=p.port+2;data=p.port
  for address,value in ((cmd,8),(data,0),(data,1),(cmd,9),(data,0x40)):p.write(address,1,value)
  self.assertIsNone(p.window)
  for address,value in ((cmd,8),(data,0),(cmd,9),(data,0x40)):p.write(address,1,value)
  p.write(data,1,0);p.write(data,1,0xf8)
  for _ in range(120*133-2):p.write(data,1,0xff);p.write(data,1,0xff)
  p.write(data,1,0x1f);self.assertFalse(p.qualified)
  p.write(data,1,0);self.assertTrue(p.qualified)
  self.assertEqual(p.frame[:3],b'\xff\x00\x00');self.assertEqual(p.frame[-3:],b'\x00\x00\xff')
  sequence=p.sequence
  # A malformed or truncated second transfer cannot combine coverage with the first.
  for address,value in ((cmd,8),(data,0),(cmd,9),(data,0x40)):p.write(address,1,value)
  for _ in range(100):p.write(data,1,0)
  p.write(cmd,2,9);self.assertEqual(p.sequence,sequence)
  for _ in range(120*133*2):p.write(data,1,0)
  self.assertEqual(p.sequence,sequence)

 def test_direct_requires_every_byte_and_preserves_partial_word_writes(self):
  p=LegacyPanel('direct16');last=176*220*2-2
  for at in range(0,last,2):p.write(p.port+at,2,0xffff)
  p.write(p.port+last,1,0);self.assertFalse(p.qualified)
  p.write(p.port+last+1,1,0xf8);self.assertTrue(p.qualified)
  self.assertEqual(p.frame[-3:],b'\xff\x00\x00')
  seq=p.sequence;p.write(p.port+last+1,2,65535)
  p.write(p.port+0x20000,2,65535);self.assertEqual(seq,p.sequence)

 def test_half43_full_clear_then_glyph_row_prefix(self):
  p=LegacyPanel('half43')
  def window(y0,y1):
   for v in (0x43,0,127,0x42,y0,y1):p.write(p.port,1,v)
  window(0,143)
  for _ in range(128*144):p.write(p.port+2,2,65535)
  self.assertTrue(p.qualified)
  for v in (0x43,0,5,0x42,1,14):p.write(p.port,1,v)
  for _ in range(6):p.write(p.port+2,2,0)
  sequence=p.sequence
  p.write(p.port,1,0x43)
  self.assertEqual(p.sequence,sequence+1)
  self.assertEqual(p.frame[128*3:128*3+18],bytes(18))
  self.assertEqual(p.frame[128*3+18:128*3+21],b'\xff'*3)


class LegacyDisplayOwnershipTests(unittest.TestCase):
 def test_complete_guest_raster_changes_snapshot_and_blocks_generic_publication(self):
  from types import SimpleNamespace
  import threading
  from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin
  class Display(DisplayControllerMixin):pass
  d=Display();d.config=SimpleNamespace(width=176,height=220,display_geometry_source='auto-default')
  d._display_lock=threading.RLock();d._lcd_legacy_panel=LegacyPanel('byte31')
  d._lcd_source_window_owned=False;d.framebuffer=bytearray(176*220*3)
  d.display_frame=bytes(d.framebuffer);d.frame_sequence=0;d._lcd_protocol='unknown'
  for field in ('_lcd_raw_streams','_lcd_raw_counts','_lcd_raw_frames','_lcd_raw_segment_streams','_lcd_raw_segment_counts'):setattr(d,field,{})
  for v in (7,0xd,0x31,0,127,0x21,0,127):self.assertFalse(d._lcd_legacy_write(0x2800000,1,v))
  for _ in range(128*128-1):self.assertFalse(d._lcd_legacy_write(0x2800004,1,255))
  self.assertEqual(d.frame_sequence,0)
  self.assertTrue(d._lcd_legacy_write(0x2800004,1,255))
  self.assertEqual(d.display_snapshot(),(128,128,b'\xff'*(128*128*3)))
  self.assertEqual(d.frame_sequence,1)
  d.framebuffer[:]=bytes(len(d.framebuffer));d._publish_frame()
  self.assertEqual(d.frame_sequence,1)
  self.assertEqual(d.display_snapshot()[2],b'\xff'*(128*128*3))
