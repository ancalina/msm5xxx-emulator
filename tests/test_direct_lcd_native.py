"""Actual raw VRAM/ASIC helpers; no firmware fixture or guest."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

class DirectLCDNativeTests(unittest.TestCase):
    def test_width_coherence_bounds_and_stream(self):
        source=(Path(__file__).resolve().parents[1]/'native/qemu/msm5xxx-poc.c').read_text()
        def function(name):
            match=re.search(r'^static [^\n]*(?:\n[^\n]*)?\b'+name+r'\(',source,re.M)
            self.assertIsNotNone(match,name)
            brace=source.index('{',match.end());depth=1;end=brace+1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[match.start():end]
        harness='''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct {
 bool direct_lcd_enabled, audio_enabled;
 uint32_t audio_base, audio_data_offset;
 uint8_t direct_lcd_pixels[0x12e80],direct_lcd_registers[0x28];
} MSM5xxxPOCMachineState;
static unsigned traces, last_size;
static hwaddr last_address;
static uint64_t last_value;
static void msm5xxx_poc_lcd_trace_write(MSM5xxxPOCMachineState *s,hwaddr a,uint64_t v,unsigned n) {
 (void)s;traces++;last_address=a;last_value=v;last_size=n;
}
'''+ '\n'.join(function(n) for n in (
 'msm5xxx_poc_direct_lcd_reset','msm5xxx_poc_direct_lcd_audio_conflict',
 'msm5xxx_poc_backing_read','msm5xxx_poc_backing_write',
 'msm5xxx_poc_direct_lcd_read','msm5xxx_poc_direct_lcd_write',
 'msm5xxx_poc_direct_lcd_control_read','msm5xxx_poc_direct_lcd_control_write'))+'''
int main(void) {
 MSM5xxxPOCMachineState s={0};
 msm5xxx_poc_direct_lcd_write(&s,0,0x1234,2);
 assert(!traces && !msm5xxx_poc_direct_lcd_read(&s,0,2));
 s.direct_lcd_enabled=true;
 msm5xxx_poc_direct_lcd_write(&s,0,0x12345678,4);
 assert(traces==1 && last_address==0x2800000 && last_value==0x12345678 && last_size==4);
 assert(msm5xxx_poc_direct_lcd_read(&s,0,1)==0x78);
 assert(msm5xxx_poc_direct_lcd_read(&s,1,2)==0x3456);
 msm5xxx_poc_direct_lcd_write(&s,0x12e7e,0xabcd,2);
 assert(msm5xxx_poc_direct_lcd_read(&s,0x12e7e,2)==0xabcd);
 unsigned before=traces;
 const hwaddr bad[]={0x12e80,0x13000,0x1ffff,0x20028,UINT64_MAX};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
  msm5xxx_poc_direct_lcd_write(&s,bad[i],0xffffffff,4);
  assert(!msm5xxx_poc_direct_lcd_read(&s,bad[i],4));
 }
 msm5xxx_poc_direct_lcd_write(&s,0x12e7f,0xffff,2);
 assert(traces==before && msm5xxx_poc_direct_lcd_read(&s,0x12e7e,2)==0xabcd);
 msm5xxx_poc_direct_lcd_control_write(&s,0xc,0xbbaa,2);
 assert(last_address==0x282000c && last_size==2);
 msm5xxx_poc_direct_lcd_control_write(&s,0xd,0x11,1);
 assert(msm5xxx_poc_direct_lcd_control_read(&s,0xc,2)==0x11aa);
 msm5xxx_poc_direct_lcd_control_write(&s,0x26,0x4321,2);
 assert(msm5xxx_poc_direct_lcd_control_read(&s,0x26,2)==0x4321);
 before=traces;
 msm5xxx_poc_direct_lcd_control_write(&s,0x27,0xffff,2);
 assert(traces==before);
 assert(!msm5xxx_poc_direct_lcd_control_read(&s,0x10,2));
 msm5xxx_poc_direct_lcd_control_write(&s,0x24,2,2);
 assert(msm5xxx_poc_direct_lcd_control_read(&s,0x24,2)==2);
 assert(!msm5xxx_poc_direct_lcd_control_read(&s,0x10,2));
 msm5xxx_poc_direct_lcd_reset(&s);
 assert(!msm5xxx_poc_direct_lcd_read(&s,0,4));
 assert(!msm5xxx_poc_direct_lcd_read(&s,0x12e7e,2));
 assert(!msm5xxx_poc_direct_lcd_control_read(&s,0xc,2));
 assert(!msm5xxx_poc_direct_lcd_control_read(&s,0x26,2));
 s.audio_enabled=true;s.audio_base=0x2800000;s.audio_data_offset=1;
 assert(msm5xxx_poc_direct_lcd_audio_conflict(&s));
 s.audio_base=0x2820027;s.audio_data_offset=0;
 assert(msm5xxx_poc_direct_lcd_audio_conflict(&s));
 s.audio_base=0x2812e80;s.audio_data_offset=0;
 assert(!msm5xxx_poc_direct_lcd_audio_conflict(&s));
 s.audio_base=0x2820028;s.audio_data_offset=0;
 assert(!msm5xxx_poc_direct_lcd_audio_conflict(&s));
 s.audio_base=0x2400000;s.audio_data_offset=4;
 assert(!msm5xxx_poc_direct_lcd_audio_conflict(&s));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);(path/'test.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(path/'test.c'),'-o',str(path/'test')],check=True,capture_output=True)
            subprocess.run([str(path/'test')],check=True,capture_output=True)
