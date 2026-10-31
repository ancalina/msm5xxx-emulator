"""Actual opt-in Sharp PCR latch helper, without QEMU or firmware."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class SharpPCRTests(unittest.TestCase):
    def test_address_latch_and_fail_closed_width_context(self):
        root = Path(__file__).resolve().parents[1]
        patch = (root / 'native/qemu/qemu-10.2.1-cfi01-sharp-pcr.patch').read_text()
        added = '\n'.join(line[1:] for line in patch.splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
        helpers = []
        for name in ('pflash_sharp_pcr_reset', 'pflash_sharp_pcr_set'):
            start = added.index(name + '(')
            start = added.rfind('static ', 0, start)
            brace = added.index('{', start)
            end, depth = brace + 1, 1
            while depth:
                depth += (added[end] == '{') - (added[end] == '}')
                end += 1
            helpers.append(added[start:end])
        helper = '\n'.join(helpers)
        harness = r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
typedef uint64_t hwaddr;
typedef struct {
 bool sharp_pcr_enabled;
 uint8_t bank_width,device_width,max_device_width,status;
 uint16_t sharp_pcr,sharp_pcr_reset;
 uint64_t sharp_pcr_setup_address;
} PFlashCFI01;
''' + helper + r'''
int main(void) {
 PFlashCFI01 s={.bank_width=2,.device_width=2,.max_device_width=2,
 .sharp_pcr_setup_address=0xc00,.sharp_pcr=0x1111,.status=0};
 assert(!pflash_sharp_pcr_set(&s,0xc00,4,2));
 assert(s.sharp_pcr==0x1111 && !s.status);
 s.sharp_pcr_enabled=true;
 assert(pflash_sharp_pcr_set(&s,0xc00,4,2));
 assert(s.sharp_pcr==0x600 && s.status==0x80);
 s.sharp_pcr_setup_address=0x180680;
 assert(pflash_sharp_pcr_set(&s,0x180680,4,2));
 assert(s.sharp_pcr==0x300);
 for(unsigned i=0;i<7;i++) {
  PFlashCFI01 bad=s;
  uint64_t address=0x180680;unsigned value=4,width=2;
  if(i==0)bad.bank_width=4;
  if(i==1)bad.device_width=1;
  if(i==2)bad.max_device_width=4;
  if(i==3)width=1;
  if(i==4)value=0x104;
  if(i==5)address+=2;
  if(i==6){address++;bad.sharp_pcr_setup_address=address;}
  assert(!pflash_sharp_pcr_set(&bad,address,value,width));
  assert(bad.sharp_pcr==0x300 && bad.status==s.status);
 }
 s.sharp_pcr_reset=0x100;pflash_sharp_pcr_reset(&s);
 assert(s.sharp_pcr==0x100 && s.sharp_pcr_setup_address==UINT64_MAX);
 s.sharp_pcr_reset=0x400;pflash_sharp_pcr_reset(&s);
 assert(s.sharp_pcr==0x400 && s.sharp_pcr_setup_address==UINT64_MAX);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'test.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'test.c'), '-o', str(path / 'test')],
                           check=True, capture_output=True)
            subprocess.run([str(path / 'test')], check=True, capture_output=True)
