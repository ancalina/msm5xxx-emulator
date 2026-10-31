"""Actual opt-in per-block Sharp lock/WP helpers; no firmware or VM."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class SharpLockTests(unittest.TestCase):
    def test_lockdown_wp_protection_width_and_block_independence(self):
        patch = (Path(__file__).resolve().parents[1] /
                 'native/qemu/qemu-10.2.1-cfi01-sharp-pcr.patch').read_text()
        added = '\n'.join(line[1:] for line in patch.splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
        helpers = []
        for name in ('pflash_sharp_block_state', 'pflash_sharp_lock_command',
                     'pflash_sharp_program_blocked'):
            start = added.index(name + '(')
            start = added.rfind('static ', 0, start)
            brace = added.index('{', start)
            end, depth = brace + 1, 1
            while depth:
                depth += (added[end] == '{') - (added[end] == '}')
                end += 1
            helpers.append(added[start:end])
        code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
typedef uint64_t hwaddr;
typedef struct {
 bool sharp_locks_enabled,sharp_wp_high;
 uint8_t *sharp_lock_state,status;
 uint64_t sector_len,sharp_pcr_setup_address;
 uint32_t nb_blocs;
} PFlashCFI01;
''' + '\n'.join(helpers) + r'''
int main(void) {
 uint8_t locks[2]={1,1};
 PFlashCFI01 s={.sector_len=0x10000,.nb_blocs=2,.sharp_lock_state=locks,
 .sharp_pcr_setup_address=0x1000};
 assert(pflash_sharp_block_state(&s,0x1000)==0);
 assert(!pflash_sharp_lock_command(&s,0x1000,0xd0,2));
 assert(!pflash_sharp_program_blocked(&s,0x1000));
 s.sharp_locks_enabled=true;
 assert(pflash_sharp_block_state(&s,0x1fffe)==1);
 assert(pflash_sharp_lock_command(&s,0x1000,0xd0,2));assert(locks[0]==0);
 assert(!pflash_sharp_program_blocked(&s,0x1000));
 assert(pflash_sharp_lock_command(&s,0x1000,0x2f,2));assert(locks[0]==3);
 s.status=0;assert(pflash_sharp_program_blocked(&s,0x1000));assert(s.status==0x92);
 s.status=0;assert(pflash_sharp_lock_command(&s,0x1000,0xd0,2));assert(locks[0]==3);
 s.sharp_wp_high=true;
 assert(pflash_sharp_lock_command(&s,0x1000,0xd0,2));assert(locks[0]==2);
 assert(!pflash_sharp_program_blocked(&s,0x1000));
 assert(pflash_sharp_lock_command(&s,0x1000,1,2));assert(locks[0]==3);
 assert(pflash_sharp_lock_command(&s,0x1000,0xd0,2));assert(locks[0]==2 && locks[1]==1);
 for(unsigned i=0;i<5;i++) {
  s.status=0;uint64_t address=0x1000;uint32_t value=0x2f;unsigned width=2;
  if(i==0)address+=2;
  if(i==1){address++;s.sharp_pcr_setup_address=address;}
  if(i==2)width=1;
  if(i==3)value=0x12f;
  if(i==4){address=0x20000;s.sharp_pcr_setup_address=address;}
  assert(pflash_sharp_lock_command(&s,address,value,width));
  assert(s.status==0xb0 && locks[0]==2 && locks[1]==1);
  s.sharp_pcr_setup_address=0x1000;
 }
 assert(!pflash_sharp_lock_command(&s,0x1000,4,2));
 assert(pflash_sharp_block_state(&s,UINT64_MAX)==3);
 s.sector_len=0;assert(pflash_sharp_block_state(&s,0)==3);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'test.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'test.c'), '-o', str(path / 'test')],
                           check=True, capture_output=True)
            subprocess.run([str(path / 'test')], check=True, capture_output=True)
