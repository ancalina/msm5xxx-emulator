"""Actual optional Sharp erase-confirm helpers; no firmware or QEMU."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class SharpEraseTests(unittest.TestCase):
    def test_deferred_confirmation_and_array_protection(self):
        patch = (Path(__file__).resolve().parents[1] /
                 'native/qemu/qemu-10.2.1-cfi01-sharp-pcr.patch').read_text()
        added = '\n'.join(line[1:] for line in patch.splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
        helpers = []
        for name in ('pflash_deferred_erase_enabled', 'pflash_sharp_block_state', 'pflash_sharp_program_frame',
                     'pflash_sharp_erase_start', 'pflash_sharp_erase_finish'):
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
#include <string.h>
typedef uint64_t hwaddr;
typedef struct {
 bool sharp_pcr_enabled,sharp_locks_enabled,defer_erase_confirm,ro;
 uint8_t *sharp_lock_state,status;
 uint64_t sector_len,sharp_erase_address;
 uint32_t nb_blocs;
 void *storage;
} PFlashCFI01;
static unsigned updates;static uint64_t updated_address,updated_size;
static void pflash_update(PFlashCFI01 *s,int address,int size){(void)s;updates++;updated_address=address;updated_size=size;}
''' + '\n'.join(helpers) + r'''
int main(void) {
 uint8_t storage[0x2000],original[0x2000],locks[2]={0,1};
 memset(storage,0x5a,sizeof(storage));memcpy(original,storage,sizeof(storage));
 PFlashCFI01 s={.sector_len=0x1000,.nb_blocs=2,.sharp_lock_state=locks,
 .storage=storage,.sharp_erase_address=UINT64_MAX};
 assert(!pflash_sharp_erase_start(&s,0x1000,0x20,2));
 assert(!pflash_sharp_erase_finish(&s,0x1000,0xd0,2));
 s.sharp_pcr_enabled=true;
 for(unsigned i=0;i<6;i++) {
  s.status=0;
  assert(pflash_sharp_erase_start(&s,0x1000,0x20,2));
  assert(!memcmp(storage,original,sizeof(storage)) && !updates);
  uint64_t address=0x1000;unsigned value=0xd0,width=2;
  if(i==0)address=0;
  if(i==1)value=0x1d0;
  if(i==2)width=1;
  if(i==3)address++;
  if(i==4)address=UINT64_MAX;
  if(i==5)s.sharp_erase_address=UINT64_MAX;
  assert(pflash_sharp_erase_finish(&s,address,value,width));
  assert(s.status==0xb0 && s.sharp_erase_address==UINT64_MAX);
  assert(!memcmp(storage,original,sizeof(storage)) && !updates);
 }
 s.status=0;s.sharp_locks_enabled=true;
 pflash_sharp_erase_start(&s,0x1000,0x20,2);
 assert(pflash_sharp_erase_finish(&s,0x1000,0xd0,2));assert(s.status==0xa2);
 assert(!memcmp(storage,original,sizeof(storage)) && !updates);
 locks[1]=0;s.status=0;s.ro=true;pflash_sharp_erase_start(&s,0x1000,0x20,2);
 assert(pflash_sharp_erase_finish(&s,0x1000,0xd0,2));assert(s.status==0xa0 && !updates);
 s.ro=false;s.status=0;pflash_sharp_erase_start(&s,0x1002,0x20,2);
 assert(!memcmp(storage,original,sizeof(storage)));
 assert(pflash_sharp_erase_finish(&s,0x1004,0xd0,2));
 assert(updates==1 && updated_address==0x1000 && updated_size==0x1000 && s.status==0x80);
 assert(!memcmp(storage,original,0x1000));
 for(unsigned i=0x1000;i<0x2000;i++)assert(storage[i]==0xff);
 assert(pflash_sharp_program_frame(&s,0x1ffe,2));
 for(unsigned i=0;i<4;i++) {
  s.status=0;uint64_t at=0;unsigned width=2;
  if(i==0)at=1;
  if(i==1)at=0x2000;
  if(i==2)at=UINT64_MAX;
  if(i==3)width=4;
  assert(!pflash_sharp_program_frame(&s,at,width));assert(s.status==0x92);
 }
 s.sharp_pcr_enabled=s.sharp_locks_enabled=false;s.defer_erase_confirm=true;
 s.status=0;memset(storage,0x6b,sizeof(storage));updates=0;
 assert(pflash_sharp_erase_start(&s,0,0x20,2));assert(storage[0]==0x6b && !updates);
 assert(pflash_sharp_erase_finish(&s,0,0xd0,2));assert(storage[0]==0xff && updates==1);
 assert(storage[0x1000]==0x6b);
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
