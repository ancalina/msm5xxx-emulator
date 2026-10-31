"""Actual completed-operation suspend/resume helper; no firmware or VM."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class SyncFlashControlTests(unittest.TestCase):
    def test_completed_state_preserves_errors_without_false_suspend(self):
        patch = (Path(__file__).resolve().parents[1] /
                 'native/qemu/qemu-10.2.1-cfi01-sharp-pcr.patch').read_text()
        added = '\n'.join(line[1:] for line in patch.splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
        functions = []
        for name in ('pflash_deferred_erase_enabled', 'pflash_sync_completed_control'):
            start = added.index(name + '(')
            start = added.rfind('static ', 0, start)
            brace = added.index('{', start)
            end, depth = brace + 1, 1
            while depth:
                depth += (added[end] == '{') - (added[end] == '}')
                end += 1
            functions.append(added[start:end])
        code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
typedef struct {
 bool defer_erase_confirm,sharp_pcr_enabled,sharp_locks_enabled;
 uint8_t cmd,wcycle,status;
} PFlashCFI01;
''' + '\n'.join(functions) + r'''
int main(void) {
 PFlashCFI01 s={.cmd=0x20,.status=0x80};
 assert(!pflash_sync_completed_control(&s,0xb0,2));assert(s.status==0x80);
 s.defer_erase_confirm=true;
 assert(pflash_sync_completed_control(&s,0xb0,2));assert(s.status==0x80);
 s.cmd=0x40;s.status=0xd6;
 assert(pflash_sync_completed_control(&s,0xd0,2));assert(s.status==0x92);
 for(unsigned i=0;i<6;i++) {
  PFlashCFI01 bad=s;uint32_t value=0xb0;unsigned width=2;
  if(i==0)bad.wcycle=1;
  if(i==1)bad.cmd=0x90;
  if(i==2)bad.cmd=0x98;
  if(i==3)width=1;
  if(i==4)value=0x1b0;
  if(i==5)value=0x50;
  assert(!pflash_sync_completed_control(&bad,value,width));assert(bad.status==s.status);
 }
 s.defer_erase_confirm=false;s.sharp_pcr_enabled=true;s.cmd=0;s.status=0;
 assert(pflash_sync_completed_control(&s,0xb0,2));assert(s.status==0x80);
 s.sharp_pcr_enabled=false;s.sharp_locks_enabled=true;
 assert(pflash_sync_completed_control(&s,0xd0,2));assert(s.status==0x80);
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
