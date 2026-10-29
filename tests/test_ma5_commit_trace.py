"""Compile the actual bounded trace callback with its logging dependency stubbed."""
from pathlib import Path
import subprocess
import tempfile
import unittest

class TraceTests(unittest.TestCase):
    def test_actual_trace_bound_and_payload(self):
        root = Path(__file__).resolve().parents[1] / 'experiments/qemu-tcg'
        source = (root / 'msm5xxx-poc.c').read_text()
        begin = source.index('static void msm5xxx_poc_ma5_commit_trace(')
        body = source.index('{', begin)
        depth = 0
        end = body
        while end < len(source):
            depth += source[end] == '{'
            depth -= source[end] == '}'
            if depth == 0:
                end += 1
                break
            end += 1
        if depth != 0:
            raise AssertionError('unterminated MA5 trace callback')
        harness = r'''
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "msm5xxx-ma5-audio.h"
#define LOG_GUEST_ERROR 1
typedef struct { uint32_t ma5_commit_traces; } MSM5xxxPOCMachineState;
static int enabled, lines, limits;
static char last[256];
static int qemu_loglevel_mask(int mask) { assert(mask==1); return enabled; }
static void qemu_log_mask(int mask, const char *format, ...) {
    assert(mask==1); va_list args; va_start(args,format);
    vsnprintf(last,sizeof(last),format,args); va_end(args); lines++;
    if (strstr(last,"trace-limit")) limits++;
}
''' + source[begin:end] + r'''
int main(void) {
    MSM5xxxPOCMachineState s={0};
    MSM5xxxMA5Commit c={MSM5XXX_MA5_COMMIT_CONTROL,5,0x40,0xc0,UINT64_MAX};
    msm5xxx_poc_ma5_commit_trace(&s,&c); assert(!s.ma5_commit_traces && !lines);
    enabled=1; msm5xxx_poc_ma5_commit_trace(&s,&c);
    assert(strstr(last,"n=1 t=18446744073709551615 kind=C address=5 value=40 raw=c0"));
    c.kind=MSM5XXX_MA5_COMMIT_SRAM; c.address=0x5fff; c.value=c.raw=0xff;
    msm5xxx_poc_ma5_commit_trace(&s,&c); assert(strstr(last,"kind=S address=5fff value=ff raw=ff"));
    c.kind=MSM5XXX_MA5_COMMIT_B; c.address=38; c.value=0; c.raw=2;
    msm5xxx_poc_ma5_commit_trace(&s,&c); assert(strstr(last,"kind=B address=26 value=00 raw=02"));
    while(s.ma5_commit_traces<16384) msm5xxx_poc_ma5_commit_trace(&s,&c);
    assert(limits==1 && lines==16385);
    msm5xxx_poc_ma5_commit_trace(&s,&c); assert(lines==16385);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            path=Path(temporary); (path/'test.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-pedantic',
                            '-I'+str(root),str(path/'test.c'),'-o',str(path/'test')],check=True)
            subprocess.run([str(path/'test')],check=True)

if __name__=='__main__': unittest.main()
