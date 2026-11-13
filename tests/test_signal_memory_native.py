"""Compile native signal-memory admission and reset with synthetic ranges."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from native_sanitizers import native_sanitizers
from test_protected_nor_native import function


class SignalMemoryNativeTests(unittest.TestCase):
    def test_ranges_are_bounded_disjoint_immutable_and_resettable(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        source = (native / 'msm5xxx-poc.c').read_text()
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef struct { uint8_t bytes[0x2000]; } MemoryRegion;
typedef struct {
    uint32_t signal_memory_ranges[16];
    unsigned signal_memory_count;
    bool signal_memory_realized;
    MemoryRegion signal_memory[8];
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
typedef int Error;
#define MSM5XXX_POC_MACHINE(s) (s)
#define g_ascii_isxdigit(c) isxdigit((unsigned char)(c))
static int error_value;
static void error_setg(Error **err,const char *format,...) {
    (void)format;*err=&error_value;
}
static int qemu_strtou64(const char *text,const char **end,int radix,uint64_t *result) {
    char *last;errno=0;*result=strtoull(text,&last,radix);*end=last;
    return errno==ERANGE || text==last ? -1:0;
}
static void *memory_region_get_ram_ptr(MemoryRegion *mr) {return mr->bytes;}
''' + '\n'.join(function(source, name) for name in (
            'msm5xxx_poc_boot_storage_hex', 'msm5xxx_poc_set_signal_memory',
            'msm5xxx_poc_signal_memory_reset')) + r'''
int main(void) {
    MSM5xxxPOCMachineState s={0},before;Error *err=NULL;
    msm5xxx_poc_set_signal_memory(&s,"8000000:1000:8200000:2000",&err);
    assert(!err && s.signal_memory_count==2);
    assert(s.signal_memory_ranges[0]==0x08000000 && s.signal_memory_ranges[3]==0x2000);
    memset(s.signal_memory[0].bytes,0x51,0x1000);
    memset(s.signal_memory[1].bytes,0x29,0x2000);
    msm5xxx_poc_signal_memory_reset(&s);
    for(unsigned i=0;i<0x1000;i++)assert(s.signal_memory[0].bytes[i]==0);
    for(unsigned i=0;i<0x2000;i++)assert(s.signal_memory[1].bytes[i]==0);
    before=s;msm5xxx_poc_set_signal_memory(&s,"8400000:1000",&err);
    assert(err && !memcmp(&s,&before,sizeof(s)));
    const char *bad[]={"", "0:1000", "8000001:1000", "8000000:1001",
        "8000000:0", "8000000:101000", "fffff000:2000", "8000000",
        "8000000:1000:8000000:1000", "8000000:2000:8001000:1000",
        "8000000:1000:", "8000000:1000 ", "-8000000:1000",
        "8000000:1000:8200000:1000:8400000:1000:8600000:1000:8800000:1000:8a00000:1000:8c00000:1000:8e00000:1000:9000000:1000"};
    for(unsigned i=0;i<ARRAY_SIZE(bad);i++) {
        memset(&s,0,sizeof(s));before=s;err=NULL;
        msm5xxx_poc_set_signal_memory(&s,bad[i],&err);
        assert(err && !memcmp(&s,&before,sizeof(s)));
    }
    memset(&s,0,sizeof(s));s.signal_memory_realized=true;before=s;err=NULL;
    msm5xxx_poc_set_signal_memory(&s,"8000000:1000",&err);
    assert(err && !memcmp(&s,&before,sizeof(s)));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                native_sanitizers(), '-fno-sanitize-recover=all',
                str(path / 'check.c'), '-o', str(path / 'check')], check=True)
            subprocess.run([str(path / 'check')], check=True)
