"""Actual passive register callbacks: bounds, backing, widths and captured data."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class Lcd029NativeTests(unittest.TestCase):
    def test_register_backing_and_actual_bus_records(self):
        source=(Path(__file__).resolve().parents[1]/'native/qemu/msm5xxx-poc.c').read_text()
        at=source.index('static uint64_t msm5xxx_poc_lcd029_read(')
        end=source.index('static const MemoryRegionOps msm5xxx_poc_lcd029_ops',at)
        code=r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct { uint8_t lcd029_backing[0x38]; uint64_t lcd029_reads,lcd029_writes; } MSM5xxxPOCMachineState;
static unsigned traces;
static uint32_t last_address,last_value;
static uint64_t msm5xxx_poc_backing_read(uint8_t *b,unsigned at,unsigned n) {
    uint64_t value=0; assert(at+n<=0x38); memcpy(&value,b+at,n); return value;
}
static void msm5xxx_poc_backing_write(uint8_t *b,unsigned at,uint64_t value,unsigned n) {
    assert(at+n<=0x38);memcpy(b+at,&value,n);
}
static void msm5xxx_poc_lcd_trace_write(MSM5xxxPOCMachineState *s,
                                       uint32_t address,uint32_t value,unsigned size) {
    (void)s;assert(size==2);traces++;last_address=address;last_value=value;
}
''' + source[at:end] + r'''
int main(void) {
    MSM5xxxPOCMachineState s={0};
    for(unsigned offset=0;offset<0x38;offset+=2) {
        assert(msm5xxx_poc_lcd029_read(&s,offset,2)==0);
        msm5xxx_poc_lcd029_write(&s,offset,0xa500|offset,2);
        assert(msm5xxx_poc_lcd029_read(&s,offset,2)==(0xa500|offset));
        assert(last_address==0x02900000+offset && last_value==(0xa500|offset));
    }
    assert(s.lcd029_reads==56 && s.lcd029_writes==28 && traces==28);
    MSM5xxxPOCMachineState saved=s;
    for(unsigned i=0;i<4;i++) {
        unsigned off=i==0?1:i==1?0x38:0;
        unsigned size=i==2?1:i==3?4:2;
        msm5xxx_poc_lcd029_write(&s,off,0xffff,size);
        assert(msm5xxx_poc_lcd029_read(&s,off,size)==0);
    }
    assert(!memcmp(&s,&saved,sizeof(s)) && traces==28);
    for(unsigned value=0;value<65536;value+=257) {
        msm5xxx_poc_lcd029_write(&s,0x10,value,2);
        assert(msm5xxx_poc_lcd029_read(&s,0x10,2)==value && last_value==value);
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory);(path/'check.c').write_text(code)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(path/'check.c'),'-o',str(path/'check')],check=True)
            subprocess.run([str(path/'check')],check=True)
