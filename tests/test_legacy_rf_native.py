"""Exercise the serial tune transaction and retune invalidation."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class LegacyRfNativeTests(unittest.TestCase):
    def test_tuning(self):
        native=Path(__file__).resolve().parents[1]/'native/qemu'
        source=(native/'msm5xxx-poc.c').read_text()
        start=source.index('static uint64_t msm5xxx_poc_legacy_rf_read(')
        end=source.index('static void msm5xxx_poc_legacy_decoder_tick(',start)
        harness=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
typedef uint64_t hwaddr;
typedef struct {int unused;} MemoryRegion;
typedef struct {uint64_t (*read)(void *,hwaddr,unsigned);void (*write)(void *,hwaddr,uint64_t,unsigned);int endianness;struct{int min_access_size,max_access_size;}valid,impl;} MemoryRegionOps;
#define DEVICE_LITTLE_ENDIAN 0
typedef struct { MemoryRegion msm;uint32_t legacy_rf_shift,legacy_rf_integer;uint16_t legacy_cell_channel;uint8_t legacy_rf_bits;bool legacy_rf_integer_valid,legacy_rf_tuned;} MSM5xxxPOCMachineState;
static bool msm5xxx_poc_legacy_gate(MSM5xxxPOCMachineState *s) {(void)s;return true;}
static uint8_t memory[0x800];
static uint8_t *memory_region_get_ram_ptr(MemoryRegion*m){(void)m;return memory;}
static uint64_t msm5xxx_poc_backing_read(uint8_t*b,hwaddr o,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)b[o+i]<<(i*8);return v;}
static void msm5xxx_poc_backing_write(uint8_t*b,hwaddr o,uint64_t v,unsigned n){for(unsigned i=0;i<n;i++)b[o+i]=v>>(i*8);}
'''+source[start:end]+r'''
static void emit(MSM5xxxPOCMachineState *s,uint32_t word,unsigned bits){
 unsigned port=0x200;msm5xxx_poc_legacy_rf_write(s,0,port,2);
 for(unsigned i=bits;i;i--){port=0x200|(((word>>(i-1))&1)<<10);msm5xxx_poc_legacy_rf_write(s,0,port,2);msm5xxx_poc_legacy_rf_write(s,0,port|0x800,2);msm5xxx_poc_legacy_rf_write(s,0,port,2);}
 msm5xxx_poc_legacy_rf_write(s,0,port|0x1000,2);
 msm5xxx_poc_legacy_rf_write(s,0,0x200,2);
}
int main(void){
 MSM5xxxPOCMachineState s={0};s.legacy_cell_channel=750;
 emit(&s,0x382,22);assert(!s.legacy_rf_tuned && s.legacy_rf_integer_valid);
 emit(&s,0x47c3,22);assert(s.legacy_rf_tuned);
 msm5xxx_poc_legacy_rf_write(&s,0,0,2);assert(!s.legacy_rf_tuned);
 s.legacy_cell_channel=625;emit(&s,0x229e47,24);assert(s.legacy_rf_tuned);
 emit(&s,0x229e4b,24);assert(!s.legacy_rf_tuned);
 emit(&s,0x229e47,24);assert(s.legacy_rf_tuned);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'test.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Wno-unused-const-variable','-Werror',
                            str(p/'test.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)
