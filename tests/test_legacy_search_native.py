"""Exercise legacy register widths, FIFO lifecycle, and pilot correlation."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class LegacySearchNativeTests(unittest.TestCase):
    def test_registers_and_pilot(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        source = (native / 'msm5xxx-poc.c').read_text()
        start = source.index('static void msm5xxx_poc_legacy_search_start(')
        end = source.index('static bool msm5xxx_poc_radio_irq_gate(', start)
        code = source[start:end]
        harness = r'''
#include "msm5xxx-search2.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct { int dummy; } MemoryRegion;
typedef struct { uint64_t (*read)(void *,hwaddr,unsigned); void (*write)(void *,hwaddr,uint64_t,unsigned); int endianness; struct {int min_access_size,max_access_size;} valid,impl; } MemoryRegionOps;
#define DEVICE_LITTLE_ENDIAN 0
#define QEMU_CLOCK_VIRTUAL 0
static uint8_t backing[0x400], rom[4096];
typedef struct {
 MSM5xxxSearch2 search2; MSM5xxxFingers fingers; MemoryRegion msm;
 uint32_t search2_position, search2_pending_position, search1_position;
 uint32_t search2_pilot_phase, search2_peak_energy, legacy_masks_i, legacy_masks_q;
 uint32_t legacy_search_hits; uint64_t search2_submits,search2_completions,search2_result_reads;
 uint16_t search2_samples[8], rex_irq_pending[1]; void *search2_timer;
} MSM5xxxPOCMachineState;
static uint8_t *memory_region_get_ram_ptr(MemoryRegion *r) { (void)r;return backing; }
static uint64_t msm5xxx_poc_backing_read(uint8_t *b, hwaddr o, unsigned n) { uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)b[o+i]<<(8*i);return v; }
static void msm5xxx_poc_backing_write(uint8_t *b, hwaddr o,uint64_t v,unsigned n) {for(unsigned i=0;i<n;i++)b[o+i]=v>>(8*i);}
static void cpu_physical_memory_read(uint32_t a,void *out,unsigned n) {assert(a+n<=sizeof rom);memcpy(out,rom+a,n);}
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s) {(void)s;}
static int64_t qemu_clock_get_ns(int n) {(void)n;return 100;}
static void timer_mod(void *t,int64_t n) {(void)t;assert(n==1000100);}
'''
        harness += code
        harness += r'''
int main(void) {
 MSM5xxxPOCMachineState s={0}; msm5xxx_search2_init(&s.search2);
 s.legacy_masks_i=16;s.legacy_masks_q=32;rom[17]=rom[33]=0x40;
 s.search2_pilot_phase=16;s.search2_peak_energy=64000;
 msm5xxx_poc_legacy_search_write(&s,20,3,1);
 uint16_t cmd[6]={0xfffe,0x4000,0x4000,64,0,0};
 for(unsigned i=0;i<6;i++)msm5xxx_poc_legacy_search_write(&s,4,cmd[i],2);
 assert(s.search2.active && s.search2_submits==1);
 msm5xxx_poc_legacy_search_complete(&s);
 assert(s.search2_completions==1 && s.legacy_search_hits==1 && s.rex_irq_pending[0]==0x80);
 assert(msm5xxx_poc_legacy_search_read(&s,8,1)==2);
 assert(msm5xxx_poc_legacy_search_read(&s,8,1)==0);
 assert(msm5xxx_poc_legacy_search_read(&s,12,2)==64000);
 assert(msm5xxx_poc_legacy_search_read(&s,12,2)==4);
 for(unsigned i=2;i<8;i++)assert(msm5xxx_poc_legacy_search_read(&s,12,2)==0);
 assert(s.search2_result_reads==8 && s.search2.result_records==0);
 msm5xxx_poc_legacy_pn_write(&s,0,0,1);
 assert(s.search2_position==0 && s.search1_position==0);
 cmd[1]=1;
 for(unsigned i=0;i<6;i++)msm5xxx_poc_legacy_search_write(&s,4,cmd[i],2);
 msm5xxx_poc_legacy_search_complete(&s);
 assert(s.legacy_search_hits==1 && msm5xxx_poc_legacy_search_read(&s,12,2)==0);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/'test.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Wno-unused-const-variable','-Werror',
                            '-I',str(native),str(path/'test.c'),str(native/'msm5xxx-search2.c'),
                            '-o',str(path/'test')],check=True)
            subprocess.run([str(path/'test')],check=True)
