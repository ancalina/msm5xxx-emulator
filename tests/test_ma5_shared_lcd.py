"""Compile actual shared wrappers, LCD fallback, and registration loop."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'experiments/qemu-tcg/msm5xxx-poc.c'


def function(source, name):
    match = re.search(r'^static [^;\n]*\b' + name + r'\([^;]*?\)\n\{', source, re.M)
    if not match:
        raise AssertionError(name)
    opening = source.index('{', match.start())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


class SharedLCDTests(unittest.TestCase):
    def test_actual_wrappers_and_mapping(self):
        source = SOURCE.read_text()
        names = ('msm5xxx_poc_lcd_read', 'msm5xxx_poc_lcd_write',
                 'msm5xxx_poc_ma5_shared_lcd_port', 'msm5xxx_poc_ma5_shared_lcd_route',
                 'msm5xxx_poc_ma5_shared_lcd_read', 'msm5xxx_poc_ma5_shared_lcd_write')
        actual = '\n'.join(function(source, name) for name in names)
        begin = source.index('    for (i = 0; i < MSM5XXX_POC_LCD_PORTS; i++) {', source.index('"msm5xxx-poc.lcd-aperture"'))
        end = source.index('    if (s->lcd_trace_enabled)', begin)
        registration = source[begin:end]
        self.assertIn('if (!s->audio_ma2 && !s->audio_shared_lcd) {', source)
        self.assertNotIn('} else if (!s->audio_ma2 && !s->audio_shared_lcd) {', source)
        ops_start = source.index('static const MemoryRegionOps msm5xxx_poc_ma5_shared_lcd_ops =')
        ops = source[ops_start:source.index('\n};', ops_start)+3]
        harness = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
typedef uint64_t hwaddr;
typedef int MemTxResult;
typedef unsigned MemTxAttrs;
#define MEMTX_OK 0
#define MEMTX_ERROR 1
#define DEVICE_LITTLE_ENDIAN 0
#define MSM5XXX_POC_LCD_PORTS 4
#define MSM5XXX_POC_LCD_SIZE 0x1000
#define MSM5XXX_POC_READY_OBSERVING 0
#define MSM5XXX_POC_READY_CANDIDATE 1
#define MSM5XXX_POC_READY_ACCEPTED 2
#define MSM5XXX_POC_READY_REJECTED 3
#define MSM5XXX_POC_READY_POLL_DELAY 200000
#define MSM5XXX_POC_UPPER_NOR_BASE 0x02800000
static const hwaddr msm5xxx_poc_lcd_bases[4]={0x02000000,0x02800000,0x02c00000,0x02200000};
typedef struct CPUState { bool running; struct { bool can_do_io; } neg; } CPUState;
static CPUState cpu;
static CPUState *current_cpu=&cpu;
static bool vcpu=true, precise=true;
static uint32_t guest_pc=0x100;
#define CPU(x) (x)
typedef struct { uint32_t (*get_pc)(CPUState*); } CPUClass;
static uint32_t get_pc(CPUState *c) { (void)c; return guest_pc; }
static CPUClass cpuclass={get_pc};
#define CPU_GET_CLASS(x) (&cpuclass)
static bool qemu_in_vcpu_thread(void) { return vcpu; }
static uint64_t icount_get_raw(void) { return 300000; }
typedef struct MSM5xxxPOCMachineState MSM5xxxPOCMachineState;
typedef struct { MSM5xxxPOCMachineState *machine; unsigned index; } MSM5xxxPOCLCDPort;
typedef struct { int id; } MemoryRegion;
typedef struct {
 MemTxResult (*read_with_attrs)(void*,hwaddr,uint64_t*,unsigned,MemTxAttrs);
 MemTxResult (*write_with_attrs)(void*,hwaddr,uint64_t,unsigned,MemTxAttrs);
 int endianness;
 struct { unsigned min_access_size,max_access_size; } valid,impl;
} MemoryRegionOps;
struct MSM5xxxPOCMachineState {
 CPUState *cpu;
 bool audio_enabled,audio_ma5,audio_ma2,audio_shared_lcd,audio_sites_enabled;
 uint64_t ma5_byte_ns;
 uint32_t audio_base,audio_data_offset;
 unsigned audio_site_count;
 uint32_t audio_site_pc[5];
 bool ready_poll_lcd_enabled;
 uint32_t ready_status_address,ready_control_address,ready_control_value;
 uint32_t ready_poll_phase,ready_poll_entry,ready_status_pc_offset,ready_control_pc_offset;
 uint32_t ready_poll_status,ready_status_mask;
 uint64_t ready_poll_reads,ready_poll_cycles,ready_poll_first_icount,ready_poll_responses;
 uint64_t lcd_reads[4],lcd_writes[4];
 uint8_t lcd_backing[4][4096];
 MSM5xxxPOCLCDPort lcd_port[4]; MemoryRegion lcd[4];
 uint32_t intel_x16_nor_base,intel_x16_nor_size,raw_nand_data_address;
 bool raw_nand_main_enabled;
};
static unsigned audio_calls,trace_calls;
static bool core_ok=true;
static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState*s,uint32_t*p) {
 (void)s;*p=guest_pc;return precise;
}
static uint64_t msm5xxx_poc_backing_read(uint8_t*b,hwaddr o,unsigned n) {
 uint64_t v=0; memcpy(&v,b+o,n);return v;
}
static void msm5xxx_poc_backing_write(uint8_t*b,hwaddr o,uint64_t v,unsigned n) { memcpy(b+o,&v,n); }
static void msm5xxx_poc_lcd_trace_write(MSM5xxxPOCMachineState*s,hwaddr a,uint64_t v,unsigned n) {
 (void)s;(void)a;(void)v;(void)n;trace_calls++;
}
/* Existing opaque guard/core is unchanged. Stub its dependencies/result boundary. */
static MemTxResult opaque_access(MSM5xxxPOCMachineState*s,hwaddr o,unsigned n,bool write) {
 audio_calls++;
 if(n!=1 || (o!=0 && o!=s->audio_data_offset) || !cpu.neg.can_do_io || !core_ok)
  return MEMTX_ERROR;
 /* site100 is write index, site200 is read data. */
 return ((write && guest_pc==0x100 && o==0) ||
         (!write && guest_pc==0x200 && o==s->audio_data_offset)) ? MEMTX_OK : MEMTX_ERROR;
}
static MemTxResult msm5xxx_poc_audio_opaque_read(void*s,hwaddr o,uint64_t*v,unsigned n,MemTxAttrs a) {
 (void)a;MemTxResult r=opaque_access(s,o,n,false);if(!r)*v=0x42;return r;
}
static MemTxResult msm5xxx_poc_audio_opaque_write(void*s,hwaddr o,uint64_t v,unsigned n,MemTxAttrs a) {
 (void)v;(void)a;return opaque_access(s,o,n,true);
}
'''
        setup = r'''
static const MemoryRegionOps msm5xxx_poc_lcd_ops={0};
static const MemoryRegionOps *registered[4];
static unsigned initialized;
#define OBJECT(x) (x)
static void *get_system_memory(void) { return NULL; }
static void memory_region_init_io(MemoryRegion*r,void*m,const MemoryRegionOps*ops,void*p,const char*n,unsigned size) {
 (void)m;(void)n;(void)size; MSM5xxxPOCLCDPort*port=p;r->id=port->index;registered[port->index]=ops;initialized++;
}
static void memory_region_add_subregion(void*m,hwaddr b,MemoryRegion*r) {(void)m;(void)b;(void)r;}
static void register_ports(MSM5xxxPOCMachineState*s,bool upper_nor_enabled,bool direct_x16_nor_enabled) {
 void *machine=NULL;unsigned i;
'''+registration+r'''
}
int main(void) {
 MSM5xxxPOCMachineState s={0}; uint64_t value=0; unsigned n;
 s.cpu=&cpu;cpu.running=true;cpu.neg.can_do_io=true;
 s.audio_enabled=true;s.audio_ma5=true;s.ma5_byte_ns=1000;
 s.audio_base=0x02c00000;s.audio_data_offset=4;s.audio_sites_enabled=true;
 s.audio_site_count=2;s.audio_site_pc[0]=0x100;s.audio_site_pc[1]=0x200;
 assert(msm5xxx_poc_ma5_shared_lcd_port(&s)==2);
 assert(!s.audio_shared_lcd);
 register_ports(&s,false,false);
 assert(initialized==4 && s.audio_shared_lcd && registered[2]==&msm5xxx_poc_ma5_shared_lcd_ops);
 assert(registered[0]==&msm5xxx_poc_lcd_ops && registered[1]==&msm5xxx_poc_lcd_ops);
 assert(msm5xxx_poc_ma5_shared_lcd_ops.impl.max_access_size==4);
 assert(msm5xxx_poc_ma5_shared_lcd_ops.impl.min_access_size==1);
 MSM5xxxPOCLCDPort *p=&s.lcd_port[2];
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,0,1,1,0)==MEMTX_OK);
 guest_pc=0x200;
 assert(msm5xxx_poc_ma5_shared_lcd_read(p,4,&value,1,0)==MEMTX_OK && value==0x42);
 /* Every malformed owned access stays an error, even outside tiny span. */
 guest_pc=0x100;
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,0,1,2,0)==MEMTX_ERROR);
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,4,1,1,0)==MEMTX_ERROR);
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,8,1,1,0)==MEMTX_ERROR);
 assert(msm5xxx_poc_ma5_shared_lcd_read(p,0,&value,1,0)==MEMTX_ERROR);
 core_ok=false;assert(msm5xxx_poc_ma5_shared_lcd_write(p,0,1,1,0)==MEMTX_ERROR);core_ok=true;
 cpu.neg.can_do_io=false;assert(msm5xxx_poc_ma5_shared_lcd_write(p,0,1,1,0)==MEMTX_ERROR);cpu.neg.can_do_io=true;
 assert(s.lcd_writes[2]==0 && s.lcd_reads[2]==0 && trace_calls==0);
 /* Known unowned transactions preserve original LCD width/backing/count/trace. */
 guest_pc=0x300;
 for(n=1;n<=4;n*=2) {
  unsigned before=audio_calls;
  assert(msm5xxx_poc_ma5_shared_lcd_write(p,4,0x12345678,n,0)==MEMTX_OK);
  assert(msm5xxx_poc_ma5_shared_lcd_read(p,4,&value,n,0)==MEMTX_OK);
  assert(value==(0x12345678u & (n==4?0xffffffffu:((1u<<(8*n))-1))));
  assert(audio_calls==before);
 }
 assert(s.lcd_writes[2]==3 && s.lcd_reads[2]==3 && trace_calls==3);
 /* Original ready-poll path remains active on fallback. */
 s.ready_poll_lcd_enabled=true;s.ready_control_address=s.audio_base;
 s.ready_control_value=7;s.ready_poll_entry=guest_pc;s.ready_control_pc_offset=0;
 s.ready_status_pc_offset=0;s.ready_status_address=s.audio_base+4;
 s.ready_status_mask=1;s.ready_poll_status=MSM5XXX_POC_READY_ACCEPTED;
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,0,7,2,0)==MEMTX_OK);
 s.lcd_backing[2][4]=1;
 assert(msm5xxx_poc_ma5_shared_lcd_read(p,4,&value,2,0)==MEMTX_OK && !(value&1));
 assert(s.ready_poll_responses==1);
 /* Debugger/non-vCPU and foreign CPU are ordinary LCD transactions. */
 guest_pc=0x100;vcpu=false;
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,0,2,1,0)==MEMTX_OK);vcpu=true;
 CPUState foreign={0};current_cpu=&foreign;
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,0,2,1,0)==MEMTX_OK);current_cpu=&cpu;
 cpu.running=false;assert(msm5xxx_poc_ma5_shared_lcd_write(p,0,2,1,0)==MEMTX_OK);cpu.running=true;
 /* Unattributable true guest I/O errors only at intersecting tiny span. */
 precise=false;unsigned before=trace_calls;
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,4,2,1,0)==MEMTX_ERROR && trace_calls==before);
 assert(msm5xxx_poc_ma5_shared_lcd_read(p,0,&value,2,0)==MEMTX_ERROR);
 assert(msm5xxx_poc_ma5_shared_lcd_write(p,8,2,1,0)==MEMTX_OK);precise=true;
 /* Defaultoff, MA2 and standalone2/128 never choose shared mapping. */
 s.ma5_byte_ns=0;assert(msm5xxx_poc_ma5_shared_lcd_port(&s)==-1);s.ma5_byte_ns=1000;
 s.audio_ma5=false;s.audio_ma2=true;assert(msm5xxx_poc_ma5_shared_lcd_port(&s)==-1);
 s.audio_ma5=true;s.audio_ma2=false;
 for(n=2;n<=128;n*=64) {s.audio_base=0x02400000;s.audio_data_offset=n;assert(msm5xxx_poc_ma5_shared_lcd_port(&s)==-1);}
 s.audio_base=0x02c00ffe;s.audio_data_offset=4;assert(msm5xxx_poc_ma5_shared_lcd_port(&s)==-1);
 /* A skipped LCD region must not set the actual-registration flag. */
 s.audio_base=0x02c00000;s.audio_data_offset=4;s.audio_shared_lcd=false;
 s.raw_nand_main_enabled=true;s.raw_nand_data_address=s.audio_base;
 register_ports(&s,false,false);assert(!s.audio_shared_lcd);
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='ma5-shared-', dir=SOURCE.parent) as tmp:
            c = Path(tmp)/'harness.c'; binary=Path(tmp)/'harness'
            c.write_text(harness+actual+'\n'+ops+'\n'+setup)
            compiled = subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            subprocess.run([str(binary)],check=True,capture_output=True,text=True)


if __name__ == '__main__':
    unittest.main()
