"""Private actual-C paired-transfer controller; no QEMU/firmware execution."""
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


class DMD5100NativeTests(unittest.TestCase):
    def test_actual_variable_stream_context_barriers_and_topology(self):
        repo=Path(__file__).resolve().parents[1]
        source=(repo/'native/qemu/msm5xxx-poc.c').read_text()
        def function(name):
            match=re.search(r'^static [^\n]*(?:\n[^\n]*)?\b'+name+r'\(',source,re.M)
            self.assertIsNotNone(match,name)
            start=source.index('{',match.end());end=start+1;depth=1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[match.start():end]
        declarations=source[source.index('typedef struct {\n    MSM5xxxPOCMachineState *machine;\n    unsigned index;\n} MSM5xxxPOCDMD5100Port;'):source.index('struct MSM5xxxPOCMachineState {')]
        fields=source[source.index('    bool dmd5100_enabled,'):source.index('    MemoryRegion dmd_5500_start;')]
        code=r'''
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <glib.h>
typedef uint64_t hwaddr;
typedef int MemTxResult;
#define MEMTX_OK 0
#define MEMTX_ERROR 1
#define MSM5XXX_POC_MSM_BASE 0x03000000u
#define MSM5XXX_POC_MSM_SIZE 0x1000000u
typedef struct { unsigned marker; } MemTxAttrs;
typedef struct { bool enabled,readonly; } MemoryRegion;
typedef struct { bool thumb; uint32_t cpsr,regs[16]; struct { uint64_t sctlr_el[4]; uint32_t fcseidr_ns,fcseidr_s; } cp15; } CPUEnv;
typedef struct { CPUEnv env; } ARMCPU;
static uint32_t cpsr_read(CPUEnv *env){return env->cpsr;}
typedef struct MSM5xxxPOCMachineState MSM5xxxPOCMachineState;
''' + declarations + r'''
struct MSM5xxxPOCMachineState {
''' + fields + r'''
    ARMCPU *cpu;
    MemoryRegion nor,msm;
    bool memory_profile_enabled;
    uint32_t primary_nor_size;
};
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(p) (p)
typedef struct {int unused;} Error;
static Error failure;
static void error_setg(Error **err,const char *fmt,...){*err=&failure;}
static int qemu_strtoul(const char *text,const char **end,int base,unsigned long *value){
 char *tail;errno=0;*value=strtoul(text,&tail,base);*end=tail;return errno ? -errno : tail==text ? -EINVAL : 0;
}
static bool actual_guest=true;
static bool mock_unwind_valid, mock_unwind_current;
static uint32_t mock_unwind_pc;
static unsigned mock_unwind_calls;
static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState *s,uint32_t *pc){
 mock_unwind_calls++;*pc=mock_unwind_current ? s->cpu->env.regs[15] : mock_unwind_pc;return mock_unwind_valid;
}

static bool msm5xxx_poc_boot_storage_guest(MSM5xxxPOCMachineState *s){return actual_guest;}
static void memory_region_set_enabled(MemoryRegion *mr,bool enabled){mr->enabled=enabled;}
static bool memory_region_is_rom(MemoryRegion *mr){return mr->readonly;}
typedef struct {MemoryRegion *mr;uint64_t offset_within_region,size;} MemoryRegionSection;
static uint64_t int128_make64(uint64_t v){return v;}
static bool int128_eq(uint64_t a,uint64_t b){return a==b;}
static void *get_system_memory(void){return NULL;}
static MSM5xxxPOCMachineState *active;
static MemoryRegion foreign;
static uint64_t bad_address=UINT64_MAX;
static unsigned bad_kind,finds,unrefs;
static MemoryRegionSection memory_region_find(void *root,uint64_t at,uint64_t size){
 finds++;bool rom=at<active->primary_nor_size;
 MemoryRegion *mr=rom?&active->nor:&active->msm;uint64_t offset=rom?at:at-MSM5XXX_POC_MSM_BASE;
 if(at==bad_address){if(bad_kind==1)mr=&foreign;if(bad_kind==2)size--;if(bad_kind==3)offset++;if(bad_kind==4)mr=NULL;}
 return (MemoryRegionSection){mr,offset,size};
}
static void memory_region_unref(MemoryRegion *mr){assert(mr);unrefs++;}
typedef struct {int unused;} AddressSpace;
static AddressSpace address_space_memory;
static uint8_t backing[MSM5XXX_POC_MSM_SIZE];
static unsigned forwarded,forwarded_size,forwarded_attrs,dirty,ram_accesses;
static uint64_t dirty_address;
static unsigned dirty_size;
static uint64_t forwarded_address;
static bool bus_error;
static uint8_t *memory_region_get_ram_ptr(MemoryRegion *mr){assert(mr==&active->msm);ram_accesses++;return backing;}
static void memory_region_set_dirty(MemoryRegion *mr,uint64_t at,unsigned size){assert(mr==&active->msm && at+size<=sizeof(backing));dirty++;dirty_address=at;dirty_size=size;}
static MemTxResult address_space_write(AddressSpace *as,uint64_t at,MemTxAttrs attrs,const void *bytes,unsigned size){
 for(unsigned n=0;n<5;n++)assert(!active->dmd5100_region[n].enabled);
 assert(at>=MSM5XXX_POC_MSM_BASE && at+size<=MSM5XXX_POC_MSM_BASE+sizeof(backing));
 forwarded++;forwarded_address=at;forwarded_size=size;forwarded_attrs=attrs.marker;
 if(bus_error){return MEMTX_ERROR;}memcpy(backing+at-MSM5XXX_POC_MSM_BASE,bytes,size);return MEMTX_OK;
}
static MemTxResult address_space_read(AddressSpace *as,uint64_t at,MemTxAttrs attrs,void *bytes,unsigned size){
 for(unsigned n=0;n<5;n++)assert(!active->dmd5100_region[n].enabled);
 assert(at>=MSM5XXX_POC_MSM_BASE && at+size<=MSM5XXX_POC_MSM_BASE+sizeof(backing));
 forwarded++;forwarded_address=at;forwarded_size=size;forwarded_attrs=attrs.marker;
 if(bus_error){return MEMTX_ERROR;}memcpy(bytes,backing+at-MSM5XXX_POC_MSM_BASE,size);return MEMTX_OK;
}
'''
        names=('backing_read','backing_write','dmd5100_active','dmd5100_regions','dmd5100_record_rejection','dmd5100_reject',
               'dmd5100_reset','dmd5100_pc','dmd5100_forward','dmd5100_write_next',
               'dmd5100_write','dmd5100_read','get_dmd5100','set_dmd5100',
               'get_dmd5100_stats','get_dmd5100_rejection','dmd5100_topology')
        code+='\n'.join(function('msm5xxx_poc_'+name)for name in names)
        code+=r'''
static ARMCPU cpu;
static uint16_t even_words[16],odd_words[16];
static void select_state(MSM5xxxPOCMachineState *s){active=s;for(unsigned n=0;n<5;n++)s->dmd5100_port[n]=(MSM5xxxPOCDMD5100Port){s,n};}
static void context(MSM5xxxPOCMachineState *s,unsigned relative){select_state(s);cpu.env.regs[15]=s->dmd5100_entry+relative;}
static MSM5xxxPOCMachineState fresh(void){
 MSM5xxxPOCMachineState s={0};Error *err=NULL;memset(&cpu,0,sizeof(cpu));cpu.env.thumb=true;
 msm5xxx_poc_set_dmd5100(&s,"1000:2000:3000:3",&err);assert(!err);
 s.cpu=&cpu;s.memory_profile_enabled=true;s.primary_nor_size=0x800000;s.nor.readonly=true;
 s.dmd5100_even=even_words;s.dmd5100_odd=odd_words;s.dmd5100_mapped=true;s.dmd5100_ram_verified=true;
 for(unsigned n=0;n<16;n++)even_words[n]=odd_words[n]=0xdead;
 msm5xxx_poc_dmd5100_reset(&s);actual_guest=true;bus_error=false;mock_unwind_valid=true;mock_unwind_current=true;mock_unwind_pc=0xdeadbeef;mock_unwind_calls=0;return s;
}
static void wr(MSM5xxxPOCMachineState *s,unsigned port,unsigned rel,uint64_t value,unsigned width){
 context(s,rel);unsigned before=forwarded+dirty;
 assert(msm5xxx_poc_dmd5100_write(&s->dmd5100_port[port],0,value,width,(MemTxAttrs){73})==MEMTX_OK);
 assert(forwarded+dirty==before+1);
 if(s->dmd5100_ram_verified && width<=4){assert(dirty_address==dmd5100_ports[port]-MSM5XXX_POC_MSM_BASE && dirty_size==width);}else{assert(forwarded_address==dmd5100_ports[port] && forwarded_size==width && forwarded_attrs==73);}
}
static uint64_t rd(MSM5xxxPOCMachineState *s,unsigned port,unsigned rel,unsigned width){
 context(s,rel);uint64_t value=0;assert(msm5xxx_poc_dmd5100_read(&s->dmd5100_port[port],0,&value,width,(MemTxAttrs){91})==MEMTX_OK);return value;
}
static void hold_config(MSM5xxxPOCMachineState *s){
 cpu.env.regs[7]=0;cpu.env.regs[3]=0xbadcafe;wr(s,2,0x1a,0,1);assert(s->dmd5100_phase==DMD5100_HOLD);
 cpu.env.regs[3]=s->dmd5100_descriptor;wr(s,0,0x24,0,2);assert(s->dmd5100_phase==DMD5100_PROGRAM);
}
static uint16_t odd(unsigned i){return (uint16_t)(0x8001+i*311);}
static uint16_t even(unsigned i){return (uint16_t)(i==1?0:0x1234+i*17);}
static void program(MSM5xxxPOCMachineState *s){
 hold_config(s);
 for(unsigned i=0;i<3;i++){
  cpu.env.regs[3]=s->dmd5100_descriptor;cpu.env.regs[7]=2*i;
  wr(s,1,0x3c,odd(i),2);cpu.env.regs[2]=s->dmd5100_payload;wr(s,1,0x42,even(i),2);
 }
 assert(s->dmd5100_pairs==3 && s->dmd5100_phase==DMD5100_FULL);
}
static void mode_rewind(MSM5xxxPOCMachineState *s){
 cpu.env.regs[7]=6;cpu.env.regs[6]=0x030007e0;wr(s,3,0x5e,0xe,1);wr(s,4,0x62,0,1);
 assert(s->dmd5100_phase==DMD5100_EVEN && !s->dmd5100_barrier);
}
static void even_context(MSM5xxxPOCMachineState *s,unsigned i){
 cpu.env.regs[7]=s->dmd5100_descriptor;cpu.env.regs[2]=s->dmd5100_payload;
 cpu.env.regs[4]=2*i;cpu.env.regs[0]=i;cpu.env.regs[3]=3;cpu.env.regs[1]=0xbeef;
}
static void odd_context(MSM5xxxPOCMachineState *s,unsigned i){
 cpu.env.regs[7]=3;cpu.env.regs[4]=s->dmd5100_payload;cpu.env.regs[1]=2*i;
 cpu.env.regs[0]=i;cpu.env.regs[2]=0x030007e0;cpu.env.regs[3]=0xbeef;
}
static void even_pass(MSM5xxxPOCMachineState *s){
 cpu.env.regs[7]=6;cpu.env.regs[6]=0x030007e0;assert(rd(s,3,0x64,1)==backing[0x7e8]);
 for(unsigned i=0;i<3;i++){even_context(s,i);unsigned before=forwarded;assert(rd(s,3,0x78,2)==even(i));assert(forwarded==before);}
 assert(s->dmd5100_phase==DMD5100_EVEN_DONE);
}
int main(void){
 MSM5xxxPOCMachineState s=fresh(),saved;Error *err=NULL;char *text;
 select_state(&s);assert(msm5xxx_poc_dmd5100_topology(&s));assert(finds==unrefs);
 text=msm5xxx_poc_get_dmd5100(&s,NULL);assert(!strcmp(text,"1000:2000:3000:3"));g_free(text);
 for(unsigned k=0;k<8;k++)for(unsigned kind=1;kind<=4;kind++){
  const uint64_t points[]={0x1000,0x2000,0x3000,0x0300004c,0x03000050,0x0300005c,0x030007e8,0x030007ec};
  bad_address=points[k];bad_kind=kind;assert(!msm5xxx_poc_dmd5100_topology(&s));
 }bad_address=UINT64_MAX;
 s.nor.readonly=false;assert(!msm5xxx_poc_dmd5100_topology(&s));s.nor.readonly=true;
 saved=s;s.dmd5100_entry=0x7fff80;assert(!msm5xxx_poc_dmd5100_topology(&s));s=saved;
 s.dmd5100_payload=0x7ffffc;assert(!msm5xxx_poc_dmd5100_topology(&s));s=saved;
 const char *bad[]={NULL,"","1001:2000:3000:3","1000:2001:3000:3","1000:2000:3001:3","1000:2000:3000:0","1000:2000:3000:8000","1000:2000:3000:3:","100000000:2000:3000:3"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++){MSM5xxxPOCMachineState t={0},copy=t;err=NULL;msm5xxx_poc_set_dmd5100(&t,bad[i],&err);assert(err && !memcmp(&t,&copy,sizeof(t)));}
 saved=s;err=NULL;msm5xxx_poc_set_dmd5100(&s,"1000:2000:3000:3",&err);assert(err && !memcmp(&s,&saved,sizeof(s)));
 /* Verified in-port RAM path has exactly one write/dirty or one read, no topology forwarding. */
 select_state(&s);unsigned fw0=forwarded,dirty0=dirty,ram0=ram_accesses;uint64_t direct=0x2468;
 assert(msm5xxx_poc_dmd5100_forward(&s.dmd5100_port[0],0,&direct,2,(MemTxAttrs){12},true)==MEMTX_OK);
 assert(forwarded==fw0 && dirty==dirty0+1 && ram_accesses==ram0+1 && dirty_address==0x4c && dirty_size==2);
 direct=0;ram0=ram_accesses;
 assert(msm5xxx_poc_dmd5100_forward(&s.dmd5100_port[0],0,&direct,2,(MemTxAttrs){13},false)==MEMTX_OK);
 assert(direct==0x2468 && forwarded==fw0 && dirty==dirty0+1 && ram_accesses==ram0+1);
 direct=0x5678;fw0=forwarded;dirty0=dirty;
 assert(msm5xxx_poc_dmd5100_forward(&s.dmd5100_port[0],3,&direct,2,(MemTxAttrs){14},true)==MEMTX_OK);
 assert(forwarded==fw0+1 && dirty==dirty0 && forwarded_address==0x0300004f && forwarded_size==2 && forwarded_attrs==14);
 s.dmd5100_ram_verified=false;fw0=forwarded;direct=0xabcd;
 assert(msm5xxx_poc_dmd5100_forward(&s.dmd5100_port[0],0,&direct,2,(MemTxAttrs){15},true)==MEMTX_OK);
 assert(forwarded==fw0+1 && dirty==dirty0 && forwarded_attrs==15);s.dmd5100_ram_verified=true;
 /* Actual variable words, not expected R1/R3 or payload memory contents. */
 program(&s);mode_rewind(&s);actual_guest=false;
 even_context(&s,0);assert(rd(&s,3,0x78,2)==even(0) && !s.dmd5100_even_reads && !s.dmd5100_barrier);
 cpu.env.regs[7]=6;cpu.env.regs[6]=0x030007e0;rd(&s,3,0x64,1);assert(!s.dmd5100_barrier);actual_guest=true;
 even_pass(&s);cpu.env.regs[7]=s.dmd5100_descriptor;cpu.env.regs[4]=6;cpu.env.regs[2]=0x030007e0;
 wr(&s,4,0x8e,0,1);assert(rd(&s,3,0x90,1)==backing[0x7e8]);
 for(unsigned i=0;i<3;i++){odd_context(&s,i);assert(rd(&s,4,0xa4,2)==odd(i));}
 assert(s.dmd5100_phase==DMD5100_ODD_DONE);cpu.env.regs[7]=3;cpu.env.regs[4]=s.dmd5100_payload;cpu.env.regs[1]=6;cpu.env.regs[0]=0;
 wr(&s,3,0xb8,0,1);wr(&s,2,0xc8,1,1);assert(s.dmd5100_phase==DMD5100_CLOSED);
 text=msm5xxx_poc_get_dmd5100_stats(&s,NULL);assert(strstr(text,"pairs=3 even=3 odd=3"));g_free(text);
 /* New hold invalidates epoch validity; unwritten/debugger observations fall back. */
 cpu.env.regs[7]=0;wr(&s,2,0x1a,0,1);actual_guest=false;uint64_t raw=msm5xxx_poc_backing_read(backing,0x7e8,2);
 assert(rd(&s,3,0x78,2)==raw && !s.dmd5100_pairs);actual_guest=true;
 for(unsigned kind=0;kind<7;kind++){
  s=fresh();cpu.env.regs[7]=0;
  if(kind==0){cpu.env.thumb=false;}if(kind==1){cpu.env.cp15.sctlr_el[1]=1;}
  if(kind==2){cpu.env.cp15.fcseidr_ns=1;}if(kind==3){cpu.env.cp15.fcseidr_s=1;}
  if(kind==4)actual_guest=false;
  wr(&s,2,kind==5?0x1c:0x1a,0,kind==6?2:1);
  assert(s.dmd5100_phase!=(unsigned)DMD5100_HOLD && !s.dmd5100_pairs);
 }
 actual_guest=true;s=fresh();hold_config(&s);cpu.env.regs[3]=s.dmd5100_descriptor;cpu.env.regs[7]=0;cpu.env.regs[2]=s.dmd5100_payload;
 wr(&s,1,0x42,0x5678,2);assert(s.dmd5100_phase==DMD5100_REJECTED); /* no odd */
 s=fresh();hold_config(&s);cpu.env.regs[3]++;wr(&s,1,0x3c,0x5678,2);assert(!s.dmd5100_pairs && s.dmd5100_phase==DMD5100_REJECTED);
 s=fresh();program(&s);cpu.env.regs[7]=6;cpu.env.regs[6]=0x030007e0;wr(&s,3,0x5e,0xf,1);assert(s.dmd5100_phase==DMD5100_REJECTED);
 s=fresh();program(&s);mode_rewind(&s);even_context(&s,0);rd(&s,3,0x78,2);assert(!s.dmd5100_even_reads && s.dmd5100_phase==DMD5100_REJECTED); /* no guest barrier */
 s=fresh();program(&s);mode_rewind(&s);even_pass(&s);even_context(&s,3);rd(&s,3,0x78,2);assert(s.dmd5100_even_reads==3 && s.dmd5100_phase==DMD5100_REJECTED); /* no wrap */
 s=fresh();program(&s);mode_rewind(&s);even_pass(&s);cpu.env.regs[7]=s.dmd5100_descriptor;cpu.env.regs[4]=6;cpu.env.regs[2]=0x030007e0;wr(&s,4,0x8e,0,1);rd(&s,3,0x90,1);
 odd_context(&s,0);cpu.env.regs[7]=s.dmd5100_descriptor;rd(&s,4,0xa4,2);assert(!s.dmd5100_odd_reads && s.dmd5100_phase==DMD5100_REJECTED);
 s=fresh();hold_config(&s);cpu.env.regs[7]=6;cpu.env.regs[6]=0x030007e0;wr(&s,3,0x5e,0xe,1);assert(s.dmd5100_phase==DMD5100_REJECTED); /* incomplete stream */
 s=fresh();hold_config(&s);cpu.env.regs[3]=s.dmd5100_descriptor;cpu.env.regs[7]=2;wr(&s,1,0x3c,0x7777,2);assert(!s.dmd5100_pairs && s.dmd5100_phase==DMD5100_REJECTED);
 s=fresh();cpu.env.regs[7]=0;wr(&s,2,0x1a,0,1);cpu.env.regs[3]=s.dmd5100_descriptor;wr(&s,0,0x24,1,2);assert(s.dmd5100_phase==DMD5100_REJECTED);
 s=fresh();hold_config(&s);unsigned original=forwarded;uint64_t unwritten=msm5xxx_poc_backing_read(backing,0x7e8,2);
 assert(rd(&s,3,0x78,2)==unwritten && forwarded==original && s.dmd5100_phase==DMD5100_REJECTED);
 s=fresh();program(&s);mode_rewind(&s);cpu.env.regs[7]=6;cpu.env.regs[6]=0x030007e0;rd(&s,3,0x64,1);
 even_context(&s,0);cpu.env.regs[0]=1;rd(&s,3,0x78,2);assert(!s.dmd5100_even_reads && s.dmd5100_phase==DMD5100_REJECTED);
 s=fresh();program(&s);mode_rewind(&s);even_pass(&s);cpu.env.regs[7]=s.dmd5100_descriptor;cpu.env.regs[4]=6;cpu.env.regs[2]=0x030007e0;wr(&s,4,0x8e,0,1);
 odd_context(&s,0);rd(&s,4,0xa4,2);assert(!s.dmd5100_odd_reads && s.dmd5100_phase==DMD5100_REJECTED); /* missing second barrier */
 {MSM5xxxPOCMachineState t={0},copy;Error *late=NULL;t.cpu=&cpu;copy=t;
  msm5xxx_poc_set_dmd5100(&t,"1000:2000:3000:3",&late);assert(late && !memcmp(&t,&copy,sizeof(t)));}
 s=fresh();hold_config(&s);saved=s;actual_guest=false;cpu.env.regs[3]=s.dmd5100_descriptor;wr(&s,1,0x3c,0xabcd,2);assert(s.dmd5100_phase==saved.dmd5100_phase && !s.dmd5100_pairs);actual_guest=true;
 s.dmd5100_ram_verified=false;bus_error=true;context(&s,0x3c);unsigned before=forwarded;
 assert(msm5xxx_poc_dmd5100_write(&s.dmd5100_port[1],0,0xabcd,2,(MemTxAttrs){15})==MEMTX_ERROR);assert(forwarded==before+1 && s.dmd5100_phase==DMD5100_REJECTED);bus_error=false;
 s=fresh();program(&s);mode_rewind(&s);s.dmd5100_ram_verified=false;actual_guest=false;bus_error=true;context(&s,0x64);uint64_t failed=0;before=forwarded;
 assert(msm5xxx_poc_dmd5100_read(&s.dmd5100_port[3],0,&failed,1,(MemTxAttrs){22})==MEMTX_ERROR);
 assert(forwarded==before+1 && s.dmd5100_phase==DMD5100_EVEN && !s.dmd5100_barrier);
 actual_guest=true;cpu.env.regs[7]=6;cpu.env.regs[6]=0x030007e0;before=forwarded;
 assert(msm5xxx_poc_dmd5100_read(&s.dmd5100_port[3],0,&failed,1,(MemTxAttrs){22})==MEMTX_ERROR);
 assert(forwarded==before+1 && s.dmd5100_phase==DMD5100_REJECTED && !s.dmd5100_barrier);bus_error=false;
 msm5xxx_poc_dmd5100_reset(&s);assert(s.dmd5100_phase==DMD5100_IDLE && !s.dmd5100_pairs && !s.dmd5100_rejections);
 for(unsigned i=0;i<5;i++)assert(s.dmd5100_region[i].enabled==(i==2));

 /* First actual-guest rejection is diagnostic only; getters consume nothing. */
 s=fresh();text=msm5xxx_poc_get_dmd5100_rejection(&s,NULL);assert(!strcmp(text,"recorded=0"));g_free(text);
 program(&s);context(&s,0x3c);
 for(unsigned i=0;i<8;i++)cpu.env.regs[i]=0x100+i;
 cpu.env.regs[14]=0xabcdef01;cpu.env.cpsr=0xa00000f3;
 cpu.env.cp15.sctlr_el[1]=0x70;cpu.env.cp15.fcseidr_ns=0x2000000;cpu.env.cp15.fcseidr_s=0x4000000;
 mock_unwind_valid=true;mock_unwind_current=false;mock_unwind_pc=s.dmd5100_entry+0x42;
 CPUEnv cpu_before=cpu.env;unsigned dirty_before=dirty,forward_before=forwarded;
 unsigned query_before=mock_unwind_calls;
 assert(msm5xxx_poc_dmd5100_write(&s.dmd5100_port[1],1,0x77,1,(MemTxAttrs){73})==MEMTX_OK);
 assert(!memcmp(&cpu.env,&cpu_before,sizeof(cpu.env)));
 assert(dirty==dirty_before+1 && forwarded==forward_before);
 assert(s.dmd5100_phase==DMD5100_REJECTED && s.dmd5100_rejections==1 && s.dmd5100_first_rejection);
 assert(s.dmd5100_rejection_write && s.dmd5100_rejection_port==1 && s.dmd5100_rejection_offset==1);
 assert(s.dmd5100_rejection_size==1 && s.dmd5100_rejection_value==0x77 && s.dmd5100_rejection_value_valid);
 assert(s.dmd5100_rejection_result==MEMTX_OK && s.dmd5100_rejection_phase==DMD5100_FULL && s.dmd5100_rejection_pairs==3);
 assert(s.dmd5100_rejection_pc==s.dmd5100_entry+0x3c && s.dmd5100_rejection_lr==0xabcdef01);
 assert(s.dmd5100_rejection_recovered_pc_valid && s.dmd5100_rejection_recovered_pc==s.dmd5100_entry+0x42 && mock_unwind_calls==query_before+1);

 for(unsigned i=0;i<8;i++)assert(s.dmd5100_rejection_regs[i]==0x100+i);
 assert(s.dmd5100_rejection_cpsr==0xa00000f3 && s.dmd5100_rejection_sctlr==0x70);
 assert(s.dmd5100_rejection_fcse_ns==0x2000000 && s.dmd5100_rejection_fcse_s==0x4000000);
 char *first=msm5xxx_poc_get_dmd5100_rejection(&s,NULL);saved=s;
 text=msm5xxx_poc_get_dmd5100_rejection(&s,NULL);
 assert(!strcmp(text,first) && !memcmp(&s,&saved,sizeof(s)) && !memcmp(&cpu.env,&cpu_before,sizeof(cpu.env)));
 assert(dirty==dirty_before+1 && forwarded==forward_before && strstr(text,"op=write port=1 offset=0x1 size=1 value_valid=1 value=0x77"));g_free(text);
 assert(mock_unwind_calls==query_before+1);text=msm5xxx_poc_get_dmd5100_rejection(&s,NULL);
 assert(strstr(text,"pc=0000103c recovered_pc_valid=1 recovered_pc=00001042"));g_free(text);

 mock_unwind_current=true;cpu.env.cp15.fcseidr_ns=cpu.env.cp15.fcseidr_s=0;cpu.env.regs[7]=0;
 wr(&s,2,0x1a,0,1);assert(s.dmd5100_phase==DMD5100_HOLD); /* HOLD does not clear first record. */
 wr(&s,0,0x24,1,2);assert(s.dmd5100_rejections==2);
 text=msm5xxx_poc_get_dmd5100_rejection(&s,NULL);assert(!strcmp(first,text));g_free(text);g_free(first);
 assert(mock_unwind_calls==query_before+2);
 msm5xxx_poc_dmd5100_reset(&s);text=msm5xxx_poc_get_dmd5100_rejection(&s,NULL);
 assert(!strcmp(text,"recorded=0") && !s.dmd5100_first_rejection);g_free(text);
 assert(!s.dmd5100_rejection_recovered_pc_valid && !s.dmd5100_rejection_recovered_pc);
 /* Non-guest accesses never create/replace the record or qualify a phase. */
 s=fresh();hold_config(&s);actual_guest=false;saved=s;query_before=mock_unwind_calls;
 uint64_t observed=0;context(&s,0x123);
 assert(msm5xxx_poc_dmd5100_read(&s.dmd5100_port[3],0,&observed,2,(MemTxAttrs){19})==MEMTX_OK);
 assert(!s.dmd5100_first_rejection && s.dmd5100_phase==saved.dmd5100_phase);
 wr(&s,1,0x3c,0x7777,2);assert(!s.dmd5100_first_rejection && s.dmd5100_phase==saved.dmd5100_phase);
 assert(mock_unwind_calls==query_before);
 /* A rejected guest read records the actual fallback value, without consuming lanes. */
 actual_guest=true;s=fresh();hold_config(&s);context(&s,0x123);backing[0x7e8]=0xef;backing[0x7e9]=0xbe;
 observed=0;assert(msm5xxx_poc_dmd5100_read(&s.dmd5100_port[3],0,&observed,2,(MemTxAttrs){19})==MEMTX_OK);
 assert(observed==0xbeef && !s.dmd5100_rejection_write && s.dmd5100_rejection_value==observed);
 assert(s.dmd5100_rejection_value_valid && s.dmd5100_rejection_phase==DMD5100_PROGRAM && !s.dmd5100_rejection_pairs);
 assert(!s.dmd5100_even_reads && !s.dmd5100_odd_reads && s.dmd5100_phase==DMD5100_REJECTED);
 text=msm5xxx_poc_get_dmd5100_rejection(&s,NULL);assert(strstr(text,"op=read port=3 offset=0x0 size=2 value_valid=1 value=0xbeef"));g_free(text);
 /* A failed read cannot expose or inspect an undefined output as valid data. */
 s=fresh();hold_config(&s);context(&s,0x123);s.dmd5100_ram_verified=false;bus_error=true;mock_unwind_valid=false;mock_unwind_current=false;observed=0xfeed;query_before=mock_unwind_calls;
 assert(msm5xxx_poc_dmd5100_read(&s.dmd5100_port[3],0,&observed,2,(MemTxAttrs){19})==MEMTX_ERROR);
 assert(observed==0xfeed && s.dmd5100_first_rejection && !s.dmd5100_rejection_value_valid);
 assert(!s.dmd5100_rejection_value && s.dmd5100_rejection_result==MEMTX_ERROR);bus_error=false;
 assert(!s.dmd5100_rejection_recovered_pc_valid && !s.dmd5100_rejection_recovered_pc && mock_unwind_calls==query_before+1);
 text=msm5xxx_poc_get_dmd5100_rejection(&s,NULL);assert(strstr(text,"recovered_pc_valid=0 recovered_pc=00000000"));g_free(text);


 /* A stale envPC never grants permission; only exact recovered MMIO PC does. */
 s=fresh();hold_config(&s);cpu.env.regs[3]=s.dmd5100_descriptor;cpu.env.regs[7]=0;
 wr(&s,1,0x3c,odd(0),2);assert(s.dmd5100_half_pending && !s.dmd5100_pairs);
 context(&s,0x3e);cpu.env.regs[2]=s.dmd5100_payload;
 mock_unwind_current=false;mock_unwind_valid=true;mock_unwind_pc=s.dmd5100_entry+0x42;cpu_before=cpu.env;
 assert(msm5xxx_poc_dmd5100_write(&s.dmd5100_port[1],0,even(0),2,(MemTxAttrs){73})==MEMTX_OK);
 assert(!memcmp(&cpu.env,&cpu_before,sizeof(cpu.env)) && s.dmd5100_pairs==1 && !s.dmd5100_half_pending && s.dmd5100_phase==DMD5100_PROGRAM);
 assert(s.dmd5100_even[0]==even(0) && s.dmd5100_odd[0]==odd(0) && !s.dmd5100_first_rejection);
 for(unsigned kind=0;kind<2;kind++){
  s=fresh();hold_config(&s);cpu.env.regs[3]=s.dmd5100_descriptor;cpu.env.regs[7]=0;
  wr(&s,1,0x3c,odd(0),2);context(&s,0x42);cpu.env.regs[2]=s.dmd5100_payload;
  mock_unwind_current=false;mock_unwind_valid=kind!=0;mock_unwind_pc=s.dmd5100_entry+0x3e;cpu_before=cpu.env;
  assert(msm5xxx_poc_dmd5100_write(&s.dmd5100_port[1],0,even(0),2,(MemTxAttrs){73})==MEMTX_OK);
  assert(!memcmp(&cpu.env,&cpu_before,sizeof(cpu.env)) && !s.dmd5100_pairs && s.dmd5100_phase==DMD5100_REJECTED);
  assert(s.dmd5100_first_rejection && s.dmd5100_rejection_pc==s.dmd5100_entry+0x42);
 }
 puts("DMD5100 actual-C variable program/readback/barrier/context/topology/reset PASS");return 0;
}
'''
        flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','glib-2.0'],text=True,timeout=10))
        with tempfile.TemporaryDirectory(prefix='.dmd5100-native-',dir=repo)as temporary:
            path=Path(temporary);(path/'check.c').write_text(code)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                            '-fsanitize=undefined','-fno-sanitize-recover=all',
                            str(path/'check.c'),'-o',str(path/'check'),*flags],check=True,timeout=30)
            subprocess.run([str(path/'check')],check=True,timeout=10)
        init=function('msm5xxx_poc_init')
        self.assertLess(init.index('msm5xxx_poc_boot_keysense_init(machine'),init.index('msm5xxx_poc_dmd5100_topology(s)'))
        self.assertIn('qemu_unregister_reset(msm5xxx_poc_dmd5100_reset, s);',source)
        self.assertIn('msm5xxx_poc_get_dmd5100_rejection, NULL);',source)
        self.assertNotIn('memory_region_get_ram_ptr(&s->nor)', '\n'.join(function('msm5xxx_poc_'+n)for n in names))


if __name__=='__main__':unittest.main()
