"""Extract and exercise actual native UART helpers; no QEMU/guest/build tree."""
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class UARTConsoleNativeTests(unittest.TestCase):
    def test_native_aliases_init_reset_and_underlay_forwarding(self):
        repo=Path(__file__).resolve().parents[1]
        source=(repo/'native/qemu/msm5xxx-poc.c').read_text()
        def function(name):
            match=re.search(r'^static [^\n]*(?:\n[^\n]*)?\b'+name+r'\(',source,re.M)
            self.assertIsNotNone(match,name)
            brace=source.index('{',match.end());depth=1;end=brace+1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[match.start():end]
        fields=source[source.index('    bool uart_console_enabled,'):
                      source.index('    bool ready_poll_enabled;')]
        constants='\n'.join(re.findall(r'^#define MSM5XXX_POC_(?:MSM_BASE|MSM_SIZE) .+$',source,re.M))
        harness=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#define MiB (1024*1024)
typedef uint64_t hwaddr;
typedef int MemTxResult;
#define MEMTX_OK 0
#define MEMTX_ERROR 1
typedef struct { unsigned marker; } MemTxAttrs;
typedef struct { bool enabled,readonly; } MemoryRegion;
typedef struct { int unused; } AddressSpace;
static AddressSpace address_space_memory;
static void memory_region_set_enabled(MemoryRegion *region,bool enabled) {
    region->enabled=enabled;
}
typedef struct { int marker; } Error;
static Error failure;
static void error_setg(Error **error,const char *format,...) {
    (void)format;*error=&failure;
}
static int qemu_strtoul(const char *text,const char **end,int base,unsigned long *value) {
    char *tail;errno=0;*value=strtoul(text,&tail,base);*end=tail;
    return errno ? -errno : tail==text ? -EINVAL : 0;
}
''' + constants + r'''
typedef struct { bool thumb; uint32_t regs[16]; struct { uint64_t sctlr_el[4]; uint32_t fcseidr_ns,fcseidr_s; } cp15; } CPUEnv;
typedef struct { CPUEnv env; } ARMCPU;
typedef struct {
''' + fields + r'''
    ARMCPU *cpu;
    bool memory_profile_enabled;
    uint32_t primary_nor_size;
    MemoryRegion msm, ready_status,nor;
    uint32_t ready_status_address;
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
static uint8_t underlay[MSM5XXX_POC_MSM_SIZE];
static unsigned forwards,old_ready_reads,old_ready_writes;
static hwaddr forwarded_address;
static unsigned forwarded_size,forwarded_attrs;
static bool forward_error;
static MemTxResult write_error;
static unsigned owner_mode, owner_finds, owner_unrefs, lower_cr_writes, lower_tf_writes;
static MemoryRegion foreign_region;
static uint64_t foreign_code_address;
typedef struct { MemoryRegion *mr; uint64_t size,offset_within_region; } MemoryRegionSection;
static void *get_system_memory(void) { return NULL; }
static bool int128_ge(uint64_t a,uint64_t b) { return a>=b; }
static bool int128_eq(uint64_t a,uint64_t b) { return a==b; }
static uint64_t int128_make64(uint64_t value) { return value; }
static MSM5xxxPOCMachineState *active;
static bool actual_guest=true;
static bool msm5xxx_poc_boot_storage_guest(MSM5xxxPOCMachineState *s) {
    (void)s;return actual_guest;
}
static MemoryRegionSection memory_region_find(void *root,hwaddr address,uint64_t size) {
    (void)root;assert(!active->uart_console_region.enabled);owner_finds++;
    MemoryRegion *mr=address<active->primary_nor_size?&active->nor:&active->msm;
    if(owner_mode==1 && address==active->uart_console_base+8)mr=&active->ready_status;
    if(owner_mode==2 && address>=MSM5XXX_POC_MSM_BASE)mr=&foreign_region;
    if(owner_mode==3)size--;
    if(owner_mode==4 && address>=MSM5XXX_POC_MSM_BASE)mr=&active->ready_status;
    if(owner_mode==5 && address>=MSM5XXX_POC_MSM_BASE)mr=NULL;
    if(owner_mode==7 && address==foreign_code_address)mr=&foreign_region;
    if(owner_mode==8 && address>=MSM5XXX_POC_MSM_BASE)size--;
    if(address==0x100 || address==0x102 || address==0x106)assert(size<=2);
    if(address==0x1fc || address==0x2fc)assert(size<=4);
    uint64_t offset=address<active->primary_nor_size?address:address-MSM5XXX_POC_MSM_BASE;
    return (MemoryRegionSection){mr,size,offset+(owner_mode==6 || (owner_mode==10 && address>=MSM5XXX_POC_MSM_BASE))};
}
static void memory_region_unref(MemoryRegion *region) { assert(region);owner_unrefs++; }
static bool memory_region_is_rom(MemoryRegion *region) {return region->readonly;}
static uint8_t *memory_region_get_ram_ptr(MemoryRegion *region) {assert(region==&active->msm);return underlay;}
static unsigned dirty;
static void memory_region_set_dirty(MemoryRegion *region,uint64_t at,unsigned size) {assert(region==&active->msm && at+size<=sizeof(underlay));dirty++;}
static MemTxResult address_space_read(AddressSpace *as,hwaddr addr,MemTxAttrs attrs,void *data,unsigned size) {
    (void)as;assert(!active->uart_console_region.enabled);
    assert(addr>=MSM5XXX_POC_MSM_BASE && addr+size<=MSM5XXX_POC_MSM_BASE+MSM5XXX_POC_MSM_SIZE);
    forwards++;forwarded_address=addr;forwarded_size=size;forwarded_attrs=attrs.marker;
    if(addr==active->uart_console_base+8 || addr==active->uart_console_base+0x10)old_ready_reads++;
    if(forward_error)return MEMTX_ERROR;
    memcpy(data,underlay+addr-MSM5XXX_POC_MSM_BASE,size);return MEMTX_OK;
}
static MemTxResult address_space_write(AddressSpace *as,hwaddr addr,MemTxAttrs attrs,const void *data,unsigned size) {
    (void)as;assert(!active->uart_console_region.enabled);
    assert(addr>=MSM5XXX_POC_MSM_BASE && addr+size<=MSM5XXX_POC_MSM_BASE+MSM5XXX_POC_MSM_SIZE);
    forwards++;forwarded_address=addr;forwarded_size=size;forwarded_attrs=attrs.marker;
    if(addr==active->uart_console_base+8 || addr==active->uart_console_base+0x10)old_ready_writes++;
    if(addr==active->uart_console_base+0x10)lower_cr_writes++;
    if(addr==active->uart_console_base+0x0c)lower_tf_writes++;
    if(forward_error)return MEMTX_ERROR;
    if(write_error)return write_error;
    memcpy(underlay+addr-MSM5XXX_POC_MSM_BASE,data,size);return MEMTX_OK;
}
''' + '\n'.join(function(n) for n in (
            'msm5xxx_poc_backing_read','msm5xxx_poc_backing_write',
            'msm5xxx_poc_uart_console_reset','msm5xxx_poc_uart_console_reject',
            'msm5xxx_poc_uart_console_forward','msm5xxx_poc_uart_console_mirror',
            'msm5xxx_poc_uart_console_isr',
            'msm5xxx_poc_uart_console_read_fixed','msm5xxx_poc_uart_console_write_fixed',
            'msm5xxx_poc_uart_console_probe_next',
            'msm5xxx_poc_uart_rearm_guest','msm5xxx_poc_uart_rearm_context',
            'msm5xxx_poc_uart_rearm_observe','msm5xxx_poc_uart_rearm_read',
            'msm5xxx_poc_uart_rearm_write','msm5xxx_poc_uart_pending_forward',
            'msm5xxx_poc_uart_console_read','msm5xxx_poc_uart_console_write',
            'msm5xxx_poc_get_uart_console','msm5xxx_poc_set_uart_console',
            'msm5xxx_poc_get_uart_console_probe','msm5xxx_poc_set_uart_console_probe',
            'msm5xxx_poc_get_uart_console_rearm','msm5xxx_poc_set_uart_console_rearm',
            'msm5xxx_poc_uart_rearm_valid','msm5xxx_poc_get_uart_console_rearm_state',
            'msm5xxx_poc_get_uart_console_probe_state',
            'msm5xxx_poc_get_uart_console_status')) + r'''
static MSM5xxxPOCMachineState fresh_wire(const char *wire) {
    MSM5xxxPOCMachineState s={0};Error *error=NULL;
    msm5xxx_poc_set_uart_console(&s,wire,&error);assert(!error);
    s.uart_console_realized=true;s.uart_console_mapped=true;msm5xxx_poc_uart_console_reset(&s);
    return s;
}
static MSM5xxxPOCMachineState fresh(void) { return fresh_wire("3000f0c"); }
static void select_state(MSM5xxxPOCMachineState *s) {active=s;}
static void write_at(MSM5xxxPOCMachineState *s,unsigned off,uint64_t value,unsigned size) {
    select_state(s);assert(msm5xxx_poc_uart_console_write(s,off,value,size,(MemTxAttrs){73})==MEMTX_OK);
}
static uint64_t read_at(MSM5xxxPOCMachineState *s,unsigned off,unsigned size) {
    uint64_t value=0;select_state(s);
    assert(msm5xxx_poc_uart_console_read(s,off,&value,size,(MemTxAttrs){91})==MEMTX_OK);return value;
}
static void configure_mode(MSM5xxxPOCMachineState *s,bool pre_reset) {
    if(pre_reset)write_at(s,0x10,0x20,1); /* Optional pre-init reset, not a readiness condition. */
    assert(read_at(s,8,1)==8 && read_at(s,0x14,1)==0);
    unsigned width=s->uart_console_register_width;
    write_at(s,0x14,0,1);write_at(s,0x20,0,width);write_at(s,0x1c,30,s->uart_console_tfwr_width);
    write_at(s,0,0,width);write_at(s,4,0x34,1);write_at(s,8,s->uart_console_expected_csr,1);
    assert(!s->uart_console_initialized && read_at(s,8,1)==8);
    const unsigned commands[]={0x30,0x10,0x10,0x20,0x20,1,4};
    for(unsigned i=0;i<7;i++)write_at(s,0x10,commands[i],1);
    assert(s->uart_console_initialized && s->uart_console_tx_enabled && s->uart_console_rx_enabled);
}
static void configure(MSM5xxxPOCMachineState *s) { configure_mode(s,true); }

static MSM5xxxPOCMachineState fresh_probe(void) {
    MSM5xxxPOCMachineState s={0};Error *error=NULL;
    msm5xxx_poc_set_uart_console_probe(&s,"3000f0c:ff:dd",&error);assert(!error);
    s.uart_console_realized=s.uart_console_mapped=true;
    msm5xxx_poc_uart_console_reset(&s);select_state(&s);
    forward_error=false;write_error=0;owner_mode=0;return s;
}
static const unsigned probe_offsets[]={0x14,0x20,0x1c,0,4,8,0x10,0x10,0x10,0x10,0x10,0x10,0x10};
static const unsigned probe_widths[]={1,2,2,2,1,1,1,1,1,1,1,1,1};
static const unsigned probe_values[]={0,0,30,0,0x34,0,0x30,0x10,0x10,0x20,0x20,1,4};
static void probe_event(unsigned index,unsigned *off,unsigned *value,unsigned *width) {
    *width=1;
    if(index<4 || index==18 || index==19) {*off=0x10;*value=0x20;return;}
    if(index==17) {*off=0xc;*value=0xa;return;}
    unsigned step=index<17?index-4:index-20;
    *off=probe_offsets[step];*width=probe_widths[step];
    *value=step==5?(index<17?0xff:0xdd):probe_values[step];
}
static void probe_run_to(MSM5xxxPOCMachineState *s,unsigned count) {
    for(unsigned i=0;i<count;i++) {
        unsigned off,value,width;probe_event(i,&off,&value,&width);
        if(i==18)assert(read_at(s,8,1)==0xc);
        write_at(s,off,value,width);assert(!s->uart_console_rejected);
    }
}
static void probe_checks(void) {
    MSM5xxxPOCMachineState s=fresh_probe();
    char *text=msm5xxx_poc_get_uart_console_probe(&s,NULL);assert(!strcmp(text,"3000f0c:ff:dd"));g_free(text);
    probe_run_to(&s,17);assert(s.uart_console_probe_stage==2 && s.uart_console_initialized);
    assert(s.uart_console_cr_step==7 && s.uart_console_expected_csr==0xff);
    assert(read_at(&s,8,1)==0xc && !s.uart_console_probe_rx_empty);
    assert(read_at(&s,0x14,1)==1);
    unsigned old_tf=lower_tf_writes,old_cr=lower_cr_writes;
    write_at(&s,0xc,0xa,1);assert(s.uart_console_probe_lf && s.uart_console_accepted==1);
    assert(lower_tf_writes==old_tf && lower_cr_writes==old_cr);
    assert(read_at(&s,0x14,1)==1 && !s.uart_console_probe_rx_empty);
    assert(read_at(&s,8,1)==0xc && s.uart_console_probe_rx_empty);
    write_at(&s,0x10,0x20,1);write_at(&s,0x10,0x20,1);
    for(unsigned step=0;step<13;step++) {
        write_at(&s,probe_offsets[step],step==5?0xdd:probe_values[step],probe_widths[step]);
        assert(!s.uart_console_rejected && s.uart_console_initialized &&
               s.uart_console_tx_enabled && s.uart_console_rx_enabled);
        assert(s.uart_console_cr_step==7); /* No invented latch/reset between probes. */
        assert(s.uart_console_expected_csr==(step<5?0xff:0xdd));
    }
    assert(s.uart_console_probe_stage==5 && s.uart_console_csr==0xdd);
    text=msm5xxx_poc_get_uart_console_probe(&s,NULL);assert(!strcmp(text,"3000f0c:ff:dd"));g_free(text);
    text=msm5xxx_poc_get_uart_console_probe_state(&s,NULL);assert(strstr(text,"stage=5"));g_free(text);
    write_at(&s,0xc,0x41,1);assert(s.uart_console_accepted==2);
    write_at(&s,8,0xff,1);assert(s.uart_console_rejected && s.uart_console_expected_csr==0xdd);
    msm5xxx_poc_uart_console_reset(&s);
    assert(!s.uart_console_probe_stage && !s.uart_console_probe_step && !s.uart_console_probe_drains);
    assert(!s.uart_console_probe_lf && !s.uart_console_probe_rx_empty && s.uart_console_expected_csr==0xff);
    assert(!s.uart_console_initialized && !s.uart_console_accepted);
    probe_run_to(&s,33);assert(s.uart_console_probe_stage==5);
    /* Debugger/QTest reads never grant permission or withdraw the new profile. */
    for(unsigned sealed=0;sealed<2;sealed++) {
        s=fresh_probe();probe_run_to(&s,sealed?33:18);
        MSM5xxxPOCMachineState before=s;
        actual_guest=false;
        const unsigned readable[]={0,4,8,0xc,0x10,0x14,0x1c,0x20};
        for(unsigned i=0;i<G_N_ELEMENTS(readable);i++) {
            unsigned width=(readable[i]==0 || readable[i]==0x1c || readable[i]==0x20)?2:1;
            read_at(&s,readable[i],width);assert(!memcmp(&s,&before,sizeof(s)));
        }
        uint64_t poison=0xabcdef;
        unsigned previous_forwards=forwards;
        assert(msm5xxx_poc_uart_console_read(&s,8,&poison,2,(MemTxAttrs){44})==MEMTX_ERROR);
        assert(msm5xxx_poc_uart_console_read(&s,0x18,&poison,1,(MemTxAttrs){44})==MEMTX_ERROR);
        assert(poison==0xabcdef && forwards==previous_forwards && !memcmp(&s,&before,sizeof(s)));
        actual_guest=true;
        if(!sealed) {
            assert(!s.uart_console_probe_rx_empty);
            read_at(&s,8,1);assert(s.uart_console_probe_rx_empty);
        }
    }
    /* Every source write rejects width/value/order mutations, without stage commit. */
    for(unsigned bad=0;bad<33;bad++)for(unsigned mutation=0;mutation<3;mutation++) {
        s=fresh_probe();probe_run_to(&s,bad);
        unsigned off,value,width;probe_event(bad,&off,&value,&width);
        if(bad==18)read_at(&s,8,1);
        unsigned stage=s.uart_console_probe_stage,step=s.uart_console_probe_step;
        unsigned drains=s.uart_console_probe_drains,csr=s.uart_console_expected_csr;
        if(mutation==0)value^=0x80;
        if(mutation==1)width=width==1?2:1;
        if(mutation==2)off++;
        write_at(&s,off,value,width);
        assert(s.uart_console_rejected && !s.uart_console_region.enabled);
        assert(s.uart_console_probe_stage==stage && s.uart_console_probe_step==step &&
               s.uart_console_probe_drains==drains && s.uart_console_expected_csr==csr);
    }
    const unsigned foreign_csrs[]={0xdd,0x99,0xcc};
    for(unsigned i=0;i<G_N_ELEMENTS(foreign_csrs);i++) {
        s=fresh_probe();probe_run_to(&s,9);write_at(&s,8,foreign_csrs[i],1);
        assert(s.uart_console_rejected && s.uart_console_expected_csr==0xff && s.uart_console_probe_step==5);
    }
    s=fresh_probe();probe_run_to(&s,25);write_at(&s,8,0xff,1);
    assert(s.uart_console_rejected && s.uart_console_expected_csr==0xff && s.uart_console_probe_step==5);
    s=fresh_probe();write_at(&s,0x14,0,1);assert(s.uart_console_rejected); /* Early config. */
    s=fresh_probe();probe_run_to(&s,4);write_at(&s,0x10,0x20,1);assert(s.uart_console_rejected); /* Fifth drain. */
    s=fresh_probe();probe_run_to(&s,17);write_at(&s,0x10,0x20,1);assert(s.uart_console_rejected); /* NoLF. */
    s=fresh_probe();probe_run_to(&s,17);read_at(&s,8,1);write_at(&s,0xc,0xa,1);
    write_at(&s,0x10,0x20,1);assert(s.uart_console_rejected); /* SR beforeLF not sufficient. */
    s=fresh_probe();probe_run_to(&s,18);read_at(&s,0x14,1);
    write_at(&s,0x10,0x20,1);assert(s.uart_console_rejected); /* ISR is not SR. */
    s=fresh_probe();probe_run_to(&s,18);write_at(&s,0xc,0xa,1);assert(s.uart_console_rejected); /* Duplicate LF. */
    s=fresh_probe();probe_run_to(&s,20);write_at(&s,0x10,0x20,1);assert(s.uart_console_rejected); /* Third DD drain. */
    s=fresh_probe();probe_run_to(&s,17);read_at(&s,0xc,1);assert(s.uart_console_rejected); /* No injected RX data. */
    s=fresh_probe();probe_run_to(&s,18);read_at(&s,8,2);assert(s.uart_console_rejected && !s.uart_console_probe_rx_empty);
    /* DD CSR permission rolls back when the passive underlay rejects or errors. */
    for(unsigned mode=0;mode<2;mode++) {
        s=fresh_probe();probe_run_to(&s,25);assert(s.uart_console_probe_stage==4 && s.uart_console_probe_step==5);
        if(mode)write_error=2;else owner_mode=2;
        select_state(&s);unsigned prior=forwards;
        MemTxResult result=msm5xxx_poc_uart_console_write(&s,8,0xdd,1,(MemTxAttrs){65});
        assert(result==(mode?2:MEMTX_OK) && forwards==prior+1 && forwarded_attrs==65);
        assert(s.uart_console_rejected && s.uart_console_probe_stage==4 && s.uart_console_probe_step==5);
        assert(s.uart_console_expected_csr==0xff && s.uart_console_csr==0xff);
    }
    owner_mode=0;write_error=0;
    const char *bad[]={NULL,"","3000f0c:ff","3000f0c:ff:dd:0","3000f0c:ff:dd ",
        "3000f0c:99:dd","3000f0c:ff:cc","3000f0c:2:ff","30007ac:ff:dd",
        "+3000f0c:ff:dd","1000000000000000000:ff:dd"};
    for(unsigned i=0;i<G_N_ELEMENTS(bad);i++) {
        MSM5xxxPOCMachineState empty={0},before=empty;Error *error=NULL;
        msm5xxx_poc_set_uart_console_probe(&empty,bad[i],&error);
        assert(error && !memcmp(&empty,&before,sizeof(empty)));
    }
    for(unsigned order=0;order<2;order++) {
        MSM5xxxPOCMachineState empty={0};Error *error=NULL;
        if(order)msm5xxx_poc_set_uart_console_probe(&empty,"3000f0c:ff:dd",&error);
        else msm5xxx_poc_set_uart_console(&empty,"3000f0c:2:ff",&error);
        assert(!error);MSM5xxxPOCMachineState before=empty;
        if(order)msm5xxx_poc_set_uart_console(&empty,"3000f0c:2:ff",&error);
        else msm5xxx_poc_set_uart_console_probe(&empty,"3000f0c:ff:dd",&error);
        assert(error && !memcmp(&empty,&before,sizeof(empty)));
    }
    MSM5xxxPOCMachineState late={0};late.uart_console_realized=true;Error *error=NULL;
    msm5xxx_poc_set_uart_console_probe(&late,"3000f0c:ff:dd",&error);assert(error && !late.uart_console_enabled);
    puts("UART finite FF/LF/RX-empty/DD strict protocol/reset/rollback/old-owner conflicts PASS");
}


static void finite_init(MSM5xxxPOCMachineState *s,unsigned drains,unsigned csr) {
    for(unsigned n=0;n<drains;n++)write_at(s,0x10,0x20,1);
    for(unsigned n=0;n<13;n++)write_at(s,probe_offsets[n],n==5?csr:probe_values[n],probe_widths[n]);
    assert(!s->uart_console_rejected);
}
static void ffcc_checks(void) {
    MSM5xxxPOCMachineState s={0};Error *err=NULL;
    msm5xxx_poc_set_uart_console_probe(&s,"3000f0c:ff:cc:99",&err);assert(!err);
    s.uart_console_mapped=s.uart_console_realized=true;msm5xxx_poc_uart_console_reset(&s);
    char *text=msm5xxx_poc_get_uart_console_probe(&s,NULL);assert(!strcmp(text,"3000f0c:ff:cc:99"));g_free(text);
    finite_init(&s,4,0xff);assert(s.uart_console_probe_stage==2);
    write_at(&s,12,10,1);assert(read_at(&s,8,1)==12 && s.uart_console_probe_rx_empty);
    finite_init(&s,4,0xcc);assert(s.uart_console_probe_stage==5 && !s.uart_console_probe_lf && !s.uart_console_probe_rx_empty);
    write_at(&s,0x10,0x20,1);assert(s.uart_console_rejected);
    msm5xxx_poc_uart_console_reset(&s);finite_init(&s,4,0xff);
    write_at(&s,12,10,1);read_at(&s,8,1);finite_init(&s,4,0xcc);
    write_at(&s,12,10,1);actual_guest=false;read_at(&s,8,1);actual_guest=true;
    assert(!s.uart_console_probe_rx_empty);write_at(&s,0x10,0x20,1);assert(s.uart_console_rejected);
    msm5xxx_poc_uart_console_reset(&s);finite_init(&s,4,0xff);
    write_at(&s,12,10,1);read_at(&s,8,1);finite_init(&s,4,0xcc);
    write_at(&s,12,10,1);read_at(&s,8,1);finite_init(&s,2,0x99);
    assert(s.uart_console_probe_stage==8 && s.uart_console_expected_csr==0x99);
    write_at(&s,12,0x41,1);assert(!s.uart_console_rejected);
    write_at(&s,8,0xcc,1);assert(s.uart_console_rejected);
    msm5xxx_poc_uart_console_reset(&s);assert(!s.uart_console_probe_stage && s.uart_console_expected_csr==0xff);
    const char *bad[]={"3000f0c","3000f0c:ff","3000f0c:ff:cc","3000f0c:ff:dd:99","3000f0c:ff:cc:99:","3000f0c:ff:cc:99:1"};
    for(unsigned n=0;n<sizeof(bad)/sizeof(*bad);n++){MSM5xxxPOCMachineState t={0};err=NULL;msm5xxx_poc_set_uart_console_probe(&t,bad[n],&err);assert(err && !t.uart_console_enabled);}
    puts("UART FFCC99 new-empty marker boundary PASS");
}
static ARMCPU rearm_cpu;
static void context(unsigned pc,unsigned lr) {rearm_cpu.env.regs[15]=pc;rearm_cpu.env.regs[14]=lr;}
static MSM5xxxPOCMachineState fresh_rearm(void) {
    MSM5xxxPOCMachineState s={0};Error *err=NULL;
    memset(&rearm_cpu,0,sizeof(rearm_cpu));rearm_cpu.env.thumb=true;s.cpu=&rearm_cpu;
    s.primary_nor_size=0x800000;s.memory_profile_enabled=true;s.nor.readonly=true;
    msm5xxx_poc_set_uart_console_rearm(&s,"100:102:106:201:301",&err);assert(!err);
    msm5xxx_poc_set_uart_console_probe(&s,"3000f0c:ff:dd",&err);assert(!err);
    s.uart_console_mapped=s.uart_console_realized=s.uart_console_rearm_mapped=true;
    msm5xxx_poc_uart_console_reset(&s);return s;
}
static void watch(MSM5xxxPOCMachineState *s,unsigned pc,unsigned lr,unsigned off,uint64_t value,unsigned width) {
    select_state(s);context(pc,lr);assert(msm5xxx_poc_uart_rearm_write(s,off,value,width,(MemTxAttrs){17})==MEMTX_OK);
}
static MSM5xxxPOCMachineState pending_rearm(void) {
    MSM5xxxPOCMachineState s=fresh_rearm();msm5xxx_poc_uart_console_reject(&s,"test");
    watch(&s,0x100,0x201,0,0x20,1);watch(&s,0x102,0x201,0,0x20,1);return s;
}
static void pending_config_resets(MSM5xxxPOCMachineState *s) {
    context(0x100,0x301);write_at(s,0x10,0x20,1);
    context(0x102,0x301);write_at(s,0x10,0x20,1);
}
static void pending_readback_checks(void) {
    MSM5xxxPOCMachineState s;
    for(unsigned ng=0;ng<2;ng++) {
        s=pending_rearm();context(0x106,0x201);
        if(ng){actual_guest=false;read_at(&s,8,1);actual_guest=true;}
        assert(!s.uart_console_rearm_ready);
        context(0x100,0x301);write_at(&s,0x10,0x20,1);
        assert(s.uart_console_rejected && !s.uart_console_rearm_ready);
        s=pending_rearm();context(0x106,0x201);read_at(&s,8,1);
        pending_config_resets(&s);context(0x106,0x301);
        if(ng){actual_guest=false;read_at(&s,8,1);actual_guest=true;}
        assert(s.uart_console_rearm_ready==1);
        write_at(&s,0x14,0,1);assert(s.uart_console_rejected && !s.uart_console_rearm_ready);
    }
    for(unsigned phase=0;phase<2;phase++) {
        s=pending_rearm();context(0x106,0x201);
        if(phase){read_at(&s,8,1);pending_config_resets(&s);context(0x106,0x301);}
        s.uart_console_empty=false;unsigned before=forwards;
        uint64_t expected=underlay[s.uart_console_base+8-MSM5XXX_POC_MSM_BASE];
        assert(read_at(&s,8,1)==expected && forwards==before+1);
        assert(s.uart_console_rejected && !s.uart_console_rearm_ready && !s.uart_console_rearm_pending);
    }
    s=pending_rearm();context(0x106,0x201);read_at(&s,8,1);pending_config_resets(&s);
    context(0x106,0x201);read_at(&s,8,1);assert(s.uart_console_rejected && !s.uart_console_rearm_ready);
    s=pending_rearm();context(0x106,0x201);forward_error=true;select_state(&s);uint64_t value=0;unsigned before=forwards;
    assert(msm5xxx_poc_uart_console_read(&s,8,&value,2,(MemTxAttrs){65})==MEMTX_ERROR);
    assert(forwards==before+1 && s.uart_console_rejected && !s.uart_console_rearm_ready);forward_error=false;
    const unsigned cuts[]={1,12};
    for(unsigned c=0;c<2;c++) {
        s=pending_rearm();context(0x106,0x201);read_at(&s,8,1);pending_config_resets(&s);
        context(0x106,0x301);read_at(&s,8,1);assert(s.uart_console_rearm_ready==3);
        for(unsigned n=0;n<cuts[c];n++)write_at(&s,probe_offsets[n],n==5?0xff:probe_values[n],probe_widths[n]);
        s.uart_console_rearm_ready=1;unsigned n=cuts[c];
        write_at(&s,probe_offsets[n],n==5?0xff:probe_values[n],probe_widths[n]);
        assert(s.uart_console_rejected && !s.uart_console_initialized && !s.uart_console_rearm_ready);
    }
    puts("UART pending root/config SR consumer readback gates PASS");
}
static void rearm_checks(void) {
    MSM5xxxPOCMachineState s=fresh_rearm(),saved;Error *err=NULL;char *text;
    owner_mode=0;actual_guest=true;select_state(&s);assert(msm5xxx_poc_uart_rearm_valid(&s));
    text=msm5xxx_poc_get_uart_console_rearm(&s,NULL);assert(!strcmp(text,"100:102:106:201:301"));g_free(text);
    text=msm5xxx_poc_get_uart_console_rearm_state(&s,NULL);assert(strstr(text,"count=0"));g_free(text);
    saved=s;msm5xxx_poc_set_uart_console_rearm(&s,"100:102:106:201:301",&err);assert(err && !memcmp(&s,&saved,sizeof(s)));
    for(unsigned mode=2;mode<=6;mode++){select_state(&s);owner_mode=mode;assert(!msm5xxx_poc_uart_rearm_valid(&s));}owner_mode=0;
    const unsigned code_sites[]={0x100,0x102,0x106,0x1fc,0x2fc};
    for(unsigned n=0;n<5;n++){select_state(&s);owner_mode=7;foreign_code_address=code_sites[n];assert(!msm5xxx_poc_uart_rearm_valid(&s));}
    owner_mode=8;assert(!msm5xxx_poc_uart_rearm_valid(&s));owner_mode=10;assert(!msm5xxx_poc_uart_rearm_valid(&s));owner_mode=0;
    s.nor.readonly=false;assert(!msm5xxx_poc_uart_rearm_valid(&s));s.nor.readonly=true;
    saved=s;s.uart_console_probe_ffcc=true;assert(!msm5xxx_poc_uart_rearm_valid(&s));s=saved;
    s.primary_nor_size=0x2ff;assert(!msm5xxx_poc_uart_rearm_valid(&s));s=saved;
    msm5xxx_poc_uart_console_reject(&s,"test");assert(s.uart_console_rearm_region.enabled && !s.uart_console_region.enabled);
    s.uart_console_accepted=7;unsigned before=forwards,dirty_before=dirty;
    watch(&s,0x100,0x201,0,0x20,1);assert(s.uart_console_rearm_step==1 && !s.uart_console_rearm_pending);
    actual_guest=false;uint64_t v=0;select_state(&s);
    assert(msm5xxx_poc_uart_rearm_read(&s,0,&v,4,(MemTxAttrs){0})==MEMTX_OK && s.uart_console_rearm_step==1);
    actual_guest=true;watch(&s,0x102,0x201,0,0x20,1);
    assert(forwards==before && dirty==dirty_before+2 && s.uart_console_rearm_pending && s.uart_console_rearms==1);
    assert(s.uart_console_accepted==7 && s.uart_console_probe_drains==2 && !s.uart_console_initialized && !s.uart_console_rearm_ready);
    context(0x106,0x201);assert(read_at(&s,8,1)==8 && s.uart_console_rearm_ready==1);
    before=forwards;actual_guest=false;read_at(&s,8,1);write_at(&s,0x10,0x20,1);
    forward_error=true;select_state(&s);uint64_t failed_value=0;
    assert(msm5xxx_poc_uart_console_read(&s,8,&failed_value,1,(MemTxAttrs){55})==MEMTX_ERROR);
    assert(s.uart_console_rearm_pending && s.uart_console_region.enabled);
    forward_error=false;actual_guest=true;
    assert(forwards==before+3 && s.uart_console_probe_drains==2 && s.uart_console_rearm_pending);
    context(0x100,0x301);write_at(&s,0x10,0x20,1);context(0x102,0x301);write_at(&s,0x10,0x20,1);
    context(0x106,0x301);assert(read_at(&s,8,1)==8 && s.uart_console_rearm_ready==3);
    for(unsigned n=0;n<13;n++)write_at(&s,probe_offsets[n],n==5?0xff:probe_values[n],probe_widths[n]);
    assert(!s.uart_console_rearm_pending && s.uart_console_probe_stage==2 && s.uart_console_initialized);
    write_at(&s,12,10,1);read_at(&s,8,1);finite_init(&s,2,0xdd);assert(s.uart_console_probe_stage==5);
    before=forwards;context(0x100,0x201);write_at(&s,0x10,0x20,1);context(0x102,0x201);write_at(&s,0x10,0x20,1);
    assert(forwards==before && s.uart_console_rearms==2 && s.uart_console_rearm_pending);
    context(0x106,0x201);read_at(&s,0x14,1);assert(s.uart_console_rejected && s.uart_console_rearm_region.enabled);
    for(unsigned kind=0;kind<8;kind++) {
        s=fresh_rearm();msm5xxx_poc_uart_console_reject(&s,"test");actual_guest=true;
        watch(&s,0x100,0x201,0,0x20,1);
        if(kind==0)rearm_cpu.env.thumb=false;
        if(kind==1)rearm_cpu.env.cp15.sctlr_el[1]=1;
        if(kind==2)rearm_cpu.env.cp15.fcseidr_ns=1;
        if(kind==3)rearm_cpu.env.cp15.fcseidr_s=1;
        if(kind==4)actual_guest=false;
        watch(&s,kind==7?0x104:0x102,kind==5?0x301:0x201,0,kind==6?0x21:0x20,1);
        assert(!s.uart_console_rearm_pending && !s.uart_console_rearms);
    }
    const char *bad[]={NULL,"","0:2:6:201:301","100:104:106:201:301",
        "100:102:108:201:301","101:103:107:201:301","100:102:106:200:301",
        "100:102:106:201:201","100:102:106:201:301:","100000100:102:106:201:301"};
    for(unsigned n=0;n<sizeof(bad)/sizeof(*bad);n++) {
        MSM5xxxPOCMachineState t={0},copy=t;err=NULL;
        msm5xxx_poc_set_uart_console_rearm(&t,bad[n],&err);assert(err && !memcmp(&t,&copy,sizeof(t)));
    }
    MSM5xxxPOCMachineState order={0};err=NULL;
    msm5xxx_poc_set_uart_console_probe(&order,"3000f0c:ff:dd",&err);assert(!err);
    msm5xxx_poc_set_uart_console_rearm(&order,"100:102:106:201:301",&err);assert(!err);
    saved=order;msm5xxx_poc_set_uart_console_rearm(&order,"100:102:106:201:301",&err);
    assert(err && !memcmp(&order,&saved,sizeof(order)));
    order=(MSM5xxxPOCMachineState){0};order.uart_console_realized=true;saved=order;err=NULL;
    msm5xxx_poc_set_uart_console_rearm(&order,"100:102:106:201:301",&err);
    assert(err && !memcmp(&order,&saved,sizeof(order)));
    actual_guest=true;s=fresh_rearm();msm5xxx_poc_uart_console_reject(&s,"test");
    watch(&s,0x100,0x201,0,0x20,1);watch(&s,0x102,0x201,1,0x3456,2);
    assert(!s.uart_console_rearm_step && !s.uart_console_rearm_pending);
    assert(underlay[s.uart_console_base+0x11-MSM5XXX_POC_MSM_BASE]==0x56);
    watch(&s,0x100,0x201,0,0x20,4);assert(!s.uart_console_rearm_step);
    msm5xxx_poc_uart_console_reset(&s);assert(!s.uart_console_rearms && !s.uart_console_rearm_pending && !s.uart_console_rearm_region.enabled && s.uart_console_region.enabled);
    s=fresh_rearm();probe_run_to(&s,33);context(0x100,0x201);write_at(&s,0x10,0x20,1);
    before=forwards;write_error=MEMTX_ERROR;context(0x102,0x201);select_state(&s);
    assert(msm5xxx_poc_uart_console_write(&s,0x10,0x20,1,(MemTxAttrs){19})==MEMTX_OK);
    assert(forwards==before && !s.uart_console_rejected && s.uart_console_rearms==1 && s.uart_console_rearm_pending);
    write_error=0;
    s=fresh_rearm();msm5xxx_poc_uart_console_reject(&s,"test");
    watch(&s,0x100,0x201,0,0x20,1);assert(s.uart_console_rearm_step==1);
    msm5xxx_poc_uart_console_reset(&s);assert(!s.uart_console_rearm_step);
    msm5xxx_poc_uart_console_reject(&s,"test");
    watch(&s,0x100,0x201,0,0x20,1);watch(&s,0x102,0x201,0,0x20,1);
    assert(s.uart_console_rearm_pending && s.uart_console_rearms==1);
    context(0x108,0x201);before=forwards;read_at(&s,8,1);
    assert(s.uart_console_rejected && forwards==before+1);
    watch(&s,0x100,0x201,0,0x20,1);watch(&s,0x102,0x201,0,0x20,1);
    assert(s.uart_console_rearm_pending && s.uart_console_rearms==2);
    msm5xxx_poc_uart_console_reset(&s);
    assert(!s.uart_console_rearm_pending && !s.uart_console_rearms && !s.uart_console_probe_drains);
    puts("UART source reset reentry/watcher/pending/foreign-context PASS");
}
int main(void) {
    const char *bad[]={"-1","+3000f0c"," 3000f0c","3000f0c ","3000f0d","2fffffc","3ffffe0","100000000000000000000000",
        "30007ac:1:dd","30007ac:2:dc","30007ac:2:de",
        "30007ac:1:99","30007ac:2:ee","30007ac:3:ff","30007ac:0:99",
        "30007ac:1","30007ac::ff","30007ac:1:","30007ac:1:ff:0",
        "30007ac:1.0:ff","30007ac:1:ff ","30007ac: 1:ff","30007ac:1:+ff"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        MSM5xxxPOCMachineState s={0},before=s;Error *error=NULL;
        msm5xxx_poc_set_uart_console(&s,bad[i],&error);
        assert(error && memcmp(&s,&before,sizeof(s))==0);
    }
    MSM5xxxPOCMachineState off={0};Error *error=NULL;
    msm5xxx_poc_set_uart_console(&off,"",&error);assert(!error&&!off.uart_console_enabled);
    char *text=msm5xxx_poc_get_uart_console(&off,&error);assert(!strcmp(text,""));g_free(text);
    off.uart_console_realized=true;MSM5xxxPOCMachineState off_before=off;
    msm5xxx_poc_set_uart_console(&off,"3000f0c",&error);
    assert(error && memcmp(&off,&off_before,sizeof(off))==0);error=NULL;
    MSM5xxxPOCMachineState s=fresh();select_state(&s);
    text=msm5xxx_poc_get_uart_console(&s,&error);assert(!strcmp(text,"3000f0c"));g_free(text);
    MSM5xxxPOCMachineState before=s;
    msm5xxx_poc_set_uart_console(&s,"3000f0c",&error);
    assert(error && memcmp(&s,&before,sizeof(s))==0);error=NULL;
    configure(&s);assert(forwards==6 && old_ready_reads==0 && old_ready_writes==1);
    assert(lower_cr_writes==0 && lower_tf_writes==0);
    assert(read_at(&s,8,1)==12 && s.uart_console_csr==0x99);
    assert(read_at(&s,0x14,1)==1 && read_at(&s,0x10,1)==0 && s.uart_console_imr==0);
    assert(!(read_at(&s,0x14,1)&0x80));
    assert(read_at(&s,0,2)==0 && read_at(&s,4,1)==0x34);
    assert(read_at(&s,0x1c,2)==30 && read_at(&s,0x20,2)==0);
    for(unsigned i=0;i<256;i++)write_at(&s,0x0c,i,1);
    assert(s.uart_console_accepted==256 && s.uart_console_last_byte==255 && s.uart_console_empty);
    assert(read_at(&s,0x0c,1)==0 && !(read_at(&s,8,1)&3));
    for(unsigned i=0;i<8;i++)assert(read_at(&s,8,1)==12 && read_at(&s,0x14,1)==1);
    assert(s.uart_console_accepted==256 && forwards==6);
    assert(lower_cr_writes==0 && lower_tf_writes==0);
    s.uart_console_tx_enabled=false;assert(read_at(&s,8,1)==8 && read_at(&s,0x14,1)==0);
    s.uart_console_tx_enabled=true;s.uart_console_empty=false;
    assert(read_at(&s,8,1)==0 && read_at(&s,0x14,1)==0);
    write_at(&s,0x10,0x20,1);assert(s.uart_console_empty && read_at(&s,0x14,1)==1);
    write_at(&s,0x10,0x10,1);write_at(&s,0x10,0x30,1);
    assert(s.uart_console_tx_enabled && s.uart_console_rx_enabled);
    text=msm5xxx_poc_get_uart_console_status(&s,&error);
    assert(strstr(text,"provisional-uncalibrated") && strstr(text,"\"acceptedcount\":256"));
    assert(strstr(text,"\"initialized\":true"));g_free(text);
    /* Each rejected write is forwarded once with the original address/width/attrs. */
    const struct {unsigned off,size;uint64_t val;} invalid[]={
        {0,2,0x40},{4,1,0x35},{8,1,0x98},{0x14,1,1},{0x1c,2,0},
        {0x20,2,1},{0x10,1,8},{0x0c,2,0x1234},{0x18,4,0xabcdef12},
        {1,2,0x4321},{0,8,0x123456789abcdef0ULL}};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        s=fresh();configure(&s);unsigned count=forwards;
        write_at(&s,invalid[i].off,invalid[i].val,invalid[i].size);
        assert(s.uart_console_rejected && !s.uart_console_region.enabled && forwards==count+1);
        assert(forwarded_address==s.uart_console_base+invalid[i].off && forwarded_size==invalid[i].size && forwarded_attrs==73);
        assert(msm5xxx_poc_backing_read(underlay,s.uart_console_base-MSM5XXX_POC_MSM_BASE+invalid[i].off,invalid[i].size)==invalid[i].val);
        msm5xxx_poc_uart_console_reset(&s);assert(!s.uart_console_rejected && s.uart_console_region.enabled);
        assert(!s.uart_console_initialized && !s.uart_console_tx_enabled && s.uart_console_empty && !s.uart_console_accepted);
    }
    s=fresh();select_state(&s);unsigned count=forwards;
    write_at(&s,0x0c,65,1);assert(s.uart_console_rejected && forwards==count+1);
    s=fresh();write_at(&s,0x10,4,1);assert(s.uart_console_rejected);
    s=fresh();write_at(&s,0x14,0,1);write_at(&s,0x20,0,2);write_at(&s,0x1c,30,2);
    write_at(&s,0,0,2);write_at(&s,4,0x34,1);write_at(&s,8,0x99,1);
    write_at(&s,0x10,4,1);assert(s.uart_console_rejected && !s.uart_console_initialized);
    s=fresh();configure(&s);count=forwards;
    unsigned off_addr=s.uart_console_base-MSM5XXX_POC_MSM_BASE;
    underlay[off_addr+8]=0x12;underlay[off_addr+9]=0x34;
    assert(read_at(&s,8,2)==0x3412 && s.uart_console_rejected && forwards==count+1);
    assert(forwarded_attrs==91 && old_ready_reads==1);
    /* Rejected callbacks also forward; errors propagate rather than fabricating data. */
    forward_error=true;uint64_t value=0;
    assert(msm5xxx_poc_uart_console_read(&s,8,&value,1,(MemTxAttrs){1})==MEMTX_ERROR);
    forward_error=false;
    /* Four explicit pairs share the engine; width/CSR remain immutable. */
    const char *wires[]={"30007ac:1:ff","3000f0c:2:99","3000f0c:2:dd","3000f0c:2:ff"};
    const unsigned expected_width[]={1,2,2,2},expected_csr[]={0xff,0x99,0xdd,0xff};
    const char *getters[]={"30007ac:1:ff","3000f0c","3000f0c:2:dd","3000f0c:2:ff"};
    for(unsigned mode=0;mode<4;mode++) {
        s=fresh_wire(wires[mode]);unsigned width=s.uart_console_register_width;
        unsigned csr=s.uart_console_expected_csr;
        assert(width==expected_width[mode] && csr==expected_csr[mode]);
        text=msm5xxx_poc_get_uart_console(&s,&error);
        assert(!strcmp(text,getters[mode]));g_free(text);
        assert(read_at(&s,8,1)==8 && !s.uart_console_initialized);
        configure_mode(&s,false); /* C11's first pre-init SR wait has no reset requirement. */
        assert(read_at(&s,8,1)==12 && read_at(&s,0x14,1)==1 && read_at(&s,0x10,1)==0);
        assert(s.uart_console_csr==csr && read_at(&s,0,width)==0);
        assert(read_at(&s,0x1c,width)==30 && read_at(&s,0x20,width)==0);
        for(unsigned value=0;value<256;value++)write_at(&s,0x0c,value,1);
        assert(s.uart_console_accepted==256 && s.uart_console_last_byte==255);
        assert(read_at(&s,0x0c,1)==0 && !(read_at(&s,8,1)&3));
        text=msm5xxx_poc_get_uart_console_status(&s,&error);
        assert(strstr(text,mode?"\"classwidth\":2":"\"classwidth\":1"));
        assert(strstr(text,mode==1?"\"expectedcsr\":153":mode==2?"\"expectedcsr\":221":"\"expectedcsr\":255"));g_free(text);
        MSM5xxxPOCMachineState saved=s;
        msm5xxx_poc_set_uart_console(&s,wires[!mode],&error);
        assert(error && memcmp(&s,&saved,sizeof(s))==0);error=NULL;
        unsigned wrong_csr=expected_csr[mode]==0x99?0xff:0x99;
        write_at(&s,8,wrong_csr,1);
        assert(s.uart_console_rejected);
        assert(underlay[s.uart_console_base-MSM5XXX_POC_MSM_BASE+8]==wrong_csr);
        msm5xxx_poc_uart_console_reset(&s);
        assert(s.uart_console_register_width==width && s.uart_console_expected_csr==csr);
        assert(!s.uart_console_initialized && s.uart_console_region.enabled && read_at(&s,8,1)==8);
        for(unsigned reg=0;reg<3;reg++) {
            configure_mode(&s,false);
            unsigned off=reg==0?0:reg==1?0x1c:0x20;
            unsigned wrongwidth=width==1?2:1;
            unsigned count=forwards;
            write_at(&s,off,reg==1?30:0,wrongwidth);
            assert(s.uart_console_rejected && forwards==count+1 && forwarded_size==wrongwidth);
            msm5xxx_poc_uart_console_reset(&s);
            configure_mode(&s,false);count=forwards;
            read_at(&s,off,wrongwidth);
            assert(s.uart_console_rejected && forwards==count+1 && forwarded_size==wrongwidth);
            msm5xxx_poc_uart_console_reset(&s);
        }
    }
    /* The source-qualified mixed class admits only the TFWR halfword. */
    s=fresh_wire("3000f0c:1:ff:2");configure(&s);
    unsigned prior_reads=forwards;
    read_at(&s,0x1c,2);
    assert(s.uart_console_rejected && forwards==prior_reads+1 && forwarded_size==2);
    s=fresh_wire("3000f0c:1:ff:2");configure(&s);
    write_at(&s,0x1c,30,1);
    assert(s.uart_console_rejected);
    msm5xxx_poc_uart_console_reset(&s);
    assert(!s.uart_console_rejected && s.uart_console_tfwr_width==2);
    s=fresh_wire("3000f0c:1:ff:2");configure(&s);
    write_at(&s,0x1c,0,2);
    assert(s.uart_console_rejected);
    s=fresh_wire("3000f0c:1:ff:2");configure(&s);
    write_at(&s,0x20,0,2);
    assert(s.uart_console_rejected);
    /* DD has no extra register/IRQ privilege: unknown register forwards once. */
    s=fresh_wire("3000f0c:2:dd");configure(&s);
    unsigned before_foreign=forwards;
    write_at(&s,0x18,0x5a,1);
    assert(s.uart_console_rejected && forwards==before_foreign+1);
    assert(forwarded_address==s.uart_console_base+0x18 && forwarded_size==1);
    assert(underlay[s.uart_console_base-MSM5XXX_POC_MSM_BASE+0x18]==0x5a);
    msm5xxx_poc_uart_console_reset(&s);configure(&s);
    before_foreign=forwards;read_at(&s,0x18,1);
    assert(s.uart_console_rejected && forwards==before_foreign+1);

    /* Passive successful writes survive handoff; no CR/TF history replay. */
    for(unsigned mode=0;mode<4;mode++) {
        memset(underlay,0xa5,sizeof(underlay));owner_mode=mode==2?1:0;
        s=fresh_wire(wires[mode]);s.ready_status_address=s.uart_console_base+8;
        unsigned origin=s.uart_console_base-MSM5XXX_POC_MSM_BASE;
        select_state(&s);unsigned before=forwards,cr_before=lower_cr_writes,tf_before=lower_tf_writes;
        assert(msm5xxx_poc_uart_console_write(&s,4,0x34,1,(MemTxAttrs){11})==MEMTX_OK);
        assert(s.uart_console_config==2 && s.uart_console_mr2==0x34 && s.uart_console_region.enabled);
        assert(forwards==before+1 && forwarded_attrs==11 && underlay[origin+4]==0x34);
        assert(underlay[origin]==0xa5 && underlay[origin+8]==0xa5 && underlay[origin+0x1c]==0xa5);
        configure(&s);
        unsigned width=s.uart_console_register_width;
        assert(msm5xxx_poc_backing_read(underlay,origin,width)==0);
        assert(underlay[origin+8]==s.uart_console_expected_csr && underlay[origin+0x14]==0);
        assert(msm5xxx_poc_backing_read(underlay,origin+0x1c,width)==30);
        assert(msm5xxx_poc_backing_read(underlay,origin+0x20,width)==0);
        assert(read_at(&s,8,1)==12); /* CSR backing does not become SR readback. */
        write_at(&s,0x0c,0x77,1);
        assert(lower_cr_writes==cr_before && lower_tf_writes==tf_before);
        before=forwards;write_at(&s,0x18,0x55,1);
        assert(s.uart_console_rejected && forwards==before+1 && forwarded_attrs==73);
        assert(read_at(&s,4,1)==0x34 && read_at(&s,0x1c,width)==30);
        assert(lower_cr_writes==cr_before && lower_tf_writes==tf_before);
        msm5xxx_poc_uart_console_reset(&s);assert(!s.uart_console_config);
        configure(&s);before=forwards;read_at(&s,0x18,1);
        assert(s.uart_console_rejected && forwards==before+1 && forwarded_attrs==91);
        assert(read_at(&s,4,1)==0x34 && read_at(&s,0x1c,width)==30);
    }
    /* Partial configuration also survives a read-triggered handoff. */
    owner_mode=0;s=fresh();select_state(&s);
    memset(underlay,0xa5,sizeof(underlay));
    write_at(&s,4,0x34,1);read_at(&s,0x18,1);
    assert(s.uart_console_rejected && read_at(&s,4,1)==0x34);
    assert(underlay[s.uart_console_base-MSM5XXX_POC_MSM_BASE+8]==0xa5);
    /* Unsupported/partial owners hand original write off once without model commit. */
    for(unsigned kind=2;kind<=5;kind++) {
        owner_mode=kind;s=fresh();select_state(&s);s.ready_status_address=s.uart_console_base+8;
        unsigned before=forwards,refs=owner_unrefs;
        unsigned off=kind==3?0:4,access_size=kind==3?2:1;
        assert(msm5xxx_poc_uart_console_write(&s,off,kind==3?0:0x34,access_size,(MemTxAttrs){17})==MEMTX_OK);
        assert(forwarded_size==access_size);
        assert(s.uart_console_rejected && !s.uart_console_region.enabled);
        assert(!s.uart_console_config && !s.uart_console_mr2 && forwards==before+1 && forwarded_attrs==17);
        assert(!strcmp(s.uart_console_reject_reason,"unsupported-passive-underlay"));
        assert(owner_unrefs==refs+(kind==5?0:1));
    }
    /* Even CSR owner needs its configured address to agree with the bus address. */
    owner_mode=1;s=fresh();select_state(&s);s.ready_status_address=s.uart_console_base+9;
    unsigned mirror_count=forwards;
    assert(msm5xxx_poc_uart_console_write(&s,8,0x99,1,(MemTxAttrs){19})==MEMTX_OK);
    assert(s.uart_console_rejected && !s.uart_console_config && forwards==mirror_count+1);
    /* Preserve the exact error and don't consume or replay a failed passive write. */
    owner_mode=0;s=fresh();select_state(&s);
    assert(msm5xxx_poc_uart_console_write(&s,0,0,2,(MemTxAttrs){29})==MEMTX_OK);
    assert(s.uart_console_config==1);
    mirror_count=forwards;write_error=2;
    assert(msm5xxx_poc_uart_console_write(&s,4,0x34,1,(MemTxAttrs){23})==2);
    assert(forwards==mirror_count+1 && forwarded_attrs==23 && s.uart_console_rejected && !s.uart_console_region.enabled);
    assert(s.uart_console_config==1 && !s.uart_console_mr2);
    assert(!strcmp(s.uart_console_reject_reason,"passive-underlay-write-error"));
    write_error=0;owner_mode=0;
    probe_checks();ffcc_checks();rearm_checks();pending_readback_checks();
    puts("UART actual-C four explicit classes/property/alias/init/reset/fallback PASS");return 0;
}
'''
        flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','glib-2.0'],text=True,timeout=10))
        with tempfile.TemporaryDirectory(prefix='.uart-console-native-',dir=repo) as directory:
            path=Path(directory);(path/'check.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                            '-fsanitize=undefined','-fno-sanitize-recover=undefined',
                            str(path/'check.c'),'-o',str(path/'check'),*flags],check=True,timeout=30)
            subprocess.run([str(path/'check')],check=True,timeout=10)
        # Verify wiring uses the same actual callback and guards at realize/reset lifetime.
        self.assertIn('&s->uart_console_region, 2);',source)
        self.assertIn('qemu_register_reset(msm5xxx_poc_uart_console_reset, s);',source)
        self.assertIn('qemu_unregister_reset(msm5xxx_poc_uart_console_reset, s);',source)
        initializer=function('msm5xxx_poc_init')
        self.assertLess(initializer.index('msm5xxx_poc_small_nand_init(machine'),initializer.index('msm5xxx_poc_uart_rearm_valid(s)'))
        self.assertLess(initializer.index('msm5xxx_poc_spi_nv_init(machine'),initializer.index('msm5xxx_poc_uart_rearm_valid(s)'))
        self.assertLess(initializer.index('msm5xxx_poc_boot_keysense_init(machine'),initializer.index('msm5xxx_poc_uart_rearm_valid(s)'))
        self.assertIn('&s->uart_console_rearm_region, 3);',initializer)
        self.assertIn('msm5xxx_poc_get_uart_console_status, NULL);',source)


if __name__=='__main__':unittest.main()
