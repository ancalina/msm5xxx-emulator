"""Actual native boot-read and SPI geometry guards, without a QEMU guest."""
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class BootStorageNativeTests(unittest.TestCase):
    def test_actual_c_guest_scope_geometry_pending_write_and_properties(self):
        repo = Path(__file__).resolve().parents[1]
        native = repo / 'experiments/qemu-tcg'
        source = (native / 'msm5xxx-poc.c').read_text()

        def function(name, text=source):
            match = re.search(r'^static [^;{}]*\b' + re.escape(name) +
                              r'\([^;{}]*\)\s*\{', text, re.M)
            self.assertIsNotNone(match, name)
            brace = match.end() - 1
            depth, end = 1, brace + 1
            while depth:
                depth += (text[end] == '{') - (text[end] == '}')
                end += 1
            return text[match.start():end]

        # A declaration must not borrow the next unrelated function's body.
        fixture = ('static bool selected(void *p);\n'
                   'static void unrelated(void) { }\n'
                   'static bool selected(\n    void *p)\n{ return p != 0; }')
        self.assertEqual(function('selected', fixture),
                         'static bool selected(\n    void *p)\n{ return p != 0; }')

        fields = source[source.index('    bool boot_keysense_enabled,'):
                        source.index('\n};', source.index('    bool boot_keysense_enabled,'))]
        code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <glib.h>
#include "msm5xxx-spi-nv.h"
#include "msm5xxx-protected-nor.h"
typedef uint64_t hwaddr;
typedef struct { uint8_t *data; } MemoryRegion;
typedef struct { uint64_t ram_size; MemoryRegion *ram; } MachineState;
typedef struct CPUState { bool running; struct { bool can_do_io; } neg; struct { bool thumb; } env; uint32_t pc; } CPUState;
typedef CPUState ARMCPU;
static CPUState *current_cpu;
static bool vcpu;
static bool qemu_in_vcpu_thread(void) { return vcpu; }
#define CPU(p) (p)
typedef struct { uint32_t (*get_pc)(CPUState *); } CPUClass;
static uint32_t get_pc(CPUState *cpu) { return cpu->pc; }
static CPUClass cpu_class = { get_pc };
#define CPU_GET_CLASS(p) (&cpu_class)
typedef struct { int unused; } BlockBackend;
typedef struct { bool active; uint64_t deadline; } QEMUTimer;
typedef struct { int unused; } Error;
static Error failure;
static void error_setg(Error **errp, const char *format, ...) { *errp = &failure; }
static int qemu_strtou64(const char *text, const char **end, int base, uint64_t *out) {
    char *tail; errno=0; *out=strtoull(text,&tail,base); *end=tail;
    return errno ? -errno : tail==text ? -EINVAL : 0;
}
#define MSM5XXX_POC_MSM_BASE 0x03000000u
#define MSM5XXX_SPI_NV_BASE 0x03000660u
#define MSM5XXX_SPI_NV_WINDOW 0x20u
#define MSM5XXX_SPI_NV_CAPACITY 0x4000u
#define QEMU_CLOCK_VIRTUAL 0
#define BDRV_REQ_FUA 1
static uint64_t now;
static unsigned persisted;
static int64_t qemu_clock_get_ns(int clock) { return now; }
static void timer_mod(QEMUTimer *timer,uint64_t deadline) { timer->active=true;timer->deadline=deadline; }
static void timer_del(QEMUTimer *timer) { timer->active=false; }
static int blk_pwrite(BlockBackend *blk,uint64_t page,unsigned size,const void *data,int flags) {
    assert(size==32 && flags==BDRV_REQ_FUA);persisted++;return 0;
}
static void error_report(const char *format,...) { abort(); }
typedef struct {
    MachineState machine;
    CPUState *cpu;
    MemoryRegion msm;
    bool memory_profile_enabled;
    uint32_t primary_nor_size,ram_base,ram_reserved_base,ram_reserved_size;
''' + fields + r'''
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(p) (p)
#define MACHINE(s) (&(s)->machine)
#define OBJECT(p) (p)
static uint8_t *memory_region_get_ram_ptr(MemoryRegion *region) { return region->data; }
static uint64_t msm5xxx_poc_backing_read(const uint8_t *data,hwaddr offset,unsigned size) {
    uint64_t result=0;for(unsigned i=0;i<size;i++)result|=(uint64_t)data[offset+i]<<(i*8);return result;
}
static void msm5xxx_poc_backing_write(uint8_t *data,hwaddr offset,uint64_t value,unsigned size) {
    for(unsigned i=0;i<size;i++)data[offset+i]=value>>(i*8);
}
typedef struct { uint64_t size; MemoryRegion *mr; } MemoryRegionSection;
static MemoryRegionSection found;
static void *get_system_memory(void) { return NULL; }
static MemoryRegionSection memory_region_find(void *root,hwaddr address,uint64_t size) { return found; }
static bool int128_eq(uint64_t a,uint64_t b) { return a==b; }
static uint64_t int128_make64(uint64_t value) { return value; }
static void memory_region_unref(MemoryRegion *region) { }
static const int msm5xxx_poc_boot_keysense_ops;
static unsigned overlays;
static void memory_region_init_io(MemoryRegion *region,void *owner,const void *ops,void *opaque,const char *name,uint64_t size) { assert(size==1); }
static void memory_region_add_subregion_overlap(void *root,hwaddr address,MemoryRegion *region,int priority) { assert(address==0x03000694 && priority==1);overlays++; }
'''
        names = ('boot_storage_guest', 'boot_storage_hex', 'boot_keysense_read',
                 'boot_keysense_write', 'boot_keysense_reset', 'boot_keysense_init',
                 'spi_nv_geometry_bounds', 'spi_nv_geometry_valid',
                 'get_boot_keysense_release', 'set_boot_keysense_release',
                 'get_boot_keysense_state', 'get_spi_nv_source_geometry',
                 'set_spi_nv_source_geometry', 'spi_nv_persist', 'spi_nv_sync',
                 'spi_nv_step', 'spi_nv_geometry_gate', 'spi_nv_read',
                 'spi_nv_revoke', 'spi_nv_write', 'spi_nv_reset',
                 'get_spi_nv_state')
        code += '\n'.join(function('msm5xxx_poc_' + name) for name in names)
        # Exercise the existing final dependency/mapping checks, not copied predicates.
        init = function('msm5xxx_poc_spi_nv_init')
        prefix = init[init.index('{') + 1:init.index('    if (!s->spi_nv_write_ns)')]
        code += '\nstatic void geometry_final_check(MachineState *machine, MSM5xxxPOCMachineState *s, Error **errp) {\n' + prefix + '\n(void)ret;\n}\n'
        code += r'''
static uint8_t msm[0x1000], ram[0x10000], image[0x4000];
static CPUState cpu,other_cpu;
static MemoryRegion memory={ram};
static QEMUTimer timer;
static MSM5xxxPOCMachineState state;
static void setup(void) {
    memset(&state,0,sizeof(state));memset(msm,0,sizeof(msm));memset(ram,0,sizeof(ram));
    memset(image,0xff,sizeof(image));memset(&timer,0,sizeof(timer));
    cpu=(CPUState){.running=true,.neg={.can_do_io=true},.env={.thumb=true},.pc=0x100};
    current_cpu=&cpu;vcpu=true;now=0;
    state.cpu=&cpu;state.msm.data=msm;state.machine.ram=&memory;
    state.machine.ram_size=sizeof(ram);state.ram_base=0x1000000;
    state.primary_nor_size=0x200000;state.memory_profile_enabled=true;
    state.spi_nv_timer=&timer;state.spi_nv_write_ns=100;
    assert(msm5xxx_spi_nv_init(&state.spi_nv,image,sizeof(image),100));
    state.spi_nv_source_geometry=0x1000100;
    found=(MemoryRegionSection){.mr=&memory,.size=6};
}
static void geometry(bool valid) { ram[0x102]=0;ram[0x103]=0x40;ram[0x104]=valid?1:2; }
static void gpio(unsigned off,uint8_t value) { msm5xxx_poc_spi_nv_write(&state,off,value,1); }
static void select_cs(bool inactive) { gpio(4,inactive?0x40:0); }
static void byte(uint8_t value) {
    for(int i=7;i>=0;i--) { gpio(8,(value>>i)&1);gpio(8,2|((value>>i)&1)); }
}
int main(void) {
    Error *err=NULL;char *text;
    setup();
    /* Setter order is independent of memory-profile, SPI enable and final NOR. */
    state.memory_profile_enabled=false;state.spi_nv_write_ns=0;state.primary_nor_size=0;
    msm5xxx_poc_set_boot_keysense_release(&state,"100:102:104",&err);assert(!err);
    state.spi_nv_source_geometry=0;
    msm5xxx_poc_set_spi_nv_source_geometry(&state,"1000100",&err);assert(!err);
    geometry_final_check(&state.machine,&state,&err);assert(err);
    state.spi_nv_realized=false;state.memory_profile_enabled=true;state.spi_nv_write_ns=100;
    err=NULL;geometry_final_check(&state.machine,&state,&err);assert(!err);
    state.primary_nor_size=0x200000;found=(MemoryRegionSection){.mr=&state.msm,.size=1};
    msm5xxx_poc_boot_keysense_init(&state.machine,&state,&err);assert(!err && overlays==1);
    text=msm5xxx_poc_get_boot_keysense_release(&state,&err);assert(!strcmp(text,"100:102:104"));g_free(text);
    text=msm5xxx_poc_get_spi_nv_source_geometry(&state,&err);assert(!strcmp(text,"1000100"));g_free(text);
    msm[0x694]=0xa0;
    vcpu=false;assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xa0 && !state.boot_keysense_phase);
    vcpu=true;current_cpu=&other_cpu;assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xa0);
    current_cpu=&cpu;cpu.running=false;assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xa0);
    cpu.running=true;cpu.neg.can_do_io=false;assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xa0);
    cpu.neg.can_do_io=true;cpu.pc=0x200;assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xa0);
    cpu.pc=0x100;assert(msm5xxx_poc_boot_keysense_read(&state,0,2)==0xa0);
    cpu.env.thumb=false;
    assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xa0 && !state.boot_keysense_phase && !state.boot_keysense_reads);
    cpu.env.thumb=true;
    for(unsigned i=0;i<3;i++) { cpu.pc=0x100+2*i;assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xaf);assert(msm[0x694]==0xa0); }
    cpu.pc=0x100;assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xa0);
    assert(state.boot_keysense_phase==3 && state.boot_keysense_releases==3);
    msm5xxx_poc_boot_keysense_write(&state,0,0xb2,1);assert(msm[0x694]==0xb2);
    msm5xxx_poc_boot_keysense_reset(&state);cpu.pc=0x102;
    assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xb2 && state.boot_keysense_rejected);
    cpu.pc=0x100;assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xb2);
    msm5xxx_poc_boot_keysense_reset(&state);assert(msm[0x694]==0xb2);
    assert(msm5xxx_poc_boot_keysense_read(&state,0,1)==0xbf);
    text=msm5xxx_poc_get_boot_keysense_state(&state,&err);assert(strstr(text,"phase=1") && strstr(text,"rejections=1"));g_free(text);
    err=NULL;msm5xxx_poc_set_boot_keysense_release(&state,"200:202:204",&err);assert(err && state.boot_keysense_pc[0]==0x100);
    err=NULL;msm5xxx_poc_set_spi_nv_source_geometry(&state,"1000200",&err);assert(err && state.spi_nv_source_geometry==0x1000100);
    const char *bad[]={"","+100:102:104","100:100:104","101:102:104","100:102","100:102:104:106","100000000:2:4","100 :102:104"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) { setup();msm5xxx_poc_set_boot_keysense_release(&state,bad[i],&err);assert(err && !state.boot_keysense_enabled);err=NULL; }
    setup();state.spi_nv_source_geometry=0;state.spi_nv_realized=true;
    msm5xxx_poc_set_spi_nv_source_geometry(&state,"1000100",&err);assert(err && !state.spi_nv_source_geometry);err=NULL;
    /* Full six-byte range, actual RAM mapping and reserved holes. */
    setup();assert(msm5xxx_poc_spi_nv_geometry_bounds(&state));
    state.spi_nv_source_geometry=0x100fffc;assert(!msm5xxx_poc_spi_nv_geometry_bounds(&state));
    state.spi_nv_source_geometry=0x1000100;state.ram_reserved_base=0x1000104;state.ram_reserved_size=0x1000;
    assert(!msm5xxx_poc_spi_nv_geometry_bounds(&state));
    setup();found.mr=&state.msm;geometry_final_check(&state.machine,&state,&err);assert(err);err=NULL;
    setup();found.size=5;geometry_final_check(&state.machine,&state,&err);assert(err);err=NULL;
    setup();state.primary_nor_size=0x100;state.boot_keysense_enabled=true;state.boot_keysense_pc[2]=0x100;
    msm5xxx_poc_boot_keysense_init(&state.machine,&state,&err);assert(err);err=NULL;
    /* Invalid initial geometry does not consume edges; valid needs inactive CS. */
    setup();gpio(0x18,0x40);gpio(0x1c,3);select_cs(false);
    assert(!state.spi_nv_geometry_ready && !state.spi_nv_qualified && !state.spi_nv_geometry_mismatches);
    geometry(true);gpio(8,0);assert(!state.spi_nv_qualified);
    select_cs(true);assert(state.spi_nv_geometry_ready && state.spi_nv_qualified);
    select_cs(false);byte(6);select_cs(true);assert(state.spi_nv.wel);
    select_cs(false);byte(2);byte(0x13);byte(0x60);byte(0x9a);select_cs(true);
    assert(state.spi_nv.wip && state.spi_nv.deadline_ns==100);
    geometry(false);gpio(8,0);
    assert(!state.spi_nv_qualified && !state.spi_nv_geometry_ready && state.spi_nv_geometry_mismatches==1);
    assert(state.spi_nv.wip && state.spi_nv.deadline_ns==100 && image[0x1360]==0xff);
    gpio(8,2);assert(state.spi_nv_geometry_mismatches==1);
    now=100;msm5xxx_poc_spi_nv_sync(&state);assert(image[0x1360]==0x9a && persisted==1);
    geometry(true);select_cs(false);assert(!state.spi_nv_geometry_ready);
    select_cs(true);assert(state.spi_nv_geometry_ready);
    /* Debugger reads/getters do not advance a pending deadline or gate transition. */
    select_cs(false);byte(6);select_cs(true);select_cs(false);byte(2);byte(0);byte(0);byte(0x66);select_cs(true);
    assert(state.spi_nv.wip);uint64_t deadline=state.spi_nv.deadline_ns;
    vcpu=false;geometry(false);now=deadline;
    assert(msm5xxx_poc_spi_nv_read(&state,4,1)==msm[0x664]);
    assert(state.spi_nv.wip && state.spi_nv_geometry_ready && persisted==1);
    text=msm5xxx_poc_get_spi_nv_state(&state,&err);assert(strstr(text,"geometry_ready=1"));g_free(text);
    assert(state.spi_nv.wip && persisted==1);
    vcpu=true;msm5xxx_poc_spi_nv_sync(&state);assert(!state.spi_nv.wip && image[0]==0x66 && persisted==2);
    msm5xxx_poc_spi_nv_read(&state,4,1);assert(!state.spi_nv_geometry_ready);
    msm5xxx_poc_spi_nv_reset(&state);assert(state.spi_nv_source_geometry==0x1000100 && !state.spi_nv_geometry_ready);
    /* A partial staged page is aborted on mismatch, never converted to WIP. */
    setup();geometry(true);gpio(0x18,0x40);gpio(0x1c,3);select_cs(true);
    select_cs(false);byte(6);select_cs(true);select_cs(false);byte(2);byte(0);byte(2);byte(0x77);
    assert(state.spi_nv.has_payload && !state.spi_nv.wip);
    geometry(false);gpio(8,0);assert(!state.spi_nv.wip && image[2]==0xff);
    geometry(true);select_cs(true);assert(state.spi_nv_geometry_ready);
    select_cs(false);byte(6);select_cs(true);select_cs(false);byte(2);byte(0);byte(3);byte(0x88);select_cs(true);
    assert(state.spi_nv.wip);deadline=state.spi_nv.deadline_ns;
    msm5xxx_poc_spi_nv_reset(&state);
    assert(state.spi_nv.wip && state.spi_nv.deadline_ns==deadline && state.spi_nv_source_geometry==0x1000100);
    now=deadline;msm5xxx_poc_spi_nv_sync(&state);assert(image[3]==0x88);
    /* Property lexical rejection is atomic; final dependencies are separate. */
    const char *bad_geometry[]={"", "-1", "+1000100", "1000101", "100000000", "1000100:1", "1000100 "};
    for(unsigned i=0;i<sizeof(bad_geometry)/sizeof(*bad_geometry);i++) {
        setup();state.spi_nv_source_geometry=0;
        msm5xxx_poc_set_spi_nv_source_geometry(&state,bad_geometry[i],&err);
        assert(err && !state.spi_nv_source_geometry);err=NULL;
    }
    setup();state.boot_keysense_enabled=true;state.boot_keysense_pc[0]=0x100;state.boot_keysense_pc[1]=0x102;state.boot_keysense_pc[2]=0x104;
    found=(MemoryRegionSection){.mr=&memory,.size=1};
    msm5xxx_poc_boot_keysense_init(&state.machine,&state,&err);assert(err);err=NULL;
    /* Old explicit SPI has no geometry requirement and keeps its existing route. */
    setup();state.spi_nv_source_geometry=0;gpio(0x18,0x40);gpio(0x1c,3);select_cs(true);
    assert(state.spi_nv_qualified);select_cs(false);byte(6);select_cs(true);assert(state.spi_nv.wel);
    puts("boot read scope/geometry/staged-vs-pending/FUA actual-C PASS");return 0;
}
'''
        flags = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True, timeout=10))
        with tempfile.TemporaryDirectory(prefix='.boot-storage-native-', dir=repo) as directory:
            path = Path(directory)
            (path / 'check.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', '-I', str(native),
                            str(path / 'check.c'), str(native / 'msm5xxx-spi-nv.c'),
                            '-o', str(path / 'check'), *flags], check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)
        self.assertIn('msm5xxx_poc_boot_keysense_init(machine, s, &error_fatal);', source)
        self.assertIn('msm5xxx_poc_boot_keysense_reset(s);', source)
        self.assertIn('msm5xxx_poc_get_boot_keysense_state, NULL);', source)
        self.assertIn('msm[0x694] = 0x10;', source)


if __name__ == '__main__':
    unittest.main()
