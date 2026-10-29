"""Compile the actual adapter and public NOR core with synthetic memory owners."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


def function(source, name):
    match = re.search(r"^static [^\n]*\b" + re.escape(name) + r"\(", source, re.M)
    assert match, name
    opening = source.index("{", match.start())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


class ProtectedNorNativeTests(unittest.TestCase):
    def test_source_ownership_commit_boundaries_and_legacy_mode(self):
        root = Path(__file__).resolve().parents[1]
        native = root / "native/qemu"
        source = (native / "msm5xxx-poc.c").read_text()
        names = ("msm5xxx_poc_boot_storage_hex", "msm5xxx_poc_protected_owned_read",
                 "msm5xxx_poc_protected_source_bounds", "msm5xxx_poc_protected_source_check",
                 "msm5xxx_poc_protected_persist", "msm5xxx_poc_protected_sync",
                 "msm5xxx_poc_protected_read", "msm5xxx_poc_protected_write",
                 "msm5xxx_poc_protected_reset", "msm5xxx_poc_get_protected_stats",
                 "msm5xxx_poc_set_protected", "msm5xxx_poc_set_protected_source",
                 "msm5xxx_poc_get_protected_source")
        realize = function(source, "msm5xxx_poc_protected_realize")
        begin = realize.index("    s->protected_nor_realized = true;")
        end = realize.index("    if (!s->protected_nor_enabled)", begin)
        final_guard = ("\n#define error_report(...) ((void)0)\n#define exit(code) return true\n"
                       "static bool final_rejected(MSM5xxxPOCMachineState *s) {\n" + realize[begin:end] +
                       "return false; }\n#undef exit\n#undef error_report\n")
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include "msm5xxx-protected-nor.h"
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define RAM_BASE 0x01000000u
#define BASE 0x4000u
#define BDRV_REQ_FUA 1
#define QEMU_CLOCK_VIRTUAL 0
#define MEMTX_OK 0
#define MEMTX_ERROR 1
#define MIN(a,b) ((a)<(b)?(a):(b))
typedef uint64_t hwaddr;
typedef int MemTxResult;
typedef int MemTxAttrs;
typedef struct { uint8_t *data; bool ram, rom; } MemoryRegion;
typedef struct { MemoryRegion *mr; uint64_t size, offset_within_region; } MemoryRegionSection;
typedef struct { uint64_t ram_size; } MachineState;
typedef struct {
    bool protected_nor_enabled,protected_nor_realized,protected_nor_source_enabled;
    bool memory_profile_enabled;
    uint32_t protected_nor_base,protected_nor_length,msm5xxx_protected_nor_sector,protected_nor_ticks;
    uint32_t protected_nor_source[6],protected_nor_source_reason;
    uint32_t ram_base,primary_nor_size;
    uint64_t protected_nor_persist_writes,protected_nor_persist_skips;
    uint64_t protected_nor_source_checks,protected_nor_source_rejections;
    int64_t protected_nor_clock;
    MSM5xxxProtectedNOR protected_nor;
    MemoryRegion nor;
    void *protected_nor_blk;
    MachineState machine;
} MSM5xxxPOCMachineState;
#define MACHINE(s) (&(s)->machine)
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(s) (s)
typedef int Error;
static int error_value;
static uint8_t ram[0x1000],rom[0x10000],working[0x400],seed[0x400],backend[0x400];
static MemoryRegion ram_owner,mmio_owner;
static MSM5xxxPOCMachineState *owner_state;
static uint32_t foreign_owner_address;
static bool partial_owner,guest=true,qtest;
static unsigned ram_pointer_calls;
static int64_t now;
static void *get_system_memory(void) { return NULL; }
static MemoryRegionSection memory_region_find(void *sys,hwaddr address,unsigned length) {
    (void)sys;MemoryRegionSection section={0};
    if (address>=RAM_BASE && address-RAM_BASE<=sizeof(ram) && length<=sizeof(ram)-(address-RAM_BASE)) {
        section=(MemoryRegionSection){&ram_owner,length,address-RAM_BASE};
    } else if (address<sizeof(rom) && length<=sizeof(rom)-address) {
        section=(MemoryRegionSection){&owner_state->nor,length,address};
    }
    if (address==foreign_owner_address) section.mr=&mmio_owner;
    if (partial_owner && section.size) section.size--;
    return section;
}
static bool memory_region_is_ram(MemoryRegion *region) { return region->ram; }
static bool memory_region_is_rom(MemoryRegion *region) { return region->rom; }
static uint64_t int128_make64(uint64_t value) { return value; }
static bool int128_eq(uint64_t a,uint64_t b) { return a==b; }
static void memory_region_unref(MemoryRegion *region) { assert(region); }
static void *memory_region_get_ram_ptr(MemoryRegion *region) {
    assert(region->ram && region->data);ram_pointer_calls++;return region->data;
}
static uint32_t ldl_le_p(const void *memory) {
    const uint8_t *p=memory;return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static void put32(uint8_t *p,uint32_t value) {
    for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(value>>(i*8));
}
static int64_t qemu_clock_get_ns(int clock) { (void)clock;return now; }
static bool msm5xxx_poc_boot_storage_guest(MSM5xxxPOCMachineState *s) { (void)s;return guest; }
static bool qtest_enabled(void) { return qtest; }
static int blk_pread(void *blk,unsigned offset,unsigned length,void *data,unsigned flags) {
    (void)blk;(void)flags;assert(offset+length<=sizeof(backend));memcpy(data,backend+offset,length);return 0;
}
static int blk_pwrite(void *blk,unsigned offset,unsigned length,const void *data,unsigned flags) {
    (void)blk;assert(flags==BDRV_REQ_FUA && offset+length<=sizeof(backend));memcpy(backend+offset,data,length);return 0;
}
static void error_report(const char *format,...) { (void)format;assert(!"unexpected I/O error"); }
static void error_setg(Error **err,const char *format,...) { (void)format;*err=&error_value; }
static int qemu_strtou64(const char *text,const char **end,int radix,uint64_t *result) {
    char *last;errno=0;*result=strtoull(text,&last,radix);if(end)*end=last;
    return errno==ERANGE || text==last ? -1:0;
}
#define g_ascii_isxdigit(c) isxdigit((unsigned char)(c))
static char *g_strdup(const char *s) { char *r=malloc(strlen(s)+1);assert(r);return strcpy(r,s); }
static char *g_strdup_printf(const char *format,...) {
    char text[1024];va_list ap;va_start(ap,format);int n=vsnprintf(text,sizeof(text),format,ap);va_end(ap);
    assert(n>=0 && n<(int)sizeof(text));return g_strdup(text);
}
''' + "\n".join(function(source, name) for name in names) + final_guard + r'''
static void setup(MSM5xxxPOCMachineState *s,unsigned sectors,bool source) {
    assert(sectors==2 || sectors==4);
    memset(s,0,sizeof(*s));memset(ram,0,sizeof(ram));memset(rom,0,sizeof(rom));
    memset(seed,0xff,sizeof(seed));memcpy(backend,seed,sizeof(seed));
    s->ram_base=RAM_BASE;s->primary_nor_size=sizeof(rom);s->machine.ram_size=sizeof(ram);s->memory_profile_enabled=true;
    s->nor=(MemoryRegion){rom,true,true};ram_owner=(MemoryRegion){ram,true,false};
    mmio_owner=(MemoryRegion){NULL,false,false};owner_state=s;foreign_owner_address=UINT32_MAX;
    partial_owner=false;guest=true;qtest=false;now=0;ram_pointer_calls=0;
    Error *err=NULL;
    if(source)msm5xxx_poc_set_protected_source(s,"1000000:100:1000004:1000008:1000040:300",&err);
    assert(!err);
    char model[80];snprintf(model,sizeof(model),"4000:%x:100:a",sectors*0x100);
    msm5xxx_poc_set_protected(s,model,&err);assert(!err);
    uint32_t sizes[4]={0x100,0x100,0x100,0x100};
    assert(msm5xxx_protected_nor_init(&s->protected_nor,seed,working,sectors*0x100,BASE,sizes,sectors,10));
    put32(ram,0x100);put32(ram+4,0x100);put32(ram+8,0);ram[12]=0;
    for(unsigned i=0;i<20;i++)ram[0x40+i]=rom[0x300+i]=(uint8_t)(0x70+i);
    put32(rom+0x104,sectors);for(unsigned i=0;i<sectors;i++)put32(rom+0x108+4*i,0x100);
    put32(rom+0x1b0,BASE/2);put32(rom+0x1b4,sectors*0x80);
}
static void write_word(MSM5xxxPOCMachineState *s,uint32_t offset,uint16_t value) {
    assert(msm5xxx_poc_protected_write(s,offset,value,2,0)==MEMTX_OK);
}
static uint16_t read_word(MSM5xxxPOCMachineState *s,unsigned offset) {
    uint64_t value;assert(msm5xxx_poc_protected_read(s,offset,&value,2,0)==MEMTX_OK);return value;
}
static void prefix(MSM5xxxPOCMachineState *s) {
    write_word(s,0,0x60);write_word(s,0,0);write_word(s,0,0xac);write_word(s,0,0x7f);write_word(s,0,0x7b);
    assert(s->protected_nor.phase==MSM5XXX_PROTECTED_NOR_GRANT);
}
static void array(MSM5xxxPOCMachineState *s) { write_word(s,0,0x50);write_word(s,0,0xff); }
int main(void) {
    MSM5xxxPOCMachineState s;Error *err=NULL;char *text;
    for(unsigned count=2;count<=4;count+=2) {
        setup(&s,count,true);assert(msm5xxx_poc_protected_source_bounds(&s));assert(!final_rejected(&s));
        assert(msm5xxx_poc_protected_source_check(&s));
        for(unsigned mode=1;mode<=2;mode++) {ram[12]=mode;assert(msm5xxx_poc_protected_source_check(&s));}
        ram[12]=0;
        text=msm5xxx_poc_get_protected_source(&s,&err);assert(!strcmp(text,"1000000:100:1000004:1000008:1000040:300"));free(text);
        prefix(&s);write_word(&s,0,0x40);write_word(&s,0,0xff6d);assert(backend[0]==0xff);
        write_word(&s,0,0x70);assert(read_word(&s,0)==0x80 && backend[0]==0x6d);array(&s);
        assert(read_word(&s,0)==0xff6d && s.protected_nor.programs==1);
        text=msm5xxx_poc_get_protected_stats(&s,&err);assert(strstr(text,"source_enabled=1") && strstr(text,"source_rejections=0"));free(text);
        msm5xxx_poc_protected_reset(&s);assert(backend[0]==0x6d && working[0]==0x6d && s.protected_nor.programs==1);
        assert(!s.protected_nor_source_checks && !s.protected_nor_source_rejections && !s.protected_nor_source_reason);
    }
    /* Bad values and all owner classes are rejected without probing MMIO. */
    for(unsigned fail=0;fail<13;fail++) {
        setup(&s,2,true);
        if(fail==0)put32(ram,0);
        if(fail==1)put32(ram+4,0x104);
        if(fail==2)put32(ram+8,4);
        if(fail==3)ram[12]=3;
        if(fail==4)ram[0x40]^=1;
        if(fail==5)put32(rom+0x104,43);
        if(fail==6)put32(rom+0x108,0x200);
        if(fail==7)put32(rom+0x1b0,BASE/2+1);
        if(fail==8)put32(rom+0x1b4,0x101);
        if(fail==9)foreign_owner_address=RAM_BASE;
        if(fail==10)foreign_owner_address=0x100;
        if(fail==11)partial_owner=true;
        if(fail==12)ram_owner.rom=true;
        write_word(&s,0,0x60);
        assert(s.protected_nor_source_rejections==1 && s.protected_nor_source_reason &&
               s.protected_nor.phase==MSM5XXX_PROTECTED_NOR_ARRAY && !s.protected_nor.programs);
        assert(!memcmp(backend,seed,s.protected_nor.length) &&
               !memcmp(working,seed,s.protected_nor.length));
        if(fail==9 || fail==11 || fail==12)assert(!ram_pointer_calls);
    }
    setup(&s,2,true);prefix(&s);write_word(&s,0,0x40);write_word(&s,0,0x12);
    put32(ram,0);write_word(&s,0,0x70);
    assert(!s.protected_nor.programs && working[0]==0xff && backend[0]==0xff && s.protected_nor_source_rejections==1);
    setup(&s,2,true);prefix(&s);write_word(&s,0,0x41);
    for(unsigned i=0;i<128;i++)write_word(&s,i*2,(uint16_t)i);
    ram[0x40]^=1;write_word(&s,0,0x70);
    assert(!s.protected_nor.programs && !memcmp(working,seed,s.protected_nor.length) &&
           !memcmp(backend,seed,s.protected_nor.length));
    for(unsigned boundary=0;boundary<2;boundary++) {
        setup(&s,2,true);prefix(&s);
        if(boundary)write_word(&s,0,0x20);
        put32(ram,0);write_word(&s,0,boundary?0xd0:0x20);
        assert(s.protected_nor.operation==MSM5XXX_PROTECTED_NOR_NONE &&
               !s.protected_nor.erases && backend[0]==0xff);
    }
    /* Foreign reads/debug peeks do not sync time or consume any source state. */
    setup(&s,2,true);prefix(&s);write_word(&s,0,0x20);write_word(&s,0,0xd0);
    put32(ram,0);uint64_t checks=s.protected_nor_source_checks;
    guest=false;now=100;uint64_t value;MSM5xxxProtectedNOR saved=s.protected_nor;
    assert(msm5xxx_poc_protected_read(&s,0,&value,8,0)==MEMTX_OK && value==UINT64_MAX);
    write_word(&s,0,0x70);assert(!memcmp(&saved,&s.protected_nor,sizeof(saved)) && !s.protected_nor_clock);
    assert(msm5xxx_poc_protected_read(&s,s.protected_nor.length,&value,2,0)==MEMTX_ERROR);
    assert(s.protected_nor_source_checks==checks);
    /* An accepted erase survives later global mutation and commits/readbacks. */
    guest=true;write_word(&s,0,0x70);assert(s.protected_nor.erases==1 && read_word(&s,0)==0x80);
    assert(s.protected_nor_source_checks==checks);array(&s);assert(read_word(&s,0)==0xffff);
    put32(ram,0x100);prefix(&s);write_word(&s,0,0x77);put32(ram+4,0);
    write_word(&s,0,0xd0);assert(!s.protected_nor.verifies && s.protected_nor.erases==1);
    /* No source property preserves the original explicit model-only path. */
    setup(&s,2,false);memset(ram,0,sizeof(ram));prefix(&s);write_word(&s,0,0x40);write_word(&s,0,0xff6d);
    write_word(&s,0,0x70);assert(read_word(&s,0)==0x80 && !s.protected_nor_source_checks && backend[0]==0x6d);
    /* Layout checks require a model but setter order is independent. */
    setup(&s,2,true);s.protected_nor_enabled=false;assert(!msm5xxx_poc_protected_source_bounds(&s));assert(final_rejected(&s));s.protected_nor_enabled=true;
    s.protected_nor_source[0]=RAM_BASE+sizeof(ram);assert(!msm5xxx_poc_protected_source_bounds(&s));
    setup(&s,2,true);s.protected_nor_source[1]=BASE;assert(!msm5xxx_poc_protected_source_bounds(&s));
    setup(&s,2,true);s.protected_nor_source[5]=s.primary_nor_size-18;assert(!msm5xxx_poc_protected_source_bounds(&s));
    setup(&s,2,false);msm5xxx_poc_set_protected_source(&s,"1000000:100:1000004:1000008:1000040:300",&err);
    assert(!err && msm5xxx_poc_protected_source_bounds(&s));
    MSM5xxxPOCMachineState before=s;msm5xxx_poc_set_protected_source(&s,"1000000:100:1000004:1000008:1000040:300",&err);
    assert(err && !memcmp(&before,&s,sizeof(s)));
    const char *bad[]={"", "1:100:1000004:1000008:1000040:300", "1000000:100:1000004:1000008:1000041:300",
        "1000000:fffffffc:1000004:1000008:1000040:300", "1000000:100:1000004:1000008:fffffffe:300",
        "1000000:100:1000004:1000008:1000040:300 ", "1000000:100:1000004:1000008:1000040",
        "1000000:100:1000004:1000008:1000040:300:0", "-1:100:1000004:1000008:1000040:300"};
    for(unsigned i=0;i<ARRAY_SIZE(bad);i++) { memset(&s,0,sizeof(s));before=s;err=NULL;
        msm5xxx_poc_set_protected_source(&s,bad[i],&err);assert(err && !memcmp(&before,&s,sizeof(s))); }
    memset(&s,0,sizeof(s));s.protected_nor_realized=true;before=s;err=NULL;
    msm5xxx_poc_set_protected_source(&s,"1000000:100:1000004:1000008:1000040:300",&err);
    assert(err && !memcmp(&before,&s,sizeof(s)));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(code)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                            "-I", str(native), str(path / "check.c"),
                            str(native / "msm5xxx-protected-nor.c"), "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True)


if __name__ == "__main__":
    unittest.main()
