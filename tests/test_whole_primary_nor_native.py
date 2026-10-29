"""Extract the explicit whole-primary selector and legacy zero-base guards."""
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class WholePrimaryNORNativeTests(unittest.TestCase):
    def test_actual_c_parser_final_context_and_legacy_guards(self):
        repo = Path(__file__).resolve().parents[1]
        source = (repo / 'experiments/qemu-tcg/msm5xxx-poc.c').read_text()

        def function(name):
            match = re.search(r'^static [^\n]*(?:\n[^\n]*)?\b' + name + r'\(', source, re.M)
            self.assertIsNotNone(match, name)
            brace = source.index('{', match.end())
            depth, end = 1, brace + 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[match.start():end]

        fields = source[source.index('    bool whole_primary_x16_enabled,'):
                        source.index('    bool raw_nand_main_enabled;')]
        code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#define MiB (1024*1024)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define MSM5XXX_POC_NOR_MAX_SIZE (32*MiB)
#define MSM5XXX_POC_NOR_MAX_REGIONS 4
#define MSM5XXX_POC_LCD_APERTURE_BASE 0x02000000
#define MSM5XXX_POC_LCD_APERTURE_SIZE 0x01000000
typedef struct { int unused; } MemoryRegion;
typedef struct { int unused; } Error;
static Error failure;
static void error_setg(Error **error,const char *format,...) { *error=&failure; }
static int qemu_strtou64(const char *text,const char **end,int base,uint64_t *value) {
    char *tail;errno=0;*value=strtoull(text,&tail,base);if(end)*end=tail;
    return errno ? -errno : tail==text ? -EINVAL : 0;
}
static int qemu_strtoul(const char *text,const char **end,int base,unsigned long *value) {
    char *tail;errno=0;*value=strtoul(text,&tail,base);if(end)*end=tail;
    return errno ? -errno : tail==text ? -EINVAL : 0;
}
typedef struct {
    bool memory_profile_enabled;
    uint32_t primary_nor_size,ram_base;
''' + fields + r'''
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(p) (p)
'''
        names = ('whole_primary_geometry', 'get_whole_primary_x16',
                 'set_whole_primary_x16', 'configure_whole_primary',
                 'get_primary_x16_nor', 'set_primary_x16_nor',
                 'set_amd_x16_nor', 'set_intel_x16_nor',
                 'get_record_x16_nor', 'set_record_x16_nor')
        code += '\n'.join(function('msm5xxx_poc_' + name) for name in names)
        code += r'''
static MSM5xxxPOCMachineState fresh(void) {
    MSM5xxxPOCMachineState s={0};s.primary_nor_size=0x200000;
    s.ram_base=0x1000000;s.memory_profile_enabled=true;return s;
}
static void select_device(MSM5xxxPOCMachineState *s,const char *value) {
    Error *err=NULL;msm5xxx_poc_set_whole_primary_x16(s,value,&err);assert(!err);
}
int main(void) {
    MSM5xxxPOCMachineState s=fresh(),saved;Error *err=NULL;char *text;
    assert(msm5xxx_poc_configure_whole_primary(&s,&err));
    assert(s.whole_primary_x16_realized && !s.primary_x16_nor_enabled);
    text=msm5xxx_poc_get_whole_primary_x16(&s,&err);assert(!strcmp(text,""));g_free(text);
    msm5xxx_poc_set_whole_primary_x16(&s,"200000:10000:1:22",&err);assert(err && !s.whole_primary_x16_enabled);err=NULL;
    /* No dependency on property application order; validation uses final context. */
    s=fresh();s.memory_profile_enabled=false;s.primary_nor_size=0;
    select_device(&s,"200000:10000:1:22");
    assert(!s.primary_x16_nor_enabled);
    s.memory_profile_enabled=true;s.primary_nor_size=0x200000;
    assert(msm5xxx_poc_configure_whole_primary(&s,&err));
    assert(s.primary_x16_nor_enabled && s.primary_x16_nor_base==0);
    assert(s.primary_x16_nor_size==0x200000 && s.primary_x16_nor_sector_size==0x10000);
    assert(s.primary_x16_nor_id0==1 && s.primary_x16_nor_id1==0x22);
    assert(!s.primary_x16_nor_region_count);
    text=msm5xxx_poc_get_whole_primary_x16(&s,&err);assert(!strcmp(text,"200000:10000:1:22"));g_free(text);
    text=msm5xxx_poc_get_primary_x16_nor(&s,&err);assert(!strcmp(text,""));g_free(text);
    saved=s;msm5xxx_poc_set_whole_primary_x16(&s,"200000:10000:2:3",&err);
    assert(err && !memcmp(&s,&saved,sizeof(s)));err=NULL;
    MSM5xxxPOCMachineState opposite=fresh();select_device(&opposite,"200000:10000:1:22");
    assert(msm5xxx_poc_configure_whole_primary(&opposite,&err));
    assert(!memcmp(&s,&opposite,sizeof(s)));
    /* Mixed-region geometry retains the existing CFI02 COUNT:LENGTH contract. */
    s=fresh();select_device(&s,"200000:1000:ffff:0:8:1000:1f8:1000");
    assert(msm5xxx_poc_configure_whole_primary(&s,&err));
    assert(s.primary_x16_nor_region_count==2 && s.primary_x16_nor_block_count[1]==0x1f8);
    text=msm5xxx_poc_get_whole_primary_x16(&s,&err);assert(!strcmp(text,"200000:1000:ffff:0:8:1000:1f8:1000"));g_free(text);
    s=fresh();select_device(&s,"200000:1000:1:2:10:1000:1f:10000");
    assert(msm5xxx_poc_configure_whole_primary(&s,&err));
    /* Rejected setters are atomic, including duplicates and range overflow. */
    const char *bad[]={NULL,"","200000:10000:1","200000:10000:1:2:",
        "+200000:10000:1:2","-200000:10000:1:2"," 200000:10000:1:2",
        "200000:10000:1:2 ","0x200000:10000:1:2","200000x:10000:1:2",
        "100000000:10000:1:2","10000000000000000:10000:1:2",
        "200000:10000:10000:2","0:10000:1:2","4000000:10000:1:2",
        "200000:0:1:2","200000:800:1:2","200000:3000:1:2","201000:10000:1:2",
        "200000:1000:1:2:0:1000","200000:1000:1:2:1:2000",
        "200000:1000:1:2:1:1000:1f:10000","200000:1000:1:2:1:1000",
        "200000:1000:1:2:ffffffff:80000000",
        "200000:1000:1:2:1:1000:1:1000:1:1000:1:1000:1:1000"};
    for(unsigned i=0;i<ARRAY_SIZE(bad);i++) {
        s=fresh();saved=s;msm5xxx_poc_set_whole_primary_x16(&s,bad[i],&err);
        assert(err && !memcmp(&s,&saved,sizeof(s)));err=NULL;
    }
    s=fresh();select_device(&s,"200000:10000:1:2");saved=s;
    msm5xxx_poc_set_whole_primary_x16(&s,"200000:10000:1:2",&err);
    assert(err && !memcmp(&s,&saved,sizeof(s)));err=NULL;
    /* Final dependency failures never populate the primary factory fields. */
    for(unsigned failure_case=0;failure_case<4;failure_case++) {
        s=fresh();select_device(&s,"200000:10000:1:2");
        if(failure_case==0)s.memory_profile_enabled=false;
        if(failure_case==1)s.primary_nor_size=0x100000;
        if(failure_case==2)s.ram_base=0x100000;
        if(failure_case==3)s.whole_primary_x16_block_count[0]=1,s.whole_primary_x16_region_count=1;
        assert(!msm5xxx_poc_configure_whole_primary(&s,&err));
        assert(err && !s.primary_x16_nor_enabled && s.whole_primary_x16_realized);err=NULL;
    }
    /* Each competing selector is rejected in either property order. */
    for(unsigned which=0;which<8;which++)for(unsigned order=0;order<2;order++) {
        s=fresh();
        if(order==0)select_device(&s,"200000:10000:1:2");
        bool *flags[]={&s.primary_x16_nor_enabled,&s.record_x16_nor_enabled,
            &s.mapped_primary_x16_nor_enabled,&s.intel_x16_nor_enabled,
            &s.amd_x16_nor_enabled,&s.fujitsu_x16_nor_enabled,
            &s.upper_x8_nor_enabled,&s.upper_x16_nor_enabled};
        *flags[which]=true;
        if(order==1)select_device(&s,"200000:10000:1:2");
        assert(!msm5xxx_poc_configure_whole_primary(&s,&err));assert(err);err=NULL;
    }
    /* Legacy base0 rejection is unchanged, even after selecting the new class. */
    for(unsigned selected=0;selected<2;selected++) {
        s=fresh();if(selected)select_device(&s,"200000:10000:1:2");
        msm5xxx_poc_set_primary_x16_nor(&s,"0:200000:10000:1:2",&err);
        assert(err && !s.primary_x16_nor_enabled);err=NULL;
        msm5xxx_poc_set_amd_x16_nor(&s,"0:200000:10000:1:2:0",&err);
        assert(err && !s.amd_x16_nor_enabled);err=NULL;
        msm5xxx_poc_set_intel_x16_nor(&s,"0:200000:10000:1:2",&err);
        assert(err && !s.intel_x16_nor_enabled);err=NULL;
    }
    s=fresh();msm5xxx_poc_set_primary_x16_nor(&s,"10000:10000:1000:1:2",&err);
    assert(!err && s.primary_x16_nor_enabled);
    text=msm5xxx_poc_get_primary_x16_nor(&s,&err);assert(!strcmp(text,"10000:10000:1000:1:2"));g_free(text);
    /* Legacy Record IDs stay erased; explicit bank IDs do not truncate. */
    s=fresh();s.primary_nor_size=0x800000;
    msm5xxx_poc_set_record_x16_nor(&s,"600000:1f0000:10000",&err);
    assert(!err && s.record_x16_nor_enabled && !s.record_x16_nor_explicit_ids);
    assert(s.record_x16_nor_id0==0xffff && s.record_x16_nor_id1==0xffff);
    text=msm5xxx_poc_get_record_x16_nor(&s,&err);
    assert(!strcmp(text,"600000:1f0000:10000"));g_free(text);
    msm5xxx_poc_set_record_x16_nor(&s,"600000:1f0000:10000:98:95",&err);
    assert(!err && s.record_x16_nor_explicit_ids);
    assert(s.record_x16_nor_id0==0x98 && s.record_x16_nor_id1==0x95);
    text=msm5xxx_poc_get_record_x16_nor(&s,&err);
    assert(!strcmp(text,"600000:1f0000:10000:98:95"));g_free(text);
    const char *record_bad[]={"600000:1f0000:10000:98",
        "600000:1f0000:10000:98:95:x", "600000:1f0000:10000:10000:95",
        "600000:1f0000:10000:100000000:95", "0:10000:1000:98:95",
        "600000:210000:10000:98:95", "600000:1f0000:3000:98:95"};
    for(unsigned n=0;n<ARRAY_SIZE(record_bad);n++) {
        saved=s;msm5xxx_poc_set_record_x16_nor(&s,record_bad[n],&err);
        assert(err && !memcmp(&s,&saved,sizeof(s)));err=NULL;
    }
    puts("whole-primary and bounded Record bank actual-C selectors PASS");return 0;
}
'''
        flags = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True, timeout=10))
        with tempfile.TemporaryDirectory(prefix='.whole-primary-native-', dir=repo) as directory:
            path = Path(directory)
            (path / 'check.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', str(path / 'check.c'),
                            '-o', str(path / 'check'), *flags], check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)
        initializer = function('msm5xxx_poc_init')
        self.assertLess(initializer.index('msm5xxx_poc_configure_whole_primary'),
                        initializer.index('memory_region_init_rom(&s->nor'))
        self.assertLess(initializer.index('msm5xxx_poc_configure_whole_primary'),
                        initializer.index('drive_get('))
        self.assertIn('dinfo = drive_get(IF_PFLASH, 0, 0);', initializer)
        self.assertIn('qdev_prop_set_uint8(dev, "width", 2);', initializer)
        self.assertIn('msm5xxx_poc_set_whole_primary_x16);', source)


if __name__ == '__main__':
    unittest.main()
