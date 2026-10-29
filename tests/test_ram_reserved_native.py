"""Compile actual reservation handlers; alias calls are recorded, not QEMU-run."""
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class RAMReservedNativeTests(unittest.TestCase):
    def test_property_final_range_and_alias_offsets(self):
        source = (Path(__file__).resolve().parents[1] /
                  'native/qemu/msm5xxx-poc.c').read_text()

        def function(name):
            start = source.index(name + '(')
            start = source.rfind('\nstatic ', 0, start) + 1
            return source[start:source.index('\nstatic ', start + 1)]

        start = source.index('    if (s->ram_reserved_size) {')
        mapping = source[start:source.index(
            '    memory_region_init_ram(&s->bootstrap', start)]
        self.assertIn('object_class_property_add_str(oc, "ram-reserved",', source)
        self.assertLess(source.index('if (s->memory_profile_enabled &&\n'),
                        source.index('if (!msm5xxx_poc_ram_reserved_valid(s))'))
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
typedef struct MemoryRegion {
    struct MemoryRegion *alias;
    void *owner;
    uint64_t offset, size, mapped;
} MemoryRegion;
typedef struct {
    uint64_t ram_size;
    MemoryRegion *ram;
    uint32_t ram_base, initial_sp, ram_reserved_base, ram_reserved_size;
    bool memory_profile_enabled;
    MemoryRegion ram_low_alias, ram_high_alias;
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState MachineState;
typedef MSM5xxxPOCMachineState Object;
typedef int Error;
#define MACHINE(obj) (obj)
#define OBJECT(obj) (obj)
#define MSM5XXX_POC_MACHINE(obj) (obj)
static Error error_value;
static void error_setg(Error **errp, const char *format, ...) {
    (void)format; *errp = &error_value;
}
/* QEMU conversion delegates to strtoull; exercise the actual caller's guards. */
static int qemu_strtou64(const char *text, const char **end, int base,
                        uint64_t *value) {
    char *last;
    errno = 0; *value = strtoull(text, &last, base); *end = last;
    return errno || last == text ? -1 : 0;
}
static MemoryRegion system_memory;
static unsigned mappings;
static MemoryRegion *get_system_memory(void) { return &system_memory; }
static void memory_region_init_alias(MemoryRegion *mr, void *owner,
                                    const char *name, MemoryRegion *orig,
                                    uint64_t offset, uint64_t size) {
    assert(name && orig && size);
    mr->alias = orig; mr->owner = owner; mr->offset = offset; mr->size = size;
}
static void memory_region_add_subregion(MemoryRegion *parent, uint64_t address,
                                        MemoryRegion *mr) {
    assert(parent == &system_memory); mr->mapped = address; mappings++;
}
''' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_ram_reserved_valid',
            'msm5xxx_poc_get_ram_reserved',
            'msm5xxx_poc_set_ram_reserved')) + r'''
static void map_ram(MachineState *machine) {
    MSM5xxxPOCMachineState *s = machine;
''' + mapping + r'''
}
int main(void) {
    MemoryRegion backing = {0};
    MSM5xxxPOCMachineState s = {
        .ram = &backing, .ram_size = 0xffc000, .ram_base = 0x1000000,
        .initial_sp = 0x1ffb000, .memory_profile_enabled = true,
    };
    Error *error = NULL;
    char *value = msm5xxx_poc_get_ram_reserved(&s, &error);
    assert(!error && !strcmp(value, "")); g_free(value);
    assert(msm5xxx_poc_ram_reserved_valid(&s));
    map_ram(&s);
    assert(mappings == 1 && backing.mapped == s.ram_base);
    assert(!s.ram_low_alias.alias && !s.ram_high_alias.alias);
    msm5xxx_poc_set_ram_reserved(&s, "1c00000:200000", &error);
    assert(!error && s.ram_reserved_base == 0x1c00000 &&
           s.ram_reserved_size == 0x200000);
    value = msm5xxx_poc_get_ram_reserved(&s, &error);
    assert(!strcmp(value, "1c00000:200000")); g_free(value);
    assert(msm5xxx_poc_ram_reserved_valid(&s));
    mappings = 0; map_ram(&s);
    assert(mappings == 2 && s.ram_low_alias.alias == &backing &&
           s.ram_high_alias.alias == &backing);
    assert(s.ram_low_alias.owner == &s && s.ram_high_alias.owner == &s);
    assert(s.ram_low_alias.mapped == 0x1000000 &&
           s.ram_low_alias.offset == 0 && s.ram_low_alias.size == 0xc00000);
    assert(s.ram_high_alias.mapped == 0x1e00000 &&
           s.ram_high_alias.offset == 0xe00000 && s.ram_high_alias.size == 0x1fc000);
    const char *invalid[] = {
        "", "1c00000", "1c00000:200000:0", "1c00000:200000x",
        "0:200000", "1c00000:0", "1c00001:200000", "1c00000:200001",
        "100000000:1000", "1c00000:100000000", "10000000000000000:1000",
        "-fffffffffe400000:200000", "1c00000:-ffffffffffe00000",
        " 1c00000:200000", "+1c00000:200000", "1c00000: 200000",
    };
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
        error = NULL;
        msm5xxx_poc_set_ram_reserved(&s, invalid[i], &error);
        assert(error && s.ram_reserved_base == 0x1c00000 &&
               s.ram_reserved_size == 0x200000);
    }
    error = NULL;
    msm5xxx_poc_set_ram_reserved(&s, "0x1C00000:0x200000", &error);
    assert(!error && msm5xxx_poc_ram_reserved_valid(&s));
    s.memory_profile_enabled = false;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.memory_profile_enabled = true;
    s.initial_sp = 0x1c00000;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.initial_sp = 0x1dffffc;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.initial_sp = 0x1bfffff;
    assert(!msm5xxx_poc_ram_reserved_valid(&s)); /* Crossing stack word. */
    s.initial_sp = 0x1bffffc;
    assert(msm5xxx_poc_ram_reserved_valid(&s));
    s.initial_sp = 0x1e00000;
    assert(!msm5xxx_poc_ram_reserved_valid(&s)); /* First descending push hits hole. */
    s.initial_sp = 0x1e00004;
    assert(msm5xxx_poc_ram_reserved_valid(&s));
    s.initial_sp = s.ram_base;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.initial_sp = 0x1e00004;
    s.ram_reserved_base = s.ram_base;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.ram_reserved_base = 0x1e00000; s.ram_reserved_size = 0x1fc000;
    assert(!msm5xxx_poc_ram_reserved_valid(&s)); /* No upper alias. */
    s.ram_reserved_base = 0x1c00000; s.ram_reserved_size = 0x400000;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.ram_reserved_base = 0xfffff000; s.ram_reserved_size = 0x2000;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.ram_reserved_base = 0x1c00000; s.ram_reserved_size = 0x200000;
    s.ram_size = UINT64_MAX;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.ram_size = 0xffc000; s.ram_reserved_base++;
    assert(!msm5xxx_poc_ram_reserved_valid(&s));
    s.ram_base = 0x14000000; s.ram_size = 0x800000;
    s.ram_reserved_base = 0x14400000; s.ram_reserved_size = 0x1000;
    s.initial_sp = 0x147ff000;
    assert(msm5xxx_poc_ram_reserved_valid(&s));
    mappings = 0; map_ram(&s);
    assert(mappings == 2 && s.ram_low_alias.size == 0x400000 &&
           s.ram_high_alias.offset == 0x401000 &&
           s.ram_high_alias.mapped == 0x14401000 &&
           s.ram_high_alias.size == 0x3ff000);
    return 0;
}
'''
        flags = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True, timeout=10))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', str(path / 'check.c'),
                            '-o', str(path / 'check'), *flags], check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
