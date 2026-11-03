"""Compile actual property, address-boundary and ready-pin helpers without QEMU."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class MiddleNandNativeTests(unittest.TestCase):
    def test_geometry_bounds_and_independent_gpio_bits(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'native/qemu/msm5xxx-poc.c').read_text()

        def function(name):
            match = re.search(r'^static [^\n]*(?:\n[^\n]*)?\b' + name + r'\(', source, re.M)
            self.assertIsNotNone(match, name)
            at = source.index('{', match.end())
            depth, end = 1, at + 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[match.start():end]

        constants = '\n'.join(re.findall(r'^#define MSM5XXX_POC_(?:RAW_NAND_.*|MSM_BASE .*)$', source, re.M))
        enum = source[source.index('typedef enum MSM5xxxPOCRawNandMode {'):
                      source.index('} MSM5xxxPOCRawNandMode;') + len('} MSM5xxxPOCRawNandMode;')]
        fields = source[source.index('    bool raw_nand_main_enabled;'):
                        source.index('    bool small_nand_enabled;')]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define MiB (1024 * 1024)
typedef uint64_t hwaddr;
typedef struct { const char *name; uint8_t bytes[4096]; } MemoryRegion;
typedef void BlockBackend;
typedef int Error;
static Error failed;
static void error_setg(Error **error, const char *format, ...) {
    (void)format; *error = &failed;
}
static void *memory_region_get_ram_ptr(MemoryRegion *region) { return region->bytes; }
''' + constants + '\n' + enum + '\ntypedef struct {\n' + fields + r'''
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
''' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_backing_read', 'msm5xxx_poc_backing_write',
            'msm5xxx_poc_set_raw_nand_main', 'msm5xxx_poc_set_raw_nand_ready',
            'msm5xxx_poc_raw_nand_latch_cursor',
            'msm5xxx_poc_raw_nand_ready_read',
            'msm5xxx_poc_raw_nand_ready_write')) + r'''
int main(void) {
    MSM5xxxPOCMachineState s = {0};
    Error *error = NULL;
    msm5xxx_poc_set_raw_nand_main(&s, "1800000:1900000:1a00000:1000000:200:20:2", &error);
    assert(!error && s.raw_nand_main_enabled && s.raw_nand_data_size == 16 * MiB);
    msm5xxx_poc_set_raw_nand_ready(&s, "3000728:1", &error);
    assert(!error && s.raw_nand_ready_address == 0x03000728 && s.raw_nand_ready_mask == 1);
    s.raw_nand_address_count = 3;
    s.raw_nand_address_bytes[0] = 255;
    s.raw_nand_address_bytes[1] = 255;
    s.raw_nand_address_bytes[2] = 127;
    assert(msm5xxx_poc_raw_nand_latch_cursor(&s));
    assert(s.raw_nand_cursor == 16 * MiB - 2);
    s.raw_nand_address_bytes[2] = 128;
    assert(!msm5xxx_poc_raw_nand_latch_cursor(&s));

    s.msm.bytes[0x728] = 0xA2;
    s.raw_nand_status = 0xC0;
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 0, 1) == 0xA3);
    msm5xxx_poc_raw_nand_ready_write(&s, 0, 0x42, 1);
    assert(s.msm.bytes[0x728] == 0x42);
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 0, 1) == 0x43);
    s.raw_nand_status = 0x80; /* Write-protect bit alone is not readiness. */
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 0, 1) == 0x42);
    s.raw_nand_status = 0xC1; /* Failed operations can still be ready. */
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 0, 1) == 0x43);
    s.raw_nand_ready_address = 0;
    msm5xxx_poc_set_raw_nand_ready(&s, "3000720:10", &error);
    assert(!error && s.raw_nand_ready_mask == 0x10);
    s.msm.bytes[0x720] = 0x83;
    s.msm.bytes[0x721] = 0xA5;
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 0, 2) == 0xA593);
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 1, 1) == 0xA5);
    msm5xxx_poc_raw_nand_ready_write(&s, 0, 0x1234, 2);
    assert(s.msm.bytes[0x720] == 0x34 && s.msm.bytes[0x721] == 0x12);
    s.raw_nand_status = 0x80;
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 0, 2) == 0x1224);

    s = (MSM5xxxPOCMachineState){0}; error = NULL;
    msm5xxx_poc_set_raw_nand_main(&s, "1800000:1900000:1a00000:2000000:200:20:2", &error);
    assert(!error && s.raw_nand_data_size == 32 * MiB);
    msm5xxx_poc_set_raw_nand_ready(&s, "3000720:2", &error);
    assert(!error && s.raw_nand_ready_mask == 2);
    s.msm.bytes[0x720] = 0x84; s.raw_nand_status = 0xC0;
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 0, 1) == 0x86);
    s.raw_nand_status = 0x80;
    assert(msm5xxx_poc_raw_nand_ready_read(&s, 0, 1) == 0x84);
    s.raw_nand_spare_selected = true; s.raw_nand_address_count = 3;
    s.raw_nand_address_bytes[0] = 2;
    assert(msm5xxx_poc_raw_nand_latch_cursor(&s));
    s.raw_nand_address_bytes[0] = 8;
    assert(!msm5xxx_poc_raw_nand_latch_cursor(&s));

    const char *accepted[] = {
        "2800000:2900000:2a00000:800000:200:20:2",
        "800000:900000:a00000:800000:200:20:2"
    };
    for (unsigned i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        memset(&s, 0, sizeof(s)); error = NULL;
        msm5xxx_poc_set_raw_nand_main(&s, accepted[i], &error);
        assert(!error && s.raw_nand_data_size == 8 * MiB);
    }
    const char *rejected[] = {
        "1800000:1900000:1a00000:800000:200:20:2",
        "2800000:2900000:2a00000:1000000:200:20:2",
        "1800000:900000:1a00000:1000000:200:20:2",
        "1800000:1900000:1a00000:1000000:800:20:2",
        "1800000:1900000:1a00000:1000000:200:20:1",
        "1800000:1900000"
    };
    for (unsigned i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        memset(&s, 0, sizeof(s)); error = NULL;
        MSM5xxxPOCMachineState before = s;
        msm5xxx_poc_set_raw_nand_main(&s, rejected[i], &error);
        assert(error && memcmp(&s, &before, sizeof(s)) == 0);
    }
    const char *invalid_ready[] = {"3000728:10", "3000720:1", "300072c:1", "3000728"};
    for (unsigned i = 0; i < sizeof(invalid_ready) / sizeof(invalid_ready[0]); i++) {
        memset(&s, 0, sizeof(s)); error = NULL;
        msm5xxx_poc_set_raw_nand_ready(&s, invalid_ready[i], &error);
        assert(error && !s.raw_nand_ready_address && !s.raw_nand_ready_mask);
    }
    puts("middle NAND actual-C geometry/bounds/ready GPIO PASS");
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='middle-nand-native-') as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', str(path / 'check.c'),
                            '-o', str(path / 'check')], check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
