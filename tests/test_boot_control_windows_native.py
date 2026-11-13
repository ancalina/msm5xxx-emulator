"""Compile native word control windows and UART reads with generated state."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from native_sanitizers import native_sanitizers
from test_protected_nor_native import function


class BootControlWindowsNativeTests(unittest.TestCase):
    def test_parser_reset_and_word_uart_mask(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        source = (native / 'msm5xxx-poc.c').read_text()
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef uint64_t hwaddr;
typedef struct { uint8_t bytes[0x1000]; size_t size; } MemoryRegion;
typedef struct { char *name; } MSM;
typedef struct { uint32_t pending; } MSM5xxxBootNand;
typedef struct {
    MSM msm;
    unsigned boot_control_count;
    uint32_t boot_control_ranges[32];
    MemoryRegion boot_control[16];
    MSM5xxxBootNand boot_nand;
    uint8_t boot_nand_backing[0x1000];
    uint8_t boot_events_backing[0x10000];
    uint16_t boot_lcd_selector, boot_lcd_registers[65536];
    uint16_t boot_lcd_control, boot_bridge_registers[32768];
    bool boot_nand_word;
    uint32_t boot_nand_peripherals;
    uint32_t boot_nand_data_port, boot_nand_lcd_id;
    struct { void *machine; bool data; } boot_lcd_context[2];
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
typedef int Error;
#define MSM5XXX_POC_MACHINE(s) (s)
#define g_ascii_isxdigit(c) isxdigit((unsigned char)(c))
static int error_value;
static void error_setg(Error **err, const char *format, ...) {
    (void)format; *err = &error_value;
}
static int qemu_strtou64(const char *text, const char **end, int radix,
                         uint64_t *result) {
    char *last; errno = 0; *result = strtoull(text, &last, radix); *end = last;
    return errno == ERANGE || text == last ? -1 : 0;
}
static void *memory_region_get_ram_ptr(MemoryRegion *region) {
    return region->bytes;
}
static size_t memory_region_size(const MemoryRegion *region) {
    return region->size;
}
static void msm5xxx_boot_nand_reset(MSM5xxxBootNand *nand) {
    nand->pending = 0;
}
static void msm5xxx_boot_nand_irq_ack(MSM5xxxBootNand *nand, uint32_t mask) {
    nand->pending &= ~mask;
}
static hwaddr traced_address;
static uint64_t traced_value;
static unsigned traced_size;
static void msm5xxx_poc_lcd_trace_write(MSM5xxxPOCMachineState *state,
        hwaddr address, uint64_t value, unsigned size) {
    (void)state;
    traced_address = address; traced_value = value; traced_size = size;
}
''' + '\n'.join(function(source, name) for name in (
            'msm5xxx_poc_boot_storage_hex',
            'msm5xxx_poc_set_boot_control_windows',
            'msm5xxx_poc_boot_nand_reset',
            'msm5xxx_poc_boot_events_read',
            'msm5xxx_poc_boot_events_write',
            'msm5xxx_poc_boot_lcd_read',
            'msm5xxx_poc_boot_lcd_write',
            'msm5xxx_poc_boot_video_read',
            'msm5xxx_poc_boot_video_write')) + r'''
int main(void) {
    MSM5xxxPOCMachineState state = {0}, before;
    Error *error = NULL;
    msm5xxx_poc_set_boot_control_windows(&state,
        "48000000:1000:50203000:1000", &error);
    assert(!error && state.boot_control_count == 2);
    assert(state.boot_control_ranges[0] == 0x48000000);
    assert(state.boot_control_ranges[1] == 0x1000);
    assert(state.boot_control_ranges[2] == 0x50203000);
    assert(state.boot_control_ranges[3] == 0x1000);

    const char *bad[] = {
        "", "0:1000", "48000001:1000", "48000000:1001",
        "48000000:0", "fffff000:2000", "48000000:1000:48000000:1000",
        "48000000:1000:", "48000000:1000 ", "-48000000:1000",
        "48000000"
    };
    for (unsigned i = 0; i < ARRAY_SIZE(bad); i++) {
        memset(&state, 0, sizeof(state));
        before = state; error = NULL;
        msm5xxx_poc_set_boot_control_windows(&state, bad[i], &error);
        assert(error && !memcmp(&state, &before, sizeof(state)));
    }
    memset(&state, 0, sizeof(state));
    state.msm.name = (char *)"realized"; before = state; error = NULL;
    msm5xxx_poc_set_boot_control_windows(&state, "48000000:1000", &error);
    assert(error && !memcmp(&state, &before, sizeof(state)));

    memset(&state, 0, sizeof(state));
    state.boot_control_count = 2;
    state.boot_control[0].size = state.boot_control[1].size = 0x1000;
    memset(state.boot_control[0].bytes, 0x31, 0x1000);
    memset(state.boot_control[1].bytes, 0x72, 0x1000);
    memset(state.boot_nand_backing, 0x23, sizeof(state.boot_nand_backing));
    memset(state.boot_events_backing, 0x45, sizeof(state.boot_events_backing));
    memset(state.boot_lcd_registers, 0x13, sizeof(state.boot_lcd_registers));
    memset(state.boot_bridge_registers, 0x57, sizeof(state.boot_bridge_registers));
    state.boot_lcd_selector = 17;
    state.boot_lcd_control = 19;
    state.boot_nand.pending = 0xfeed;
    msm5xxx_poc_boot_nand_reset(&state);
    assert(state.boot_nand.pending == 0);
    assert(state.boot_lcd_selector == 0 && state.boot_lcd_control == 0);
    for (unsigned i = 0; i < 0x1000; i++) {
        assert(state.boot_control[0].bytes[i] == 0);
        assert(state.boot_control[1].bytes[i] == 0);
        assert(state.boot_nand_backing[i] == 0);
    }
    for (unsigned i = 0; i < sizeof(state.boot_events_backing); i++)
        assert(state.boot_events_backing[i] == 0);
    for (unsigned i = 0; i < ARRAY_SIZE(state.boot_lcd_registers); i++)
        assert(state.boot_lcd_registers[i] == 0);
    for (unsigned i = 0; i < ARRAY_SIZE(state.boot_bridge_registers); i++)
        assert(state.boot_bridge_registers[i] == 0);

    state.boot_nand_word = true;
    state.boot_nand.pending = 0x6000;
    msm5xxx_poc_boot_events_write(&state, 0x904, 0x6000, 4);
    assert(msm5xxx_poc_boot_events_read(&state, 0x950, 4) == 0);
    state.boot_nand.pending = 0x2000;
    msm5xxx_poc_boot_events_write(&state, 0x904, 0x4000, 4);
    assert(msm5xxx_poc_boot_events_read(&state, 0x950, 4) == 0x2000);
    state.boot_nand_word = false;
    msm5xxx_poc_boot_events_write(&state, 0xc84, 0x2000, 4);
    assert(msm5xxx_poc_boot_events_read(&state, 0xc84, 4) == 0);
    state.boot_nand_word = true;
    state.boot_lcd_context[0].machine = &state;
    state.boot_lcd_selector = 1;
    state.boot_nand_lcd_id = 0;
    msm5xxx_poc_boot_lcd_write(&state.boot_lcd_context[0], 4, 0x1234, 2);
    assert(msm5xxx_poc_boot_lcd_read(&state.boot_lcd_context[0], 4, 2) == 0x1234);
    state.boot_nand_lcd_id = 0x7068;
    msm5xxx_poc_boot_lcd_write(&state.boot_lcd_context[0], 4, 0x5678, 2);
    assert(msm5xxx_poc_boot_lcd_read(&state.boot_lcd_context[0], 4, 2) == 0x7068);
    state.boot_lcd_selector = 3;
    msm5xxx_poc_boot_lcd_write(&state.boot_lcd_context[0], 4, 0x9abc, 2);
    assert(msm5xxx_poc_boot_lcd_read(&state.boot_lcd_context[0], 4, 2) == 0x9abc);
    const uint32_t ports[] = {0x20040000, 0x20080000};
    for (unsigned i = 0; i < ARRAY_SIZE(ports); i++) {
        state.boot_nand_data_port = ports[i];
        state.boot_lcd_selector = 0x202;
        msm5xxx_poc_boot_video_write(&state, 12, 0xf80007e0, 4);
        assert(traced_address == ports[i] + 12 && traced_size == 4);
        assert(traced_value == 0xf80007e0);
        assert(msm5xxx_poc_boot_video_read(&state, 0, 4) == 0xf800f800);
        msm5xxx_poc_boot_video_write(&state, 0, 0x001f, 2);
        assert(traced_address == ports[i] && traced_size == 2);
        assert(msm5xxx_poc_boot_video_read(&state, 0, 2) == 0x001f);
    }
    state.boot_nand_peripherals = 2;
    state.boot_events_backing[0x1408] = 0xaa;
    state.boot_events_backing[0x1508] = 0xbb;
    assert(msm5xxx_poc_boot_events_read(&state, 0x1408, 4) == 8);
    assert(msm5xxx_poc_boot_events_read(&state, 0x1508, 4) == 8);
    state.boot_nand_peripherals = 1;
    assert(msm5xxx_poc_boot_events_read(&state, 0x1408, 1) == 0xaa);
    assert(msm5xxx_poc_boot_events_read(&state, 0x1508, 1) == 0xbb);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(code)
            subprocess.run([
                'cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                native_sanitizers(), '-fno-sanitize-recover=all',
                str(path / 'check.c'), '-o', str(path / 'check')
            ], check=True)
            subprocess.run([str(path / 'check')], check=True)


if __name__ == '__main__':
    unittest.main()
