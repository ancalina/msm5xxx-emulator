"""Compile the production source-gated shared LCD/audio dispatch helpers."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class SharedAudioLCDNativeTests(unittest.TestCase):
    def test_ma2_shared_dispatch_and_lcd_fallbacks(self) -> None:
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        source = (native / "msm5xxx-poc.c").read_text(encoding="utf-8")

        def function(name: str) -> str:
            match = re.search(r"^static [^;\n]*\b" + name + r"\([^;]*?\)\n\{", source, re.M)
            self.assertIsNotNone(match, name)
            start = source.index("{", match.start())
            depth, cursor = 1, start + 1
            while depth:
                depth += (source[cursor] == "{") - (source[cursor] == "}")
                cursor += 1
            return source[match.start():cursor]

        helpers = "\n".join(function(name) for name in (
            "msm5xxx_poc_ma5_shared_lcd_port",
            "msm5xxx_poc_ma5_shared_lcd_route",
            "msm5xxx_poc_ma5_shared_lcd_read",
            "msm5xxx_poc_ma5_shared_lcd_write",
        ))
        harness = r'''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef int MemTxAttrs;
typedef enum { MEMTX_OK, MEMTX_ERROR } MemTxResult;
typedef struct { int unused; } MemoryRegion;
typedef struct CPUState { bool running; } CPUState;
typedef struct {
    bool audio_enabled, audio_ma2, audio_ma3, audio_ma5, audio_shared_lcd;
    bool ma5_byte_ns, audio_sites_enabled;
    uint32_t audio_base, audio_data_offset;
    bool audio_site_write[8];
    uint8_t audio_site_port[8];
    uint32_t audio_site_pc[8];
    unsigned audio_site_count;
    CPUState *cpu;
    uint8_t backing[16];
} MSM5xxxPOCMachineState;
typedef struct { MSM5xxxPOCMachineState *machine; unsigned index; } MSM5xxxPOCLCDPort;
typedef struct { int placeholder; } MemoryRegionOps;
static const uint64_t msm5xxx_poc_lcd_bases[] = {0x02000000, 0x02800000, 0x02c00000};
#define MSM5XXX_POC_LCD_PORTS 3
#define MSM5XXX_POC_LCD_SIZE 0x1000
#define CPU(p) (p)
static CPUState *current_cpu;
static bool in_vcpu = true, pc_valid = true;
static uint32_t current_pc;
static unsigned lcd_reads, lcd_writes, audio_reads, audio_writes, opaque_reads, opaque_writes;
static uint64_t lcd_read_value = 0xA55A;
static bool audio_read_supported = true, audio_write_supported = true;
static bool qemu_in_vcpu_thread(void) { return in_vcpu; }
static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState *s, uint32_t *pc) {
    (void)s; if (!pc_valid) return false; *pc = current_pc; return true;
}
static uint64_t msm5xxx_poc_lcd_read(void *opaque, hwaddr offset, unsigned size) {
    MSM5xxxPOCLCDPort *port = opaque; (void)offset; (void)size; lcd_reads++;
    return lcd_read_value + port->index;
}
static void msm5xxx_poc_lcd_write(void *opaque, hwaddr offset, uint64_t value, unsigned size) {
    MSM5xxxPOCLCDPort *port = opaque; (void)offset; (void)value; (void)size; (void)port; lcd_writes++;
}
static bool msm5xxx_poc_audio_read_owned(MSM5xxxPOCMachineState *s, hwaddr offset,
                                         unsigned size, uint64_t *value) {
    (void)s; (void)offset; (void)size; audio_reads++; if (!audio_read_supported) return false;
    *value = 0xB000 + offset; return true;
}
static bool msm5xxx_poc_audio_write_owned(MSM5xxxPOCMachineState *s, hwaddr offset,
                                          uint64_t value, unsigned size) {
    (void)s; (void)offset; (void)value; (void)size; audio_writes++; return audio_write_supported;
}
static MemTxResult msm5xxx_poc_audio_opaque_read(MSM5xxxPOCMachineState *s,
        hwaddr offset, uint64_t *value, unsigned size, MemTxAttrs attrs) {
    (void)s; (void)size; (void)attrs; opaque_reads++; *value = 0xC000 + offset; return MEMTX_OK;
}
static MemTxResult msm5xxx_poc_audio_opaque_write(MSM5xxxPOCMachineState *s,
        hwaddr offset, uint64_t value, unsigned size, MemTxAttrs attrs) {
    (void)s; (void)offset; (void)value; (void)size; (void)attrs; opaque_writes++; return MEMTX_OK;
}
''' + helpers + r'''
int main(void) {
    MSM5xxxPOCMachineState s = {0};
    CPUState cpu = {.running = true}; current_cpu = &cpu; s.cpu = &cpu;
    s.audio_enabled = s.audio_ma2 = s.audio_shared_lcd = s.audio_sites_enabled = true;
    s.audio_base = 0x02000000; s.audio_data_offset = 2;
    s.audio_site_count = 2; s.audio_site_pc[0] = 0x100; s.audio_site_pc[1] = 0x104;
    MSM5xxxPOCLCDPort port = {.machine = &s, .index = 0};
    uint64_t value = 0;
    assert(msm5xxx_poc_ma5_shared_lcd_port(&s) == 0);

    /* The declared MA2 PC reaches the existing byte register handlers. */
    current_pc = 0x100;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 0, &value, 1, 0) == MEMTX_OK);
    assert(value == 0xB000 && audio_reads == 1 && lcd_reads == 0);
    assert(msm5xxx_poc_ma5_shared_lcd_write(&port, 2, 0x55, 1, 0) == MEMTX_OK);
    assert(audio_writes == 1 && lcd_writes == 0);

    /* Unsupported MA2 reads and writes retain the original LCD behavior. */
    audio_read_supported = false; value = 0;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 0, &value, 1, 0) == MEMTX_OK);
    assert(value == lcd_read_value && lcd_reads == 1);
    audio_write_supported = false;
    assert(msm5xxx_poc_ma5_shared_lcd_write(&port, 2, 0x66, 1, 0) == MEMTX_OK);
    assert(lcd_writes == 1);

    /* A foreign PC, an unowned port offset, or non-vCPU I/O stays on LCD. */
    audio_read_supported = true; audio_write_supported = true;
    current_pc = 0x108; value = 0;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 0, &value, 1, 0) == MEMTX_OK);
    assert(value == lcd_read_value && lcd_reads == 2);
    current_pc = 0x108; value = 0;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 0, &value, 1, 0) == MEMTX_OK);
    assert(value == lcd_read_value && lcd_reads == 3);
    in_vcpu = false; value = 0;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 0, &value, 1, 0) == MEMTX_OK);
    assert(value == lcd_read_value && lcd_reads == 4); in_vcpu = true;

    /* Unavailable PC attribution inside the configured aperture is an error. */
    pc_valid = false;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 0, &value, 1, 0) == MEMTX_ERROR);
    assert(msm5xxx_poc_ma5_shared_lcd_write(&port, 0, 1, 1, 0) == MEMTX_ERROR);
    pc_valid = true;

    /* Existing MA3 and MA5 opaque handlers retain the same PC gate. */
    s.audio_ma2 = false; s.audio_ma3 = true; current_pc = 0x104; value = 0;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 2, &value, 1, 0) == MEMTX_OK);
    assert(value == 0xC002 && opaque_reads == 1);
    assert(msm5xxx_poc_ma5_shared_lcd_write(&port, 2, 1, 1, 0) == MEMTX_OK && opaque_writes == 1);
    s.audio_ma3 = false; s.audio_ma5 = true; current_pc = 0x100;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 0, &value, 1, 0) == MEMTX_OK);
    assert(opaque_reads == 2);

    /* Declared sites continue to dispatch the configured byte offset. */
    s.audio_ma5 = false; s.audio_ma2 = true; current_pc = 0x100;
    assert(msm5xxx_poc_ma5_shared_lcd_read(&port, 2, &value, 1, 0) == MEMTX_OK);
    assert(audio_reads == 3);
    s.audio_base = 0x02000FFF;
    assert(msm5xxx_poc_ma5_shared_lcd_port(&s) == -1);
    return 0;
}
'''
        temporary_root = Path(os.environ.get("TMPDIR", Path(__file__).resolve().parents[2] / "tmp"))
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
            c_file = Path(temporary) / "shared-audio.c"
            binary = Path(temporary) / "shared-audio"
            c_file.write_text(harness, encoding="utf-8")
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                            "-o", str(binary), str(c_file)], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
