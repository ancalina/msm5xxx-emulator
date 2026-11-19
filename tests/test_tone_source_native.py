"""Synthetic source ownership and backing tests for the tone aperture."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from test_matrix_wires_native import _function


@unittest.skipUnless(shutil.which(os.environ.get("CC", "cc")), "C compiler unavailable")
class ToneSourceNativeTests(unittest.TestCase):
    def test_owned_byte_stores_preserve_other_accesses_and_widths(self):
        source = (Path(__file__).resolve().parents[1] / "native/qemu/msm5xxx-poc.c").read_text()
        functions = "\n".join(_function(source, "msm5xxx_poc_" + name) for name in (
            "tone_source_sites_valid", "tone_source_owns_write",
            "tone_source_read", "tone_source_write"))
        fields = sorted(set(re.findall(r"s->(\w+)", functions)))
        declarations = "\n".join(
            ("CPUState *" if field == "cpu" else "uint32_t ") + field +
            ("[12]" if field == "tone_source_sites" else "") + ";" for field in fields)
        program = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
typedef uint32_t hwaddr;
typedef struct { bool running; struct { bool can_do_io; } neg;
                 struct { bool thumb; } env; } CPUState;
typedef struct {
""" + declarations + r"""
} MSM5xxxPOCMachineState;
static CPUState active_cpu, other_cpu;
static CPUState *current_cpu = &active_cpu;
static bool vcpu_thread = true;
static uint32_t current_pc;
static uint8_t backing[0x1000];
static unsigned forwarded;
static uint64_t get_pc(CPUState *cpu) { (void)cpu; return current_pc; }
static struct { uint64_t (*get_pc)(CPUState *); } cpu_class = {get_pc};
#define CPU_GET_CLASS(cpu) (&cpu_class)
#define CPU(cpu) (cpu)
static bool qemu_in_vcpu_thread(void) { return vcpu_thread; }
static uint64_t msm5xxx_poc_halfword_backing_read(
    MSM5xxxPOCMachineState *s, unsigned offset, unsigned size)
{
    uint64_t result = 0;
    (void)s;
    for (unsigned i = 0; i < size; i++) { result |= (uint64_t)backing[offset+i] << (8*i); }
    return result;
}
static void msm5xxx_poc_halfword_backing_write(
    MSM5xxxPOCMachineState *s, unsigned offset, uint64_t value, unsigned size)
{
    (void)s;
    for (unsigned i = 0; i < size; i++) { backing[offset+i] = value >> (8*i); }
}
static void msm5xxx_poc_tone_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{ (void)opaque; (void)value; assert(size == 1 && offset == 0x18); forwarded++; }
""" + functions + r"""
int main(void)
{
    MSM5xxxPOCMachineState s = {0};
    assert(msm5xxx_poc_tone_source_sites_valid(&s));
    s.tone_enabled = true;
    s.primary_nor_size = 0x200;
    s.tone_source_site_count = 12;
    for (unsigned i = 0; i < 12; i++) { s.tone_source_sites[i] = 0x100 + i*2; }
    assert(msm5xxx_poc_tone_source_sites_valid(&s));
    s.tone_source_sites[11] = 0x100;
    assert(!msm5xxx_poc_tone_source_sites_valid(&s));
    s.tone_source_sites[11] = 0x201;
    assert(!msm5xxx_poc_tone_source_sites_valid(&s));
    s.tone_source_sites[11] = 0x200;
    assert(!msm5xxx_poc_tone_source_sites_valid(&s));
    s.tone_source_sites[11] = 0x116;
    s.cpu = &active_cpu;
    active_cpu.running = active_cpu.neg.can_do_io = active_cpu.env.thumb = true;
    current_pc = 0x180;
    msm5xxx_poc_tone_source_write(&s, 0x18, 0xfedcba98, 4);
    assert(msm5xxx_poc_tone_source_read(&s, 0x18, 4) == 0xfedcba98);
    assert(!forwarded);
    current_pc = 0x100;
    msm5xxx_poc_tone_source_write(&s, 0x18, 0x1234, 2);
    assert(msm5xxx_poc_tone_source_read(&s, 0x18, 2) == 0x1234 && !forwarded);
    active_cpu.env.thumb = false;
    msm5xxx_poc_tone_source_write(&s, 0x18, 0xaa, 1);
    assert(msm5xxx_poc_tone_source_read(&s, 0x18, 1) == 0xaa && !forwarded);
    active_cpu.env.thumb = true;
    current_cpu = &other_cpu;
    msm5xxx_poc_tone_source_write(&s, 0x18, 0xbb, 1);
    assert(!forwarded);
    current_cpu = &active_cpu;
    vcpu_thread = false;
    msm5xxx_poc_tone_source_write(&s, 0x18, 0xcc, 1);
    assert(!forwarded);
    vcpu_thread = true;
    msm5xxx_poc_tone_source_write(&s, 0x18, 0x55, 1);
    assert(forwarded == 1 && msm5xxx_poc_tone_source_read(&s, 0x18, 1) == 0x55);
    return 0;
}
"""
        with tempfile.TemporaryDirectory(prefix="tone-source-") as directory:
            root = Path(directory)
            (root / "test.c").write_text(program)
            compiled = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1",
                "-Wall", "-Wextra", "-Werror", str(root / "test.c"), "-o", str(root / "test")],
                capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(root / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
