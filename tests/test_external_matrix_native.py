"""Synthetic electrical tests for the external keypad latch plane."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_matrix_wires_native import _function


SOURCE = Path(__file__).resolve().parents[1] / "native/qemu/msm5xxx-poc.c"


@unittest.skipUnless(shutil.which(os.environ.get("CC", "cc")), "C compiler unavailable")
class ExternalMatrixNativeTests(unittest.TestCase):
    def test_two_latch_rows_five_senses_and_unrelated_bits(self):
        source = SOURCE.read_text()
        functions = "\n".join(_function(source, "msm5xxx_poc_" + name)
            for name in ("matrix_external_word_address", "matrix_external_read",
                         "matrix_external_write"))
        program = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct {
    bool running;
    struct { bool can_do_io; } neg;
} CPUState;
static CPUState cpu = { true, { true } };
static CPUState *current_cpu = &cpu;
static bool guest = true;
#define CPU(p) ((CPUState *)(p))
static bool qemu_in_vcpu_thread(void) { return guest; }
typedef struct {
    uint8_t *external_cs09;
    void *cpu;
    uint32_t matrix_input_address, matrix_input_wire_port[2];
    uint16_t matrix_input_wire_mask[2];
    uint8_t matrix_input_no_key, matrix_input_row, matrix_input_rows;
    uint8_t matrix_input_sense;
    bool matrix_input_pressed, matrix_input_external_active_high;
    uint64_t matrix_input_active_reads;
} MSM5xxxPOCMachineState;
static uint8_t *memory_region_get_ram_ptr(uint8_t **region) { return *region; }
static uint64_t msm5xxx_poc_backing_read(uint8_t *data, hwaddr offset, unsigned size)
{
    uint64_t value = 0;
    assert(offset + size <= 0x1000);
    for (unsigned i = 0; i < size; i++) {
        value |= (uint64_t)data[offset + i] << (8 * i);
    }
    return value;
}
static void msm5xxx_poc_backing_write(uint8_t *data, hwaddr offset,
                                     uint64_t value, unsigned size)
{
    assert(offset + size <= 0x1000);
    for (unsigned i = 0; i < size; i++) {
        data[offset + i] = value >> (8 * i);
    }
}
""" + functions + r"""
int main(void)
{
    uint8_t backing[0x1000] = {0};
    MSM5xxxPOCMachineState s = {
        .external_cs09 = backing, .cpu = &cpu,
        .matrix_input_address = 0x09000074,
        .matrix_input_wire_port = {0x09000010, 0x09000020},
        .matrix_input_wire_mask = {0x1050, 0x0085},
        .matrix_input_no_key = 31, .matrix_input_rows = 6,
        .matrix_input_external_active_high = true,
    };
    const unsigned ports[] = {0x10, 0x10, 0x10, 0x20, 0x20, 0x20};
    const unsigned bits[] = {0x10, 0x40, 0x1000, 1, 4, 0x80};
    const unsigned senses[] = {30, 29, 27, 23, 15};
    assert(msm5xxx_poc_matrix_external_word_address(0x09000074));
    assert(!msm5xxx_poc_matrix_external_word_address(0x09000075));
    assert(!msm5xxx_poc_matrix_external_word_address(0x08fffffc));
    assert(!msm5xxx_poc_matrix_external_word_address(0x09001000));
    msm5xxx_poc_backing_write(backing, 0x74, 0xa5c330e5, 4);
    assert(msm5xxx_poc_matrix_external_read(&s, 0, 4) == 0xa5c330ff);
    assert(s.matrix_input_active_reads == 0);
    for (unsigned row = 0; row < 6; row++) {
        for (unsigned column = 0; column < 5; column++) {
            uint64_t before = s.matrix_input_active_reads;
            s.matrix_input_pressed = true;
            s.matrix_input_row = row;
            s.matrix_input_sense = senses[column];
            msm5xxx_poc_backing_write(backing, 0x10, 0, 4);
            msm5xxx_poc_backing_write(backing, 0x20, 0, 4);
            assert(msm5xxx_poc_matrix_external_read(&s, 0, 4) == 0xa5c330ff);
            assert(s.matrix_input_active_reads == before);
            msm5xxx_poc_backing_write(backing, ports[row], bits[row], 4);
            assert(msm5xxx_poc_matrix_external_read(&s, 0, 4) ==
                   (0xa5c330e0 | senses[column]));
            assert(s.matrix_input_active_reads == before + 1);
            assert(msm5xxx_poc_matrix_external_read(&s, 0, 1) ==
                   (0xe0 | senses[column]));
            assert(msm5xxx_poc_matrix_external_read(&s, 0, 2) ==
                   (0x30e0 | senses[column]));
            assert(msm5xxx_poc_matrix_external_read(&s, 1, 2) == 0xc330);
            msm5xxx_poc_backing_write(backing, 0x10, 0x1050, 4);
            msm5xxx_poc_backing_write(backing, 0x20, 0x0085, 4);
            assert(msm5xxx_poc_matrix_external_read(&s, 0, 4) ==
                   (0xa5c330e0 | senses[column]));
            s.matrix_input_external_active_high = false;
            assert(msm5xxx_poc_matrix_external_read(&s, 0, 4) == 0xa5c330ff);
            msm5xxx_poc_backing_write(backing, ports[row],
                (ports[row] == 0x10 ? 0x1050 : 0x0085) & ~bits[row], 4);
            assert(msm5xxx_poc_matrix_external_read(&s, 0, 4) ==
                   (0xa5c330e0 | senses[column]));
            s.matrix_input_external_active_high = true;
        }
    }
    s.matrix_input_pressed = false;
    assert(msm5xxx_poc_matrix_external_read(&s, 0, 4) == 0xa5c330ff);
    msm5xxx_poc_matrix_external_write(&s, 1, 0x67, 1);
    assert(msm5xxx_poc_backing_read(backing, 0x74, 4) == 0xa5c367e5);
    msm5xxx_poc_matrix_external_write(&s, 4, 0, 1);
    assert(msm5xxx_poc_backing_read(backing, 0x74, 4) == 0xa5c367e5);
    assert(msm5xxx_poc_matrix_external_read(&s, 4, 1) == 0);
    assert(msm5xxx_poc_matrix_external_read(&s, UINT64_MAX, 4) == 0);
    s.matrix_input_pressed = true;
    s.matrix_input_row = 5;
    s.matrix_input_sense = 30;
    msm5xxx_poc_backing_write(backing, 0x20, 0x80, 4);
    guest = false;
    uint64_t before = s.matrix_input_active_reads;
    assert(msm5xxx_poc_matrix_external_read(&s, 0, 4) == 0xa5c367fe);
    assert(s.matrix_input_active_reads == before);
    return 0;
}
"""
        with tempfile.TemporaryDirectory(prefix="external-matrix-") as directory:
            root = Path(directory)
            path = root / "test.c"
            executable = root / "test"
            path.write_text(program)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Werror", str(path), "-o", str(executable)], check=True,
                           capture_output=True, text=True)
            subprocess.run([str(executable)], check=True, capture_output=True,
                           text=True)


if __name__ == "__main__":
    unittest.main()
