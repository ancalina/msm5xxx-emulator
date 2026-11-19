"""Synthetic native checks for descriptor-linked encoded keypad ports."""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_matrix_wires_native import _function


SOURCE = Path(__file__).resolve().parents[1] / "native/qemu/msm5xxx-poc.c"


@unittest.skipUnless(shutil.which(os.environ.get("CC", "cc")),
                     "C compiler unavailable")
class EncodedPortsNativeTests(unittest.TestCase):
    def test_encoded_port_values_gates_writeback_and_conflicts(self):
        source = SOURCE.read_text()
        values = "\n".join(_function(source, "msm5xxx_poc_" + name) for name in (
            "matrix_halfword_backing_read", "matrix_encoded_read_gate", "encoded_port_value"))
        writing = _function(source, "msm5xxx_poc_matrix_encoded_row_write")
        conflicts = _function(source, "msm5xxx_poc_matrix_encoded_conflict")
        fields = sorted(set(re.findall(r"s->(\w+)", values + writing + conflicts)))
        declarations = "\n".join(
            ("CPUState *" if field == "cpu" else "uint32_t ") + field + ";"
            for field in fields)
        pause_size = re.search(
            r"^#define MSM5XXX_POC_PAUSE_TIMER_SIZE\s+(.+)$", source, re.M).group(1)
        eeprom_size = re.search(
            r"^#define MSM5XXX_POC_EEPROM_GPIO_SIZE\s+(.+)$", source, re.M).group(1)
        program = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define MSM5XXX_POC_PAUSE_TIMER_SIZE """ + pause_size + r"""
#define MSM5XXX_POC_EEPROM_GPIO_SIZE """ + eeprom_size + r"""
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
typedef uint32_t hwaddr;
typedef struct { bool running; struct { bool can_do_io; } neg;
                 struct { bool thumb; } env; } CPUState;
typedef struct {
""" + declarations + r"""
} MSM5xxxPOCMachineState;
static uint8_t backing[0x1000];
static CPUState active_cpu;
static CPUState other_cpu;
static CPUState *current_cpu = &active_cpu;
static bool vcpu_thread = true;
static unsigned last_write_offset;
static uint64_t msm5xxx_poc_halfword_backing_read(
    MSM5xxxPOCMachineState *s, uint32_t offset, unsigned size)
{ (void)s; assert(size == 2); return backing[offset] | backing[offset + 1] << 8; }
static void msm5xxx_poc_halfword_backing_write(
    MSM5xxxPOCMachineState *s, uint32_t offset, uint64_t value, unsigned size)
{ (void)s; assert(size == 2); last_write_offset = offset;
  backing[offset] = value; backing[offset + 1] = value >> 8; }
#define CPU(cpu) (cpu)
static bool qemu_in_vcpu_thread(void) { return vcpu_thread; }
""" + values + writing + conflicts + r"""
static MSM5xxxPOCMachineState make_matrix(void)
{
    MSM5xxxPOCMachineState s = {0};
    s.matrix_input_encoded = true;
    s.matrix_input_encoded_aliases = true;
    s.matrix_input_encoded_row_site = 0x100;
    s.matrix_input_encoded_row_site2 = 0x102;
    s.matrix_input_encoded_col_site = 0x200;
    s.matrix_input_encoded_col_site2 = 0x202;
    s.matrix_input_encoded_idle_site = 0x204;
    s.matrix_input_address = 0x0300072c;
    s.cpu = &active_cpu;
    return s;
}
int main(void)
{
    MSM5xxxPOCMachineState s = make_matrix();
    const uint16_t row_backing = 0xa5b1;
    const uint16_t col_backing = 0x5ac5;
    backing[0x72c] = 0xc5; backing[0x72d] = 0x5a;
    assert(msm5xxx_poc_matrix_halfword_backing_read(&s, 0, 2) == 0x5ac5);
    active_cpu.running = true;
    active_cpu.neg.can_do_io = true;
    active_cpu.env.thumb = true;
    assert(msm5xxx_poc_matrix_encoded_read_gate(&s, 0, 2));
    active_cpu.env.thumb = false;
    assert(!msm5xxx_poc_matrix_encoded_read_gate(&s, 0, 2));
    active_cpu.env.thumb = true;
    for (unsigned row = 0; row < 8; row++) {
        for (unsigned sense = 0; sense < 32; sense++) {
            unsigned rawcode = row * 32 + sense;
            s.matrix_input_pressed = true;
            s.matrix_input_row = (rawcode >> 5) & 7;
            s.matrix_input_sense = rawcode & 31;
            uint16_t got_row = msm5xxx_poc_encoded_port_value(
                &s, 0x100, row_backing, 0x03000728, 0x0300072c);
            uint16_t got_col = msm5xxx_poc_encoded_port_value(
                &s, 0x200, col_backing, 0x03000728, 0x0300072c);
            uint16_t alias_row = msm5xxx_poc_encoded_port_value(
                &s, 0x102, row_backing, 0x03000728, 0x0300072c);
            uint16_t alias_col = msm5xxx_poc_encoded_port_value(
                &s, 0x202, col_backing, 0x03000728, 0x0300072c);
            assert(got_row == ((row_backing & ~0x0eU) | (row << 1)));
            assert(alias_row == got_row);
            assert(msm5xxx_poc_encoded_port_value(&s, 0x100,
                row_backing & ~1U, 0x03000728, 0x0300072c) ==
                ((row_backing & ~0x0fU) | (row << 1)));
            assert((got_row & 1) == (row_backing & 1));
            assert(got_col == ((col_backing & ~0x1fU) | sense));
            assert(alias_col == got_col);
            assert((got_row & ~0x0eU) == (row_backing & ~0x0eU));
            assert((got_col & ~0x1fU) == (col_backing & ~0x1fU));
            s.matrix_input_encoded_aux_site = 0x300;
            uint16_t released_row = msm5xxx_poc_encoded_port_value(
                &s, 0x100, row_backing & ~1U, 0x03000728, 0x0300072c);
            assert(released_row == ((row_backing & ~0x0fU) | (row << 1) | 1U));
            assert(msm5xxx_poc_encoded_port_value(&s, 0x102,
                row_backing & ~1U, 0x03000728, 0x0300072c) == released_row);
            assert(msm5xxx_poc_encoded_port_value(&s, 0x300,
                row_backing & ~1U, 0x03000728, 0x0300072c) == (row_backing | 1U));
            assert(msm5xxx_poc_encoded_port_value(&s, 0x200,
                col_backing, 0x03000728, 0x0300072c) == got_col);
            s.matrix_input_encoded_aux_site = 0;
        }
    }
    s.matrix_input_pressed = false;
    assert(msm5xxx_poc_encoded_port_value(&s, 0x100, row_backing,
        0x03000728, 0x0300072c) == ((row_backing & ~0x0eU) | 0x0e));
    assert(msm5xxx_poc_encoded_port_value(&s, 0x102, row_backing,
        0x03000728, 0x0300072c) == ((row_backing & ~0x0eU) | 0x0e));
    assert(msm5xxx_poc_encoded_port_value(&s, 0x204, col_backing,
        0x03000728, 0x0300072c) == ((col_backing & ~0x1fU) | 0x1f));
    assert(msm5xxx_poc_encoded_port_value(&s, 0x202, col_backing,
        0x03000728, 0x0300072c) == ((col_backing & ~0x1fU) | 0x1f));
    s = make_matrix();
    s.matrix_input_encoded_aliases = false;
    s.matrix_input_encoded_row_site2 = 0;
    s.matrix_input_encoded_col_site2 = 0;
    s.matrix_input_encoded_aux_site = 0x300;
    s.matrix_input_pressed = true;
    s.matrix_input_row = 3;
    assert(msm5xxx_poc_encoded_port_value(&s, 0x100,
        row_backing & ~1U, 0x03000728, 0x0300072c) ==
        ((row_backing & ~0x0fU) | 6U | 1U));
    assert(msm5xxx_poc_encoded_port_value(&s, 0x300,
        row_backing & ~1U, 0x03000728, 0x0300072c) == (row_backing | 1U));
    s = make_matrix();
    unsigned rejected = s.matrix_input_rejections;
    assert(msm5xxx_poc_encoded_port_value(&s, 0x206, col_backing,
        0x03000728, 0x0300072c) == col_backing);
    assert(s.matrix_input_rejections == rejected);
    assert(msm5xxx_poc_encoded_port_value(&s, 0x100, row_backing,
        0x03000724, 0x0300072c) == row_backing);
    assert(s.matrix_input_rejections == ++rejected);
    assert(msm5xxx_poc_encoded_port_value(&s, 0x200, col_backing,
        0x03000728, 0x03000728) == col_backing);
    assert(s.matrix_input_rejections == ++rejected);
    assert(msm5xxx_poc_encoded_port_value(&s, 0x102, row_backing,
        0x03000724, 0x0300072c) == row_backing);
    assert(s.matrix_input_rejections == ++rejected);

    assert(msm5xxx_poc_matrix_encoded_read_gate(&s, 0, 2));
    assert(!msm5xxx_poc_matrix_encoded_read_gate(&s, 1, 2));
    assert(!msm5xxx_poc_matrix_encoded_read_gate(&s, 0, 1));
    vcpu_thread = false;
    assert(!msm5xxx_poc_matrix_encoded_read_gate(&s, 0, 2));
    vcpu_thread = true;
    current_cpu = &other_cpu;
    assert(!msm5xxx_poc_matrix_encoded_read_gate(&s, 0, 2));
    current_cpu = &active_cpu;
    active_cpu.running = false;
    assert(!msm5xxx_poc_matrix_encoded_read_gate(&s, 0, 2));
    active_cpu.running = true;
    active_cpu.neg.can_do_io = false;
    assert(!msm5xxx_poc_matrix_encoded_read_gate(&s, 0, 2));
    assert(s.matrix_input_rejections == rejected + 6);

    msm5xxx_poc_matrix_encoded_row_write(&s, 0, 0x1234, 2);
    assert(last_write_offset == 0x728);
    assert(backing[0x728] == 0x34 && backing[0x729] == 0x12);

    s = make_matrix();
    assert(!msm5xxx_poc_matrix_encoded_conflict(&s));
    s.board_status_input_enabled = true;
    s.board_status_input_address = 0x03000728;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.board_status_input_enabled = true;
    s.board_status_input_descriptor = 0x1000;
    s.board_status_input_address = 0x03000727;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.board_status_peer_address = 0x0300072d;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.board_revision_enabled = true;
    s.board_revision_address = 0x0300072a;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.ready_poll_enabled = true;
    s.ready_status_address = 0x0300072c;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.raw_nand_main_enabled = true;
    s.raw_nand_ready_address = 0x03000728;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.raw_nand_main_enabled = true;
    s.raw_nand_data_address = 0x03000728; s.raw_nand_data_size = 2;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.small_nand_enabled = true;
    s.small_nand_ready_address = 0x0300072c;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.pause_timer_enabled = true;
    s.pause_timer_address = 0x03000727;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.watchdog_register = 0x0300072a;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.uart_console_enabled = true;
    s.uart_console_base = 0x03000720;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    s = make_matrix(); s.eeprom_gpio_enabled = true;
    s.eeprom_gpio_base = 0x03000720;
    assert(msm5xxx_poc_matrix_encoded_conflict(&s));
    return 0;
}
"""
        with tempfile.TemporaryDirectory(prefix="encoded-ports-") as temporary:
            path = Path(temporary)
            (path / "test.c").write_text(program)
            compiled = subprocess.run(
                [os.environ.get("CC", "cc"), "-std=c11", "-O1", "-Wall",
                 "-Wextra", "-Werror", str(path / "test.c"), "-o",
                 str(path / "test")], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(path / "test")], capture_output=True,
                                    text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_property_forms_round_trip_and_reject_invalid_sites(self):
        if not shutil.which("pkg-config"):
            self.skipTest("GLib metadata unavailable")
        source = SOURCE.read_text()
        functions = "\n".join(_function(source, "msm5xxx_poc_" + name) for name in (
            "get_matrix_encoded_ports", "set_matrix_encoded_ports"))
        fields = sorted(set(re.findall(r"s->(\w+)", functions)))
        declarations = "\n".join("uint32_t " + field + ";" for field in fields)
        program = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <glib.h>
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
typedef GError Error;
#define error_setg(target, ...) g_set_error(target, 1, 1, __VA_ARGS__)
static int qemu_strtou64(const char *s, const char **end, int base, uint64_t *value)
{
    char *tail;
    errno = 0;
    *value = g_ascii_strtoull(s, &tail, base);
    *end = tail;
    return errno ? -1 : 0;
}
typedef struct {
""" + declarations + r"""
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
""" + functions + r"""
static void round_trip(const char *input)
{
    MSM5xxxPOCMachineState s = {0};
    Error *error = NULL;
    msm5xxx_poc_set_matrix_encoded_ports(&s, input, &error);
    assert(!error && s.matrix_input_encoded);
    char *output = msm5xxx_poc_get_matrix_encoded_ports(&s, NULL);
    assert(!strcmp(output, input));
    g_free(output);
}
static void reject(const char *input)
{
    MSM5xxxPOCMachineState s = {0}, before = s;
    Error *error = NULL;
    msm5xxx_poc_set_matrix_encoded_ports(&s, input, &error);
    assert(error && memcmp(&s, &before, sizeof(s)) == 0);
    g_error_free(error);
}
int main(void)
{
    round_trip("1000100:300:310:320");
    round_trip("1000100:300:310:320:330");
    round_trip("1000100:300:310:320:330:340");
    round_trip("1000100:300:310:320:330:340:350");
    reject("1000100:300:310");
    reject("1000100:300:310:320:330:340:350:360");
    reject("1000100:300:310:320:300");
    reject("1000100:300:310:320:330:340:330");
    return 0;
}
"""
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "glib-2.0"], text=True))
        with tempfile.TemporaryDirectory(prefix="encoded-property-") as temporary:
            path = Path(temporary)
            (path / "test.c").write_text(program)
            compiled = subprocess.run(
                [os.environ.get("CC", "cc"), "-std=c11", "-O1", "-Wall",
                 "-Wextra", "-Werror", str(path / "test.c"), "-o",
                 str(path / "test"), *flags], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(path / "test")], capture_output=True,
                                    text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
