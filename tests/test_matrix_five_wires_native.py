"""Synthetic property parsing and ownership tests for five-column wiring."""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_matrix_wires_native import _function


@unittest.skipUnless(shutil.which("cc") and shutil.which("pkg-config"),
                     "C compiler and GLib metadata required")
class FiveWirePropertyTests(unittest.TestCase):
    def test_aliases_exclusivity_and_property_round_trip(self):
        source = (Path(__file__).resolve().parents[1] /
                  "native/qemu/msm5xxx-poc.c").read_text()
        functions = "\n".join(_function(source, "msm5xxx_poc_" + name) for name in (
            "matrix_wire_register", "matrix_wire_registers", "matrix_wire_field_count_valid",
            "format_matrix_halfword_wires", "get_matrix_halfword_wires",
            "get_matrix_halfword_five_wires", "set_matrix_halfword",
            "set_matrix_halfword_wires_common", "set_matrix_halfword_wires",
            "set_matrix_halfword_five_wires"))
        fields = sorted(set(re.findall(r"s->(\w+)", functions)))
        declarations = "\n".join(
            "void *cpu;" if name == "cpu" else "uint32_t " + name +
            ("[8]" if name == "matrix_input_wire_sites" else
             "[2]" if name in {"matrix_input_wire_port", "matrix_input_wire_mask"} else "") + ";"
            for name in fields)
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
#define error_propagate g_propagate_error
static int qemu_strtou64(const char *s, const char **end, int base, uint64_t *value)
{
    char *tail;
    errno = 0;
    *value = g_ascii_strtoull(s, &tail, base);
    *end = tail;
    return errno ? -1 : 0;
}
""" + "typedef struct {\n" + declarations + "\n} MSM5xxxPOCMachineState;\n" + r"""
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
""" + functions + r"""
static void reject(const char *text, bool five)
{
    MSM5xxxPOCMachineState s = {0}, before = s;
    Error *error = NULL;
    if (five) {
        msm5xxx_poc_set_matrix_halfword_five_wires(&s, text, &error);
    } else {
        msm5xxx_poc_set_matrix_halfword_wires(&s, text, &error);
    }
    assert(error && memcmp(&s, &before, sizeof(s)) == 0);
    g_error_free(error);
}
int main(void)
{
    const char *plain = "1801000:100:104:3000724:4000:3000728:1f";
    const char *extra = "1801000:100:104:3000724:4000:3000728:1f:102";
    MSM5xxxPOCMachineState s = {0};
    Error *error = NULL;
    msm5xxx_poc_set_matrix_halfword_five_wires(&s, extra, &error);
    assert(!error && s.matrix_input_wires && s.matrix_input_rows == 6);
    assert(s.matrix_input_no_key == 31 && s.matrix_input_address == 0x0300072c);
    assert(s.matrix_input_sense_bitmap ==
           ((1U << 30) | (1U << 29) | (1U << 27) | (1U << 23) | (1U << 15)));
    assert(s.matrix_input_wire_site_count == 3 && s.matrix_input_wire_sites[2] == 0x102);
    char *value = msm5xxx_poc_get_matrix_halfword_five_wires(&s, NULL);
    assert(!strcmp(value, extra));
    g_free(value);
    value = msm5xxx_poc_get_matrix_halfword_wires(&s, NULL);
    assert(!*value);
    g_free(value);
    MSM5xxxPOCMachineState before = s;
    msm5xxx_poc_set_matrix_halfword_five_wires(&s, plain, &error);
    assert(error && memcmp(&s, &before, sizeof(s)) == 0);
    g_clear_error(&error);
    s = (MSM5xxxPOCMachineState){0};
    s.cpu = &s;
    before = s;
    msm5xxx_poc_set_matrix_halfword_five_wires(&s, plain, &error);
    assert(error && memcmp(&s, &before, sizeof(s)) == 0);
    g_clear_error(&error);
    s = (MSM5xxxPOCMachineState){0};
    msm5xxx_poc_set_matrix_halfword_wires(&s, plain, &error);
    assert(!error && s.matrix_input_no_key == 15);
    value = msm5xxx_poc_get_matrix_halfword_wires(&s, NULL);
    assert(!strcmp(value, plain));
    g_free(value);
    value = msm5xxx_poc_get_matrix_halfword_five_wires(&s, NULL);
    assert(!*value);
    g_free(value);
    reject(extra, false);
    reject("1801000:100:104:3000724:4000:3000728:1f:100", true);
    reject("1801000:100:104:3000724:4000:3000728:1f:103", true);
    reject("1801000:100:104:3000724:4000:3000728:1f:102:102", true);
    reject("1801000:100:104:3000724:4000:3000664:1f", true);
    reject("1801000:100:104:3000728:4000:3000724:1f", true);
    reject("1801000:100:104:3000724:4000:0:1f", true);
    reject("1801000:100:104:3000724:4000:3000728:ff", true);
    reject("1801000:100:104:3000724:4000:3000728:1f:fffffffe", true);
    reject("1801000:100:100:3000724:4000:3000728:1f", true);
    return 0;
}
"""
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "glib-2.0"], text=True))
        with tempfile.TemporaryDirectory(prefix="matrix-five-") as temporary:
            path = Path(temporary)
            (path / "test.c").write_text(program)
            result = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1",
                                     "-Wall", "-Wextra", "-Werror", str(path / "test.c"),
                                     "-o", str(path / "test"), *flags],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(path / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
