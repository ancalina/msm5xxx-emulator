"""Synthetic electrical and resource tests for the native matrix wiring."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "native/qemu/msm5xxx-poc.c"


def _function(source, name):
    match = re.search(r"^static [^\n;{]*\b" + re.escape(name) + r"\s*\(", source, re.M)
    if match is None:
        raise AssertionError(f"native function missing: {name}")
    brace = source.index("{", match.end())
    depth = 0
    for index in range(brace, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[match.start():index + 1] + "\n"
    raise AssertionError(f"native function is incomplete: {name}")


@unittest.skipUnless(shutil.which(os.environ.get("CC", "cc")), "C compiler unavailable")
class MatrixWireNativeTests(unittest.TestCase):
    def test_electrical_contacts_and_independent_gpio_owners(self):
        source = SOURCE.read_text()
        sensing = "\n".join(_function(source, "msm5xxx_poc_" + name) for name in (
            "matrix_wire_register", "matrix_wire_field_count_valid", "matrix_wire_site",
            "matrix_wire_registers", "matrix_wire_backing_read", "matrix_halfword_backing_read",
            "matrix_wire_sense", "matrix_contact_site_valid", "matrix_wire_contact",
            "matrix_wire_boot_contact_shared", "matrix_wire_boot_value"))
        conflicts = _function(source, "msm5xxx_poc_matrix_wires_conflict")
        writing = _function(source, "msm5xxx_poc_matrix_halfword_write")
        fields = sorted(set(re.findall(r"s->(\w+)", sensing + conflicts)) | {"gpio_ready_bit21"})
        declarations = "\n".join(
            ("uint16_t " if field == "matrix_input_wire_mask" else "uint32_t ") +
            field + ("[2]" if field in ("matrix_input_wire_port",
                                         "matrix_input_wire_mask") else
                     "[8]" if field == "matrix_input_wire_sites" else "") + ";"
            for field in fields)
        size = re.search(r"^#define MSM5XXX_POC_EEPROM_GPIO_SIZE\s+(.+)$", source, re.M).group(1)
        program = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
typedef uint32_t hwaddr;
""" + "#define MSM5XXX_POC_EEPROM_GPIO_SIZE " + size + "\n" + \
            "typedef struct {\n" + declarations + "\n} MSM5xxxPOCMachineState;\n" + r"""
static uint8_t backing[0x1000];
static unsigned last_write_offset;
static void msm5xxx_poc_halfword_backing_write(MSM5xxxPOCMachineState *s,
        uint32_t offset, uint64_t value, unsigned size)
{ (void)s; (void)value; assert(size == 2); last_write_offset = offset; }
static uint64_t msm5xxx_poc_halfword_backing_read(MSM5xxxPOCMachineState *s,
                                                uint32_t offset, unsigned size)
{ (void)s; assert(size == 2); return backing[offset] | backing[offset + 1] << 8; }
static void output(unsigned offset, uint16_t value)
{ backing[offset] = value; backing[offset + 1] = value >> 8; }
""" + sensing + conflicts + writing + r"""
static MSM5xxxPOCMachineState matrix(void)
{
    MSM5xxxPOCMachineState s = {0};
    s.matrix_input_wires = true;
    s.matrix_input_halfword = true;
    s.primary_nor_size = 0x1000;
    s.matrix_input_rows = 6;
    s.matrix_input_no_key = 0xf;
    s.matrix_input_address = 0x0300072c;
    s.matrix_input_wire_port[0] = 0x03000720;
    s.matrix_input_wire_mask[0] = 0x0e00;
    s.matrix_input_wire_port[1] = 0x03000728;
    s.matrix_input_wire_mask[1] = 0x000e;
    s.matrix_input_wire_site_count = 2;
    s.matrix_input_wire_sites[0] = 0x100;
    s.matrix_input_wire_sites[1] = 0x102;
    return s;
}
static MSM5xxxPOCMachineState matrix660(void)
{
    MSM5xxxPOCMachineState s = {0};
    s.matrix_input_wires = true;
    s.matrix_input_halfword = true;
    s.primary_nor_size = 0x1000;
    s.matrix_input_rows = 6;
    s.matrix_input_no_key = 0xf;
    s.matrix_input_address = 0x0300066c;
    s.matrix_input_wire_port[0] = 0x03000660;
    s.matrix_input_wire_mask[0] = 0x0007;
    s.matrix_input_wire_port[1] = 0x03000664;
    s.matrix_input_wire_mask[1] = 0x0038;
    s.matrix_input_wire_site_count = 4;
    s.matrix_input_wire_sites[0] = 0x100;
    s.matrix_input_wire_sites[1] = 0x102;
    s.matrix_input_wire_sites[2] = 0x200;
    s.matrix_input_wire_sites[3] = 0x202;
    return s;
}
int main(void)
{
    const unsigned senses[] = {14, 13, 11, 7};
    const unsigned ports[] = {0x720, 0x720, 0x720, 0x728, 0x728, 0x728};
    const unsigned bits[] = {9, 10, 11, 1, 2, 3};
    MSM5xxxPOCMachineState s = matrix();
    uint16_t value;
    assert(!msm5xxx_poc_matrix_wire_field_count_valid(6));
    assert(msm5xxx_poc_matrix_wire_field_count_valid(7));
    assert(msm5xxx_poc_matrix_wire_field_count_valid(9));
    assert(msm5xxx_poc_matrix_wire_field_count_valid(13));
    assert(!msm5xxx_poc_matrix_wire_field_count_valid(15));
    assert(!msm5xxx_poc_matrix_wire_field_count_valid(8));
    for (unsigned row = 0; row < 6; row++) {
        for (unsigned column = 0; column < 4; column++) {
            s.matrix_input_pressed = true;
            s.matrix_input_row = row;
            s.matrix_input_sense = senses[column];
            output(0x720, 0xffff); output(0x728, 0xffff);
            assert(msm5xxx_poc_matrix_wire_sense(&s, 0xa5c4, &value));
            assert(value == 0xa5cf);
            output(ports[row], (uint16_t)~(1U << bits[row]));
            assert(msm5xxx_poc_matrix_wire_sense(&s, 0xa5c4, &value));
            assert(value == (0xa5c0 | senses[column]));
            /* Additional low outputs do not disconnect the held contact. */
            output(0x720, 0); output(0x728, 0);
            assert(msm5xxx_poc_matrix_wire_sense(&s, 0xa5c4, &value));
            assert(value == (0xa5c0 | senses[column]));
            s.matrix_input_pressed = false;
            assert(msm5xxx_poc_matrix_wire_sense(&s, 0xa5c4, &value));
            assert(value == 0xa5cf);
        }
    }
    s.matrix_input_pressed = true; s.matrix_input_row = 6;
    assert(!msm5xxx_poc_matrix_wire_sense(&s, 0, &value));
    s.matrix_input_row = 0; s.matrix_input_sense = 0;
    assert(!msm5xxx_poc_matrix_wire_sense(&s, 0, &value));
    s = matrix();
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s.eeprom_gpio_enabled = true;
    s.eeprom_gpio_base = 0x03000720;
    s.eeprom_data_offset = s.eeprom_clock_offset = 0;
    s.eeprom_direction_offset = 0x0c;
    s.eeprom_data_mask = 2; s.eeprom_clock_mask = 1;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s.eeprom_data_offset = 0x0c;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s.eeprom_data_offset = 0; s.eeprom_clock_offset = 0x0c;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s.eeprom_clock_offset = 0; s.eeprom_direction_offset = 1;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix();
    s.board_status_input_enabled = true;
    s.board_status_input_address = 0x03000720; s.board_status_input_mask = 4;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s.board_status_input_address++; s.board_status_input_mask = 2;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix(); s.raw_nand_main_enabled = true;
    s.raw_nand_ready_address = 0x03000720; s.raw_nand_ready_mask = 2;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s.raw_nand_ready_address++; assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix(); s.small_nand_enabled = true;
    s.small_nand_ready_address = 0x03000720; s.small_nand_ready_mask = 2;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s.small_nand_ready_address++; assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix(); s.gpio_ready_bit21 = true;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s.experimental_contract_gpio_bit9_low = true;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s.matrix_input_wire_mask[0] = 0x100;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix(); s.experimental_contract_gpio_pmic_serial = true;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s.matrix_input_wire_mask[0] = 0x100;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix(); s.board_status_input_enabled = true;
    s.board_status_input_address = 0x0300072c; s.board_status_input_mask = 16;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix();
    s.boot_contact_enabled = true;
    s.boot_contact_address = 0x0300072c;
    s.boot_contact_pc = 0x300;
    s.boot_contact_mask = 4;
    s.boot_contact_width = 1;
    assert(msm5xxx_poc_matrix_wire_boot_contact_shared(&s));
    assert(msm5xxx_poc_matrix_wire_boot_value(&s, 0x5a00, 0x300, 1, &value));
    assert(value == 0x5a04 && s.boot_contact_releases == 1);
    s.matrix_input_pressed = true;
    s.matrix_input_row = 0;
    s.matrix_input_sense = 11;
    output(0x720, (uint16_t)~0x200U);
    output(0x728, 0xffff);
    assert(msm5xxx_poc_matrix_wire_boot_value(&s, 0x5a00, 0x300, 1, &value));
    assert(value == 0x5a00 && s.boot_contact_releases == 1);
    output(0x720, 0xffff);
    assert(msm5xxx_poc_matrix_wire_boot_value(&s, 0x5a00, 0x300, 1, &value));
    assert(value == 0x5a04 && s.boot_contact_releases == 2);
    assert(!msm5xxx_poc_matrix_wire_boot_value(&s, 0x5a00, 0x302, 1, &value));
    assert(!msm5xxx_poc_matrix_wire_boot_value(&s, 0x5a00, 0x300, 2, &value));
    s.boot_contact_pc = 0x100;
    assert(!msm5xxx_poc_matrix_wire_boot_contact_shared(&s));
    s.boot_contact_pc = 0x300;
    s.boot_contact_mask = 0x10;
    assert(!msm5xxx_poc_matrix_wire_boot_contact_shared(&s));
    s = matrix();
    s.experimental_matrix_contact_enabled = true;
    s.experimental_matrix_contact_site = 0x300;
    s.experimental_matrix_contact_level = 0x10;
    assert(msm5xxx_poc_matrix_contact_site_valid(&s));
    s.experimental_matrix_contact_site = 0x100;
    assert(!msm5xxx_poc_matrix_contact_site_valid(&s));
    s.experimental_matrix_contact_site = 0x301;
    assert(!msm5xxx_poc_matrix_contact_site_valid(&s));
    s.experimental_matrix_contact_site = 0x1000;
    assert(!msm5xxx_poc_matrix_contact_site_valid(&s));
    s.experimental_matrix_contact_site = 0x300;
    assert(msm5xxx_poc_matrix_wire_contact(&s, 0xa5c0, 0x300,
        0x0300072c, 0x0300072c, &value));
    assert(value == 0xa5d0);
    assert(!msm5xxx_poc_matrix_wire_contact(&s, 0xa5c0, 0x302,
        0x0300072c, 0x0300072c, &value));
    assert(msm5xxx_poc_matrix_wire_contact(&s, 0xa5c0, 0x300,
        0x0300066c, 0x0300072c, &value));
    assert(value == 0xa5c0 && s.matrix_input_rejections == 1);
    s.small_nand_enabled = true;
    s.small_nand_ready_address = 0x0300072c;
    s.small_nand_ready_mask = 0x10;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s.experimental_matrix_contact_enabled = false;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix660();
    s.experimental_matrix_contact_enabled = true;
    s.experimental_matrix_contact_site = 0x300;
    s.experimental_matrix_contact_level = 0x10;
    assert(msm5xxx_poc_matrix_wire_contact(&s, 0xa5cf, 0x300,
        0x0300066c, 0x0300066c, &value));
    assert(value == 0xa5df);
    backing[0x66c] = 0x34; backing[0x66d] = 0x12;
    backing[0x72c] = 0xcd; backing[0x72d] = 0xab;
    assert(msm5xxx_poc_matrix_halfword_backing_read(&s, 0, 2) == 0x1234);
    assert(msm5xxx_poc_matrix_halfword_backing_read(&s, 0, 2) != 0xabcd);
    msm5xxx_poc_matrix_halfword_write(&s, 0, 0x1234, 2);
    assert(last_write_offset == 0x66c);
    assert(msm5xxx_poc_matrix_wire_registers(0x03000660, 0x03000664) ==
           0x0300066c);
    assert(msm5xxx_poc_matrix_wire_registers(0x03000720, 0x03000728) ==
           0x0300072c);
    assert(msm5xxx_poc_matrix_wire_registers(0x03000660, 0x03000728) == 0);
    assert(msm5xxx_poc_matrix_wire_site(&s, 0x200));
    assert(!msm5xxx_poc_matrix_wire_site(&s, 0x204));
    const unsigned ports660[] = {0x660, 0x660, 0x660, 0x664, 0x664, 0x664};
    const unsigned bits660[] = {0, 1, 2, 3, 4, 5};
    s.matrix_input_pressed = true;
    for (unsigned row = 0; row < 6; row++) {
        for (unsigned column = 0; column < 4; column++) {
            s.matrix_input_row = row;
            s.matrix_input_sense = senses[column];
            output(0x660, 0xffff); output(0x664, 0xffff);
            assert(msm5xxx_poc_matrix_wire_sense(&s, 0x5a00, &value));
            assert(value == 0x5a0f);
            output(ports660[row], (uint16_t)~(1U << bits660[row]));
            assert(msm5xxx_poc_matrix_wire_sense(&s, 0x5a00, &value));
            assert(value == (0x5a00 | senses[column]));
        }
    }
    s = matrix660();
    msm5xxx_poc_matrix_halfword_write(&s, 0, 0x1234, 2);
    assert(last_write_offset == 0x66c);
    s.board_status_input_enabled = true;
    s.board_status_input_address = 0x0300072c;
    s.board_status_input_mask = 1;
    assert(!msm5xxx_poc_matrix_wires_conflict(&s));
    s.board_status_input_address = 0x0300066c;
    assert(msm5xxx_poc_matrix_wires_conflict(&s));
    s = matrix();
    assert(msm5xxx_poc_matrix_halfword_backing_read(&s, 0, 2) == 0xabcd);
    msm5xxx_poc_matrix_halfword_write(&s, 0, 0x1234, 2);
    assert(last_write_offset == 0x72c);
    /* Five columns share the same row latches, including arbitrary row sets. */
    const unsigned five_senses[] = {30, 29, 27, 23, 15};
    for (unsigned bank = 0; bank < 2; bank++) {
        s = bank ? matrix660() : matrix();
        s.matrix_input_no_key = 31;
        s.matrix_input_pressed = true;
        const unsigned *row_ports = bank ? ports660 : ports;
        const unsigned *row_bits = bank ? bits660 : bits;
        for (unsigned row = 0; row < 6; row++) {
            s.matrix_input_row = row;
            for (unsigned column = 0; column < 5; column++) {
                s.matrix_input_sense = five_senses[column];
                for (unsigned selected = 0; selected < 64; selected++) {
                    output(bank ? 0x660 : 0x720, 0xffff);
                    output(bank ? 0x664 : 0x728, 0xffff);
                    for (unsigned other = 0; other < 6; other++) {
                        if (selected & (1U << other)) {
                            unsigned offset = row_ports[other];
                            uint16_t latch = backing[offset] | backing[offset + 1] << 8;
                            output(offset, latch & ~(1U << row_bits[other]));
                        }
                    }
                    assert(msm5xxx_poc_matrix_wire_sense(&s, 0xa5c2, &value));
                    unsigned low = selected & (1U << row) ? five_senses[column] : 31;
                    assert(value == (0xa5c0 | low));
                }
            }
        }
        for (unsigned sense = 0; sense < 64; sense++) {
            bool valid = false;
            for (unsigned column = 0; column < 5; column++) {
                valid |= sense == five_senses[column];
            }
            s.matrix_input_sense = sense;
            assert(msm5xxx_poc_matrix_wire_sense(&s, 0, &value) == valid);
        }
        s.experimental_matrix_contact_enabled = true;
        s.experimental_matrix_contact_site = 0x300;
        assert(!msm5xxx_poc_matrix_contact_site_valid(&s));
        s.experimental_matrix_contact_enabled = false;
        s.board_status_input_enabled = true;
        s.board_status_input_address = s.matrix_input_address;
        s.board_status_input_mask = 16;
        assert(msm5xxx_poc_matrix_wires_conflict(&s));
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory(prefix="matrix-wires-") as temporary:
            path = Path(temporary)
            (path / "test.c").write_text(program)
            compiled = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                            str(path / "test.c"), "-o", str(path / "test")], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(path / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
