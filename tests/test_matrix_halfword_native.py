"""Exercise the native active-low matrix combiner independently of QEMU."""
import subprocess
import tempfile
import unittest
from pathlib import Path

class MatrixHalfwordTests(unittest.TestCase):
    def test_row_selection_release_and_shared_bits(self):
        source = (Path(__file__).resolve().parents[1] /
                  "experiments/qemu-tcg/msm5xxx-poc.c").read_text()
        start = source.index("static uint16_t msm5xxx_poc_halfword_sense(")
        end = source.index("/* Temporary electrical approximation", start)
        harness = "#include <stdint.h>\n#include <stdbool.h>\n#include <assert.h>\n" + source[start:end] + r"""
int main(void) {
    const unsigned senses[] = {14, 13, 11, 7};
    /* Every shared-bit combination survives a released key. */
    for (unsigned backing = 0; backing <= 0xffff; backing++) {
        assert(msm5xxx_poc_halfword_sense(backing, 0, false, 0, 14) ==
               ((backing & 0xfff0) | 15));
    }
    for (unsigned row = 0; row < 6; row++) {
        for (unsigned col = 0; col < 4; col++) {
            /* All rows selected: presence. No rows selected: no key. */
            assert(msm5xxx_poc_halfword_sense(0x61f2, 0, true, row,
                                             senses[col]) == (0x61f0 | senses[col]));
            assert(msm5xxx_poc_halfword_sense(0x61f2, 0x3f00, true, row,
                                             senses[col]) == 0x61ff);
            for (unsigned selected = 0; selected < 6; selected++) {
                unsigned output = 0x3f00 & ~(1u << (selected + 8));
                assert(msm5xxx_poc_halfword_sense(0x61f2, output, true, row,
                    senses[col]) == (0x61f0 | (row == selected ? senses[col] : 15)));
            }
        }
    }
    assert(msm5xxx_poc_halfword_sense(0x61f2, 0, true, 6, 14) == 0x61ff);
    assert(msm5xxx_poc_halfword_sense(0x61f2, 0, true, 255, 14) == 0x61ff);
    assert(msm5xxx_poc_halfword_sense(0x61f2, 0, true, 0, 2) == 0x61ff);
}
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(path / "check.c"), "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True)

    def test_low5_native_read_host_and_property_gates(self):
        source = (Path(__file__).resolve().parents[1] /
                  "experiments/qemu-tcg/msm5xxx-poc.c").read_text()
        def section(first, last):
            start = source.index(first)
            return source[start:source.index(last, start)]
        helper = section("static bool msm5xxx_poc_low5_sense(",
                         "static uint32_t msm5xxx_poc_guest_u32")
        mapped = section("static bool msm5xxx_poc_mapped_halfword_sense(",
                         "/* Temporary electrical approximation: firmware-qualified")
        old_helper = section("static uint16_t msm5xxx_poc_halfword_sense(",
                             "/* Temporary electrical approximation")
        owner = section("static uint64_t msm5xxx_poc_eeprom_gpio_read(",
                        "static uint64_t msm5xxx_poc_matrix_halfword_read")
        read = section("static uint64_t msm5xxx_poc_matrix_halfword_read(",
                       "static const MemoryRegionOps msm5xxx_poc_matrix_halfword_ops")
        gpio = section("static bool msm5xxx_poc_matrix_gpio_conflict(",
                       "static const MemoryRegionOps msm5xxx_poc_matrix_input_ops")
        direct_get = section("static char *msm5xxx_poc_get_matrix_input(",
                             "static char *msm5xxx_poc_get_board_status_input")
        direct_get = direct_get.replace("    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);",
                                        "    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);\n    (void)errp;")
        board = section("static void msm5xxx_poc_set_board_status_input(",
                        "static char *msm5xxx_poc_get_board_status_descriptor")
        eeprom = section("static void msm5xxx_poc_eeprom_gpio_update(",
                         "static const MemoryRegionOps msm5xxx_poc_eeprom_gpio_ops")
        overlap = section("    /* Reject an EEPROM boundary through either mapped halfword register. */",
                          "    /* Final property ordering must preserve GPIO owners and code bounds. */")
        low5 = section("static void msm5xxx_poc_set_matrix_low5(",
                       "static void msm5xxx_poc_set_fujitsu_x16_nor")
        half = section("static char *msm5xxx_poc_get_matrix_halfword(",
                       "static char *msm5xxx_poc_get_matrix_low5")
        direct = section("static void msm5xxx_poc_set_matrix_input(",
                         "static char *msm5xxx_poc_get_matrix_halfword")
        status = section("static void msm5xxx_poc_set_board_status_descriptor(",
                         "static char *msm5xxx_poc_get_audio_aperture")
        status_read = section("static bool msm5xxx_poc_loop_status_matches(",
                              "static const MemoryRegionOps msm5xxx_poc_board_status_halfword_ops")
        status_final = section("    if (s->board_status_input_descriptor &&",
                               "    if (s->raw_nand_main_enabled &&")
        # Compile the actual receive rejection condition; no mirrored validator.
        host = section("        if (!s->matrix_input_host_enabled ||",
                       "            s->matrix_input_rejections++;")
        host = host.replace("        if (", "return (", 1).replace(" {\n", ";\n")
        harness = r"""
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define MSM5XXX_POC_MSM_SIZE 0x1000
#define MSM5XXX_POC_EEPROM_GPIO_SIZE 0x20
#define MSM5XXX_POC_HOST_INPUT 0x80
#define MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW UINT8_MAX
typedef uint64_t hwaddr;
typedef struct { bool running; struct { bool can_do_io; } neg; struct { uint32_t regs[16]; } env; } CPUState;
static CPUState cpu_state = { .running = true, .neg = { true } };
static CPUState *current_cpu = &cpu_state;
static bool vcpu = true;
static uint32_t pc;
static uint32_t get_pc(CPUState *cpu) { (void)cpu; return pc; }
typedef struct { uint32_t (*get_pc)(CPUState *); } CPUClass;
static CPUClass cpu_class = { get_pc };
#define CPU_GET_CLASS(cpu) (&cpu_class)
#define CPU(cpu) ((CPUState *)(cpu))
static bool qemu_in_vcpu_thread(void) { return vcpu; }
static uint8_t backing[0x1000];
static void *memory_region_get_ram_ptr(void *mr) { (void)mr; return backing; }
static uint64_t msm5xxx_poc_backing_read(uint8_t *ram, hwaddr offset, unsigned size) {
    uint64_t value = 0; assert(offset + size <= sizeof(backing));
    memcpy(&value, ram + offset, size); return value;
}
static void msm5xxx_poc_backing_write(uint8_t *ram, hwaddr offset,
                                      uint64_t value, unsigned size) {
    memcpy(ram+offset,&value,size);
}
static uint32_t descriptor_words[14];
static uint32_t msm5xxx_poc_guest_u32(hwaddr address) {
    assert(address >= 0x01801000 && address <= 0x01801034);
    return descriptor_words[(address - 0x01801000) / 4];
}
typedef struct {
    CPUState *cpu; int msm;
    bool matrix_input_gpio; uint32_t matrix_input_gpio_port[3];
    uint8_t matrix_input_gpio_mask[3];
    uint8_t matrix_input_backing;
    bool board_revision_enabled, ready_poll_enabled, ready_poll_lcd_enabled;
    bool ready_poll_control_enabled;
    uint32_t board_revision_address, ready_status_address;
    uint32_t ready_pulse_address, ready_control_address;
    bool board_status_input_enabled;
    uint32_t board_status_input_address, board_status_input_mask;
    uint32_t board_status_input_default, board_status_input_level, board_status_input_rejections;
    bool matrix_input_halfword, matrix_input_low5, matrix_input_loop, matrix_input_enabled;
    uint32_t matrix_input_contact_site;
    bool experimental_matrix_contact_enabled;
    uint32_t experimental_matrix_contact_site;
    uint8_t experimental_matrix_contact_level;
    bool experimental_matrix_status_enabled;
    uint32_t experimental_matrix_status_site;
    uint8_t experimental_matrix_status_level;
    uint16_t matrix_input_row_mask;
    bool matrix_input_host_enabled, matrix_input_pressed;
    uint32_t matrix_input_descriptor, matrix_input_presence_site;
    uint32_t matrix_input_sense_site, matrix_input_address, matrix_input_sense_bitmap;
    unsigned matrix_input_rows, matrix_input_no_key, matrix_input_sideband_mask;
    unsigned matrix_input_reset, matrix_input_row_register;
    unsigned matrix_input_row, matrix_input_sense;
    unsigned matrix_input_rejections, matrix_input_active_reads;
    uint32_t board_status_input_descriptor;
    uint32_t primary_nor_size;
    bool eeprom_gpio_enabled, eeprom_sda;
    uint32_t eeprom_gpio_base;
    unsigned eeprom_data_offset, eeprom_data_mask, eeprom_clock_offset;
    unsigned eeprom_clock_mask, eeprom_direction_offset;
    uint8_t eeprom_gpio_backing[MSM5XXX_POC_EEPROM_GPIO_SIZE];
    int eeprom_i2c;
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
typedef int Error;
#define MSM5XXX_POC_MACHINE(obj) (obj)
static Error error_value;
static void error_setg(Error **errp, const char *format, ...) {
    (void)format; *errp = &error_value;
}
static int qemu_strtou64(const char *text, const char **end, int base, uint64_t *value) {
    char *last; errno = 0;
    *value = strtoull(text, &last, base);
    if (end) *end = last;
    return errno == ERANGE || last == text ? -1 : 0;
}
#define g_ascii_isxdigit(c) isxdigit((unsigned char)(c))
static char *g_strdup(const char *text) {
    char *result = malloc(strlen(text)+1); assert(result);
    return strcpy(result,text);
}
static char *g_strdup_printf(const char *format, ...) {
    va_list ap; char text[128];
    va_start(ap,format); int size = vsnprintf(text,sizeof(text),format,ap); va_end(ap);
    assert(size >= 0 && size < (int)sizeof(text)); return g_strdup(text);
}
#define BITBANG_I2C_SDA 0
#define BITBANG_I2C_SCL 1
static unsigned bitbang_calls;
static bool external_sda = true;
static bool bitbang_i2c_set(void *bus, unsigned pin, bool value) {
    (void)bus; (void)pin; (void)value; bitbang_calls++; return external_sda;
}
""" + old_helper + mapped + helper + eeprom + owner + read + gpio + low5 + half + direct + direct_get + status + board + status_read + r"""
#define error_report(...) ((void)0)
#define exit(code) return true
static bool partial_owner_rejected(MSM5xxxPOCMachineState *s) {
""" + overlap + status_final + r"""
    return false;
}
#undef exit
#undef error_report
static bool host_rejected(MSM5xxxPOCMachineState *s, uint8_t *record) {
""" + host + r"""
}
static void put(unsigned offset, uint16_t value) { memcpy(backing + offset, &value, 2); }
int main(void) {
    const unsigned senses[] = {30,29,27,23,15};
    uint16_t value;
    for (unsigned b = 0; b <= 0xffff; b++) {
        assert(msm5xxx_poc_low5_sense(b,0x0a00,0x2843,true,false,0,0,&value));
        assert(value == ((b & 0xffe0) | 31));
        /* Captured A16 selects anchor3 + row0, not row2. */
        assert(msm5xxx_poc_low5_sense(b,0x0a16,0x6843,false,true,2,30,&value));
        assert(value == ((b & 0xffe0) | 31));
        assert(msm5xxx_poc_low5_sense(b,0x0a16,0x6843,false,true,0,30,&value));
        assert(value == ((b & 0xffe0) | 30));
        assert(msm5xxx_poc_low5_sense(b,0x0a17,0x2843,false,true,5,23,&value));
        assert(value == ((b & 0xffe0) | 23));
    }
    for (unsigned first = 0; first < 6; first++) {
        for (unsigned current = first + 1; current < 6; current++) {
            unsigned selected = (1U << first) | (1U << current);
            unsigned o728 = 0xa00 | ((selected ^ 31) & 31);
            unsigned o724 = selected & 32 ? 0x2843 : 0x6843;
            for (unsigned held = 0; held < 6; held++) {
                for (unsigned col = 0; col < 5; col++) {
                    assert(msm5xxx_poc_low5_sense(0x6dd2,o728,o724,false,true,
                                                held,senses[col],&value));
                    assert(value == (0x6dc0 | ((selected & (1U << held)) ? senses[col] : 31)));
                }
            }
            assert(msm5xxx_poc_low5_sense(0x6dd2,o728,o724,false,false,0,0,&value));
            assert(value == 0x6ddf);
        }
    }
    for (unsigned selected = 0; selected < 64; selected++) {
        unsigned count = 0;
        for (unsigned row = 0; row < 6; row++) count += !!(selected & (1U << row));
        unsigned o728 = 0xa00 | ((selected ^ 31) & 31);
        unsigned o724 = selected & 32 ? 0x2843 : 0x6843;
        bool valid = count == 1 || count == 2;
        assert(msm5xxx_poc_low5_sense(0x6dd2,o728,o724,false,false,0,0,&value) == valid);
        assert(value == (valid ? 0x6ddf : 0x6dd2));
        assert(msm5xxx_poc_low5_sense(0x6dd2,o728,o724,true,false,0,0,&value) == (selected == 63));
        assert(value == (selected == 63 ? 0x6ddf : 0x6dd2));
    }
    for (unsigned row = 0; row < 6; row++) {
        unsigned o728 = row == 5 ? 31 : 31 ^ (1U << row);
        unsigned o724 = row == 5 ? 0x2843 : 0x6843;
        for (unsigned col = 0; col < 5; col++) {
            assert(msm5xxx_poc_low5_sense(0x6dd2,0,0,true,true,row,senses[col],&value));
            assert(value == (0x6dc0 | senses[col]));
            assert(msm5xxx_poc_low5_sense(0x6dd2,o728,o724,false,true,row,senses[col],&value));
            assert(value == (0x6dc0 | senses[col]));
            for (unsigned held = 0; held < 6; held++) {
                assert(msm5xxx_poc_low5_sense(0x6dd2,o728,o724,false,true,held,senses[col],&value));
                assert(value == (0x6dc0 | (held == row ? senses[col] : 31)));
            }
        }
    }
    assert(!msm5xxx_poc_low5_sense(0x6dd2,31,0x4000,false,false,0,0,&value));
    assert(value == 0x6dd2);
    assert(!msm5xxx_poc_low5_sense(0x6dd2,0,0,false,false,0,0,&value));
    assert(!msm5xxx_poc_low5_sense(0x6dd2,0,0x4000,true,false,0,0,&value));
    assert(!msm5xxx_poc_low5_sense(0x6dd2,0,0,true,true,6,30,&value));
    assert(!msm5xxx_poc_low5_sense(0x6dd2,0,0,true,true,0,31,&value));
    MSM5xxxPOCMachineState s = { .cpu = &cpu_state };
    Error *err = NULL;
    msm5xxx_poc_set_matrix_low5(&s,"1801000:78956:78a9e",&err);
    assert(!err && s.matrix_input_enabled && s.matrix_input_low5);
    assert(s.matrix_input_sense_bitmap & (1U << 30));
    descriptor_words[0] = 0x3000720; descriptor_words[4] = 0x3000724;
    descriptor_words[8] = 0x3000728; descriptor_words[13] = 0x300072c;
    put(0x72c,0x6dd2); put(0x728,0xa00); put(0x724,0x2843);
    pc = 0x78956;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6ddf);
    s.matrix_input_pressed = true; s.matrix_input_row = 3; s.matrix_input_sense = 30;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dde);
    pc = 0x78a9e; put(0x728,0xa17); put(0x724,0x6843);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dde);
    s.matrix_input_row = 0;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6ddf);
    put(0x728,0xa16);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dde);
    s.matrix_input_row = 2;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6ddf);
    put(0x728,0xa17); put(0x724,0x2843); s.matrix_input_row = 5;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dde);
    for (unsigned i = 0; i < 4; i++) {
        unsigned slot = (unsigned[]){0,4,8,13}[i]; descriptor_words[slot]++;
        assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
        descriptor_words[slot]--;
    }
    put(0x728,31); put(0x724,0x6843);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
    put(0x728,0xa17);
    pc = 0x78954; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
    pc = 0x78a9e;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,1) == 0xd2);
    assert(msm5xxx_poc_matrix_halfword_read(&s,1,1) == 0x6d);
    vcpu = false; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); vcpu = true;
    cpu_state.running = false; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); cpu_state.running = true;
    cpu_state.neg.can_do_io = false; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); cpu_state.neg.can_do_io = true;
    current_cpu = NULL; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); current_cpu = &cpu_state;
    s.matrix_input_pressed = false;
    uint8_t record[] = {0x80,1,3,30};
    assert(!host_rejected(&s,record));
    s.matrix_input_low5 = false; assert(host_rejected(&s,record)); s.matrix_input_low5 = true;
    record[3] = 13; assert(host_rejected(&s,record));
    record[3] = 31; assert(host_rejected(&s,record));
    record[3] = 32; assert(host_rejected(&s,record));
    record[2] = 255; record[3] = 1; s.matrix_input_sideband_mask = 1; assert(host_rejected(&s,record));
    record[2] = 3; record[3] = 30; s.matrix_input_pressed = true; assert(host_rejected(&s,record));
    record[1] = 0; record[2] = 0; record[3] = 0; assert(!host_rejected(&s,record));
    record[3] = 1; assert(host_rejected(&s,record));
    msm5xxx_poc_set_matrix_halfword(&s,"1801000:78956:78a9e",&err); assert(err);
    err = NULL; msm5xxx_poc_set_board_status_descriptor(&s,"1801000",&err); assert(err);
    s = (MSM5xxxPOCMachineState){ .board_status_input_descriptor = 0x1801000 };
    err = NULL; msm5xxx_poc_set_matrix_low5(&s,"1801000:78956:78a9e",&err); assert(err && !s.matrix_input_enabled);
    s = (MSM5xxxPOCMachineState){0};
    err = NULL; msm5xxx_poc_set_matrix_halfword(&s,"1801000:78956:78a9e",&err); assert(!err);
    msm5xxx_poc_set_matrix_low5(&s,"1801000:78956:78a9e",&err); assert(err);
    for (unsigned i = 0; i < 5; i++) {
        const char *invalid[] = {"0:2:4","1801001:2:4","1801000:3:4","1801000:2:2","1801000:2:4:6"};
        s = (MSM5xxxPOCMachineState){0}; err = NULL;
        msm5xxx_poc_set_matrix_low5(&s,invalid[i],&err); assert(err && !s.matrix_input_enabled);
    }

    /* Mapped seven-row class: ascending bits0,1,8,9,11,12,13. */
    const unsigned row_bits[] = {1,2,0x100,0x200,0x800,0x1000,0x2000};
    const unsigned senses4[] = {14,13,11,7};
    const unsigned mask = 0x3b03;
    for (unsigned b = 0; b <= 0xffff; b++) {
        assert(msm5xxx_poc_mapped_halfword_sense(b,~mask,mask,true,false,0,0,&value));
        assert(value == ((b & 0xfff0) | 15));
    }
    for (unsigned shared = 0; shared <= 0xfff0; shared += 16) {
        for (unsigned row = 0; row < 7; row++) {
            for (unsigned col = 0; col < 4; col++) {
                assert(msm5xxx_poc_mapped_halfword_sense(shared|2,~mask,mask,
                    true,true,row,senses4[col],&value));
                assert(value == (shared | senses4[col]));
                for (unsigned selected = 0; selected < 7; selected++) {
                    assert(msm5xxx_poc_mapped_halfword_sense(shared|2,~row_bits[selected],
                        mask,false,true,row,senses4[col],&value));
                    assert(value == (shared | (selected == row ? senses4[col] : 15)));
                }
            }
        }
    }
    /* Every selector subset: global=all seven; row=exactly one. */
    for (unsigned subset = 0; subset < 128; subset++) {
        unsigned selected = 0, count = 0;
        for (unsigned i = 0; i < 7; i++) {
            if (subset & (1U << i)) { selected |= row_bits[i]; count++; }
        }
        assert(msm5xxx_poc_mapped_halfword_sense(0x6dd2,~selected,mask,
            true,false,0,0,&value) == (subset == 127));
        assert(value == (subset == 127 ? 0x6ddf : 0x6dd2));
        assert(msm5xxx_poc_mapped_halfword_sense(0x6dd2,~selected,mask,
            false,false,0,0,&value) == (count == 1));
        assert(value == (count == 1 ? 0x6ddf : 0x6dd2));
    }
    assert(!msm5xxx_poc_mapped_halfword_sense(0x6dd2,~mask,0,true,false,0,0,&value));
    assert(!msm5xxx_poc_mapped_halfword_sense(0x6dd2,~mask,mask,true,true,7,14,&value));
    assert(!msm5xxx_poc_mapped_halfword_sense(0x6dd2,~mask,mask,true,true,0,15,&value));
    assert(msm5xxx_poc_mapped_halfword_sense(0x6dd2,0x7fff,0x8001,
        false,true,1,14,&value) && value == 0x6dde);

    s = (MSM5xxxPOCMachineState){ .cpu = &cpu_state }; err = NULL;
    msm5xxx_poc_set_matrix_halfword(&s,"1801000:78956:78a9e:3b03",&err);
    assert(!err && s.matrix_input_row_mask == mask && s.matrix_input_rows == 7);
    char *property = msm5xxx_poc_get_matrix_halfword(&s,&err);
    assert(!strcmp(property,"1801000:78956:78a9e:3b03"));
    MSM5xxxPOCMachineState copy = {0};
    msm5xxx_poc_set_matrix_halfword(&copy,property,&err); free(property);
    assert(!err && copy.matrix_input_row_mask == mask && copy.matrix_input_rows == 7);
    descriptor_words[4] = 0x3000724; descriptor_words[13] = 0x300072c;
    s.matrix_input_pressed = true; s.matrix_input_row = 6; s.matrix_input_sense = 14;
    put(0x724,~mask); put(0x72c,0x6dd2); pc = 0x78956;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dde);
    put(0x724,~row_bits[6]); pc = 0x78a9e;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dde);
    put(0x724,~row_bits[0]);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6ddf);
    s.matrix_input_pressed = false;
    record[0] = 0x80; record[1] = 1; record[2] = 6; record[3] = 14;
    assert(!host_rejected(&s,record));
    record[2] = 7; assert(host_rejected(&s,record));
    record[2] = 6; record[3] = 15; assert(host_rejected(&s,record));
    for (unsigned slot = 4; slot <= 13; slot += 9) {
        descriptor_words[slot]++;
        unsigned rejected = s.matrix_input_rejections;
        assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
        assert(s.matrix_input_rejections == rejected+1); descriptor_words[slot]--;
    }
    pc = 0x78954; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
    pc = 0x78a9e;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,1) == 0xd2);
    assert(msm5xxx_poc_matrix_halfword_read(&s,1,1) == 0x6d);
    vcpu = false; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); vcpu = true;
    cpu_state.neg.can_do_io = false; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); cpu_state.neg.can_do_io = true;
    cpu_state.running = false; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); cpu_state.running = true;
    current_cpu = NULL; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); current_cpu = &cpu_state;
    const unsigned bad_output[] = {0xffff,~mask,~3U};
    for (unsigned i = 0; i < 3; i++) {
        put(0x724,bad_output[i]); unsigned rejected = s.matrix_input_rejections;
        assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
        assert(s.matrix_input_rejections == rejected+1);
    }
    pc = 0x78956; put(0x724,~row_bits[0]);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
    err = NULL; msm5xxx_poc_set_matrix_halfword(&s,"1801000:78956:78a9e:1",&err);
    assert(err && s.matrix_input_row_mask == mask); /* Duplicate config is atomic reject. */
    err = NULL; msm5xxx_poc_set_matrix_low5(&s,"1801000:78956:78a9e",&err); assert(err);
    err = NULL; msm5xxx_poc_set_matrix_input(&s,"3000800:100:0:f",&err); assert(err);
    err = NULL; msm5xxx_poc_set_board_status_descriptor(&s,"1801000",&err); assert(err);
    s = (MSM5xxxPOCMachineState){ .board_status_input_descriptor = 0x1801000 }; err = NULL;
    msm5xxx_poc_set_matrix_halfword(&s,"1801000:78956:78a9e:3b03",&err);
    assert(err && !s.matrix_input_enabled);
    s = (MSM5xxxPOCMachineState){ .primary_nor_size = 0x800000 }; err = NULL;
    msm5xxx_poc_set_matrix_input(&s,"3000800:100:0:f",&err); assert(!err);
    msm5xxx_poc_set_matrix_halfword(&s,"1801000:78956:78a9e:3b03",&err); assert(err);
    const char *malformed[] = {"1801000:2:4:0","1801000:2:4:10000",
        "1801000:2:4:100000001","1801000:2:4:10000000000000000",
        "1801000:2:4:1x","1801000:2:4:1:","1801000:2:4:",
        "1801000:2:4:1:1","1801000:2:4:-1","1801000:2:4: 1",
        "1801000:2:4:+1","1801001:2:4:1","1801000:3:4:1",
        "1801000:2:2:1","1801000:fffffffe:4:1","100000000:2:4:1",
        "1801000:100000000:4:1","1801000:2:100000000:1","1801000:2"};
    for (unsigned i = 0; i < sizeof(malformed)/sizeof(malformed[0]); i++) {
        s = (MSM5xxxPOCMachineState){0}; err = NULL;
        msm5xxx_poc_set_matrix_halfword(&s,malformed[i],&err);
        assert(err && !s.matrix_input_enabled && !s.matrix_input_row_mask);
    }
    s = (MSM5xxxPOCMachineState){0}; err = NULL;
    msm5xxx_poc_set_matrix_halfword(&s,"1801000:2:4:ffff",&err);
    assert(!err && s.matrix_input_rows == 16);
    record[3] = 14; record[2] = 15; assert(!host_rejected(&s,record));
    record[2] = 16; assert(host_rejected(&s,record));
    s = (MSM5xxxPOCMachineState){0}; err = NULL;
    msm5xxx_poc_set_matrix_halfword(&s,"1801000:2:4:1",&err);
    assert(!err && s.matrix_input_rows == 1);
    s = (MSM5xxxPOCMachineState){0}; err = NULL;
    msm5xxx_poc_set_matrix_halfword(&s,"1801000:2:4",&err);
    assert(!err && s.matrix_input_rows == 6 && !s.matrix_input_row_mask);
    property = msm5xxx_poc_get_matrix_halfword(&s,&err);
    assert(!strcmp(property,"1801000:2:4")); free(property);
    s.cpu = &cpu_state; s.matrix_input_pressed = true;
    s.matrix_input_row = 3; s.matrix_input_sense = 14;
    pc = 2; put(0x724,0x3f00 & ~(1U << 11));
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dde);
    put(0x724,0x3f00); pc = 4;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6ddf);
    err = NULL; msm5xxx_poc_set_board_status_descriptor(&s,"1801000",&err);
    assert(!err); /* Old halfword/status compatibility is retained. */

    /* Actual EEPROM handlers own selector/sense backing, not its stale MSM copy. */
    s = copy; s.cpu = &cpu_state;
    s.eeprom_gpio_enabled = true; s.eeprom_gpio_base = 0x3000720;
    s.eeprom_data_offset = 0; s.eeprom_data_mask = 0x20;
    s.eeprom_clock_offset = 0; s.eeprom_clock_mask = 0x40;
    s.eeprom_direction_offset = 0xc;
    put(0x724,0xffff); put(0x72c,0x1232);
    msm5xxx_poc_eeprom_gpio_write(&s,4,~mask,2);
    msm5xxx_poc_eeprom_gpio_write(&s,0xc,0x6dd2,2);
    pc = s.matrix_input_presence_site;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6ddf);
    s.matrix_input_pressed = true; s.matrix_input_sense = 14;
    for (unsigned row = 0; row < 7; row++) {
        s.matrix_input_row = row;
        pc = s.matrix_input_presence_site;
        msm5xxx_poc_eeprom_gpio_write(&s,4,~mask,2);
        assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dde);
        pc = s.matrix_input_sense_site;
        for (unsigned selected = 0; selected < 7; selected++) {
            msm5xxx_poc_eeprom_gpio_write(&s,4,~row_bits[selected],2);
            assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) ==
                (row == selected ? 0x6dde : 0x6ddf));
        }
    }
    pc = 0;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
    vcpu = false; assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); vcpu = true;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,1) == 0xd2);
    assert(msm5xxx_poc_matrix_halfword_read(&s,1,1) == 0x6d);
    pc = s.matrix_input_sense_site;
    msm5xxx_poc_eeprom_gpio_write(&s,4,0xffff,2);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2);
    descriptor_words[13]++;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x6dd2); descriptor_words[13]--;
    /* Preserve SDA read semantics as well as stored direction bits. */
    s.eeprom_gpio_backing[0] = 0x20; s.eeprom_sda = false;
    assert(!(msm5xxx_poc_halfword_backing_read(&s,0x720,1) & 0x20));
    s.eeprom_sda = true;
    assert(msm5xxx_poc_halfword_backing_read(&s,0x720,1) & 0x20);
    s.eeprom_data_offset = 0xc; s.eeprom_sda = false;
    pc = 0;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == (0x6dd2 & ~0x20));
    s.eeprom_sda = true;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == (0x6dd2 | 0x20));
    pc = s.matrix_input_presence_site; s.matrix_input_pressed = false;
    msm5xxx_poc_eeprom_gpio_write(&s,4,~mask,2);
    s.eeprom_sda = false;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == (0x6ddf & ~0x20));
    s.eeprom_sda = true;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2) == (0x6ddf | 0x20));
    s.eeprom_data_offset = 0;
    pc = 0;
    bitbang_calls = 0;
    msm5xxx_poc_matrix_halfword_write(&s,0,0xbeef,2);
    assert(bitbang_calls == 2); /* Actual update invokes SDA and SCL once each. */
    assert(msm5xxx_poc_backing_read(s.eeprom_gpio_backing,0xc,2) == 0xbeef);
    assert(msm5xxx_poc_backing_read(backing,0x72c,2) == 0x1232);
    bitbang_calls = 0; msm5xxx_poc_matrix_halfword_write(&s,1,0x66,1);
    assert(bitbang_calls == 2 && s.eeprom_gpio_backing[0xd] == 0x66);
    bitbang_calls = 0; msm5xxx_poc_matrix_halfword_write(&s,0,0x55,1);
    assert(bitbang_calls == 2 && s.eeprom_gpio_backing[0xc] == 0x55);
    s.eeprom_gpio_base = 0x3000800; bitbang_calls = 0;
    msm5xxx_poc_matrix_halfword_write(&s,0,0x2345,2);
    assert(!bitbang_calls && msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x2345);
    assert(s.eeprom_gpio_backing[0xc] == 0x55);
    s.eeprom_gpio_base = 0x3000720; s.matrix_input_row_mask = 0;
    for (unsigned low = 0; low < 2; low++) {
        s.matrix_input_low5 = low; bitbang_calls = 0;
        msm5xxx_poc_matrix_halfword_write(&s,0,0x3456,2);
        assert(!bitbang_calls && msm5xxx_poc_matrix_halfword_read(&s,0,2) == 0x3456);
        assert(s.eeprom_gpio_backing[0xc] == 0x55);
    }
    /* Actual realize block: all partial boundaries fail closed, full/outside don't. */
    s.matrix_input_row_mask = mask;
    const unsigned partial_bases[] = {0x3000725,0x300072d,0x3000705,0x300070d};
    for (unsigned i = 0; i < 4; i++) {
        s.eeprom_gpio_base = partial_bases[i]; assert(partial_owner_rejected(&s));
    }
    s.eeprom_gpio_base = 0x3000720; assert(!partial_owner_rejected(&s));
    s.eeprom_gpio_base = 0x3000800; assert(!partial_owner_rejected(&s));
    s.matrix_input_row_mask = 0; s.eeprom_gpio_base = 0x3000725;
    assert(!partial_owner_rejected(&s));

    /* Explicit contact: actual parser, final admission and owner-aware read/write. */
    MSM5xxxPOCMachineState contact = copy;
    contact.cpu = &cpu_state; contact.primary_nor_size = 0x800000;
    descriptor_words[2] = descriptor_words[13] = 0x300072c;
    pc = 0xa09ea; put(0x72c,0xabd5);
    property = msm5xxx_poc_get_experimental_matrix_contact(&contact,&err);
    assert(!*property); free(property);
    assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0xabd5);
    err = NULL;
    msm5xxx_poc_set_experimental_matrix_contact(&contact,"a09ea:0",&err);
    assert(!err && !partial_owner_rejected(&contact));
    property = msm5xxx_poc_get_experimental_matrix_contact(&contact,&err);
    assert(!strcmp(property,"a09ea:0")); free(property);
    unsigned contact_reads = contact.matrix_input_active_reads;
    unsigned contact_rejects = contact.matrix_input_rejections;
    for (unsigned level = 0; level < 2; level++) {
        contact.experimental_matrix_contact_level = level ? 0x10 : 0;
        for (unsigned word = 0; word <= 0xffff; word++) {
            put(0x72c,word);
            assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) ==
                   ((word & ~0x10U) | (level ? 0x10 : 0)));
            assert(msm5xxx_poc_backing_read(backing,0x72c,2) == word);
        }
    }
    assert(contact.matrix_input_active_reads == contact_reads &&
           contact.matrix_input_rejections == contact_rejects);
    put(0x72c,0xabd5); contact.experimental_matrix_contact_level = 0;
    pc += 2; assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0xabd5); pc -= 2;
    assert(msm5xxx_poc_matrix_halfword_read(&contact,0,1) == 0xd5);
    assert(msm5xxx_poc_matrix_halfword_read(&contact,1,1) == 0xab);
    assert(msm5xxx_poc_matrix_halfword_read(&contact,1,2) == 0xab);
    vcpu = false; assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0xabd5); vcpu = true;
    cpu_state.running = false; assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0xabd5); cpu_state.running = true;
    cpu_state.neg.can_do_io = false; assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0xabd5); cpu_state.neg.can_do_io = true;
    current_cpu = NULL; assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0xabd5); current_cpu = &cpu_state;
    for (unsigned slot = 2; slot <= 13; slot += 11) {
        descriptor_words[slot]++;
        assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0xabd5);
        assert(contact.matrix_input_rejections == ++contact_rejects);
        descriptor_words[slot]--;
    }
    /* Numeric path keeps its low-four plane and bit4 backing unchanged. */
    pc = contact.matrix_input_presence_site; put(0x724,~mask);
    contact.matrix_input_pressed = true; contact.matrix_input_row = 2;
    contact.matrix_input_sense = 11;
    assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0xabdb);
    contact.matrix_input_pressed = false; pc = contact.experimental_matrix_contact_site;

    contact.eeprom_gpio_enabled = true; contact.eeprom_gpio_base = 0x3000720;
    contact.eeprom_data_offset = 0xc; contact.eeprom_data_mask = 0x20;
    contact.eeprom_clock_offset = 0; contact.eeprom_clock_mask = 0x40;
    contact.eeprom_direction_offset = 0xc;
    assert(!partial_owner_rejected(&contact));
    msm5xxx_poc_backing_write(contact.eeprom_gpio_backing,0xc,0x6df5,2);
    contact.eeprom_sda = false;
    assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0x6dc5);
    contact.experimental_matrix_contact_level = 0x10;
    assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0x6dd5);
    contact.eeprom_sda = true;
    assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0x6df5);
    pc += 2; assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0x6df5); pc -= 2;
    descriptor_words[2]++;
    assert(msm5xxx_poc_matrix_halfword_read(&contact,0,2) == 0x6df5); descriptor_words[2]--;
    assert(contact.matrix_input_rejections == ++contact_rejects);
    bitbang_calls = 0; msm5xxx_poc_matrix_halfword_write(&contact,0,0xbeef,2);
    assert(bitbang_calls == 2 && msm5xxx_poc_backing_read(contact.eeprom_gpio_backing,0xc,2) == 0xbeef);
    assert(msm5xxx_poc_backing_read(backing,0x72c,2) == 0xabd5);
    bitbang_calls = 0; msm5xxx_poc_matrix_halfword_write(&contact,0,0x25,1);
    assert(bitbang_calls == 2 && contact.eeprom_gpio_backing[0xc] == 0x25);
    /* Pin ownership includes direction's data mask, but only at byte72C. */
    for (unsigned owner = 0; owner < 3; owner++) {
        s = contact; s.eeprom_data_offset = 0; s.eeprom_clock_offset = 0;
        s.eeprom_direction_offset = 0; s.eeprom_data_mask = 0x10;
        s.eeprom_clock_mask = 0x10;
        if (owner == 0) s.eeprom_data_offset = 0xc;
        if (owner == 1) s.eeprom_clock_offset = 0xc;
        if (owner == 2) s.eeprom_direction_offset = 0xc;
        assert(partial_owner_rejected(&s));
        s.eeprom_data_offset = s.eeprom_clock_offset = s.eeprom_direction_offset = 0xd;
        assert(!partial_owner_rejected(&s));
        s.eeprom_data_offset = s.eeprom_clock_offset = s.eeprom_direction_offset = 0;
        assert(!partial_owner_rejected(&s));
    }
    s = contact; s.eeprom_data_offset = 0; s.eeprom_data_mask = 0x20;
    s.eeprom_clock_offset = 0; s.eeprom_clock_mask = 0x10;
    s.eeprom_direction_offset = 0xc; assert(!partial_owner_rejected(&s));
    for (unsigned i = 0; i < 4; i++) {
        s = contact; s.eeprom_gpio_base = partial_bases[i];
        assert(partial_owner_rejected(&s));
    }
    for (unsigned bad = 0; bad < 10; bad++) {
        s = contact; s.eeprom_gpio_enabled = false;
        switch (bad) {
        case 0: s.matrix_input_halfword = false; break;
        case 1: s.matrix_input_row_mask = 0; break;
        case 2: s.matrix_input_loop = true; break;
        case 3: s.matrix_input_low5 = true; break;
        case 4: s.matrix_input_gpio = true; break;
        case 5: s.experimental_matrix_contact_site |= 1; break;
        case 6: s.experimental_matrix_contact_site = s.matrix_input_presence_site; break;
        case 7: s.experimental_matrix_contact_site = s.matrix_input_sense_site; break;
        case 8: s.experimental_matrix_contact_site = 0x800000; break;
        case 9: s.primary_nor_size = 1; break;
        }
        assert(partial_owner_rejected(&s));
    }
    s = contact; s.experimental_matrix_contact_site = 0x7ffffe;
    assert(!partial_owner_rejected(&s));
    const char *bad_contact[] = {"","a09ea","a09ea:","a09ea:10:0","a09ea:1",
        "a09eb:0","a09ea:-10","a09ea:+10","a09ea: 10"," a09ea:0","a09ea:10x",
        "100000000:0","a09ea:100000000","fffffffffffffffe:0","fffffffe:0"};
    for (unsigned i = 0; i < sizeof(bad_contact)/sizeof(bad_contact[0]); i++) {
        s = copy; err = NULL;
        msm5xxx_poc_set_experimental_matrix_contact(&s,bad_contact[i],&err);
        assert(err && !s.experimental_matrix_contact_enabled);
    }
    s = contact; err = NULL;
    msm5xxx_poc_set_experimental_matrix_contact(&s,"a09ec:0",&err);
    assert(err && s.experimental_matrix_contact_site == 0xa09ea &&
           s.experimental_matrix_contact_level == 0x10);
    for (unsigned first = 0; first < 2; first++) {
        s = (MSM5xxxPOCMachineState){.primary_nor_size=0x800000}; err = NULL;
        if (first) msm5xxx_poc_set_experimental_matrix_contact(&s,"a09ea:10",&err);
        msm5xxx_poc_set_matrix_halfword(&s,"1801000:78956:78a9e:3b03",&err);
        if (!first) msm5xxx_poc_set_experimental_matrix_contact(&s,"a09ea:10",&err);
        assert(!err && !partial_owner_rejected(&s));
        property = msm5xxx_poc_get_experimental_matrix_contact(&s,&err);
        assert(!strcmp(property,"a09ea:10")); free(property);
    }

    /* Explicit status diagnostic stays inside the actual EEPROM read owner. */
    MSM5xxxPOCMachineState status = contact;
    descriptor_words[9] = 0x3000728; pc = 0xa07ba;
    status.eeprom_data_offset = status.eeprom_clock_offset = 0;
    status.eeprom_data_mask = 0x20; status.eeprom_clock_mask = 0x40;
    status.eeprom_direction_offset = 0xc;
    msm5xxx_poc_backing_write(status.eeprom_gpio_backing,8,0xabc7,2);
    put(0x728,0xdead);
    property = msm5xxx_poc_get_experimental_matrix_status(&status,&err);
    assert(!*property); free(property);
    assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0xabc7);
    err = NULL; msm5xxx_poc_set_experimental_matrix_status(&status,"a07ba:0",&err);
    assert(!err && !partial_owner_rejected(&status));
    property = msm5xxx_poc_get_experimental_matrix_status(&status,&err);
    assert(!strcmp(property,"a07ba:0")); free(property);
    unsigned status_reads = status.matrix_input_active_reads;
    unsigned status_rejects = status.matrix_input_rejections;
    for (unsigned level = 0; level < 2; level++) {
        status.experimental_matrix_status_level = level ? 2 : 0;
        for (unsigned word = 0; word <= 0xffff; word++) {
            msm5xxx_poc_backing_write(status.eeprom_gpio_backing,8,word,2);
            assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) ==
                   ((word & ~2U) | (level ? 2 : 0)));
            assert(msm5xxx_poc_backing_read(status.eeprom_gpio_backing,8,2) == word);
        }
    }
    assert(status.matrix_input_active_reads == status_reads &&
           status.matrix_input_rejections == status_rejects);
    msm5xxx_poc_backing_write(status.eeprom_gpio_backing,8,0x1237,2);
    status.experimental_matrix_status_level = 0;
    pc += 2; assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0x1237); pc -= 2;
    assert(msm5xxx_poc_eeprom_gpio_read(&status,8,1) == 0x37);
    assert(msm5xxx_poc_eeprom_gpio_read(&status,9,1) == 0x12);
    assert(msm5xxx_poc_eeprom_gpio_read(&status,8,4) == 0x1237);
    assert(msm5xxx_poc_eeprom_gpio_read(&status,9,2) == 0x12);
    vcpu = false; assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0x1237); vcpu = true;
    cpu_state.running = false; assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0x1237); cpu_state.running = true;
    cpu_state.neg.can_do_io = false; assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0x1237); cpu_state.neg.can_do_io = true;
    current_cpu = NULL; assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0x1237); current_cpu = &cpu_state;
    descriptor_words[9]++;
    assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0x1237); descriptor_words[9]--;
    assert(status.matrix_input_rejections == ++status_rejects);
    /* SDA is resolved first; the contact bit does not alter data bit0x20. */
    status.eeprom_data_offset = 8; status.eeprom_sda = false;
    assert(!partial_owner_rejected(&status));
    assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0x1215);
    status.eeprom_sda = true;
    assert(msm5xxx_poc_eeprom_gpio_read(&status,8,2) == 0x1235);
    bitbang_calls = 0; msm5xxx_poc_eeprom_gpio_write(&status,8,0xbeef,2);
    assert(bitbang_calls == 2 && msm5xxx_poc_backing_read(status.eeprom_gpio_backing,8,2) == 0xbeef);
    assert(msm5xxx_poc_backing_read(backing,0x728,2) == 0xdead);
    bitbang_calls = 0; msm5xxx_poc_eeprom_gpio_write(&status,8,0x33,1);
    assert(bitbang_calls == 2 && status.eeprom_gpio_backing[8] == 0x33);
    status.eeprom_data_offset = 0;
    pc = status.experimental_matrix_contact_site;
    assert(msm5xxx_poc_matrix_halfword_read(&status,0,2) ==
           (msm5xxx_poc_backing_read(status.eeprom_gpio_backing,0xc,2) | 0x10));
    /* Absolute728 supports a different fully covering EEPROM aperture base. */
    s = status; s.eeprom_gpio_base = 0x3000710; s.eeprom_direction_offset = 0;
    assert(!partial_owner_rejected(&s)); pc = s.experimental_matrix_status_site;
    msm5xxx_poc_backing_write(s.eeprom_gpio_backing,0x18,0xabc7,2);
    assert(msm5xxx_poc_eeprom_gpio_read(&s,0x18,2) == 0xabc5);
    for (unsigned pin = 0; pin < 3; pin++) {
        s = status; s.eeprom_data_offset = s.eeprom_clock_offset = s.eeprom_direction_offset = 0;
        s.eeprom_data_mask = s.eeprom_clock_mask = 2;
        if (pin == 0) s.eeprom_data_offset = 8;
        if (pin == 1) s.eeprom_clock_offset = 8;
        if (pin == 2) s.eeprom_direction_offset = 8;
        assert(partial_owner_rejected(&s));
        s.eeprom_data_offset = s.eeprom_clock_offset = s.eeprom_direction_offset = 9;
        assert(!partial_owner_rejected(&s));
    }
    s = status; s.eeprom_data_mask = 0x20; s.eeprom_clock_mask = 2;
    s.eeprom_clock_offset = 0; s.eeprom_direction_offset = 8;
    assert(!partial_owner_rejected(&s)); /* Direction uses data mask, not clock mask. */
    for (unsigned bad = 0; bad < 14; bad++) {
        s = status;
        switch (bad) {
        case 0: s.matrix_input_halfword = false; break;
        case 1: s.matrix_input_row_mask = 0; break;
        case 2: s.matrix_input_loop = true; break;
        case 3: s.matrix_input_low5 = true; break;
        case 4: s.matrix_input_gpio = true; break;
        case 5: s.eeprom_gpio_enabled = false; break;
        case 6: s.eeprom_gpio_base = 0x3000729; break;
        case 7: s.eeprom_gpio_base = 0x3000708; break;
        case 8: s.experimental_matrix_status_site |= 1; break;
        case 9: s.experimental_matrix_status_site = s.matrix_input_presence_site; break;
        case 10: s.experimental_matrix_status_site = s.matrix_input_sense_site; break;
        case 11: s.experimental_matrix_status_site = s.experimental_matrix_contact_site; break;
        case 12: s.experimental_matrix_status_site = 0x800000; break;
        case 13: s.primary_nor_size = 1; break;
        }
        assert(partial_owner_rejected(&s));
    }
    for (unsigned owner = 0; owner < 6; owner++) {
        s = status;
        switch (owner) {
        case 0: s.board_status_input_enabled = true; s.board_status_input_address = 0x3000728; break;
        case 1: s.board_status_input_enabled = true; s.board_status_input_address = 0x3000727; s.board_status_input_descriptor = 0x1801000; break;
        case 2: s.board_revision_enabled = true; s.board_revision_address = 0x3000725; break;
        case 3: s.ready_poll_enabled = true; s.ready_status_address = 0x3000728; break;
        case 4: s.ready_poll_enabled = true; s.ready_pulse_address = 0x3000729; break;
        case 5: s.ready_poll_enabled = s.ready_poll_control_enabled = true; s.ready_control_address = 0x3000729; break;
        }
        assert(partial_owner_rejected(&s));
    }
    s = status; s.board_revision_enabled = true; s.board_revision_address = 0x3000724;
    assert(!partial_owner_rejected(&s)); /* adjacent 4-byte owner ends at728 */
    s = status; s.ready_poll_enabled = s.ready_poll_lcd_enabled = true;
    s.ready_status_address = 0x3000728; assert(!partial_owner_rejected(&s));
    const char *bad_status[] = {"","a07ba","a07ba:","a07ba:2:0","a07ba:10","a07bb:0",
        "a07ba:-2","a07ba:+2","a07ba: 2"," a07ba:0","a07ba:2x",
        "100000000:0","a07ba:100000000","fffffffffffffffe:0","fffffffe:0"};
    for (unsigned i = 0; i < sizeof(bad_status)/sizeof(bad_status[0]); i++) {
        s = copy; err = NULL;
        msm5xxx_poc_set_experimental_matrix_status(&s,bad_status[i],&err);
        assert(err && !s.experimental_matrix_status_enabled);
    }
    s = status; err = NULL;
    msm5xxx_poc_set_experimental_matrix_status(&s,"a07bc:2",&err);
    assert(err && s.experimental_matrix_status_site == 0xa07ba && !s.experimental_matrix_status_level);
    for (unsigned first = 0; first < 2; first++) {
        s = (MSM5xxxPOCMachineState){.primary_nor_size=0x800000,.eeprom_gpio_enabled=true,
            .eeprom_gpio_base=0x3000720,.eeprom_data_mask=0x20,.eeprom_clock_mask=0x40}; err = NULL;
        if (first) msm5xxx_poc_set_experimental_matrix_status(&s,"a07ba:2",&err);
        msm5xxx_poc_set_matrix_halfword(&s,"1801000:78956:78a9e:3b03",&err);
        if (!first) msm5xxx_poc_set_experimental_matrix_status(&s,"a07ba:2",&err);
        assert(!err && !partial_owner_rejected(&s));
        property = msm5xxx_poc_get_experimental_matrix_status(&s,&err);
        assert(!strcmp(property,"a07ba:2")); free(property);
    }

    const char *gpio_property = "3000694:801fc:80442:300066c:62:3000668:6:3000664:80";
    s = (MSM5xxxPOCMachineState){.primary_nor_size=0x800000,.cpu=&cpu_state}; err=NULL;
    msm5xxx_poc_set_matrix_gpio(&s,gpio_property,&err);
    assert(!err && s.matrix_input_gpio && !s.matrix_input_halfword);
    property=msm5xxx_poc_get_matrix_gpio(&s,&err);
    assert(!strcmp(property,gpio_property)); free(property);
    assert(!msm5xxx_poc_matrix_gpio_conflict(&s));
    property=msm5xxx_poc_get_matrix_input(&s,&err); assert(!*property); free(property);
    s.eeprom_gpio_enabled=true; s.eeprom_gpio_base=0x3000660;
    s.eeprom_data_offset=8; s.eeprom_data_mask=8;
    s.eeprom_clock_offset=12; s.eeprom_clock_mask=1;
    s.eeprom_direction_offset=28;
    assert(!msm5xxx_poc_matrix_gpio_conflict(&s));
    backing[0x694]=0xa0;
    const unsigned ports[] = {12,8,4}, masks[] = {0x62,6,0x80};
    const unsigned row_port[] = {0,0,0,1,1,2};
    const unsigned row_bit[] = {2,0x20,0x40,2,4,0x80};
    for(unsigned held=0;held<6;held++) {
        s.matrix_input_pressed=true; s.matrix_input_row=held;
        for(unsigned col=0;col<4;col++) {
            s.matrix_input_sense=(unsigned[]){14,13,11,7}[col];
            for(unsigned i=0;i<3;i++) s.eeprom_gpio_backing[ports[i]]=~masks[i];
            pc=s.matrix_input_presence_site;
            assert(msm5xxx_poc_matrix_input_read(&s,0,1)==(0xa0|s.matrix_input_sense));
            pc=s.matrix_input_sense_site;
            for(unsigned selected=0;selected<6;selected++) {
                for(unsigned i=0;i<3;i++) s.eeprom_gpio_backing[ports[i]]=0xff;
                s.eeprom_gpio_backing[ports[row_port[selected]]]&=~row_bit[selected];
                assert(msm5xxx_poc_matrix_input_read(&s,0,1)==
                       (0xa0|(selected==held?s.matrix_input_sense:15)));
                s.matrix_input_pressed=false;
                assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xaf);
                s.matrix_input_pressed=true;
            }
        }
    }
    record[0]=0x80; record[1]=1; record[2]=5; record[3]=14;
    s.matrix_input_pressed=false; assert(!host_rejected(&s,record));
    record[2]=6; assert(host_rejected(&s,record));
    record[2]=255; assert(host_rejected(&s,record));
    record[2]=0; record[3]=1; assert(host_rejected(&s,record));
    for(unsigned i=0;i<3;i++) s.eeprom_gpio_backing[ports[i]]=0xff;
    pc=s.matrix_input_sense_site;
    unsigned rejection=s.matrix_input_rejections;
    assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa0);
    assert(s.matrix_input_rejections==rejection+1);
    s.eeprom_gpio_backing[12]&=~0x22; /* two selected, invalid row phase */
    assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa0);
    pc=s.matrix_input_presence_site;
    assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa0);
    s.eeprom_gpio_backing[12]=(uint8_t)~2U; s.eeprom_gpio_backing[8]=0xff;
    pc=0; assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa0);
    pc=s.matrix_input_sense_site;
    vcpu=false; assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa0); vcpu=true;
    current_cpu=NULL; assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa0); current_cpu=&cpu_state;
    cpu_state.running=false; assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa0); cpu_state.running=true;
    cpu_state.neg.can_do_io=false; assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa0); cpu_state.neg.can_do_io=true;
    assert(msm5xxx_poc_matrix_input_read(&s,0,2)==0xa0);
    assert(msm5xxx_poc_matrix_input_read(&s,1,1)==0);
    msm5xxx_poc_matrix_input_write(&s,0,0xb2,1); assert(backing[0x694]==0xb2);
    msm5xxx_poc_matrix_input_write(&s,1,0,1); assert(backing[0x694]==0xb2);
    /* Sense write-through uses the actual owner; bitbang update unchanged. */
    s.matrix_input_address=0x3000670; bitbang_calls=0;
    msm5xxx_poc_matrix_input_write(&s,0,0xd2,1);
    assert(bitbang_calls==2 && s.eeprom_gpio_backing[16]==0xd2);
    pc=0; assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xd2);
    s.matrix_input_address=0x3000694;
    /* Optional independent input pin: legacy GPIO rows and EEPROM stay owned. */
    MSM5xxxPOCMachineState legacy_gpio = s;
    const char *sideband_gpio = "3000694:801fc:80442:300066c:62:3000668:6:3000664:80:10";
    s = (MSM5xxxPOCMachineState){.primary_nor_size=0x800000,.cpu=&cpu_state}; err=NULL;
    msm5xxx_poc_set_matrix_gpio(&s,sideband_gpio,&err);
    assert(!err && s.matrix_input_sideband_mask==0x10);
    property=msm5xxx_poc_get_matrix_gpio(&s,&err);
    assert(!strcmp(property,sideband_gpio)); free(property);
    s.eeprom_gpio_enabled=true; s.eeprom_gpio_base=0x3000660;
    s.eeprom_data_offset=8; s.eeprom_data_mask=8;
    s.eeprom_clock_offset=12; s.eeprom_clock_mask=1;
    s.eeprom_direction_offset=28;
    for(unsigned i=0;i<3;i++) s.eeprom_gpio_backing[ports[i]]=(uint8_t)~masks[i];
    uint8_t original_port8 = s.eeprom_gpio_backing[8];
    record[0]=0x80; record[1]=1; record[2]=255; record[3]=0x10;
    assert(!host_rejected(&s,record));
    record[3]=0x20; assert(host_rejected(&s,record)); record[3]=0x10;
    for(unsigned value=0;value<=255;value++) {
        backing[0x694]=value; pc=0x8016a;
        s.matrix_input_pressed=false;
        assert(msm5xxx_poc_matrix_input_read(&s,0,1)==(value|0x10));
        s.matrix_input_pressed=true; s.matrix_input_row=255; s.matrix_input_sense=0x10;
        assert(msm5xxx_poc_matrix_input_read(&s,0,1)==(value&~0x10));
        pc=s.matrix_input_presence_site;
        assert(msm5xxx_poc_matrix_input_read(&s,0,1)==((value&~0x1f)|15));
        assert(backing[0x694]==value && s.eeprom_gpio_backing[8]==original_port8);
    }
    for(unsigned i=0;i<3;i++) s.eeprom_gpio_backing[ports[i]]=0xff;
    s.eeprom_gpio_backing[12]&=~2U; pc=s.matrix_input_sense_site;
    assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xef);
    record[1]=0; record[2]=0; record[3]=0; assert(!host_rejected(&s,record));
    s.matrix_input_pressed=false; backing[0x694]=0xa5; pc=0x8016a;
    assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xb5);
    vcpu=false; assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa5); vcpu=true;
    cpu_state.neg.can_do_io=false; assert(msm5xxx_poc_matrix_input_read(&s,0,1)==0xa5); cpu_state.neg.can_do_io=true;
    assert(msm5xxx_poc_matrix_input_read(&s,0,2)==0xa5);
    s.eeprom_gpio_base=0x3000680; s.eeprom_data_offset=20;
    s.eeprom_direction_offset=12; s.eeprom_clock_offset=28;
    s.eeprom_data_mask=0x10; s.eeprom_clock_mask=1;
    assert(msm5xxx_poc_matrix_gpio_conflict(&s));
    s.eeprom_data_mask=0x20; assert(!msm5xxx_poc_matrix_gpio_conflict(&s));
    s.eeprom_data_mask=0x10; s.eeprom_data_offset=0; s.eeprom_direction_offset=20;
    assert(msm5xxx_poc_matrix_gpio_conflict(&s));
    s.eeprom_direction_offset=12; s.eeprom_clock_offset=20; s.eeprom_clock_mask=0x10;
    assert(msm5xxx_poc_matrix_gpio_conflict(&s));
    s=legacy_gpio;
    s.eeprom_data_mask=2; assert(msm5xxx_poc_matrix_gpio_conflict(&s));
    s.eeprom_data_mask=8; s.eeprom_clock_mask=2; assert(msm5xxx_poc_matrix_gpio_conflict(&s));
    s.eeprom_clock_mask=1; s.eeprom_direction_offset=4; s.eeprom_data_mask=0x80;
    assert(msm5xxx_poc_matrix_gpio_conflict(&s));
    s.eeprom_data_mask=8; s.eeprom_direction_offset=28;
    s.matrix_input_address=0x3000668; assert(msm5xxx_poc_matrix_gpio_conflict(&s));
    s.matrix_input_address=0x3000694;
    s.primary_nor_size=0x100; assert(msm5xxx_poc_matrix_gpio_conflict(&s));
    s.primary_nor_size=0x800000;
    err=NULL; msm5xxx_poc_set_board_status_input(&s,"300066c:1:0",&err); assert(err);
    err=NULL; msm5xxx_poc_set_board_status_descriptor(&s,"1801000",&err); assert(err);
    err=NULL; msm5xxx_poc_set_matrix_input(&s,"3000800:100:0:f",&err); assert(err);
    err=NULL; msm5xxx_poc_set_matrix_halfword(&s,"1801000:2:4",&err); assert(err);
    err=NULL; msm5xxx_poc_set_matrix_low5(&s,"1801000:2:4",&err); assert(err);
    const char *bad_gpio[]={
        "3000694:2:4:300066c:62:3000668:6:3000664",
        "3000694:2:4:300066c:62:3000668:6:3000664:80:1",
        "3000694:2:4:300066c:62:3000668:6:3000664:80:30",
        "3000694:2:4:300066c:62:3000668:6:3000664:80:100",
        "3000694:2:4:300066c:62:3000668:6:3000664:80:10:",
        "3000694:2:4:300066c:62:3000668:6:3000664:80:-10",
        "3000694:2:4:300066c:62:3000668:6:3000664:80:10 ",
        "3000694:2:4:300066c:62:3000668:6:3000664:80 ",
        "3000694:2:100000000:300066c:62:3000668:6:3000664:80",
        "3000694:2:4:300066c:62:3000668:6:3000664:0",
        "3000694:2:4:300066c:62:3000668:6:3000664:100",
        "3000694:2:4:300066c:62:3000668:6:300066c:80",
        "300066c:2:4:300066c:62:3000668:6:3000664:80",
        "3000694:3:4:300066c:62:3000668:6:3000664:80",
        "3000694:2:2:300066c:62:3000668:6:3000664:80",
        "3000694:800000:4:300066c:62:3000668:6:3000664:80",
        "3000694:2:4:3001000:62:3000668:6:3000664:80",
        "3000694:2:4:300066c:63:3000668:6:3000664:80",
        "3000694:2:4:300066c:62:3000668:6:3000664:-80",
        "3000694:2:4:300066c:62:3000668:6:3000664:+80",
        "3000694:2:4:300066c:62:3000668:6:3000664: 80",
        "3000694:2:4:300066c:62:3000668:6:3000664:80x",
        "3000694:2:4:300066c:62:3000668:6:3000664:80:",
        "3000694:2:4:300066c:62:3000668:6:3000664:10000000000000000"};
    for(unsigned i=0;i<sizeof(bad_gpio)/sizeof(bad_gpio[0]);i++) {
        s=(MSM5xxxPOCMachineState){.primary_nor_size=0x800000}; err=NULL;
        msm5xxx_poc_set_matrix_gpio(&s,bad_gpio[i],&err);
        assert(err && !s.matrix_input_enabled);
    }
    for(unsigned conflict=0;conflict<4;conflict++) {
        s=(MSM5xxxPOCMachineState){.primary_nor_size=0x800000};err=NULL;
        if(conflict==0) msm5xxx_poc_set_matrix_input(&s,"3000800:100:0:f",&err);
        if(conflict==1) msm5xxx_poc_set_matrix_halfword(&s,"1801000:2:4",&err);
        if(conflict==2) msm5xxx_poc_set_matrix_low5(&s,"1801000:2:4",&err);
        if(conflict==3) msm5xxx_poc_set_board_status_input(&s,"3000668:1:0",&err);
        assert(!err); msm5xxx_poc_set_matrix_gpio(&s,gpio_property,&err); assert(err);
    }

    /* Independent six-row/four-column read plane and contact approximation. */

    /* Original status handlers preserve writable bits, with only bit4 overlaid. */
    for (unsigned order=0;order<2;order++) {
        s=(MSM5xxxPOCMachineState){.cpu=&cpu_state};err=NULL;
        if(order) msm5xxx_poc_set_board_status_descriptor(&s,"1801000",&err);
        assert(!err);msm5xxx_poc_set_matrix_loop(&s,"1801000:2:4:6",&err);assert(!err);
        if(!order) msm5xxx_poc_set_board_status_descriptor(&s,"1801000",&err);
        msm5xxx_poc_set_board_status_input(&s,"3000720:10:0",&err);assert(!err);
        assert(!partial_owner_rejected(&s));
        descriptor_words[1]=0x3000720;put(0x720,0x73e0);
        assert(msm5xxx_poc_board_status_halfword_read(&s,0,2)==0x73e0);
        s.board_status_input_level=0x10;
        assert(msm5xxx_poc_board_status_halfword_read(&s,0,2)==0x73f0);
        msm5xxx_poc_board_status_halfword_write(&s,0,0x1234,2);
        assert(msm5xxx_poc_backing_read(backing,0x720,2)==0x1234);
        s.board_status_input_level=0;
        assert(msm5xxx_poc_board_status_halfword_read(&s,0,2)==0x1224);
        descriptor_words[1]=0x3000724;
        assert(msm5xxx_poc_board_status_halfword_read(&s,0,2)==0x1234);
        descriptor_words[1]=0x3000720;
        assert(msm5xxx_poc_board_status_halfword_read(&s,0,1)==0x34);
        assert(msm5xxx_poc_board_status_halfword_read(&s,1,1)==0x12);
        s.board_status_input_mask=4;assert(partial_owner_rejected(&s));
        s.board_status_input_mask=0x10;
        s.board_status_input_descriptor+=4;assert(partial_owner_rejected(&s));
        s.board_status_input_descriptor-=4;
        s.eeprom_gpio_enabled=true;s.eeprom_gpio_base=0x3000720;
        assert(partial_owner_rejected(&s));
        s.eeprom_gpio_base=0x3000722;assert(!partial_owner_rejected(&s));
    }
    const unsigned loop_senses[] = {30,29,27,23};
    for (unsigned shared=0; shared<=0xffe0; shared+=32) {
        for(unsigned r=0;r<6;r++) for(unsigned col=0;col<4;col++) {
            unsigned sel = r==5 ? 31 : 31 ^ (1U<<r);
            unsigned ctl = r==5 ? 0 : 32;
            assert(msm5xxx_poc_loop_sense(shared|2,sel,ctl,false,true,r,loop_senses[col],&value));
            assert(value==(shared|loop_senses[col]));
            assert(msm5xxx_poc_loop_sense(shared|2,sel,ctl,false,false,r,loop_senses[col],&value));
            assert(value==(shared|31));
            assert(msm5xxx_poc_loop_sense(shared|2,0,0,true,true,r,loop_senses[col],&value));
            assert(value==(shared|loop_senses[col]));
            assert(msm5xxx_poc_loop_sense(shared|2,30,32,true,true,r,loop_senses[col],&value));
            assert(value==(shared|(r==0?loop_senses[col]:31)));
        }
    }
    assert(!msm5xxx_poc_loop_sense(0x73e0,0,32,false,false,0,30,&value));
    assert(value==0x73e0);
    s=(MSM5xxxPOCMachineState){.cpu=&cpu_state};err=NULL;
    msm5xxx_poc_set_matrix_loop(&s,"1801000:2:4:6",&err);
    assert(!err && s.matrix_input_loop && s.matrix_input_rows==6);
    s.eeprom_gpio_enabled=true;s.eeprom_gpio_base=0x3000725;
    assert(!partial_owner_rejected(&s)); /* unused724 boundary is irrelevant */
    s.eeprom_gpio_base=0x3000729;assert(partial_owner_rejected(&s));
    s.eeprom_gpio_base=0x300072d;assert(partial_owner_rejected(&s));
    s.eeprom_gpio_enabled=false;
    assert(!partial_owner_rejected(&s));
    s.board_revision_enabled=true;s.board_revision_address=0x300071e;
    assert(partial_owner_rejected(&s));s.board_revision_enabled=false;
    s.board_status_input_enabled=true;s.board_status_input_address=0x3000729;
    assert(partial_owner_rejected(&s));s.board_status_input_enabled=false;
    s.ready_poll_enabled=true;s.ready_status_address=0x300072c;
    assert(partial_owner_rejected(&s));s.ready_status_address=0x3000800;
    s.ready_pulse_address=0x3000721;assert(partial_owner_rejected(&s));
    s.ready_pulse_address=0x3000801;s.ready_poll_control_enabled=true;
    s.ready_control_address=0x3000728;assert(partial_owner_rejected(&s));
    s.ready_poll_enabled=false;

    property=msm5xxx_poc_get_matrix_loop(&s,&err);
    assert(!strcmp(property,"1801000:2:4:6"));free(property);
    assert(!strcmp(msm5xxx_poc_get_matrix_halfword(&s,&err),""));
    descriptor_words[0]=0x3000720;descriptor_words[2]=0x300072c;
    descriptor_words[8]=0x3000728;descriptor_words[13]=0x300072c;
    put(0x72c,0x73e0);put(0x728,0);put(0x720,0);
    pc=2;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0x73f0);
    pc=4;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0x73ff);
    s.matrix_input_pressed=true;s.matrix_input_row=3;s.matrix_input_sense=29;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0x73fd);
    pc=6;put(0x728,23);put(0x720,32);
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0x73fd);
    s.matrix_input_pressed=false;
    assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0x73ff);
    pc=8;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0x73e0);
    pc=2;assert(msm5xxx_poc_matrix_halfword_read(&s,0,1)==0xe0);
    descriptor_words[2]=0;assert(msm5xxx_poc_matrix_halfword_read(&s,0,2)==0x73e0);
    descriptor_words[2]=0x300072c;
    uint8_t loop_record[]={0x80,1,3,29};assert(!host_rejected(&s,loop_record));
    loop_record[3]=15;assert(host_rejected(&s,loop_record));
    loop_record[3]=31;assert(host_rejected(&s,loop_record));
    loop_record[3]=29;loop_record[2]=6;assert(host_rejected(&s,loop_record));
    s.matrix_input_pressed=true;loop_record[2]=0;loop_record[3]=0;
    loop_record[1]=0;assert(!host_rejected(&s,loop_record));
    err=NULL;msm5xxx_poc_set_matrix_low5(&s,"1801000:2:4",&err);assert(err);
    const char *bad_loop[]={"1801001:2:4:6","1801000:2:2:6","1801000:3:4:6",
        "1801000:2:4:100000000","1801000:2:4:6x","1801000:2:4:6:8"};
    for(unsigned i=0;i<sizeof(bad_loop)/sizeof(bad_loop[0]);i++) {
        s=(MSM5xxxPOCMachineState){0};err=NULL;
        msm5xxx_poc_set_matrix_loop(&s,bad_loop[i],&err);
        assert(err && !s.matrix_input_enabled);
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(path / "check.c"), "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True)

if __name__ == "__main__":
    unittest.main()
