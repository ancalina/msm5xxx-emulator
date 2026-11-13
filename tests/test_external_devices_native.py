"""Compile selected external-device callbacks from the machine source."""
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class ExternalDeviceNativeTests(unittest.TestCase):
    def test_uart_gpio_lcd_and_status_callbacks(self):
        repo = Path(__file__).resolve().parents[1]
        source = (repo / 'native/qemu/msm5xxx-poc.c').read_text()
        self.assertIn('"external-lcd-18-data-offset", "uint32"', source)
        self.assertIn('"external-lcd-18-dcs"', source)
        self.assertIn('s->external_lcd_18_data_offset ?', source)
        self.assertIn(': 0x40000);', source)

        def function(name):
            match = re.search(r'^static [^;{}]*\b' + name +
                              r'\([^;{}]*\)\s*\{', source, re.M | re.S)
            self.assertIsNotNone(match, name)
            brace = match.end() - 1
            depth, cursor = 1, brace + 1
            while depth:
                depth += (source[cursor] == '{') - (source[cursor] == '}')
                cursor += 1
            return source[match.start():cursor]

        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct { uint8_t bytes[0x1000]; } MemoryRegion;
typedef struct { unsigned unused; } MSM5xxxNAND;
typedef struct MSM5xxxPOCMachineState MSM5xxxPOCMachineState;
struct MSM5xxxPOCMachineState {
    MemoryRegion msm;
    bool external_uart, external_uart_tx_log, uart_console_enabled;
    bool external_cs09_enabled;
    MemoryRegion external_cs09;
    bool gpio_ready_bit21;
    bool experimental_contract_lcd_1c_selector;
    bool external_lcd_18, external_lcd_18_window, external_lcd_18_dcs;
    uint32_t external_lcd_18_data_offset;
    uint32_t external_lcd_18_register_offset;
    uint16_t external_lcd_18_register_selector;
    uint16_t external_lcd_18_registers[65536];
    MemoryRegion external_lcd_18_window_region;
    uint8_t external_lcd_18_bounds[4], external_lcd_18_bounds_seen;
    uint8_t external_lcd_18_cursor_x, external_lcd_18_cursor_y;
    uint16_t external_lcd_18_command;
    uint8_t external_lcd_18_parameter_index;
    uint8_t external_lcd_18_parameters_left;
    bool external_lcd_18_parameter_valid, external_lcd_18_window_valid;
    bool external_indexed_18;
    uint16_t external_indexed_18_selector;
    uint16_t external_indexed_18_registers[65536];
    bool experimental_contract_gpio_bit9_low;
    bool experimental_contract_gpio_pmic_serial;
    uint8_t gpio_pmic_serial_registers[64];
    uint8_t gpio_pmic_serial_command, gpio_pmic_serial_data;
    uint8_t gpio_pmic_serial_command_bits, gpio_pmic_serial_data_bits;
    uint8_t gpio_pmic_serial_register, gpio_pmic_serial_read_bits;
    bool gpio_pmic_serial_read, gpio_pmic_serial_read_started;
    uint32_t uart_console_base;
    bool board_status_input_enabled, board_status_input_descriptor;
    bool raw_nand_main_enabled, small_nand_enabled;
    uint32_t board_status_input_address, board_status_input_mask;
    uint32_t board_status_input_backing;
    uint32_t raw_nand_ready_address, raw_nand_ready_mask;
    uint32_t small_nand_ready_address, small_nand_ready_mask;
    uint8_t raw_nand_status;
    MSM5xxxNAND small_nand;
    uint8_t external_lcd_backing[3][0x1000];
    MemoryRegion external_indexed_18_regions[2];
    uint8_t experimental_contract_status_0b408_backing[2];
    struct { MSM5xxxPOCMachineState *machine; unsigned index; } external_lcd_context[3];
    struct { MSM5xxxPOCMachineState *machine; bool data; } external_indexed_18_context[2];
};
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define LOG_GUEST_ERROR 1
#define QEMU_CLOCK_VIRTUAL 0
static char log_text[128];
static unsigned small_nand_sync_calls, small_nand_arm_calls;
static uint64_t qemu_clock_get_ns(int clock) {
    assert(clock == QEMU_CLOCK_VIRTUAL);
    return 1234;
}
static bool msm5xxx_poc_small_nand_sync(MSM5xxxPOCMachineState *s, uint64_t now) {
    (void)s; assert(now == 1234); small_nand_sync_calls++; return true;
}
static void msm5xxx_poc_small_nand_arm(MSM5xxxPOCMachineState *s) {
    (void)s; small_nand_arm_calls++;
}
static void qemu_log_mask(int mask, const char *format, ...) {
    va_list args; (void)mask; va_start(args, format);
    vsnprintf(log_text, sizeof(log_text), format, args); va_end(args);
}
static uint8_t *memory_region_get_ram_ptr(MemoryRegion *region) { return region->bytes; }
static uint64_t msm5xxx_poc_backing_read(const uint8_t *backing,
                                         hwaddr offset, unsigned size) {
    uint64_t value = 0;
    for (unsigned i = 0; i < size; i++) value |= (uint64_t)backing[offset+i] << (8*i);
    return value;
}
static void msm5xxx_poc_backing_write(uint8_t *backing, hwaddr offset,
                                      uint64_t value, unsigned size) {
    for (unsigned i = 0; i < size; i++) backing[offset+i] = value >> (8*i);
}
static bool msm5xxx_nand_ready(MSM5xxxNAND *nand) { (void)nand; return true; }
static uint64_t lcd_address, lcd_value;
static unsigned lcd_size, lcd_writes;
static void msm5xxx_poc_lcd_trace_write(MSM5xxxPOCMachineState *s,
                                        hwaddr address, uint64_t value,
                                        unsigned size) {
    (void)s; lcd_address = address; lcd_value = value;
    lcd_size = size; lcd_writes++;
}
static uint64_t msm5xxx_poc_gpio_bank_read(void *opaque, hwaddr offset,
                                           unsigned size);
static void msm5xxx_poc_gpio_bank_write(void *opaque, hwaddr offset,
                                        uint64_t value, unsigned size);
static void pmic_gpio_write(MSM5xxxPOCMachineState *s, uint32_t offset,
                            uint32_t value) {
    msm5xxx_poc_gpio_bank_write(s, offset, value, 4);
}
static void pmic_clock_bit(MSM5xxxPOCMachineState *s, unsigned bit) {
    pmic_gpio_write(s, 0, bit ? (1u << 9) : 0);
    pmic_gpio_write(s, 0, (1u << 10) | (bit ? (1u << 9) : 0));
    pmic_gpio_write(s, 0, bit ? (1u << 9) : 0);
}
static void pmic_send_byte(MSM5xxxPOCMachineState *s, uint8_t value) {
    for (int bit = 7; bit >= 0; bit--) {
        pmic_clock_bit(s, (value >> bit) & 1);
    }
}
static void pmic_send_command(MSM5xxxPOCMachineState *s, unsigned reg,
                              bool read) {
    uint8_t command = (reg << 1) | read;
    for (int bit = 6; bit >= 0; bit--) {
        pmic_clock_bit(s, (command >> bit) & 1);
    }
}
static uint64_t pmic_read_value(MSM5xxxPOCMachineState *s, unsigned offset,
                                unsigned size) {
    return msm5xxx_poc_gpio_bank_read(s, offset, size);
}
''' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_external_lcd_18_window_reset',
            'msm5xxx_poc_external_lcd_register_reset',
            'msm5xxx_poc_external_lcd_18_window_command',
            'msm5xxx_poc_external_lcd_18_window_advance',
            'msm5xxx_poc_external_lcd_18_window_read',
            'msm5xxx_poc_external_lcd_18_window_write',
            'msm5xxx_poc_external_lcd_18_data_configuration_valid',
            'msm5xxx_poc_external_uart_read',
            'msm5xxx_poc_external_uart_configuration_valid',
            'msm5xxx_poc_external_uart_write',
            'msm5xxx_poc_external_lcd_read',
            'msm5xxx_poc_external_lcd_write',
            'msm5xxx_poc_indexed_18_read',
            'msm5xxx_poc_indexed_18_write',
            'msm5xxx_poc_indexed_18_reset',
            'msm5xxx_poc_gpio_input_merge',
            'msm5xxx_poc_gpio_pmic_serial_reset',
            'msm5xxx_poc_gpio_pmic_serial_abort_frame',
            'msm5xxx_poc_gpio_pmic_serial_edge',
            'msm5xxx_poc_gpio_bank_read',
            'msm5xxx_poc_gpio_bank_write',
            'msm5xxx_poc_experimental_status_read',
            'msm5xxx_poc_experimental_status_write')) + r'''
int main(void) {
    MSM5xxxPOCMachineState s = {0};
    assert(msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_data_offset = 0x40000;
    assert(!msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18 = true;
    s.external_lcd_18_window = true;
    assert(msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_data_offset = 0x80000;
    assert(msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_data_offset = 0x60000;
    assert(!msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_data_offset = 0;
    s.external_lcd_18_window = false;
    assert(msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_data_offset = 0x40000;
    s.external_lcd_18_dcs = true;
    assert(msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_dcs = false;
    s.external_lcd_18_data_offset = 0x80000;
    s.external_lcd_18_dcs = true;
    assert(msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_window = true;
    assert(!msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_window = false;
    s.external_lcd_18 = false;
    assert(!msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18 = true;
    s.external_lcd_18_dcs = false;
    s.external_lcd_18_data_offset = 0x60000;
    assert(!msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_data_offset = 0;
    assert(msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    assert(msm5xxx_poc_external_uart_configuration_valid(&s));
    s.external_uart_tx_log = true;
    assert(!msm5xxx_poc_external_uart_configuration_valid(&s));
    s.external_uart = true;
    assert(msm5xxx_poc_external_uart_configuration_valid(&s));
    s.uart_console_enabled = true;
    s.uart_console_base = 0x03000b00;
    assert(!msm5xxx_poc_external_uart_configuration_valid(&s));
    s.uart_console_base = 0x03000b24;
    assert(msm5xxx_poc_external_uart_configuration_valid(&s));
    assert(msm5xxx_poc_external_uart_read(&s, 4, 1) == 8);
    assert(msm5xxx_poc_external_uart_read(&s, 4, 4) == 8);
    assert(msm5xxx_poc_external_uart_read(&s, 16, 1) == 1);
    assert(msm5xxx_poc_external_uart_read(&s, 12, 1) == 0);
    s.external_uart_tx_log = false;
    msm5xxx_poc_external_uart_write(&s, 8, 0x41, 1);
    assert(!log_text[0]);
    s.external_uart_tx_log = true;
    msm5xxx_poc_external_uart_write(&s, 8, 0x41, 1);
    assert(strstr(log_text, "'A'") != NULL);
    msm5xxx_poc_external_uart_write(&s, 8, 0xff, 1);
    assert(strstr(log_text, "\\xff") != NULL);
    msm5xxx_poc_external_uart_write(&s, 8, 0x1b, 1);
    assert(strstr(log_text, "\\x1b") != NULL);

    s.experimental_contract_gpio_bit9_low = true;
    s.msm.bytes[0x721] = 0x02;
    assert(msm5xxx_poc_gpio_bank_read(&s, 0, 4) == 0);
    assert(s.msm.bytes[0x721] == 0x02);
    s.board_status_input_enabled = true;
    s.board_status_input_address = MSM5XXX_POC_MSM_BASE + 0x720;
    s.board_status_input_mask = 4;
    s.board_status_input_backing = 4;
    assert(msm5xxx_poc_gpio_bank_read(&s, 0, 4) == 4);
    s.small_nand_enabled = true;
    s.small_nand_ready_address = MSM5XXX_POC_MSM_BASE + 0x720;
    s.small_nand_ready_mask = 2;
    assert(msm5xxx_poc_gpio_bank_read(&s, 0, 4) == 6);
    assert(small_nand_sync_calls == 1 && small_nand_arm_calls == 1);
    assert(s.msm.bytes[0x721] == 0x02);
    s.small_nand_enabled = false;
    msm5xxx_poc_gpio_bank_write(&s, 0, 0x00000200, 4);
    assert(s.msm.bytes[0x721] == 0x02);
    assert(msm5xxx_poc_gpio_bank_read(&s, 0, 4) == 4);
    s.board_status_input_enabled = false;
    s.gpio_ready_bit21 = true;
    assert(msm5xxx_poc_gpio_bank_read(&s, 0, 4) == (1u << 21));
    msm5xxx_poc_gpio_bank_write(&s, 0, 0x10, 4);
    assert(msm5xxx_poc_gpio_bank_read(&s, 0, 4) == ((1u << 21) | 0x10));
    assert(msm5xxx_poc_gpio_bank_read(&s, 2, 1) == 0x20);
    msm5xxx_poc_gpio_bank_write(&s, 0, 0xffffffff, 4);
    assert(msm5xxx_poc_gpio_bank_read(&s, 0, 4) ==
           (((1u << 21) | 0xffdfffff) & ~0x200u));
    assert(msm5xxx_poc_gpio_bank_read(&s, 4, 1) == 0);
    s.raw_nand_main_enabled = true;
    s.raw_nand_ready_address = MSM5XXX_POC_MSM_BASE + 0x720;
    s.raw_nand_ready_mask = 2;
    s.raw_nand_status = 0x40;
    assert((msm5xxx_poc_gpio_bank_read(&s, 0, 4) & ((1u << 21) | 2)) ==
           ((1u << 21) | 2));

    s.external_lcd_context[1].machine = &s;
    s.external_lcd_context[1].index = 1;
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 0x80, 0x1234, 2);
    assert(lcd_writes == 1 && lcd_address == 0x02000002);
    assert(lcd_value == 0x1234 && lcd_size == 2);
    assert(msm5xxx_poc_external_lcd_read(&s.external_lcd_context[1], 0x80, 2) == 0x1234);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 1, 0x5a, 1);
    assert(lcd_writes == 2 && lcd_address == 0x02000001);
    assert(lcd_value == 0x5a && lcd_size == 1);
    assert(msm5xxx_poc_external_lcd_read(&s.external_lcd_context[1], 1, 1) == 0x5a);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 3, 0xa5, 1);
    assert(lcd_writes == 3 && lcd_address == 0x02000003);
    assert(lcd_value == 0xa5 && lcd_size == 1);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 0x14, 0x12345678, 4);
    assert(lcd_writes == 3);
    assert(msm5xxx_poc_external_lcd_read(&s.external_lcd_context[1], 0x14, 4) == 0x12345678);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 0x78, 0x22, 2);
    assert(lcd_writes == 4 && lcd_address == 0x02000000);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 0xfa, 0x5678, 2);
    assert(lcd_writes == 5 && lcd_address == 0x02000002);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 0xfff, 0xffff, 2);
    assert(lcd_writes == 5);
    assert(msm5xxx_poc_external_lcd_read(&s.external_lcd_context[1], 0x1000, 1) == 0);
    s.experimental_contract_lcd_1c_selector = true;
    s.external_lcd_context[1].machine = &s;
    s.external_lcd_context[1].index = 1;
    unsigned selector_trace_start = lcd_writes;
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 0, 0, 2);
    assert(lcd_writes == selector_trace_start);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 2, 0x44, 2);
    assert(lcd_writes == selector_trace_start + 1);
    assert(lcd_address == 0x02000000 && lcd_value == 0x44);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 0, 1, 2);
    assert(lcd_writes == selector_trace_start + 1);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 2, 0x3f00, 2);
    assert(lcd_writes == selector_trace_start + 2);
    assert(lcd_address == 0x02000002 && lcd_value == 0x3f00);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 0, 2, 2);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 2, 0xffff, 2);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[1], 6, 1, 2);
    assert(lcd_writes == selector_trace_start + 2);

    s.external_lcd_context[0].machine = &s;
    s.external_lcd_context[0].index = 0;
    unsigned default_window_trace = lcd_writes;
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[0], 0, 0x42, 2);
    assert(lcd_writes == default_window_trace + 1);
    assert(lcd_address == 0x02000000);
    assert(s.external_lcd_18_parameters_left == 0);

    s.external_lcd_18 = true;
    s.external_lcd_18_window = true;
    msm5xxx_poc_external_lcd_18_window_reset(&s);
    unsigned window_trace_start = lcd_writes;
    const uint16_t window_commands[] = {
        0x42, 3, 4, 0x43, 5, 6, 0x60, 0, 0x61, 0, 0x51
    };
    for (unsigned i = 0; i < sizeof(window_commands) / sizeof(window_commands[0]); i++) {
        msm5xxx_poc_external_lcd_write(&s.external_lcd_context[0], 0,
                                       window_commands[i], 2);
    }
    assert(s.external_lcd_18_window_valid);
    assert(s.external_lcd_18_cursor_x == 5 && s.external_lcd_18_cursor_y == 3);
    assert(lcd_writes == window_trace_start + 11);
    assert(lcd_address == 0x02000000);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0x12345678, 2);
    assert(lcd_address == 0x02000002 && lcd_value == 0x5678 && lcd_size == 2);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0x2222, 2);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0x3333, 2);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0x4444, 2);
    assert(s.external_lcd_18_cursor_x == 5 && s.external_lcd_18_cursor_y == 3);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);


    assert(s.external_lcd_18_cursor_x == 5 && s.external_lcd_18_cursor_y == 3);
    unsigned pixel_trace = lcd_writes;
    msm5xxx_poc_external_lcd_18_window_write(&s, 2, 0xaaaa, 2);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0xbbbb, 1);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0xcccc, 4);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 2, 2) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 1) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 4) == 0);
    assert(lcd_writes == pixel_trace);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x51);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    msm5xxx_poc_external_lcd_18_window_reset(&s);
    assert(!s.external_lcd_18_window_valid);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    pixel_trace = lcd_writes;
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0xffff, 2);
    assert(lcd_writes == pixel_trace);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x42);
    msm5xxx_poc_external_lcd_18_window_command(&s, 3);
    msm5xxx_poc_external_lcd_18_window_command(&s, 4);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x43);
    msm5xxx_poc_external_lcd_18_window_command(&s, 5);
    msm5xxx_poc_external_lcd_18_window_command(&s, 6);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x51);
    assert(s.external_lcd_18_window_valid);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    msm5xxx_poc_external_lcd_18_window_reset(&s);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x42);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x100);
    msm5xxx_poc_external_lcd_18_window_command(&s, 1);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x43);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0);
    msm5xxx_poc_external_lcd_18_window_command(&s, 1);
    assert(!s.external_lcd_18_window_valid);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);

    msm5xxx_poc_external_lcd_18_window_reset(&s);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x42);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0);
    msm5xxx_poc_external_lcd_18_window_command(&s, 1);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x43);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0);
    msm5xxx_poc_external_lcd_18_window_command(&s, 1);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x51);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0xf800, 2);
    assert(s.external_lcd_18_cursor_x == 1 &&
           s.external_lcd_18_cursor_y == 0);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x60);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x61);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0);
    assert(s.external_lcd_18_cursor_x == 1 &&
           s.external_lcd_18_cursor_y == 0);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0x07e0, 2);
    assert(s.external_lcd_18_cursor_x == 0 &&
           s.external_lcd_18_cursor_y == 1);
    msm5xxx_poc_external_lcd_18_window_command(&s, 0x51);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);

    s.external_lcd_18_dcs = true;
    msm5xxx_poc_external_lcd_18_window_reset(&s);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    unsigned dcs_trace_start = lcd_writes;
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0x12345678, 2);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    assert(lcd_writes == dcs_trace_start + 1);
    assert(lcd_address == 0x02000002 && lcd_value == 0x5678 && lcd_size == 2);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0xabcd, 2);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    assert(lcd_writes == dcs_trace_start + 2);
    msm5xxx_poc_external_lcd_18_window_write(&s, 2, 0x1111, 2);
    msm5xxx_poc_external_lcd_18_window_write(&s, 0, 0x2222, 1);
    assert(lcd_writes == dcs_trace_start + 2);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 2, 2) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 1) == 0);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    msm5xxx_poc_external_lcd_18_window_reset(&s);
    assert(msm5xxx_poc_external_lcd_18_window_read(&s, 0, 2) == 0);
    s.external_lcd_18_dcs = false;

    s.external_indexed_18_context[0].machine = &s;
    s.external_indexed_18_context[0].data = false;
    s.external_indexed_18_context[1].machine = &s;
    s.external_indexed_18_context[1].data = true;
    msm5xxx_poc_indexed_18_reset(&s);
    assert(msm5xxx_poc_indexed_18_read(&s.external_indexed_18_context[0], 0, 2) == 0);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[0], 0, 0x12345, 2);
    assert(s.external_indexed_18_selector == 0x2345);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[1], 0, 0x12345678, 2);
    assert(msm5xxx_poc_indexed_18_read(&s.external_indexed_18_context[1], 0, 2) == 0x5678);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[0], 0, 0x3456, 2);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[1], 0, 0x1beef, 2);
    assert(msm5xxx_poc_indexed_18_read(&s.external_indexed_18_context[1], 0, 2) == 0xbeef);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[0], 0, 0x2345, 2);
    assert(msm5xxx_poc_indexed_18_read(&s.external_indexed_18_context[1], 0, 2) == 0x5678);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[0], 0, 0x3456, 2);
    assert(msm5xxx_poc_indexed_18_read(&s.external_indexed_18_context[1], 0, 2) == 0xbeef);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[0], 0, 0x1ffff, 2);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[1], 0, 0x1beef, 2);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[0], 1, 0x1111, 2);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[0], 0, 0x2222, 1);
    msm5xxx_poc_indexed_18_write(&s.external_indexed_18_context[1], 0, 0x3333, 4);
    assert(msm5xxx_poc_indexed_18_read(&s.external_indexed_18_context[0], 1, 2) == 0);
    assert(msm5xxx_poc_indexed_18_read(&s.external_indexed_18_context[1], 0, 1) == 0);
    assert(msm5xxx_poc_indexed_18_read(&s.external_indexed_18_context[1], 0, 4) == 0);
    assert(s.external_indexed_18_selector == 0xffff);
    assert(s.external_indexed_18_registers[0x2345] == 0x5678);
    assert(s.external_indexed_18_registers[0xffff] == 0xbeef);
    msm5xxx_poc_indexed_18_reset(&s);
    assert(s.external_indexed_18_selector == 0);
    assert(s.external_indexed_18_registers[0x2345] == 0);
    assert(s.external_indexed_18_registers[0xffff] == 0);
    assert(msm5xxx_poc_experimental_status_read(&s, 0, 2) == 0);
    msm5xxx_poc_experimental_status_write(&s, 0, 0xffff, 2);
    assert(msm5xxx_poc_experimental_status_read(&s, 0, 2) == 0xffff);
    assert(msm5xxx_poc_experimental_status_read(&s, 0, 1) == 0xff);
    assert(msm5xxx_poc_experimental_status_read(&s, 1, 1) == 0xff);
    msm5xxx_poc_experimental_status_write(&s, 0, 0, 1);
    assert(msm5xxx_poc_experimental_status_read(&s, 0, 2) == 0xff00);

    assert(msm5xxx_poc_experimental_status_read(&s, 2, 1) == 0);
    msm5xxx_poc_experimental_status_write(&s, 2, 0xffff, 2);
    assert(msm5xxx_poc_experimental_status_read(&s, 0, 2) == 0xff00);

    s.external_lcd_18 = true;
    s.external_lcd_18_window = s.external_lcd_18_dcs = false;
    s.external_lcd_18_data_offset = 0;
    s.external_lcd_18_register_offset = 0x10;
    assert(msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_register_offset = 0x11;
    assert(!msm5xxx_poc_external_lcd_18_data_configuration_valid(&s));
    s.external_lcd_18_register_offset = 0x10;
    s.external_lcd_context[0].machine = &s;
    s.external_lcd_context[0].index = 0;
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[0], 0, 0x44, 2);
    assert(lcd_address == 0x18000000 && lcd_value == 0x44);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[0], 0x10, 0x1234, 2);
    assert(lcd_address == 0x18000010 && lcd_value == 0x1234);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[0], 0, 0x45, 2);
    assert(msm5xxx_poc_external_lcd_read(&s.external_lcd_context[0], 0x10, 2) == 0);
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[0], 0, 0x44, 2);
    assert(msm5xxx_poc_external_lcd_read(&s.external_lcd_context[0], 0x10, 2) == 0x1234);
    unsigned indexed_trace = lcd_writes;
    msm5xxx_poc_external_lcd_write(&s.external_lcd_context[0], 0x10, 0xff, 1);
    assert(lcd_writes == indexed_trace);
    assert(msm5xxx_poc_external_lcd_read(&s.external_lcd_context[0], 0x10, 2) == 0x1234);
    msm5xxx_poc_external_lcd_register_reset(&s);
    assert(!s.external_lcd_18_register_selector && !s.external_lcd_18_registers[0x44]);
    s.external_lcd_18_register_offset = 0;

    s.experimental_contract_gpio_pmic_serial = true;
    s.experimental_contract_gpio_bit9_low = false;
    msm5xxx_poc_gpio_pmic_serial_reset(&s);
    for (unsigned i = 0; i < 64; i++) {
        assert(s.gpio_pmic_serial_registers[i] == 0);
    }
    pmic_gpio_write(&s, 0xc, (1u << 9) | (1u << 10));
    for (unsigned i = 0; i < 64; i++) {
        uint8_t expected = (i * 37u + 0x53u) & 0xff;
        pmic_send_command(&s, i, false);
        pmic_send_byte(&s, expected);
        assert(s.gpio_pmic_serial_command_bits == 0);
        assert(s.gpio_pmic_serial_data_bits == 0);
    }
    for (unsigned i = 0; i < 64; i++) {
        assert(s.gpio_pmic_serial_registers[i] ==
               (uint8_t)(i * 37u + 0x53u));
    }

    /* A direction change in a partial command must discard that frame. */
    msm5xxx_poc_gpio_pmic_serial_reset(&s);
    pmic_gpio_write(&s, 0xc, (1u << 9) | (1u << 10));
    pmic_clock_bit(&s, 1);
    pmic_clock_bit(&s, 0);
    pmic_clock_bit(&s, 1);
    assert(s.gpio_pmic_serial_command_bits == 3);
    pmic_gpio_write(&s, 0xc, 1u << 10);
    assert(s.gpio_pmic_serial_command_bits == 0);
    pmic_gpio_write(&s, 0xc, (1u << 9) | (1u << 10));
    for (unsigned i = 0; i < 8; i++) {
        pmic_clock_bit(&s, (0x5au >> (7 - i)) & 1);
    }
    assert(s.gpio_pmic_serial_registers[0] == 0);

    /* Read serial data through byte, halfword, and word GPIO accesses. */
    s.gpio_pmic_serial_registers[0x2d] = 0xa6;
    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s.msm), 0x720,
                              0xa5a5a5a5, 4);
    pmic_gpio_write(&s, 0xc, (1u << 9) | (1u << 10));
    pmic_send_command(&s, 0x2d, true);
    pmic_gpio_write(&s, 0xc, 1u << 10); /* SDA input; clock output. */
    unsigned actual = 0;
    for (unsigned i = 0; i < 8; i++) {
        unsigned offset = i % 3 == 0 ? 0x39 : 0x38;
        unsigned size = i % 3 == 0 ? 1 : (i % 3 == 1 ? 2 : 4);
        uint64_t value = pmic_read_value(&s, offset, size);
        unsigned shift = offset == 0x39 ? 1 : 9;
        uint64_t mask = UINT64_C(1) << shift;
        uint64_t backing = offset == 0x39 ? 0xa5 :
                           (size == 2 ? 0xa5a5 : 0xa5a5a5a5u);
        assert((value & ~mask) == (backing & ~mask));
        unsigned bit = (value >> shift) & 1;
        actual = (actual << 1) | bit;
        pmic_gpio_write(&s, 0, 1u << 10);
        pmic_gpio_write(&s, 0, 0);
        if (i == 6) {
            assert(s.gpio_pmic_serial_read_bits == 7);
        }
    }
    assert(actual == 0xa6);
    assert(s.gpio_pmic_serial_read_bits == 0);
    assert(!s.gpio_pmic_serial_read && s.gpio_pmic_serial_command_bits == 0);
    assert(msm5xxx_poc_gpio_bank_read(&s, 0x39, 1) == 0xa5);
    puts("external-device actual-C callbacks: UART/GPIO/LCD-window/indexed/status/PMIC serial PASS");
    return 0;
}
'''
        flags = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True, timeout=10))
        with tempfile.TemporaryDirectory(prefix='.external-devices-native-') as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', str(path / 'check.c'),
                            '-o', str(path / 'check'), *flags], check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
