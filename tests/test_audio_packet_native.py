"""Compile actual packet ownership/controller/LCD callbacks; no guest or realize."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class AudioPacketNativeTests(unittest.TestCase):
    def test_owned_packet_and_foreign_lcd_fallback(self):
        core = Path(__file__).resolve().parents[1] / 'native/qemu'
        source = (core / 'msm5xxx-poc.c').read_text()

        def function(name):
            match = re.search(r'^static [^\n]*(?:\n[^\n]*)?\b' + name + r'\(', source, re.M)
            self.assertIsNotNone(match, name)
            start = match.start()
            brace = source.index('{', match.end())
            depth = 1
            cursor = brace + 1
            while depth:
                depth += (source[cursor] == '{') - (source[cursor] == '}')
                cursor += 1
            return source[start:cursor]

        names = ('msm5xxx_poc_backing_read', 'msm5xxx_poc_backing_write',
                 'msm5xxx_poc_audio_packet_nor', 'msm5xxx_poc_audio_packet_gate',
                 'msm5xxx_poc_audio_packet_reject', 'msm5xxx_poc_audio_packet_read',
                 'msm5xxx_poc_audio_packet_write', 'msm5xxx_poc_lcd_aperture_read',
                 'msm5xxx_poc_lcd_aperture_write')
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msm5xxx-audio-request.h"
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MSM5XXX_POC_LCD_APERTURE_BASE 0x02000000u
#define MSM5XXX_POC_LCD_APERTURE_SIZE 0x00800000u
#define MEMTXATTRS_UNSPECIFIED 0
#define MEMTX_OK 0
typedef uint64_t hwaddr;
typedef uint64_t Int128;
typedef struct { unsigned marker; } MemoryRegion;
typedef struct { MemoryRegion *mr; Int128 size; } MemoryRegionSection;
typedef struct { bool running; struct { bool can_do_io; } neg; uint32_t pc; } CPUState;
typedef struct { CPUState parent; struct { bool thumb; } env; } ARMCPU;
typedef struct { uint64_t (*get_pc)(CPUState *); } CPUClass;
static uint64_t get_pc(CPUState *cpu) { return cpu->pc; }
static CPUClass cpu_class = {get_pc};
#define CPU(p) (&(p)->parent)
#define CPU_GET_CLASS(p) ((void)(p), &cpu_class)
typedef struct {
    ARMCPU *cpu;
    MemoryRegion nor;
    uint32_t primary_nor_size, audio_packet_begin;
    uint8_t audio_packet_index, audio_packet_control, audio_packet_mode;
    uint8_t audio_packet_init[4][2], audio_packet_init_valid;
    bool audio_packet_fault, audio_packet_reported, audio_packet_gate_reported;
    bool audio_packet_fifo_empty_known;
    bool audio_packet_sequence, audio_packet_reset_armed, audio_packet_ready;
    bool audio_packet_clear_pulse, audio_packet_clear_armed;
    unsigned audio_packet_trace_count;
    MSM5xxxAudioPacketSink audio_packet_sink;
    bool audio_enabled;
    uint32_t audio_base, audio_data_offset;
    uint64_t lcd_aperture_reads, lcd_aperture_writes;
    uint8_t *lcd_aperture_backing;
} MSM5xxxPOCMachineState;
static ARMCPU arm;
static CPUState other_cpu, *current_cpu;
static MSM5xxxPOCMachineState s;
static MemoryRegion system_memory, foreign_region;
static uint8_t rom[0x2000];
static bool in_vcpu = true, short_section, read_error, no_section;
static unsigned reads, unrefs, traces, old_routes;
static hwaddr hidden_begin = UINT64_MAX, hidden_end;
static int address_space_memory;
static uint16_t lduw_le_p(const uint8_t *p) { return p[0] | ((uint16_t)p[1] << 8); }
static bool qemu_in_vcpu_thread(void) { return in_vcpu; }
static Int128 int128_make64(uint64_t value) { return value; }
static bool int128_ge(Int128 a, Int128 b) { return a >= b; }
static MemoryRegion *get_system_memory(void) { return &system_memory; }
static MemoryRegionSection memory_region_find(MemoryRegion *root, hwaddr addr, unsigned size) {
    assert(root == &system_memory);
    assert(addr <= sizeof(rom) && size <= sizeof(rom) - addr);
    bool hidden = addr < hidden_end && addr + size > hidden_begin;
    return (MemoryRegionSection){no_section ? NULL : hidden ? &foreign_region : &s.nor,
                                short_section ? size - 1 : size};
}
static void memory_region_unref(MemoryRegion *region) { assert(region); unrefs++; }
static int address_space_read(int *space, hwaddr addr, int attrs, uint8_t *data, unsigned size) {
    assert(space == &address_space_memory && attrs == 0);
    assert(addr <= sizeof(rom) && size <= sizeof(rom) - addr);
    reads++;
    if (read_error) { return 1; }
    memcpy(data, rom + addr, size); return MEMTX_OK;
}
static void warn_report(const char *format, ...) { (void)format; }
static bool msm5xxx_poc_audio_read_owned(MSM5xxxPOCMachineState *state, hwaddr off,
                                        unsigned size, uint64_t *value) {
    (void)state; (void)off; (void)size; (void)value; old_routes++; return false;
}
static bool msm5xxx_poc_audio_write_owned(MSM5xxxPOCMachineState *state, hwaddr off,
                                         uint64_t value, unsigned size) {
    (void)state; (void)off; (void)value; (void)size; old_routes++; return false;
}
static void msm5xxx_poc_lcd_trace_write(MSM5xxxPOCMachineState *state, hwaddr addr,
                                      uint64_t value, unsigned size) {
    assert(state == &s); (void)addr; (void)value; (void)size; traces++;
}
''' + '\n'.join(function(name) for name in names) + r'''
static void put16(unsigned pc, uint16_t word) {
    assert(pc + 2 <= sizeof(rom)); rom[pc] = word; rom[pc + 1] = word >> 8;
}
static void encode_bl(unsigned pc, unsigned target) {
    int32_t delta = (int32_t)target - (int32_t)pc - 4;
    assert(!(delta & 1) && delta >= -0x400000 && delta <= 0x3ffffe);
    uint32_t bits = (uint32_t)delta & 0x7fffff;
    put16(pc, 0xf000 | ((bits >> 12) & 0x7ff));
    put16(pc + 2, 0xf800 | ((bits >> 1) & 0x7ff));
}
static void fixture(unsigned entry, unsigned delay) {
    /* Independently encoded Thumb instruction sequence, no product shape import. */
    const uint16_t words[] = {
        0x2141,0x04c9,0xb500,0x7008,0,0,0xbc08,0x4718,
        0x2041,0x04c0,0xb580,0x7807,0,0,0x1c38,0xbc80,0xbc08,0x4718,
        0x2141,0x04c9,0xb500,0x7088,0,0,0xbc08,0x4718,
        0x2041,0x04c0,0xb580,0x7887,0,0,0x1c38,0xbc80,0xbc08,0x4718,
    };
    const unsigned calls[] = {8,24,44,60};
    uint8_t *backing = s.lcd_aperture_backing;
    memset(&s, 0, sizeof(s)); s.lcd_aperture_backing = backing;
    memset(backing, 0, MSM5XXX_POC_LCD_APERTURE_SIZE);
    memset(rom, 0, sizeof(rom));
    s.cpu = &arm; s.primary_nor_size = sizeof(rom); s.audio_packet_begin = entry + 6;
    arm.parent.running = arm.parent.neg.can_do_io = arm.env.thumb = in_vcpu = true;
    current_cpu = CPU(&arm); short_section = read_error = no_section = false;
    hidden_begin = UINT64_MAX; hidden_end = 0; reads = unrefs = traces = old_routes = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(words); i++) { put16(entry + 2 * i, words[i]); }
    for (unsigned i = 0; i < ARRAY_SIZE(calls); i++) { encode_bl(entry + calls[i], delay); }
    put16(delay, 0x4770);
}
static void select_index(uint8_t index) {
    arm.parent.pc = s.audio_packet_begin;
    msm5xxx_poc_lcd_aperture_write(&s, 0x80000, index, 1);
}
static void data(uint8_t byte) {
    arm.parent.pc = s.audio_packet_begin + 0x24;
    msm5xxx_poc_lcd_aperture_write(&s, 0x80002, byte, 1);
}
static unsigned status(void) {
    arm.parent.pc = s.audio_packet_begin + 0x10;
    return msm5xxx_poc_lcd_aperture_read(&s, 0x80000, 1);
}
static void full_reset(void) { select_index(4); data(0x80); assert(!status()); data(0); }
static void packet(void) {
    const uint8_t bytes[] = {0x2e,0x82,0x1b,0,0x84};
    select_index(2); for (unsigned i = 0; i < sizeof(bytes); i++) { data(bytes[i]); }
}
static void fallback(hwaddr address, unsigned size) {
    unsigned writes = s.lcd_aperture_writes, rd = s.lcd_aperture_reads, tr = traces;
    MSM5xxxAudioPacketSink before = s.audio_packet_sink;
    unsigned index = s.audio_packet_index, control = s.audio_packet_control;
    unsigned mode = s.audio_packet_mode, valid = s.audio_packet_init_valid;
    bool empty_known = s.audio_packet_fifo_empty_known;
    uint8_t banks[8]; memcpy(banks, s.audio_packet_init, sizeof(banks));
    hwaddr off = address - MSM5XXX_POC_LCD_APERTURE_BASE;
    msm5xxx_poc_lcd_aperture_write(&s, off, 0x78563412, size);
    assert(s.lcd_aperture_writes == writes + 1 && traces == tr + 1);
    uint64_t mask = (UINT64_C(1) << (size * 8)) - 1;
    assert(msm5xxx_poc_lcd_aperture_read(&s, off, size) == (0x78563412 & mask));
    assert(s.lcd_aperture_reads == rd + 1);
    assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
    assert(index == s.audio_packet_index && control == s.audio_packet_control);
    assert(mode == s.audio_packet_mode && valid == s.audio_packet_init_valid);
    assert(s.audio_packet_sequence && s.audio_packet_fault ?
           !s.audio_packet_fifo_empty_known : empty_known == s.audio_packet_fifo_empty_known);
    assert(!memcmp(banks, s.audio_packet_init, sizeof(banks)));
}

static void control(uint8_t byte) { select_index(4); data(byte); }
static void controller(void) {
    fixture(0x400, 0x100);
    assert(!s.audio_packet_mode && !s.audio_packet_init_valid);
    packet();
    const uint8_t controls[] = {0x31,0x82,0x51,0x23,0xbf};
    select_index(2); for (unsigned i = 0; i < sizeof(controls); i++) { data(controls[i]); }
    assert(s.audio_packet_sink.channel[29].pitch == 0x28a3);
    assert(s.audio_packet_sink.channel[29].control == 0x3f);
    assert(s.audio_packet_sink.channel[29].pitch_valid && s.audio_packet_sink.channel[29].control_valid);
    select_index(2); data(0x2e);
    MSM5xxxAudioPacketSink before = s.audio_packet_sink;
    /* Distinct backing exposes unintended cross-bank/slot writes, not reset defaults. */
    const uint8_t seeded[4][2] = {{0x11,0x22},{0x33,0x44},{0x55,0x66},{0x77,0x88}};
    memcpy(s.audio_packet_init, seeded, sizeof(seeded));
    unsigned valid = 0;
    for (unsigned mode = 0; mode < 4; mode++) {
        control(mode);
        assert(s.audio_packet_mode == mode && s.audio_packet_control == mode);
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
        for (unsigned slot = 0; slot < 2; slot++) {
            select_index(5 + slot);
            for (unsigned byte = 0; byte < 256; byte++) {
                uint8_t latches[4][2]; memcpy(latches, s.audio_packet_init, sizeof(latches));
                bool fault = s.audio_packet_fault, reported = s.audio_packet_reported;
                unsigned tr = s.audio_packet_trace_count;
                data(byte);
                valid |= 1u << (2 * mode + slot);
                latches[mode][slot] = byte;
                assert(s.audio_packet_init_valid == valid);
                assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
                assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
                assert(s.audio_packet_mode == mode && s.audio_packet_control == mode);
                assert(s.audio_packet_fault == fault && s.audio_packet_reported == reported);
                assert(s.audio_packet_trace_count == tr);
            }
        }
        assert(status() == 1);
    }
    select_index(2); data(0x82); data(0x1b); data(0); data(0x84);
    assert(s.audio_packet_sink.register_writes == 9); /* Partial packet survived every latch write. */
    uint8_t latches[4][2]; memcpy(latches, s.audio_packet_init, sizeof(latches));
    for (unsigned pulse = 0x10; pulse <= 0x40; pulse += 0x30) {
        control(2); select_index(2); data(0x2e);
        control(pulse | 2);
        assert(!s.audio_packet_sink.packet.phase && s.audio_packet_control == (pulse | 2));
        assert(s.audio_packet_mode == 2 && s.audio_packet_init_valid == 255);
        assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
        assert(s.audio_packet_sink.channel[29].pitch == 0x28a3);
        assert(s.audio_packet_sink.channel[29].pitch_high_valid && s.audio_packet_sink.channel[29].pitch_valid);
        assert(s.audio_packet_sink.channel[29].control_valid && s.audio_packet_sink.channel[29].control == 0x3f);
        assert(s.audio_packet_sink.register_writes == 9 && s.audio_packet_sink.channel[29].pointer == 0x1b00);
        select_index(2); data(0x2e); before = s.audio_packet_sink;
        control(pulse | 2); /* Repeated high bit clears mirror, no rising edge. */
        assert(s.audio_packet_control == 2 && s.audio_packet_mode == 2);
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
        assert(s.audio_packet_init_valid == 255 && !memcmp(latches, s.audio_packet_init, sizeof(latches)));
        control(pulse | 2); /* Cleared mirror now permits next pulse. */
        assert(!s.audio_packet_sink.packet.phase && s.audio_packet_control == (pulse | 2));
        assert(s.audio_packet_sink.register_writes == 9 && s.audio_packet_init_valid == 255);
    }
    memcpy(s.audio_packet_init, seeded, sizeof(seeded));
    control(0x83);
    assert(s.audio_packet_control == 0x83 && !s.audio_packet_mode);
    assert(!s.audio_packet_init_valid && !s.audio_packet_fault && !status());
    assert(!s.audio_packet_sink.register_writes && !s.audio_packet_sink.channel[29].pointer);
    assert(!s.audio_packet_sink.channel[29].pitch_high_valid && !s.audio_packet_sink.channel[29].pitch_valid);
    assert(!s.audio_packet_sink.channel[29].control_valid);
    assert(!s.audio_packet_sink.channel[29].pitch && !s.audio_packet_sink.channel[29].control);
    memset(latches, 0, sizeof(latches));
    assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
    for (unsigned index = 5; index <= 6; index++) {
        select_index(index); data(0xff); /* Reset hold prohibits both initialization latches. */
        assert(s.audio_packet_fault && !s.audio_packet_init_valid);
        assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
    }
    control(0x83); /* Repeat clears high bit, updates low mode, preserves fault. */
    assert(s.audio_packet_control == 3 && s.audio_packet_mode == 3 && !status());
    assert(!s.audio_packet_init_valid);
    full_reset(); assert(!s.audio_packet_mode && !s.audio_packet_init_valid && status() == 3);
    control(1); select_index(5); data(31); select_index(6); data(127);
    assert(s.audio_packet_init_valid == 12 && s.audio_packet_init[1][0] == 31 && s.audio_packet_init[1][1] == 127);
    memcpy(latches, s.audio_packet_init, sizeof(latches));
    select_index(2); data(0x2e); before = s.audio_packet_sink;
    select_index(7); data(1); /* Truly unsupported selector leaves all latches/parser intact. */
    assert(s.audio_packet_fault && s.audio_packet_init_valid == 12);
    assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
    assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
    control(2);
    for (unsigned index = 5; index <= 6; index++) {
        select_index(index); data(0xff); /* Fault cannot be repaired by either supported latch. */
        assert(s.audio_packet_init_valid == 12 && !status());
        assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
    }
    for (unsigned pulse = 0x10; pulse <= 0x40; pulse += 0x30) {
        control(pulse | 2); control(2);
        assert(s.audio_packet_fault && s.audio_packet_init_valid == 12 && !status());
        assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
    }
    full_reset(); assert(!s.audio_packet_fault && !s.audio_packet_init_valid && status() == 3);
    memset(latches, 0, sizeof(latches)); assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
    const uint8_t unsupported[] = {0x04,0x08,0x20};
    for (unsigned i = 0; i < ARRAY_SIZE(unsupported); i++) {
        fixture(0x400, 0x100); packet(); control(2); select_index(5); data(0x55); select_index(6); data(0xaa);
        memcpy(latches, s.audio_packet_init, sizeof(latches));
        select_index(2); data(0x2e); before = s.audio_packet_sink;
        control(unsupported[i] | 1);
        assert(s.audio_packet_fault && !status());
        assert(s.audio_packet_control == 2 && s.audio_packet_mode == 2 && s.audio_packet_init_valid == 48);
        assert(!memcmp(latches, s.audio_packet_init, sizeof(latches)));
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
    }
    puts("mode / banked command5+6 all bytes / reset pulse / fault isolation PASS");
}


static void known_empty(void) {
    fixture(0x400, 0x100);
    assert(!s.audio_packet_fifo_empty_known && status() == 1);
    full_reset(); assert(s.audio_packet_fifo_empty_known && status() == 3);
    packet(); assert(s.audio_packet_fifo_empty_known && status() == 3);
    control(1); select_index(5); data(0x55); select_index(6); data(0xaa);
    assert(s.audio_packet_fifo_empty_known && status() == 3);
    for (unsigned pulse = 0x10; pulse <= 0x40; pulse += 0x30) {
        select_index(2); data(0x2e); control(pulse | 1); control(1);
        assert(!s.audio_packet_sink.packet.phase && s.audio_packet_fifo_empty_known && status() == 3);
    }
    arm.parent.pc = s.audio_packet_begin + 2;
    fallback(0x02080000, 1);
    assert(s.audio_packet_fifo_empty_known && status() == 3);
    select_index(4); data(0x80); /* Reassert full reset; held reset is not capacity. */
    assert(s.audio_packet_fifo_empty_known && !status());
    data(0x80); /* Existing repeated-pulse folding releases reset. */
    assert(s.audio_packet_fifo_empty_known && status() == 3);
    select_index(1); data(0);
    assert(s.audio_packet_fault && !s.audio_packet_fifo_empty_known && !status());
    control(0x10); control(0);
    assert(s.audio_packet_fault && !s.audio_packet_fifo_empty_known && !status());
    full_reset(); assert(s.audio_packet_fifo_empty_known && status() == 3);
    select_index(2); data(0x63); data(0x82); data(0xbf);
    assert(!s.audio_packet_fault && s.audio_packet_fifo_empty_known && status() == 3);
    assert(s.audio_packet_sink.smoothing_config_valid && s.audio_packet_sink.smoothing_config == 0x3f);
    for (unsigned pulse = 0x10; pulse <= 0x40; pulse += 0x30) {
        select_index(2); data(0x63); control(pulse | 1); control(1);
        assert(!s.audio_packet_sink.packet.phase && s.audio_packet_mode == 1);
        assert(s.audio_packet_sink.smoothing_config_valid && s.audio_packet_sink.smoothing_config == 0x3f);
        assert(s.audio_packet_sink.register_writes == 1 && status() == 3);
    }
    select_index(2); data(0x63); data(0x82); data(0xff);
    assert(s.audio_packet_sink.reject == MSM5XXX_AUDIO_PACKET_REJECT_REGISTER);
    assert(s.audio_packet_sink.rejected_address == 0x163);
    assert(s.audio_packet_sink.smoothing_config_valid && s.audio_packet_sink.smoothing_config == 0x3f);
    assert(s.audio_packet_sink.register_writes == 1);
    assert(s.audio_packet_fault && !s.audio_packet_fifo_empty_known && !status());
    full_reset(); assert(!s.audio_packet_sink.smoothing_config_valid && status() == 3);
    puts("full-reset known empty / unchanged capacity and rejection / no FIFO acceptance PASS");
}

static void sequence_receiver(void) {
    fixture(0x400, 0x100);
    assert(!s.audio_packet_sequence && status() == 1);
    s.audio_packet_sequence = true;
    assert(!status() && !s.audio_packet_ready);
    control(0); assert(!status());
    select_index(2); data(0x5e);
    assert(s.audio_packet_fault && !status());
    full_reset(); assert(status() == 3);
    control(0x80); control(0x80);
    assert(!status() && s.audio_packet_control == 0x80);
    assert(s.audio_packet_reset_armed && !s.audio_packet_ready);
    control(0); assert(status() == 3 && s.audio_packet_ready);
    const uint8_t bytes[] = {0x5e, 0x82, 0x1b, 0, 0x84};
    select_index(2); data(bytes[0]);
    MSM5xxxAudioPacket partial = s.audio_packet_sink.packet;
    select_index(1); select_index(2);
    assert(!memcmp(&partial, &s.audio_packet_sink.packet, sizeof(partial)));
    for (unsigned i = 1; i < sizeof(bytes); i++) { data(bytes[i]); }
    assert(s.audio_packet_sink.sequence_parameter_valid);
    assert(s.audio_packet_sink.sequence_parameter == 3456);
    assert(s.audio_packet_sink.sequence_config_valid && s.audio_packet_sink.sequence_config == 4);
    assert(status() == 3);
    select_index(2); data(0x5e); data(0x82); data(0x1f);
    assert(s.audio_packet_sink.sequence_pending_stage == 1);
    control(0x10);
    assert(!s.audio_packet_sink.sequence_pending_stage &&
           !s.audio_packet_sink.sequence_pending_parameter);
    assert(!s.audio_packet_sink.sequence_parameter_valid &&
           !s.audio_packet_sink.sequence_config_valid &&
           s.audio_packet_sink.sequence_parameter == 3456 &&
           s.audio_packet_sink.sequence_config == 4 && status() == 3);
    control(0);
    MSM5xxxAudioPacketSink before = s.audio_packet_sink;
    select_index(1); data(0x80);
    assert(s.audio_packet_fault && !status() && !s.audio_packet_fifo_empty_known);
    assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
    select_index(2); data(0xff);
    assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
    full_reset(); assert(status() == 3 && !s.audio_packet_sink.sequence_parameter_valid);
    arm.parent.pc = 0x1800;
    fallback(0x02080000, 1);
    assert(s.audio_packet_ready && !s.audio_packet_fault && status() == 3);
    arm.parent.pc = s.audio_packet_begin;
    fallback(0x02080000, 2);
    assert(s.audio_packet_ready && !s.audio_packet_fault);
    put16(0x100, 0x46c0);
    arm.parent.pc = s.audio_packet_begin;
    fallback(0x02080000, 1);
    assert(s.audio_packet_fault && !s.audio_packet_ready && !s.audio_packet_fifo_empty_known);
    put16(0x100, 0x4770); assert(!status());
    full_reset(); assert(status() == 3);
    short_section = true;
    arm.parent.pc = s.audio_packet_begin;
    fallback(0x02080000, 1);
    assert(s.audio_packet_fault && !s.audio_packet_ready);
    short_section = false; full_reset(); assert(status() == 3);
    rom[0x400] ^= 1;
    arm.parent.pc = s.audio_packet_begin;
    fallback(0x02080000, 1);
    assert(s.audio_packet_fault && !s.audio_packet_ready);
    rom[0x400] ^= 1; full_reset(); assert(status() == 3);
    arm.parent.pc = s.audio_packet_begin + 0x34;
    s.lcd_aperture_backing[0x80002] = 0x5a;
    assert(msm5xxx_poc_lcd_aperture_read(&s, 0x80002, 1) == 0x5a);
    assert(s.audio_packet_fault && !s.audio_packet_ready && !status());
    full_reset(); select_index(2);
    data(0x5e); data(0x82); data(0x1b); data(0); data(0x85);
    assert(s.audio_packet_fault && !status() && !s.audio_packet_sink.sequence_config_valid);
    full_reset(); control(0x80); control(1);
    assert(s.audio_packet_fault && !s.audio_packet_ready && !status());
    puts("sequence opt-in / executed reset / unsupported and contract withdrawal PASS");
}

static void clear_fixture(void) {
    fixture(0x400, 0x100);
    s.audio_packet_sequence = s.audio_packet_clear_pulse = true;
    full_reset(); packet();
    select_index(2);
    const uint8_t period[] = {0x5e,0x82,0x1b,0,0x84};
    for (unsigned i = 0; i < sizeof(period); i++) { data(period[i]); }
    assert(s.audio_packet_sink.sequence_parameter_valid &&
           s.audio_packet_sink.sequence_parameter == 3456);
    s.audio_packet_sink.memory[3] = 0xa7;
    s.audio_packet_sink.timer_time = 7; s.audio_packet_sink.timer_time_valid = true;
    s.audio_packet_sink.timer0_timebase = 0x1b;
    s.audio_packet_sink.timer0_timebase_valid = true;
    memcpy(s.audio_packet_init, "rawbanks", 8); s.audio_packet_init_valid = 255;
    select_index(4);
}
static void clear_pulse(void) {
    for (unsigned empty = 0; empty < 2; empty++) {
        clear_fixture(); s.audio_packet_fifo_empty_known = empty;
        MSM5xxxAudioPacketSink before = s.audio_packet_sink;
        uint8_t banks[8]; memcpy(banks, s.audio_packet_init, 8);
        data(0x28);
        assert(s.audio_packet_clear_armed && !s.audio_packet_ready && !status());
        assert(s.audio_packet_control == 0x28 && !s.audio_packet_fault);
        assert(s.audio_packet_fifo_empty_known == (bool)empty);
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
        data(0);
        assert(!s.audio_packet_clear_armed && s.audio_packet_ready);
        assert(s.audio_packet_control == 0 && status() == (empty ? 3 : 1));
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
        assert(s.audio_packet_init_valid == 255 && !memcmp(banks, s.audio_packet_init, 8));
    }
    /* Capability defaults off; no widening of legacy control mask. */
    fixture(0x400, 0x100);
    assert(!s.audio_packet_clear_pulse && !s.audio_packet_clear_armed);
    s.audio_packet_sequence = true; full_reset(); control(0x28);
    assert(s.audio_packet_fault && !s.audio_packet_clear_armed && !status());
    /* Reject every non-clean entry while preserving existing parser/raw mirrors. */
    for (unsigned kind = 0; kind < 8; kind++) {
        clear_fixture();
        switch (kind) {
        case 0: select_index(2); data(0x5e); break; /* Partial packet. */
        case 1: select_index(2); data(0x5e); data(0x82); data(0x1f); break;
        case 2: control(0x80); break;
        case 3: s.audio_packet_fault = true; break;
        case 4: s.audio_packet_sink.reject = MSM5XXX_AUDIO_PACKET_REJECT_REGISTER; break;
        case 5: control(1); break;
        case 6: s.audio_packet_sequence = false; break;
        case 7: s.audio_packet_ready = false; break;
        }
        MSM5xxxAudioPacketSink before = s.audio_packet_sink;
        uint8_t banks[8]; memcpy(banks, s.audio_packet_init, 8);
        unsigned valid = s.audio_packet_init_valid;
        control(0x28);
        assert(s.audio_packet_fault && !s.audio_packet_ready && !s.audio_packet_clear_armed);
        assert(!s.audio_packet_fifo_empty_known && !status());
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
        assert(s.audio_packet_init_valid == valid && !memcmp(banks, s.audio_packet_init, 8));
        control(0); assert(s.audio_packet_fault && !s.audio_packet_ready && !status());
    }
    for (unsigned kind = 0; kind < 4; kind++) {
        clear_fixture(); data(0x28);
        MSM5xxxAudioPacketSink before = s.audio_packet_sink;
        switch (kind) {
        case 0: select_index(2); break; /* Owned selector interleave. */
        case 1: data(1); break;
        case 2:
            arm.parent.pc = s.audio_packet_begin + 0x34;
            (void)msm5xxx_poc_lcd_aperture_read(&s, 0x80002, 1); break;
        case 3: data(0x28); break;
        }
        assert(s.audio_packet_fault && !s.audio_packet_clear_armed && !status());
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
        control(0); assert(!s.audio_packet_ready && !status()); /* Late release cannot heal. */
    }
    clear_fixture(); data(0x28); data(0x80);
    assert(!s.audio_packet_clear_armed && s.audio_packet_reset_armed && !status());
    assert(!s.audio_packet_sink.sequence_parameter_valid && !s.audio_packet_init_valid);
    data(0); assert(s.audio_packet_ready && !s.audio_packet_reset_armed && status() == 3);
    /* Foreign PC/width/address keeps the in-flight owned pulse unchanged. */
    for (unsigned kind = 0; kind < 3; kind++) {
        clear_fixture(); data(0x28);
        arm.parent.pc = kind ? s.audio_packet_begin : 0x1800;
        fallback(kind == 2 ? 0x02080004 : 0x02080000, kind == 1 ? 2 : 1);
        assert(s.audio_packet_clear_armed && !s.audio_packet_ready && !s.audio_packet_fault);
        assert(s.audio_packet_control == 0x28 && !status());
        data(0); assert(status() == 3 && !s.audio_packet_clear_armed);
    }
    clear_fixture(); data(0x28);
    MSM5xxxAudioPacketSink before = s.audio_packet_sink;
    rom[0x400] ^= 1; arm.parent.pc = s.audio_packet_begin;
    fallback(0x02080000, 1);
    assert(s.audio_packet_fault && !s.audio_packet_clear_armed && !s.audio_packet_ready);
    assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
    rom[0x400] ^= 1; control(0); assert(!status());
    puts("clear28 opt-in / clean pulse knowledge preservation / interleave sticky / fallback PASS");
}

int main(void) {
    s.lcd_aperture_backing = calloc(1, MSM5XXX_POC_LCD_APERTURE_SIZE);
    assert(s.lcd_aperture_backing);
    const unsigned entries[] = {0x400, 0x900}, delays[] = {0x100, 0x1500};
    for (unsigned k = 0; k < ARRAY_SIZE(entries); k++) {
        fixture(entries[k], delays[k]);
        assert(status() == 1); packet();
        assert(s.audio_packet_sink.register_writes == 3 && !s.audio_packet_sink.reject);
        assert(s.audio_packet_sink.channel[29].pointer == 0x1b00);
        assert(s.audio_packet_sink.channel[29].level == 1 && status() == 1);
        assert(!s.lcd_aperture_reads && !s.lcd_aperture_writes && !traces);
        assert(reads && unrefs);
        MSM5xxxAudioPacketSink before = s.audio_packet_sink;
        select_index(2); data(0x63); data(0x82); data(0xbf);
        assert(s.audio_packet_sink.smoothing_config_valid && s.audio_packet_sink.smoothing_config == 0x3f);
        assert(s.audio_packet_sink.register_writes == 4 && !s.audio_packet_fault && status() == 1);
        assert(!memcmp(before.channel, s.audio_packet_sink.channel, sizeof(before.channel)));
        assert(!memcmp(before.memory, s.audio_packet_sink.memory, sizeof(before.memory)));
    }
    /* Unsupported shared control and reserved smoothing bit must reject atomically. */
    const uint8_t shared[][3] = {{0x5e,0x82,0x1b}, {0x63,0x82,0xff}};
    for (unsigned i = 0; i < ARRAY_SIZE(shared); i++) {
        fixture(0x400, 0x100); packet();
        select_index(2); data(0x63); data(0x82); data(0x95);
        MSM5xxxAudioPacketSink before = s.audio_packet_sink;
        select_index(2);
        for (unsigned j = 0; j < 3; j++) { data(shared[i][j]); }
        assert(s.audio_packet_fault && !status());
        assert(s.audio_packet_sink.reject == MSM5XXX_AUDIO_PACKET_REJECT_REGISTER);
        assert(s.audio_packet_sink.rejected_address == (i ? 0x163 : 0x15e));
        assert(!memcmp(before.channel, s.audio_packet_sink.channel, sizeof(before.channel)));
        assert(!memcmp(before.memory, s.audio_packet_sink.memory, sizeof(before.memory)));
        assert(before.register_writes == s.audio_packet_sink.register_writes);
        assert(before.memory_writes == s.audio_packet_sink.memory_writes);
        assert(s.audio_packet_sink.smoothing_config_valid && s.audio_packet_sink.smoothing_config == 0x15);
        before = s.audio_packet_sink; data(0); data(0x84);
        assert(!memcmp(&before, &s.audio_packet_sink, sizeof(before)));
        full_reset(); assert(!s.audio_packet_fault && status() == 3);
    }
    puts("owned relocated four sites / packet consumer PASS");
    for (unsigned i = 0; i < 27; i++) {
        fixture(0x400, 0x100); arm.parent.pc = s.audio_packet_begin;
        hwaddr addr = 0x02080000; unsigned size = 1;
        switch (i) {
        case 0: arm.parent.pc += 2; break;
        case 1: size = 2; break;
        case 2: size = 4; break;
        case 3: current_cpu = &other_cpu; break;
        case 4: in_vcpu = false; break;
        case 5: arm.parent.running = false; break;
        case 6: arm.parent.neg.can_do_io = false; break;
        case 7: arm.env.thumb = false; break;
        case 8: addr = 0x02080001; break;
        case 9: addr = 0x02080004; break;
        case 10: addr = 0x02070000; break;
        case 11: hidden_begin = 0x400; hidden_end = 0x448; break;
        case 12: short_section = true; break;
        case 13: s.primary_nor_size = 0x447; break;
        case 14: put16(0x100, 0); break;
        case 15: put16(0x408, 0); break;
        case 16: encode_bl(0x418, 0x102); break;
        case 17: put16(0x404, 0); break;
        case 18: hidden_begin = 0x100; hidden_end = 0x102; break;
        case 19: read_error = true; break;
        case 20: put16(0x400, 0x2151); break; /* Wrong synthesized base. */
        case 21: put16(0x41c, 0); break; /* Destroy original read result return. */
        case 22: s.audio_packet_begin++; arm.parent.pc++; break;
        case 23: s.audio_packet_begin = 4; arm.parent.pc = 4; break;
        case 24: no_section = true; break;
        case 25: {
            const unsigned calls[] = {8,24,44,60};
            for (unsigned j = 0; j < ARRAY_SIZE(calls); j++) { encode_bl(0x400 + calls[j], 0x2000); }
            break;
        }
        case 26: current_cpu = NULL; break; /* Debugger/non-vCPU caller. */
        }
        s.audio_packet_mode = 3; s.audio_packet_init_valid = 255;
        s.audio_packet_fifo_empty_known = true;
        memcpy(s.audio_packet_init, "bankbank", 8);
        s.audio_packet_sink.smoothing_config = 0x15;
        s.audio_packet_sink.smoothing_config_valid = true;
        s.audio_packet_sink.channel[29] = (MSM5xxxAudioPacketChannel){
            .pitch_high=0x51, .pitch=0x28a3, .control=0x3f,
            .pitch_high_valid=true, .pitch_valid=true, .control_valid=true};
        fallback(addr, size);
    }
    puts("foreign access / mapped-ROM / BL / ABI LCD fallback PASS");
    fixture(0x400, 0x100); select_index(2); data(0x2e);
    MSM5xxxAudioPacket partial = s.audio_packet_sink.packet;
    select_index(0); select_index(2);
    assert(!memcmp(&partial, &s.audio_packet_sink.packet, sizeof(partial)));
    data(0x82); data(0x1b); data(0); data(0x84);
    assert(s.audio_packet_sink.register_writes == 3);
    for (unsigned reset = 0x10; reset <= 0x40; reset += 0x30) {
        select_index(2); data(0x2e); select_index(4); data(reset); data(0);
        assert(s.audio_packet_sink.packet.phase == 0);
        assert(s.audio_packet_sink.register_writes == 3 && s.audio_packet_sink.channel[29].pointer == 0x1b00);
    }
    full_reset(); assert(!s.audio_packet_sink.register_writes && status() == 3);
    packet(); select_index(2);
    /* Raw counted memory through real decoder+consumer; preserve on parser reset. */
    const uint8_t memory[] = {0,0,0x81,0x82,0xaa,0xbb};
    for (unsigned i = 0; i < sizeof(memory); i++) { data(memory[i]); }
    assert(s.audio_packet_sink.memory_writes == 2 && s.audio_packet_sink.memory[0] == 0xaa);
    select_index(4); data(0x10); data(0);
    assert(s.audio_packet_sink.memory[1] == 0xbb);
    select_index(3); data(0x90); assert(s.audio_packet_fault && !status());
    select_index(2); packet(); assert(s.audio_packet_sink.register_writes == 3 && !status());
    select_index(4); data(0x40); data(0); assert(!status()); /* Fault sticky. */
    full_reset(); assert(status() == 3 && !s.audio_packet_fault && !s.audio_packet_sink.memory_writes);
    select_index(0x43);
    arm.parent.pc = s.audio_packet_begin + 0x34;
    s.lcd_aperture_backing[0x80002] = 0x5a;
    unsigned rd = s.lcd_aperture_reads;
    assert(msm5xxx_poc_lcd_aperture_read(&s, 0x80002, 1) == 0x5a);
    assert(s.lcd_aperture_reads == rd + 1 && s.audio_packet_fault && !status());
    full_reset(); select_index(2); data(0x80); data(0x80);
    assert(s.audio_packet_sink.register_writes == 1);
    data(0xe0); data(0x80); /* Truly unmodeled register window 0x60. */
    assert(s.audio_packet_sink.reject == MSM5XXX_AUDIO_PACKET_REJECT_REGISTER && !status());
    MSM5xxxAudioPacketSink saved = s.audio_packet_sink;
    data(0xff); assert(!memcmp(&saved, &s.audio_packet_sink, sizeof(saved)));
    puts("selector persistence / full+parser reset / unknown and sticky rejection PASS");
    controller(); known_empty(); sequence_receiver(); clear_pulse();
    free(s.lcd_aperture_backing); return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                            '-I', str(core), str(path / 'check.c'),
                            str(core / 'msm5xxx-audio-request.c'), '-o', str(path / 'check')],
                           check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
