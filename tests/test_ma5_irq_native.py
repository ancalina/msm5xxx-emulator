"""Actual class-local GPIO/SoC IRQ C with RAM and IRQ-line dependencies stubbed."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class MA5NativeIRQTests(unittest.TestCase):
    def test_live_gates_ack_layers_and_all_gpio_banks(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        source = (native / "msm5xxx-poc.c").read_text()

        def function(name):
            match = re.search(r'^static [^;\n]*\b' + name + r'\([^;]*?\)\n\{',
                              source, re.MULTILINE)
            self.assertIsNotNone(match, name)
            opening = source.index('{', match.start())
            depth, end = 1, opening + 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[match.start():end]

        # The two-SoC-bank aperture must also cover the third GPIO polarity word.
        init = function("msm5xxx_poc_init")
        self.assertIn("s->rex_irq_controller_size = MAX(s->rex_irq_controller_size, 0x3a);", init)
        self.assertLess(init.index("s->rex_irq_controller_size = MAX("),
                        init.index('"msm5xxx-poc.rex-irq"'))
        self.assertEqual(0x03000cb8 + 2 - 0x03000c80, 0x3a)

        begin = source.index("enum {\n    MA5R_TABLE")
        end = source.index("static const MemoryRegionOps msm5xxx_poc_ma5_trigger_ops", begin)
        helpers = source[begin:end]
        harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "msm5xxx-ma5-audio.h"
#define G_N_ELEMENTS(x) (sizeof(x) / sizeof((x)[0]))
#define MACHINE(s) (s)
#define LOG_GUEST_ERROR 1
typedef uint64_t hwaddr;
typedef struct { uint8_t *data; } MemoryRegion;
typedef struct {
    uint32_t ram_base;
    uint64_t ram_size, ma5_byte_ns, ma5_clki_hz;
    uint32_t ma5_irq_route[18];
    bool ma5_irq_configured, ma5_irq_qualified, ma5_irq_level;
    uint16_t ma5_gpio_pending[3], ma5_parent_pending;
    uint32_t ma5_irq_gate_status, ma5_irq_assertions, ma5_gpio_acks, ma5_parent_acks;
    bool rex_irq_enabled, rex_irq_c80, rex_irq_read_consume, rex_irq_route_active;
    uint32_t rex_irq_status_address, rex_irq_enable_address, rex_irq_handler_address;
    uint32_t rex_irq_handler_slot, rex_irq_bank_count, rex_irq_mask, rex_irq_acks;
    uint16_t rex_irq_pending[3];
    uint8_t rex_irq_backing[256];
    bool rex_irq_level, irq_level;
    unsigned rex_irq_assertions;
    void *cpu_irq;
    MemoryRegion msm;
    MSM5xxxMA5Device ma5_device;
} MSM5xxxPOCMachineState;
static uint8_t guest[0x800000], msm[0x10000];
static bool cpu_level;
static unsigned schedules;
static uint8_t *memory_region_get_ram_ptr(MemoryRegion *r) { return r->data; }
static void cpu_physical_memory_read(hwaddr a, void *b, unsigned size) {
    assert(a >= 0x1800000 && a + size <= 0x2000000);
    memcpy(b, guest + a - 0x1800000, size);
}
static uint32_t msm5xxx_poc_guest_u32(hwaddr a) {
    uint8_t b[4]; cpu_physical_memory_read(a, b, 4);
    return b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static void put(unsigned a, unsigned v, unsigned n) {
    assert(a >= 0x1800000 && a + n <= 0x2000000);
    for (unsigned i = 0; i < n; i++) guest[a - 0x1800000 + i] = v >> (8*i);
}
static void qemu_log_mask(int mask, const char *format, ...) { (void)mask; (void)format; }
static void qemu_set_irq(void *line, int level) { (void)line; cpu_level = level; }
static void msm5xxx_poc_rex_irq_schedule(MSM5xxxPOCMachineState *s) { (void)s; schedules++; }
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s);
''' + function("msm5xxx_poc_backing_read") + '\n' + function("msm5xxx_poc_backing_write") + '\n' + helpers + '\n' + function("msm5xxx_poc_rex_irq_update") + r'''
static void setup(MSM5xxxPOCMachineState *s, unsigned pin) {
    memset(s, 0, sizeof(*s)); memset(guest, 0, sizeof(guest)); memset(msm, 0, sizeof(msm));
    cpu_level = false;
    s->ram_base = 0x1800000; s->ram_size = sizeof(guest); s->msm.data = msm;
    s->ma5_byte_ns = 1000; s->ma5_clki_hz = 19660800;
    s->ma5_irq_configured = s->rex_irq_enabled = s->rex_irq_c80 = true;
    s->rex_irq_route_active = true; s->rex_irq_status_address = 0x3000c80;
    s->rex_irq_enable_address = 0x3000c94; s->rex_irq_handler_address = 0x2000;
    s->rex_irq_handler_slot = 0x1804004; s->rex_irq_bank_count = 3; s->rex_irq_mask = 0x200;
    const uint32_t r[] = {0x1801000,0x1802000,pin,0x1803000,0x3000c84,0x3000c98,
        0x2000,0x1804000,0x1804002,0x1001,0x2001,0x1804004,0x3001,0,
        0x1804008,0,0,0x180400c};
    memcpy(s->ma5_irq_route, r, sizeof(r));
    for (unsigned i = 0; i < 5; i++) put(r[MA5R_DESCRIPTOR] + i*4, r[MA5R_STATUS+i], 4);
    put(r[MA5R_DESCRIPTOR]+20,r[MA5R_GPIO_DISPATCH],4);
    put(r[MA5R_EXCEPTION_SLOT],r[MA5R_SOC_DISPATCH],4);
    put(r[MA5R_CALLBACKS]+pin*4,r[MA5R_DIRECT],4);
    put(r[MA5R_INSTALLED],1,1); put(r[MA5R_CONTEXT],0x1805000,4);
    put(r[MA5R_SHADOW],0x2000,2); put(r[MA5R_PRIORITY],0x2000,2);
    for (unsigned b = 0; b < 3; b++) {
        const uint32_t row[] = {0x3000c88+b*4,0x3000ca4+b*4,0x3000cb0+b*4,0x300074c+b*4};
        for (unsigned i = 0; i < 4; i++) put(r[MA5R_TABLE]+b*24+i*4,row[i],4);
    }
    unsigned bank=pin>>4, mask=1u<<(pin&15);
    put(r[MA5R_TABLE]+bank*24+16,mask,2);
    msm5xxx_poc_backing_write(s->rex_irq_backing,0x24+bank*4,mask,2);
    msm5xxx_poc_backing_write(s->rex_irq_backing,0x18,0x2000,2);
    assert(msm5xxx_ma5_device_init(&s->ma5_device,1000));
    s->ma5_device.pending=0x80; s->ma5_device.b[17]=0x80;
    s->ma5_device.backing.irq_enabled=true;
}
int main(void) {
    MSM5xxxPOCMachineState s;
    const unsigned pins[] = {5,22,35};
    for (unsigned k=0;k<3;k++) {
        unsigned pin=pins[k],bank=pin>>4,mask=1u<<(pin&15),off=8+bank*4;
        setup(&s,pin); msm5xxx_poc_ma5_irq_update(&s);
        assert(cpu_level && s.ma5_gpio_pending[bank]==mask && s.ma5_parent_pending==0x2000);
        assert(msm5xxx_poc_ma5_irq_read(&s,off,2)==mask);
        assert(msm5xxx_poc_ma5_irq_read(&s,4,2)==0x2000);
        msm5xxx_poc_ma5_irq_write(&s,off,mask,2); /* Chip still asserts: relatch. */
        msm5xxx_poc_ma5_irq_write(&s,5,0x20,1);
        assert(cpu_level && s.ma5_parent_pending==0x2000 && s.ma5_gpio_pending[bank]==mask);
        s.ma5_device.pending=0; msm5xxx_poc_ma5_irq_update(&s);
        assert(cpu_level); /* Chip withdrawal does not ACK other layers. */
        msm5xxx_poc_ma5_irq_write(&s,off,mask,2);
        assert(cpu_level && !s.ma5_gpio_pending[bank] && s.ma5_parent_pending==0x2000);
        msm5xxx_poc_ma5_irq_write(&s,4,0x2000,2);
        assert(!cpu_level && !s.ma5_parent_pending);
        assert(s.ma5_gpio_acks==2 && s.ma5_parent_acks==2 && !s.ma5_device.delayed_count);
    }
    /* Direct registration can have no separate installed byte. */
    setup(&s,22); s.ma5_irq_route[MA5R_INSTALLED]=0;
    msm5xxx_poc_ma5_irq_update(&s); assert(cpu_level);
    put(s.ma5_irq_route[MA5R_CALLBACKS]+22*4,0x3003,4);
    msm5xxx_poc_ma5_irq_update(&s); assert(!cpu_level);
    for (unsigned bad=0;bad<6;bad++) {
        setup(&s,22); uint32_t *r=s.ma5_irq_route; r[MA5R_INSTALLED]=0;
        if (bad==0) put(r[MA5R_DESCRIPTOR]+20,0x1003,4);
        if (bad==1) put(r[MA5R_EXCEPTION_SLOT],0x2003,4);
        if (bad==2) put(r[MA5R_CONTEXT],0x2000000,4);
        if (bad==3) r[MA5R_DEFERRED]=0x4001;
        if (bad==4) r[MA5R_SELECT]=0x1804011;
        if (bad==5) r[MA5R_OVERRIDE]=0x1804014;
        msm5xxx_poc_ma5_irq_update(&s);
        assert(!cpu_level && s.ma5_irq_gate_status);
    }
    setup(&s,5); s.ma5_irq_configured=false; msm5xxx_poc_ma5_irq_update(&s);
    assert(!cpu_level && !s.ma5_gpio_pending[0]);
    for (unsigned bad=0;bad<6;bad++) {
        setup(&s,5); uint32_t *r=s.ma5_irq_route;
        if (bad==0) put(r[MA5R_CALLBACKS]+20,0x3003,4);
        if (bad==1) put(r[MA5R_DESCRIPTOR],0x3000c88,4);
        if (bad==2) put(r[MA5R_EXCEPTION_SLOT],0x2003,4);
        if (bad==3) put(r[MA5R_INSTALLED],0,1);
        if (bad==4) put(r[MA5R_CONTEXT],0x2000000,4);
        if (bad==5) s.ma5_irq_route[MA5R_TABLE]|=2;
        msm5xxx_poc_ma5_irq_update(&s);
        assert(!cpu_level && !s.ma5_gpio_pending[0] && s.ma5_irq_gate_status);
    }
    setup(&s,5); msm5xxx_poc_ma5_trigger_write(&s,0,0x20,2);
    assert(!cpu_level && msm5xxx_poc_ma5_trigger_read(&s,0,2)==0x20);
    msm5xxx_poc_ma5_trigger_write(&s,0,0,2); assert(cpu_level);
    setup(&s,5); put(0x1801010,0,2);
    msm5xxx_poc_ma5_irq_write(&s,0x24,0,2); assert(!cpu_level);
    put(0x1801010,0x20,2); msm5xxx_poc_ma5_irq_write(&s,0x24,0x20,2); assert(cpu_level);
    setup(&s,5); s.ma5_irq_route[MA5R_DEFERRED]=0x4001;
    s.ma5_irq_route[MA5R_SELECT]=0x1804011; s.ma5_irq_route[MA5R_OVERRIDE]=0x1804014;
    put(0x1804011,1,1); put(0x1802014,0x4001,4);
    put(0x1804015,1,1); /* Adjacent bytes are not the byte-sized override. */
    msm5xxx_poc_ma5_irq_update(&s); assert(cpu_level);
    put(0x1802014,0x3001,4); msm5xxx_poc_ma5_irq_update(&s); assert(!cpu_level);
    put(0x1804014,1,4); msm5xxx_poc_ma5_irq_update(&s); assert(cpu_level);
    setup(&s,5); put(0x1802014,0x3003,4);
    s.rex_irq_pending[0]=0x200; msm5xxx_poc_backing_write(s.rex_irq_backing,0x14,0x200,2);
    msm5xxx_poc_ma5_irq_update(&s); assert(cpu_level); /* Existing timer survives invalid audio gate. */
    msm5xxx_poc_ma5_irq_write(&s,0,0x200,2);
    assert(!cpu_level && s.rex_irq_acks==1 && schedules);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            c = Path(temporary) / "ma5-irq.c"
            binary = Path(temporary) / "ma5-irq"
            c.write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                            "-fsanitize=undefined", "-fno-sanitize-recover=all",
                            "-I" + str(native), str(c), str(native / "msm5xxx-ma5-audio.c"),
                            "-o", str(binary)], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)
