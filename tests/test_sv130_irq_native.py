"""Exercise the SV130 byte arm and live copied-handler gate."""
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_matrix_row734_native import native_function


class SV130NativeIRQTest(unittest.TestCase):
    def test_arm_and_live_overlay_guard(self):
        source = (Path(__file__).resolve().parents[1] / 'native/qemu/msm5xxx-poc.c').read_text()
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
#define QEMU_CLOCK_VIRTUAL 0
enum { MSM5XXX_POC_REX_GATE_VECTOR_WAIT, MSM5XXX_POC_REX_GATE_WRAPPER_WAIT,
       MSM5XXX_POC_REX_GATE_HANDLER_WAIT, MSM5XXX_POC_REX_GATE_CALLBACK_WAIT,
       MSM5XXX_POC_REX_GATE_ACCEPTED };
typedef struct { struct { bool thumb; uint32_t regs[16]; } env; } CPU;
typedef struct {
    CPU *cpu; uint8_t msm[0x1000];
    unsigned rex_irq_gate_attempts, rex_irq_gate_status;
    uint32_t rex_irq_vector_target, rex_irq_wrapper_address, rex_irq_handler_slot;
    uint32_t rex_irq_handler_address, rex_irq_callback_slot, rex_irq_callback_address;
    uint32_t rex_irq_wrapper_rom, rex_irq_wrapper_size, rex_irq_vector_rom;
    uint64_t rex_irq_next, rex_irq_interval;
    bool rex_irq_copied, rex_irq_sv130_overlay, rex_irq_route_active, rex_irq_armed;
} MSM5xxxPOCMachineState;
static uint8_t overlay[0x27c], rom[0x27c], msm[0x1000];
static uint32_t vector0, vector1, handler, callback, actual_pc=0xe414;
static uint16_t opcode=0x7008; static unsigned scheduled; static bool guest=true;
static uint32_t branch(uint32_t from,uint32_t to) {
    return 0xea000000 | (((to-from-8)>>2)&0xffffff);
}
static void cpu_physical_memory_read(uint64_t p,void *out,unsigned n) {
    if (p==0x03800068 && n==sizeof(overlay)) memcpy(out,overlay,n);
    else if (p==0x00de5d00 && n==sizeof(rom)) memcpy(out,rom,n);
    else if (p==0xe414 && n==2) memcpy(out,&opcode,2);
    else assert(0);
}
static uint32_t msm5xxx_poc_guest_u32(uint32_t p) {
    if(p==0x18) return vector0; if(p==0x01800000) return vector1;
    if(p==0x01a3c398) return handler; if(p==0x0183c548) return callback;
    assert(0);return 0;
}
static uint8_t *memory_region_get_ram_ptr(void *p) { (void)p;return msm; }
static uint64_t msm5xxx_poc_backing_read(uint8_t *p,unsigned off,unsigned n) {
    uint64_t v=0;memcpy(&v,p+off,n);return v;
}
static void msm5xxx_poc_backing_write(uint8_t *p,unsigned off,uint64_t v,unsigned n) {
    memcpy(p+off,&v,n);
}
static void memory_region_set_dirty(void *p,unsigned off,unsigned n) {(void)p;(void)off;(void)n;}
static bool msm5xxx_poc_boot_storage_guest(MSM5xxxPOCMachineState *s) {(void)s;return guest;}
static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState *s,uint32_t *p) {(void)s;*p=actual_pc;return true;}
static uint16_t lduw_le_p(const uint8_t *p) {return p[0]|(p[1]<<8);}
static uint64_t qemu_clock_get_ns(unsigned c) {(void)c;return 100;}
static void msm5xxx_poc_rex_irq_schedule(MSM5xxxPOCMachineState *s) {assert(s->rex_irq_armed);scheduled++;}
''' + '\n'.join(native_function(source, n) for n in (
            'msm5xxx_poc_arm_b_target', 'msm5xxx_poc_rex_static_gate',
            'msm5xxx_poc_sv130_arm_read', 'msm5xxx_poc_sv130_arm_write')) + r'''
int main(void) {
    CPU cpu={.env={.thumb=true,.regs={2,0x030007a0}}};
    MSM5xxxPOCMachineState s={.cpu=&cpu,.rex_irq_sv130_overlay=true,
        .rex_irq_vector_target=0x01800000,.rex_irq_wrapper_address=0x3460,
        .rex_irq_handler_slot=0x01a3c398,.rex_irq_handler_address=0x03800068,
        .rex_irq_callback_slot=0x0183c548,.rex_irq_callback_address=0xe3a4,
        .rex_irq_interval=5000000};
    vector0=branch(0x18,0x01800000);vector1=branch(0x01800000,0x3460);
    handler=0x03800069;callback=0xe3a5;
    assert(msm5xxx_poc_rex_static_gate(&s));
    for(unsigned i=0;i<sizeof(overlay);i++) {
        overlay[i]^=1;s.rex_irq_route_active=false;
        assert(!msm5xxx_poc_rex_static_gate(&s));overlay[i]^=1;
    }
    callback=0;assert(!msm5xxx_poc_rex_static_gate(&s));callback=0xe3a5;
    msm5xxx_poc_sv130_arm_write(&s,0,2,2);assert(!scheduled);
    guest=false;msm5xxx_poc_sv130_arm_write(&s,0,2,1);assert(!scheduled);guest=true;
    actual_pc+=2;msm5xxx_poc_sv130_arm_write(&s,0,2,1);assert(!scheduled);actual_pc-=2;
    opcode=0x8008;msm5xxx_poc_sv130_arm_write(&s,0,2,1);assert(!scheduled);opcode=0x7008;
    msm5xxx_poc_sv130_arm_write(&s,0,2,1);assert(scheduled==1 && s.rex_irq_next==5000100);
    assert(msm5xxx_poc_sv130_arm_read(&s,0,1)==2);
}
'''
        # Keep -Werror useful without depending on indentation in the C fixture.
        code = code.replace('return vector0; if', 'return vector0;\n    if').replace(
            'return handler; if', 'return handler;\n    if')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'check.c'), '-o', str(path / 'check')], check=True)
            subprocess.run([str(path / 'check')], check=True)

    def test_c80_tick_enable_status_and_ack(self):
        source = (Path(__file__).resolve().parents[1] / 'native/qemu/msm5xxx-poc.c').read_text()
        start = source.index('static const hwaddr msm5xxx_poc_rex_irq_status_offsets[]')
        end = source.index('static uint64_t msm5xxx_poc_rex_irq_read(', start)
        update_start = source.index('static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s)\n{')
        update_end = source.index('\nstatic ', update_start + 1)
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct {
    uint32_t rex_irq_status_address,rex_irq_enable_address,rex_irq_controller_size;
    uint8_t rex_irq_backing[0x60],rex_irq_bank_count;
    uint16_t rex_irq_pending[3],rex_irq_mask;
    bool rex_irq_c80,rex_irq_read_consume,rex_irq_route_active;
    bool rex_irq_level,irq_level,ma5_irq_configured,ma5_irq_qualified,ma5_irq_level;
    bool ma3_gpio_irq_configured,ma3_gpio_irq_qualified;
    bool sd810_fold_irq_enabled; bool *cpu_irq; unsigned rex_irq_assertions,rex_irq_acks;
} MSM5xxxPOCMachineState;
static bool msm5xxx_poc_rex_irq_shadow_active(MSM5xxxPOCMachineState *s) {(void)s;return true;}
static uint64_t msm5xxx_poc_backing_read(uint8_t *p,hwaddr off,unsigned n) {
    uint64_t v=0;memcpy(&v,p+off,n);return v;
}
static void msm5xxx_poc_backing_write(uint8_t *p,hwaddr off,uint64_t v,unsigned n) {memcpy(p+off,&v,n);}
static void qemu_set_irq(bool *p,bool v) {*p=v;}
static uint64_t msm5xxx_poc_ma5_irq_read(MSM5xxxPOCMachineState *s,hwaddr o,unsigned n) {(void)s;(void)o;(void)n;return 0;}
static void msm5xxx_poc_ma5_irq_write(MSM5xxxPOCMachineState *s,hwaddr o,uint64_t v,unsigned n) {(void)s;(void)o;(void)v;(void)n;}
static uint64_t msm5xxx_poc_ma3_gpio_irq_read(MSM5xxxPOCMachineState *s,hwaddr o,unsigned n) {(void)s;(void)o;(void)n;assert(false);return 0;}
static void msm5xxx_poc_ma3_gpio_irq_write(MSM5xxxPOCMachineState *s,hwaddr o,uint64_t v,unsigned n) {(void)s;(void)o;(void)v;(void)n;assert(false);}
static void msm5xxx_poc_ma2_irq_update(MSM5xxxPOCMachineState *s) {(void)s;}
static void msm5xxx_poc_rex_irq_schedule(MSM5xxxPOCMachineState *s) {(void)s;}
''' + source[update_start:update_end] + '\n' + source[start:end] + '\n' + '\n'.join(
            native_function(source, n) for n in ('msm5xxx_poc_rex_irq_read',
                                                   'msm5xxx_poc_fold_gpio_ack',
                                                   'msm5xxx_poc_rex_irq_write')) + r'''
int main(void) {
    bool cpu=false;
    MSM5xxxPOCMachineState s={.rex_irq_status_address=0x03000c80,
        .rex_irq_enable_address=0x03000c94,.rex_irq_controller_size=0x4a,
        .rex_irq_bank_count=3,.rex_irq_mask=0x200,.rex_irq_c80=true,
        .rex_irq_route_active=true,.cpu_irq=&cpu};
    s.rex_irq_pending[0]=0x200;
    msm5xxx_poc_rex_irq_update(&s);assert(!cpu);
    msm5xxx_poc_rex_irq_write(&s,0x14,0x200,2);assert(cpu);
    assert(msm5xxx_poc_rex_irq_read(&s,0,2)==0x200);
    msm5xxx_poc_rex_irq_write(&s,0,0x100,2);assert(cpu);
    msm5xxx_poc_rex_irq_write(&s,0,0x200,2);assert(!cpu && !s.rex_irq_pending[0]);
    assert(s.rex_irq_acks==1 && msm5xxx_poc_rex_irq_read(&s,0,2)==0);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'check.c'), '-o', str(path / 'check')], check=True)
            subprocess.run([str(path / 'check')], check=True)
