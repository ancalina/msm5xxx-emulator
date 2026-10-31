"""Exercise actual copied IRQ gate and passive halfword arm callbacks."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class CopiedIRQTests(unittest.TestCase):
    def test_live_copies_slots_arm_width_pc_and_backing(self):
        source = (Path(__file__).resolve().parents[1] /
                  'native/qemu/msm5xxx-poc.c').read_text()
        def function(name):
            at = source.index(name)
            start = source.rfind('\nstatic ', 0, at) + 1
            end = source.index('\nstatic ', at)
            return source[start:end]
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint64_t hwaddr;
#define QEMU_CLOCK_VIRTUAL 0
enum { MSM5XXX_POC_REX_GATE_VECTOR_WAIT, MSM5XXX_POC_REX_GATE_WRAPPER_WAIT,
       MSM5XXX_POC_REX_GATE_HANDLER_WAIT, MSM5XXX_POC_REX_GATE_CALLBACK_WAIT,
       MSM5XXX_POC_REX_GATE_ACCEPTED };
typedef struct {
    struct { bool thumb; uint32_t regs[16]; } env;
} CPU;
typedef struct {
    CPU *cpu;
    uint8_t msm[0x1000];
    unsigned rex_irq_gate_attempts, rex_irq_gate_status;
    uint32_t rex_irq_vector_target, rex_irq_wrapper_address;
    uint32_t rex_irq_wrapper_rom, rex_irq_wrapper_size, rex_irq_vector_rom;
    uint32_t rex_irq_handler_slot, rex_irq_handler_address;
    uint32_t rex_irq_callback_slot, rex_irq_callback_address;
    uint32_t rex_irq_halfword_arm_pc, rex_irq_interval;
    uint64_t rex_irq_next;
    bool rex_irq_copied, rex_irq_armed;
} MSM5xxxPOCMachineState;
static uint8_t memory[0x4000];
static unsigned scheduled, dirtied;
static bool guest = true, unwind = true;
static uint32_t actual_pc = 0x800;
static void cpu_physical_memory_read(uint64_t p, void *out, unsigned n) {
    assert(p + n <= sizeof(memory)); memcpy(out, memory+p, n);
}
static uint32_t msm5xxx_poc_guest_u32(uint32_t p) {
    uint32_t value; cpu_physical_memory_read(p, &value, 4); return value;
}
static uint8_t *memory_region_get_ram_ptr(void *region) { return region; }
static uint64_t msm5xxx_poc_backing_read(uint8_t *b, unsigned p, unsigned n) {
    uint64_t v=0; assert(p+n <= 0x1000); memcpy(&v,b+p,n); return v;
}
static void msm5xxx_poc_backing_write(uint8_t *b, unsigned p, uint64_t v, unsigned n) {
    assert(p+n <= 0x1000); memcpy(b+p,&v,n);
}
static void memory_region_set_dirty(void *b, unsigned p, unsigned n) {
    (void)b; assert(p >= 0x7a0 && p+n <= 0x7a4); dirtied++;
}
static bool msm5xxx_poc_boot_storage_guest(MSM5xxxPOCMachineState *s) {
    (void)s; return guest;
}
static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState *s, uint32_t *p) {
    (void)s; *p=actual_pc; return unwind;
}
static uint16_t lduw_le_p(const uint8_t *p) { return p[0] | (p[1]<<8); }
static uint64_t qemu_clock_get_ns(unsigned c) { (void)c; return 100; }
static void msm5xxx_poc_rex_irq_schedule(MSM5xxxPOCMachineState *s) {
    assert(s->rex_irq_armed); scheduled++;
}
static void word(unsigned at, uint32_t v) { memcpy(memory+at,&v,4); }
static uint32_t branch(unsigned from, unsigned to) {
    return 0xea000000 | (((to-from-8)>>2)&0xffffff);
}
''' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_arm_b_target(', 'msm5xxx_poc_rex_static_gate(',
            'msm5xxx_poc_rex_copied_arm_read(',
            'msm5xxx_poc_rex_copied_arm_write(')) + r'''
int main(void) {
    CPU cpu = { .env = { .thumb = true, .regs = {2, 0x030007a0} } };
    MSM5xxxPOCMachineState s = { .cpu=&cpu, .rex_irq_copied=true,
        .rex_irq_vector_target=0x100, .rex_irq_vector_rom=0x1000,
        .rex_irq_wrapper_address=0x200, .rex_irq_wrapper_rom=0x1100,
        .rex_irq_wrapper_size=16, .rex_irq_handler_slot=0x300,
        .rex_irq_handler_address=0x500, .rex_irq_callback_slot=0x304,
        .rex_irq_callback_address=0x600, .rex_irq_halfword_arm_pc=0x800,
        .rex_irq_interval=5000000 };
    word(0x18, branch(0x18,0x100));
    word(0x100, branch(0x100,0x108)); word(0x108,0xe51ff004);
    word(0x10c,0x200); memcpy(memory+0x1000,memory+0x100,16);
    for (unsigned i=0;i<16;i++) memory[0x200+i]=memory[0x1100+i]=(uint8_t)i;
    word(0x300,0x501); word(0x304,0x601);
    assert(msm5xxx_poc_rex_static_gate(&s));
    for (unsigned i=0;i<16;i++) {
        memory[0x200+i]^=1; s.rex_irq_route_active=false;
        assert(!msm5xxx_poc_rex_static_gate(&s)); memory[0x200+i]^=1;
    }
    for (unsigned i=0;i<16;i++) {
        memory[0x100+i]^=1;
        assert(!msm5xxx_poc_rex_static_gate(&s)); memory[0x100+i]^=1;
    }
    word(0x300,0); assert(!msm5xxx_poc_rex_static_gate(&s)); word(0x300,0x501);
    word(0x304,0); assert(!msm5xxx_poc_rex_static_gate(&s)); word(0x304,0x601);
    word(0x18,0); assert(!msm5xxx_poc_rex_static_gate(&s)); word(0x18,branch(0x18,0x100));
    s.rex_irq_copied=false;
    assert(!msm5xxx_poc_rex_static_gate(&s)); /* Old class rejects copied veneer. */
    word(0x100,branch(0x100,0x200));
    assert(msm5xxx_poc_rex_static_gate(&s)); /* Old direct branch still works. */
    s.rex_irq_copied=true;
    word(0x800,0x8008);
    msm5xxx_poc_rex_copied_arm_write(&s,0,2,1); assert(!scheduled && s.msm[0x7a0]==2);
    msm5xxx_poc_rex_copied_arm_write(&s,0,2,4); assert(!scheduled);
    msm5xxx_poc_rex_copied_arm_write(&s,2,2,2); assert(!scheduled && s.msm[0x7a2]==2);
    actual_pc+=2; msm5xxx_poc_rex_copied_arm_write(&s,0,2,2); assert(!scheduled); actual_pc-=2;
    unwind=false; msm5xxx_poc_rex_copied_arm_write(&s,0,2,2); assert(!scheduled); unwind=true;
    guest=false; msm5xxx_poc_rex_copied_arm_write(&s,0,2,2); assert(!scheduled); guest=true;
    cpu.env.thumb=false; msm5xxx_poc_rex_copied_arm_write(&s,0,2,2); assert(!scheduled); cpu.env.thumb=true;
    cpu.env.regs[1]++; msm5xxx_poc_rex_copied_arm_write(&s,0,2,2); assert(!scheduled); cpu.env.regs[1]--;
    cpu.env.regs[0]=3; msm5xxx_poc_rex_copied_arm_write(&s,0,2,2); assert(!scheduled); cpu.env.regs[0]=2;
    word(0x800,0); msm5xxx_poc_rex_copied_arm_write(&s,0,2,2); assert(!scheduled); word(0x800,0x8008);
    msm5xxx_poc_rex_copied_arm_write(&s,0,3,2); assert(!scheduled);
    msm5xxx_poc_rex_copied_arm_write(&s,0,2,2);
    assert(scheduled==1 && s.rex_irq_next==5000100);
    msm5xxx_poc_rex_copied_arm_write(&s,0,2,2); assert(scheduled==1);
    assert(msm5xxx_poc_rex_copied_arm_read(&s,0,4)==0x00020002 && dirtied==13);
    return 0;
}
'''
        code = code.replace('    bool rex_irq_copied, rex_irq_armed;',
                            '    bool rex_irq_copied, rex_irq_armed, rex_irq_route_active;')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/'check.c').write_text(code)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                            str(path/'check.c'),'-o',str(path/'check')],check=True)
            subprocess.run([str(path/'check')],check=True)
