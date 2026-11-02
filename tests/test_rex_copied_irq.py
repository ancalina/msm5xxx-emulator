"""Exercise actual copied IRQ gate and passive halfword arm callbacks."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class CopiedIRQTests(unittest.TestCase):
    def test_property_parser_bounds_and_exclusive_owner(self):
        source = (Path(__file__).resolve().parents[1] /
                  'native/qemu/msm5xxx-poc.c').read_text()
        at = source.index('static void msm5xxx_poc_set_rex_copied_c80(')
        end = source.index('\nstatic ', at + 1)
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef int Error;
typedef struct {
    bool rex_irq_enabled, rex_irq_c80, rex_irq_copied;
    uint32_t rex_irq_status_address, rex_irq_enable_address, rex_irq_arm_address;
    uint32_t rex_irq_mask, rex_irq_interval, rex_irq_vector_target;
    uint32_t rex_irq_wrapper_address, rex_irq_handler_slot, rex_irq_handler_address;
    uint32_t rex_irq_handler_size, rex_irq_callback_slot, rex_irq_callback_address;
    uint32_t rex_irq_wrapper_rom, rex_irq_wrapper_size, rex_irq_vector_rom;
    uint32_t rex_irq_halfword_arm_pc, rex_irq_controller_size;
    uint32_t rex_irq_bank_count, rex_irq_gate_status;
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(o) (o)
#define MSM5XXX_POC_REX_C80_CONTROLLER_SIZE 0x1a
#define MSM5XXX_POC_REX_GATE_VECTOR_WAIT 1
static void error_setg(Error **err, const char *message) {
    static Error value; assert(message); *err=&value;
}
''' + source[at:end] + r'''
int main(void) {
    const char *valid = "4c4b40:1000000:380ddc8:10cca24:1d1dc8:188:1007824:106f2c:35e040:104:345b80:106fc0";
    const char *bad[] = {
        "", "0:1000000:380ddc8:10cca24:1d1dc8:188:1007824:106f2c:35e040:104:345b80:106fc0",
        "1:1000001:380ddc8:10cca24:1d1dc8:188:1007824:106f2c:35e040:104:345b80:106fc0",
        "1:1000000:37fffc0:10cca24:1d1dc8:188:1007824:106f2c:35e040:104:345b80:106fc0",
        "1:1000000:380ffc0:10cca24:1d1dc8:188:1007824:106f2c:35e040:104:345b80:106fc0",
        "1:1000000:380ddc8:10cca24:1d1dc8:188:1007824:106f2c:35e040:204:345b80:106fc0",
        "1:1000000:380ddc8:10cca24:1d1dc8:188:1007824:106f2c:35e040:102:345b80:106fc0",
        "1:1000000:380ddc8:10cca24:1d1dc8:0:1007824:106f2c:35e040:104:345b80:106fc0",
        "1:1000000:380ddc8:10cca24:1d1dc8:188:1007824:106f2c:35e040:104:345b80:106fc1",
        "1:1000000:380ddc8:10cca24:1d1dc8:188:1007824:106f2c:35e040:104:345b80:106fc0:0",
        "1:1000000:380ddc8:10cca24:1d1dc8:188:1007824:106f2c:35e040:104:345b80:106fc0junk"
    };
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        MSM5xxxPOCMachineState s={0}; Error *err=0;
        msm5xxx_poc_set_rex_copied_c80(&s,bad[i],&err);
        assert(err && !s.rex_irq_enabled && !s.rex_irq_copied);
    }
    MSM5xxxPOCMachineState s={0}; Error *err=0;
    msm5xxx_poc_set_rex_copied_c80(&s,valid,&err);
    assert(!err && s.rex_irq_enabled && s.rex_irq_copied && s.rex_irq_c80);
    assert(s.rex_irq_arm_address==0x30007a0 && s.rex_irq_mask==0x200);
    assert(s.rex_irq_wrapper_size==0x104 && s.rex_irq_handler_size==0x188);
    assert(s.rex_irq_interval==5000000 && s.rex_irq_bank_count==2);
    msm5xxx_poc_set_rex_copied_c80(&s,valid,&err); assert(err);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory); (path/'check.c').write_text(code)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                            str(path/'check.c'),'-o',str(path/'check')],check=True)
            subprocess.run([str(path/'check')],check=True)

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
    bool rex_irq_copied, rex_irq_armed, rex_irq_sv130_overlay;
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
        code = code.replace('    bool rex_irq_copied, rex_irq_armed, rex_irq_sv130_overlay;',
                            '    bool rex_irq_copied, rex_irq_armed, rex_irq_sv130_overlay, rex_irq_route_active;')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/'check.c').write_text(code)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                            str(path/'check.c'),'-o',str(path/'check')],check=True)
            subprocess.run([str(path/'check')],check=True)
