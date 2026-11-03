"""Exercise the native C80 status and W1C path independently of the CPU PC."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class LegacyC80NativeTests(unittest.TestCase):
    def test_pending_enable_and_acknowledge(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        source = (native / 'msm5xxx-poc.c').read_text()
        def extract(name):
            at = source.index('static ', source.index(name) - 80)
            while name not in source[at:source.index('{', at)]:
                at = source.index('static ', at + 7)
            start = source.index('{', at)
            depth = 1
            end = start + 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[at:end]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct CPUState { bool running; struct {bool can_do_io;} neg; } CPUState;
typedef struct {uint32_t (*get_pc)(CPUState *);} CPUClass;
typedef struct { CPUState *cpu; bool rex_irq_c80, legacy_cdma, rex_irq_route_active;
 bool ma5_irq_configured, rex_irq_read_consume; unsigned rex_irq_controller_size;
 unsigned rex_irq_bank_count; uint16_t rex_irq_pending[3], rex_irq_mask;
 uint8_t rex_irq_backing[128]; unsigned rex_irq_acks; uint32_t rex_irq_handler_address, rex_irq_handler_size;
} MSM5xxxPOCMachineState;
static bool msm5xxx_poc_legacy_gate(MSM5xxxPOCMachineState *s) {(void)s;return true;}
static CPUState *current_cpu;
#define CPU(x) (x)
static bool qemu_in_vcpu_thread(void) { return false; }
static CPUClass *CPU_GET_CLASS(CPUState *c) { (void)c; return 0; }
static uint64_t msm5xxx_poc_backing_read(uint8_t *b, hwaddr o, unsigned n) {
 uint64_t v=0; for (unsigned i=0;i<n;i++) v|=(uint64_t)b[o+i]<<(8*i); return v;
}
static void msm5xxx_poc_backing_write(uint8_t *b, hwaddr o, uint64_t v, unsigned n) {
 for (unsigned i=0;i<n;i++) b[o+i]=v>>(8*i);
}
static uint64_t msm5xxx_poc_ma5_irq_read(MSM5xxxPOCMachineState *s, hwaddr o, unsigned n) { (void)s;(void)o;(void)n;return 0; }
static void msm5xxx_poc_ma5_irq_write(MSM5xxxPOCMachineState *s, hwaddr o, uint64_t v, unsigned n) { (void)s;(void)o;(void)v;(void)n; }
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s) {(void)s;}
static void msm5xxx_poc_rex_irq_schedule(MSM5xxxPOCMachineState *s) {(void)s;}
static void msm5xxx_poc_ma2_irq_update(MSM5xxxPOCMachineState *s) {(void)s;}
static const hwaddr msm5xxx_poc_rex_irq_status_offsets[] = {0,4,0x30};
static const hwaddr msm5xxx_poc_rex_irq_clear_offsets[] = {0,4,0x4c};
'''
        harness += '\n'.join(extract(x) for x in (
            'msm5xxx_poc_rex_irq_shadow_active(', 'msm5xxx_poc_rex_irq_read(',
            'msm5xxx_poc_rex_irq_write('))
        harness += r'''
int main(void) {
 MSM5xxxPOCMachineState s = {0};
 s.rex_irq_c80=true; s.legacy_cdma=true; s.rex_irq_controller_size=0x1a;
 s.rex_irq_bank_count=2; s.rex_irq_mask=0x200;
 s.rex_irq_pending[0]=0x390;
 msm5xxx_poc_rex_irq_write(&s,0x14,0x190,2);
 assert(msm5xxx_poc_rex_irq_read(&s,0x14,2)==0x190);
 assert(msm5xxx_poc_rex_irq_read(&s,0,2)==0x390);
 msm5xxx_poc_rex_irq_write(&s,0,0x80,2);
 assert(msm5xxx_poc_rex_irq_read(&s,0,2)==0x310);
 msm5xxx_poc_rex_irq_write(&s,1,2,1);
 assert(msm5xxx_poc_rex_irq_read(&s,0,2)==0x110);
 assert(s.rex_irq_acks==1);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'test.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)
