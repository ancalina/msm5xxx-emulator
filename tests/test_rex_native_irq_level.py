"""Compile the real native IRQ combiner; isolate only its QEMU dependencies."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class NativeIRQLevelTests(unittest.TestCase):
    def test_both_banks_masking_ack_and_other_controller_fallback(self):
        source = (Path(__file__).resolve().parents[1] /
                  'experiments/qemu-tcg/msm5xxx-poc.c').read_text()
        start = source.index('static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s)\n{')
        end = source.index('\nstatic ', start + 1)
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
typedef uint64_t hwaddr;
typedef struct {
    uint32_t rex_irq_enable_address, rex_irq_status_address;
    uint8_t rex_irq_backing[0x60], rex_irq_bank_count;
    uint16_t rex_irq_pending[3];
    bool rex_irq_c80, rex_irq_read_consume, rex_irq_route_active;
    bool rex_irq_level, irq_level;
    unsigned rex_irq_assertions;
    bool *cpu_irq;
} MSM5xxxPOCMachineState;
static uint16_t msm5xxx_poc_backing_read(uint8_t *b, hwaddr o, unsigned n) {
    assert(n == 2 && o + n <= 0x60);
    return b[o] | ((uint16_t)b[o+1] << 8);
}
static void qemu_set_irq(bool *irq, bool level) { *irq = level; }
''' + source[start:end] + r'''
int main(void) {
    bool cpu = false;
    MSM5xxxPOCMachineState s = {
        .rex_irq_status_address = 0x03000620,
        .rex_irq_enable_address = 0x03000628,
        .rex_irq_bank_count = 2, .cpu_irq = &cpu,
    };
    s.rex_irq_pending[1] = 2;
    msm5xxx_poc_rex_irq_update(&s);
    assert(!cpu); /* Masked pending must not assert. */
    s.rex_irq_backing[12] = 2;
    msm5xxx_poc_rex_irq_update(&s);
    assert(cpu && s.rex_irq_assertions == 1);
    msm5xxx_poc_rex_irq_update(&s);
    assert(s.rex_irq_assertions == 1); /* Level, not repeated edges. */
    s.rex_irq_pending[0] = 0x200; s.rex_irq_backing[9] = 2;
    s.rex_irq_pending[1] = 0; /* ACK bank1 preserves active bank0. */
    msm5xxx_poc_rex_irq_update(&s); assert(cpu);
    s.rex_irq_pending[0] = 0;
    msm5xxx_poc_rex_irq_update(&s); assert(!cpu);
    s.rex_irq_pending[1] = 2; s.rex_irq_backing[12] = 4;
    msm5xxx_poc_rex_irq_update(&s); assert(!cpu); /* No cross-bit enable. */
    s.rex_irq_backing[12] = 2; s.rex_irq_read_consume = true;
    msm5xxx_poc_rex_irq_update(&s); assert(!cpu);
    s.rex_irq_read_consume = false; s.rex_irq_c80 = true;
    msm5xxx_poc_rex_irq_update(&s); assert(!cpu);
    s.rex_irq_c80 = false; s.rex_irq_status_address = 0x03000c80;
    s.rex_irq_enable_address = 0x03000c88;
    msm5xxx_poc_rex_irq_update(&s); assert(!cpu);
    s.irq_level = true;
    msm5xxx_poc_rex_irq_update(&s); assert(cpu && !s.rex_irq_level);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'check.c'), '-o', str(path / 'check')], check=True)
            subprocess.run([str(path / 'check')], check=True)


if __name__ == '__main__':
    unittest.main()
