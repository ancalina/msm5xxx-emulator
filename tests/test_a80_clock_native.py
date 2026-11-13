"""Native timer starts only after the complete channel configuration."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from native_sanitizers import native_sanitizers
from test_protected_nor_native import function


class A80ClockNativeTests(unittest.TestCase):
    def test_mode_channel_reload_and_reset_transaction(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        source = (native / 'msm5xxx-poc.c').read_text()
        code = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "msm5xxx-timer-irq.h"
typedef uint64_t hwaddr;
typedef struct {
    uint8_t a80_arm, a80_clock_regs[0x18];
    MSM5xxxTimerIRQ a80_irq;
    int64_t a80_clock_ns;
} MSM5xxxPOCMachineState;
#define QEMU_CLOCK_VIRTUAL 0
static int64_t qemu_clock_get_ns(int clock) { (void)clock; return 100; }
static void msm5xxx_poc_a80_sync(MSM5xxxPOCMachineState *s) { (void)s; }
static void msm5xxx_poc_a80_update(MSM5xxxPOCMachineState *s) { (void)s; }
''' + '\n'.join(function(source, name) for name in (
            'msm5xxx_poc_a80_arm_read', 'msm5xxx_poc_a80_arm_write',
            'msm5xxx_poc_a80_reset')) + r'''
int main(void) {
    MSM5xxxPOCMachineState s = {0}, before;
    msm5xxx_timer_irq_init(&s.a80_irq, 0x200, 5000000);
    msm5xxx_poc_a80_arm_write(&s, 0, 2, 1);
    assert(!s.a80_irq.armed); /* Mode alone is not channel setup. */
    msm5xxx_poc_a80_arm_write(&s, 0xc, 3, 1);
    msm5xxx_poc_a80_arm_write(&s, 0x10, 0x80, 1);
    assert(!s.a80_irq.armed);
    msm5xxx_poc_a80_arm_write(&s, 0x14, 0x80, 1);
    assert(s.a80_irq.armed);
    assert(msm5xxx_poc_a80_arm_read(&s, 0, 1) == 2);
    assert(msm5xxx_poc_a80_arm_read(&s, 0xc, 4) == 3);
    msm5xxx_timer_irq_advance(&s.a80_irq, 4000000);
    msm5xxx_poc_a80_arm_write(&s, 0, 2, 1);
    assert(s.a80_irq.remaining_ns == 1000000);
    msm5xxx_poc_a80_arm_write(&s, 0xc, 0x23, 1);
    assert(!s.a80_irq.armed);
    msm5xxx_poc_a80_arm_write(&s, 0xc, 3, 1);
    assert(s.a80_irq.armed && s.a80_irq.remaining_ns == 5000000);
    before = s;
    msm5xxx_poc_a80_arm_write(&s, 0x17, 0, 2);
    msm5xxx_poc_a80_arm_write(&s, 0x18, 0, 1);
    msm5xxx_poc_a80_arm_write(&s, 0, 0, 3);
    assert(!memcmp(&s, &before, sizeof(s)));
    assert(msm5xxx_poc_a80_arm_read(&s, 0x17, 2) == 0);
    msm5xxx_poc_a80_reset(&s);
    assert(!s.a80_irq.armed && !s.a80_arm && s.a80_clock_ns == 100);
    assert(s.a80_irq.timer_mask == 0x200 && s.a80_irq.period_ns == 5000000);
    for (unsigned i = 0; i < sizeof(s.a80_clock_regs); i++)
        assert(s.a80_clock_regs[i] == 0);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'check.c').write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                native_sanitizers(), '-fno-sanitize-recover=all', '-I', str(native),
                str(root / 'check.c'), str(native / 'msm5xxx-timer-irq.c'),
                '-o', str(root / 'check')], check=True)
            subprocess.run([str(root / 'check')], check=True)


if __name__ == '__main__':
    unittest.main()
