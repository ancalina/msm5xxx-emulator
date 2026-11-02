"""Exercise the source-qualified SD810 GPIO edge latch."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class SD810FoldIRQNativeTests(unittest.TestCase):
    def test_live_route_edge_polarity_and_ack(self):
        source = (Path(__file__).resolve().parents[1] /
                  'native/qemu/msm5xxx-poc.c').read_text()
        start = source.index('static void msm5xxx_poc_sd810_fold_edge(',
                             source.index('static uint32_t msm5xxx_poc_guest_u32(hwaddr address)\n{'))
        end = source.index('\nstatic ', start + 1)
        ack_start = source.index('static uint16_t msm5xxx_poc_fold_gpio_ack(')
        ack_end = source.index('\nstatic ', ack_start + 1)
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
typedef struct {
    bool sd810_fold_irq_enabled, rex_irq_c80, rex_irq_route_active;
    bool rex_irq_read_consume, ma5_irq_configured;
    uint32_t sd810_fold_group, sd810_fold_vector, sd810_fold_callback;
    uint32_t sd810_fold_parent_slot, sd810_fold_parent_handler;
    uint8_t msm[0x1000], rex_irq_backing[0x60];
    uint16_t rex_irq_pending[3];
} MSM5xxxPOCMachineState;
static bool valid = true;
static bool callback_valid = true;
static unsigned updates;
static uint32_t msm5xxx_poc_guest_u32(uint32_t address) {
    switch (address) {
    case 0x1000100: return valid ? 0x03000c88 : 0;
    case 0x1000104: return 0x03000ca4;
    case 0x1000108: return 0x03000cb0;
    case 0x1000110: return 1;
    case 0x1000200: return callback_valid ? 0x101 : 0;
    case 0x10000ac: return 0x201;
    default: return 0;
    }
}
static uint16_t msm5xxx_poc_backing_read(uint8_t *p, unsigned o, unsigned n) {
    assert(n == 2 && o + n <= 0x1000); return p[o] | ((uint16_t)p[o+1] << 8);
}
#define memory_region_get_ram_ptr(p) ((uint8_t *)(p))
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s) { (void)s; updates++; }
''' + source[start:end] + '\n' + source[ack_start:ack_end] + r'''
int main(void) {
    MSM5xxxPOCMachineState s = {
        .sd810_fold_irq_enabled=true, .rex_irq_c80=true, .rex_irq_route_active=true,
        .sd810_fold_group=0x1000100, .sd810_fold_vector=0x1000200,
        .sd810_fold_callback=0x101, .sd810_fold_parent_slot=0x10000ac,
        .sd810_fold_parent_handler=0x201,
    };
    s.msm[0xca4]=1; /* Enabled, falling edge selected. */
    msm5xxx_poc_sd810_fold_edge(&s, 1, 0);
    assert(s.rex_irq_backing[8] == 1 && s.rex_irq_pending[1] == 0x2000 && updates == 1);
    assert(msm5xxx_poc_fold_gpio_ack(1, 0) == 1);
    assert(msm5xxx_poc_fold_gpio_ack(1, 1) == 0);
    assert(msm5xxx_poc_fold_gpio_ack(1, 0x8001) == 0x8000);
    s.rex_irq_backing[8]=0; s.rex_irq_pending[1]=0;
    msm5xxx_poc_sd810_fold_edge(&s, 0, 1); /* Wrong polarity. */
    assert(!s.rex_irq_backing[8] && !s.rex_irq_pending[1] && updates == 1);
    s.msm[0xcb0]=1;
    msm5xxx_poc_sd810_fold_edge(&s, 0, 1);
    assert(s.rex_irq_backing[8] == 1 && s.rex_irq_pending[1] == 0x2000 && updates == 2);
    s.rex_irq_backing[8]=0; s.rex_irq_pending[1]=0; valid=false;
    msm5xxx_poc_sd810_fold_edge(&s, 0, 1); /* Live descriptor no longer matches. */
    assert(!s.rex_irq_backing[8] && !s.rex_irq_pending[1] && updates == 2);
    valid=true; s.msm[0xca4]=0;
    msm5xxx_poc_sd810_fold_edge(&s, 0, 1); /* GPIO disabled. */
    assert(!s.rex_irq_backing[8] && !s.rex_irq_pending[1]);
    s.msm[0xca4]=1; s.ma5_irq_configured=true;
    msm5xxx_poc_sd810_fold_edge(&s, 0, 1); /* Separate IRQ owner. */
    assert(!s.rex_irq_backing[8] && !s.rex_irq_pending[1]);
    s.ma5_irq_configured=false; callback_valid=false;
    msm5xxx_poc_sd810_fold_edge(&s, 0, 1); /* Callback not installed. */
    assert(!s.rex_irq_backing[8] && !s.rex_irq_pending[1]);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'test.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)
