"""Compile and exercise the source-backed timer/IRQ core with synthetic accesses."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from native_sanitizers import native_sanitizers


class TimerIRQNativeTests(unittest.TestCase):
    def test_register_lanes_irq_timer_reset_and_bounds(self):
        root = Path(__file__).resolve().parents[1]
        native = root / "native/qemu"
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "msm5xxx-timer-irq.h"

int main(void) {
    MSM5xxxTimerIRQ p;
    uint32_t value;
    msm5xxx_timer_irq_init(&p, 0x200, 10);

    /* Status is W1C by lane; the access at offset 3 crosses into upper status. */
    p.pending[0] = 0xA1B2C3D4;
    p.pending[1] = 0xD5;
    assert(msm5xxx_timer_irq_write(&p, 1, 2, 0x00C3));
    assert(p.pending[0] == 0xA1B200D4 && p.pending[1] == 0xD5);
    assert(msm5xxx_timer_irq_write(&p, 3, 4, 0xFFFF00A1));
    assert(p.pending[0] == 0x00B200D4 && p.pending[1] == 0xD5);
    assert(msm5xxx_timer_irq_write(&p, 4, 4, 0xFFFFFFFF));
    assert(p.pending[1] == 0);

    /* Reserved status lanes 5..7 read zero and ignore writes. */
    p.pending[1] = 0x5A;
    assert(msm5xxx_timer_irq_write(&p, 4, 4, 0xFFFFFF00));
    assert(p.pending[1] == 0x5A);
    assert(msm5xxx_timer_irq_read(&p, 4, 4, &value) && value == 0x5A);

    /* Enable low word and upper byte are backed; reserved high lanes are not. */
    assert(msm5xxx_timer_irq_write(&p, 0x14, 4, 0xDEADBEEF));
    assert(msm5xxx_timer_irq_read(&p, 0x14, 4, &value) && value == 0xDEADBEEF);
    assert(msm5xxx_timer_irq_write(&p, 0x18, 4, 0xFFFFFFFF));
    assert(msm5xxx_timer_irq_read(&p, 0x18, 4, &value) && value == 0xFF);
    assert(msm5xxx_timer_irq_write(&p, 0x18, 4, 0xFFFFFF00));
    assert(msm5xxx_timer_irq_read(&p, 0x18, 4, &value) && value == 0);
    p.pending[0] = 0;
    p.pending[1] = 0x80;
    assert(msm5xxx_timer_irq_write(&p, 0x18, 1, 0x80));
    assert(msm5xxx_timer_irq_level(&p));
    assert(msm5xxx_timer_irq_write(&p, 4, 1, 0x80));
    assert(!msm5xxx_timer_irq_level(&p));
    assert(msm5xxx_timer_irq_write(&p, 8, 4, 0x12345678));
    assert(msm5xxx_timer_irq_read(&p, 8, 4, &value) && value == 0x12345678);

    /* Expiry sets a real pending source; the enable mask gates the IRQ line. */
    msm5xxx_timer_irq_init(&p, 0x200, 10);
    msm5xxx_timer_irq_set_armed(&p, true);
    msm5xxx_timer_irq_advance(&p, 10);
    assert(p.pending[0] == 0x200 && !msm5xxx_timer_irq_level(&p));
    assert(msm5xxx_timer_irq_write(&p, 0x14, 4, 0x200));
    assert(msm5xxx_timer_irq_level(&p));
    assert(msm5xxx_timer_irq_write(&p, 1, 1, 2));
    assert(!msm5xxx_timer_irq_level(&p) && p.pending[0] == 0);

    /* Periodic expiry, acknowledge, and next-period reassertion. */
    msm5xxx_timer_irq_set_armed(&p, false);
    msm5xxx_timer_irq_set_armed(&p, true);
    msm5xxx_timer_irq_advance(&p, 9);
    assert(p.pending[0] == 0 && p.remaining_ns == 1);
    msm5xxx_timer_irq_advance(&p, 1);
    assert(p.pending[0] == 0x200 && p.remaining_ns == 10);
    assert(msm5xxx_timer_irq_write(&p, 0, 4, 0x200));
    msm5xxx_timer_irq_advance(&p, 9);
    assert(p.pending[0] == 0);
    msm5xxx_timer_irq_advance(&p, 1);
    assert(p.pending[0] == 0x200);

    /* Disarming freezes the phase but leaves pending state intact. */
    msm5xxx_timer_irq_set_armed(&p, false);
    assert(p.pending[0] == 0x200);
    msm5xxx_timer_irq_advance(&p, 1000);
    assert(p.pending[0] == 0x200 && p.remaining_ns == 0);

    /* Repeated arm does not restart the active countdown. */
    msm5xxx_timer_irq_write(&p, 0, 4, 0x200);
    msm5xxx_timer_irq_set_armed(&p, true);
    msm5xxx_timer_irq_advance(&p, 3);
    assert(p.remaining_ns == 7);
    msm5xxx_timer_irq_set_armed(&p, true);
    assert(p.remaining_ns == 7);

    /* Large elapsed time uses overflow-safe periodic arithmetic. */
    msm5xxx_timer_irq_advance(&p, UINT64_MAX);
    assert(p.pending[0] == 0x200 && p.remaining_ns == 2);

    /* Reset clears runtime registers and pending/timer state, keeps config. */
    p.pending[0] = 0xFFFFFFFF;
    p.pending[1] = 0xFFFFFFFF;
    msm5xxx_timer_irq_write(&p, 0x14, 4, 0xFFFFFFFF);
    msm5xxx_timer_irq_write(&p, 8, 4, 0xAABBCCDD);
    msm5xxx_timer_irq_reset(&p);
    assert(p.timer_mask == 0x200 && p.period_ns == 10);
    assert(!p.armed && !p.remaining_ns && !p.pending[0] && !p.pending[1]);
    assert(msm5xxx_timer_irq_read(&p, 0x14, 4, &value) && value == 0);
    assert(msm5xxx_timer_irq_read(&p, 8, 4, &value) && value == 0);

    /* Unsupported sizes and out-of-range accesses fail without mutation. */
    p.backing[0x1f] = 0xA5;
    p.pending[0] = 0x12345678;
    MSM5xxxTimerIRQ before = p;
    value = 0xCAFEBABE;
    assert(!msm5xxx_timer_irq_read(&p, 0, 3, &value));
    assert(value == 0xCAFEBABE);
    assert(!msm5xxx_timer_irq_read(&p, 0x1f, 2, &value));
    assert(!msm5xxx_timer_irq_read(&p, 0x20, 1, &value));
    assert(!msm5xxx_timer_irq_write(&p, 0, 3, 0xFFFFFFFF));
    assert(!msm5xxx_timer_irq_write(&p, 0x1f, 2, 0xFFFF));
    assert(!msm5xxx_timer_irq_write(&p, 0x20, 1, 0xFF));
    assert(!memcmp(&p, &before, sizeof(p)));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(code)
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                native_sanitizers(), "-fno-sanitize-recover=all",
                "-I", str(native), str(path / "check.c"),
                str(native / "msm5xxx-timer-irq.c"), "-o", str(path / "check"),
            ], check=True)
            subprocess.run([str(path / "check")], check=True)
