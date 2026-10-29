"""Compile actual native property/arm handlers; no realize/reset/guest execution."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class FB0NativeTimerTests(unittest.TestCase):
    def test_property_and_byte_two_arm(self):
        source = (Path(__file__).resolve().parents[1] /
                  'native/qemu/msm5xxx-poc.c').read_text()

        def function(name):
            start = source.index(name + '(')
            start = source.rfind('\nstatic ', 0, start) + 1
            return source[start:source.index('\nstatic ', start + 1)]

        constants = '\n'.join(re.findall(
            r'^#define MSM5XXX_POC_(?:MSM_BASE|MSM_SIZE|'
            r'REX_C80_CONTROLLER_SIZE|REX_C80_THREE_BANK_SIZE) .+$',
            source, re.MULTILINE))
        start = source.index('typedef enum MSM5xxxPOCRexGateStatus {')
        enum = source[start:source.index('} MSM5xxxPOCRexGateStatus;', start)
                      + len('} MSM5xxxPOCRexGateStatus;')]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define MiB (1024 * 1024)
#define QEMU_CLOCK_VIRTUAL 0
typedef uint64_t hwaddr;
typedef struct { int unused; } Error;
typedef struct {
    uint32_t rex_irq_status_address, rex_irq_enable_address, rex_irq_arm_address;
    uint32_t rex_irq_mask, rex_irq_interval, rex_irq_vector_target;
    uint32_t rex_irq_wrapper_address, rex_irq_handler_slot, rex_irq_handler_address;
    uint32_t rex_irq_handler_size, rex_irq_callback_slot, rex_irq_callback_address;
    uint32_t rex_irq_controller_size, rex_irq_gate_status;
    uint8_t rex_irq_bank_count, rex_irq_arm_backing;
    bool rex_irq_c80, rex_irq_enabled, rex_irq_armed;
    int64_t rex_irq_next;
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
static Error failure;
static unsigned schedules;
static int64_t now = 1000;
static void error_setg(Error **errp, const char *format, ...) {
    (void)format; *errp = &failure;
}
static int64_t qemu_clock_get_ns(int clock) {
    assert(clock == QEMU_CLOCK_VIRTUAL); return now;
}
static void msm5xxx_poc_rex_irq_schedule(MSM5xxxPOCMachineState *s) {
    assert(s->rex_irq_armed); schedules++;
}
''' + constants + '\n' + enum + '\n' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_set_rex_static_c80',
            'msm5xxx_poc_rex_irq_arm_read',
            'msm5xxx_poc_rex_irq_arm_write')) + r'''
int main(void) {
    MSM5xxxPOCMachineState old = {0}, s = {0};
    Error *error = NULL;
    msm5xxx_poc_set_rex_static_c80(&old,
        "3000c80:3000c94:200:4c4b40:1000000:3520:10a5788:a9444:16a:1003078:b480",
        &error);
    assert(!error && old.rex_irq_enabled && old.rex_irq_c80);
    assert(old.rex_irq_arm_address == 0 && old.rex_irq_bank_count == 2);
    msm5xxx_poc_set_rex_static_c80(&s,
        "3000fb0:3000fc4:200:4c4b40:1000000:231994:10a5788:a9444:182:1003078:b480:2",
        &error);
    assert(!error && s.rex_irq_enabled && s.rex_irq_arm_address == 0x30006e0);
    assert(s.rex_irq_bank_count == 2 && !s.rex_irq_armed);
    const char *invalid[] = {
        "3000fb0:3000fc4:200:4c4b40:1000000:231994:10a5788:a9444:182:1003078:b480:3",
        "3000fb0:3000fc4:200:4c4b40:1000000:231994:10a5788:a9444:180:1003078:b480:2",
    };
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
        MSM5xxxPOCMachineState rejected;
        unsigned char zero[sizeof(rejected)] = {0};
        memset(&rejected, 0, sizeof(rejected));
        error = NULL;
        msm5xxx_poc_set_rex_static_c80(&rejected, invalid[i], &error);
        assert(error && !rejected.rex_irq_enabled);
        assert(memcmp(&rejected, zero, sizeof(zero)) == 0);
    }
    msm5xxx_poc_rex_irq_arm_write(&s, 0, 2, 2); /* Wrong width. */
    msm5xxx_poc_rex_irq_arm_write(&s, 1, 2, 1); /* Wrong offset. */
    assert(!s.rex_irq_armed && !schedules && !s.rex_irq_arm_backing);
    msm5xxx_poc_rex_irq_arm_write(&s, 0, 1, 1);
    assert(!s.rex_irq_armed && !schedules);
    assert(msm5xxx_poc_rex_irq_arm_read(&s, 0, 1) == 1);
    assert(msm5xxx_poc_rex_irq_arm_read(&s, 1, 1) == 0);
    assert(msm5xxx_poc_rex_irq_arm_read(&s, 0, 2) == 0);
    msm5xxx_poc_rex_irq_arm_write(&s, 0, 2, 1);
    assert(s.rex_irq_armed && schedules == 1);
    assert(s.rex_irq_next == now + s.rex_irq_interval);
    assert(msm5xxx_poc_rex_irq_arm_read(&s, 0, 1) == 2);
    int64_t first_next = s.rex_irq_next;
    now += 100;
    msm5xxx_poc_rex_irq_arm_write(&s, 0, 2, 1);
    assert(schedules == 1 && s.rex_irq_next == first_next);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                            str(path / 'check.c'), '-o', str(path / 'check')],
                           check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
