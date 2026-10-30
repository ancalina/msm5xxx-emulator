"""Compile the actual watchdog timer/edge helpers; no QEMU or firmware run."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class WatchdogNativeTests(unittest.TestCase):
    def test_edges_timer_reset_and_shared_port(self):
        repo = Path(__file__).resolve().parents[1]
        source = (repo / 'native/qemu/msm5xxx-poc.c').read_text()

        def function(name):
            match = re.search(r'^static [^\n]*\b' + name + r'\(', source, re.M)
            self.assertIsNotNone(match, name)
            brace = source.index('{', match.end())
            cursor, depth = brace + 1, 1
            while depth:
                depth += (source[cursor] == '{') - (source[cursor] == '}')
                cursor += 1
            return source[match.start():cursor]

        fields = source[source.index('    uint32_t watchdog_register;'):
                        source.index('    bool memory_profile_enabled;')]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef uint64_t hwaddr;
typedef struct { int64_t deadline; bool pending; } QEMUTimer;
typedef struct { int unused; } MemoryRegion;
typedef struct {
''' + fields + r'''
    bool memory_profile_enabled;
    bool ready_poll_enabled, ready_poll_lcd_enabled;
    uint32_t ready_pulse_address;
} MSM5xxxPOCMachineState;
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define MSM5XXX_POC_MSM_SIZE 0x01000000
#define QEMU_CLOCK_VIRTUAL 0
#define SHUTDOWN_CAUSE_GUEST_RESET 1
static int64_t now;
static unsigned resets, shared_writes;
static uint8_t shared_backing;
static int64_t qemu_clock_get_ns(int clock) { (void)clock; return now; }
static void timer_del(QEMUTimer *timer) { timer->pending = false; }
static void timer_mod(QEMUTimer *timer, int64_t deadline) {
    timer->pending = true; timer->deadline = deadline;
}
static void qemu_system_reset_request(int cause) {
    assert(cause == SHUTDOWN_CAUSE_GUEST_RESET); resets++;
}
static uint64_t msm5xxx_poc_ready_pulse_read(void *s, hwaddr offset, unsigned size) {
    (void)s; assert(offset == 0 && size == 1); return shared_backing;
}
static void msm5xxx_poc_ready_pulse_write(void *s, hwaddr offset,
                                          uint64_t value, unsigned size) {
    (void)s; assert(offset == 0 && size == 1); shared_writes++; shared_backing = value;
}
''' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_watchdog_valid',
            'msm5xxx_poc_watchdog_expire', 'msm5xxx_poc_watchdog_reset',
            'msm5xxx_poc_watchdog_pulse', 'msm5xxx_poc_watchdog_read',
            'msm5xxx_poc_watchdog_write')) + r'''
int main(void) {
    QEMUTimer timer = {0};
    MSM5xxxPOCMachineState s = {.watchdog_timer=&timer,
        .watchdog_mask=1, .watchdog_register=0x03000700,
        .watchdog_timeout_ms=30000};
    assert(!msm5xxx_poc_watchdog_valid(&s));
    s.memory_profile_enabled = true;
    assert(msm5xxx_poc_watchdog_valid(&s));
    s.watchdog_mask = 3; assert(!msm5xxx_poc_watchdog_valid(&s));
    s.watchdog_mask = 0; assert(!msm5xxx_poc_watchdog_valid(&s));
    s.watchdog_mask = 0x100; assert(!msm5xxx_poc_watchdog_valid(&s));
    s.watchdog_mask = 1;
    s.watchdog_register = 0x04000000; assert(!msm5xxx_poc_watchdog_valid(&s));
    s.watchdog_register = 0x02ffffff; assert(!msm5xxx_poc_watchdog_valid(&s));
    s.watchdog_register = 0x03000700;
    s.watchdog_timeout_ms = 0; assert(!msm5xxx_poc_watchdog_valid(&s));
    s.watchdog_timeout_ms = 3600001; assert(!msm5xxx_poc_watchdog_valid(&s));
    s.watchdog_timeout_ms = 30000;
    msm5xxx_poc_watchdog_reset(&s);
    assert(!timer.pending && !s.watchdog_armed);
    msm5xxx_poc_watchdog_expire(&s); assert(resets == 0);
    msm5xxx_poc_watchdog_write(&s, 0, 0x10, 1);
    assert(!timer.pending); /* control bit4 alone is not a pet */
    now = 17;
    msm5xxx_poc_watchdog_write(&s, 0, 0x11, 1);
    assert(!timer.pending); /* rising edge alone does not arm */
    msm5xxx_poc_watchdog_write(&s, 0, 0x10, 1);
    assert(timer.pending && s.watchdog_armed);
    assert(timer.deadline == now + 30000000000LL);
    assert(s.watchdog_last_edge_ns == now);
    int64_t deadline = timer.deadline;
    now++;
    msm5xxx_poc_watchdog_write(&s, 0, 0, 1);
    assert(timer.deadline == deadline); /* repeated low cannot postpone */
    msm5xxx_poc_watchdog_write(&s, 0, 1, 1);
    msm5xxx_poc_watchdog_write(&s, 0, 0, 1);
    assert(timer.deadline == deadline + 1);
    now = timer.deadline;
    msm5xxx_poc_watchdog_expire(&s);
    assert(resets == 1 && !s.watchdog_armed);
    msm5xxx_poc_watchdog_expire(&s); assert(resets == 1);
    msm5xxx_poc_watchdog_reset(&s);
    assert(!timer.pending && !s.watchdog_high && !s.watchdog_last_edge_ns);
    s.ready_poll_enabled = true;
    s.ready_pulse_address = s.watchdog_register;
    msm5xxx_poc_watchdog_write(&s, 0, 1, 1);
    msm5xxx_poc_watchdog_write(&s, 0, 0, 1);
    assert(shared_writes == 2 && timer.pending);
    assert(msm5xxx_poc_watchdog_read(&s, 0, 1) == 0);
    s.ready_poll_enabled = false;
    msm5xxx_poc_watchdog_write(&s, 0, 0x42, 1);
    assert(msm5xxx_poc_watchdog_read(&s, 0, 1) == 0x42);
    msm5xxx_poc_watchdog_reset(&s);
    msm5xxx_poc_watchdog_write(&s, 1, 1, 1);
    msm5xxx_poc_watchdog_write(&s, 0, 1, 2);
    assert(!s.watchdog_high && !timer.pending);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='.watchdog-native-', dir=repo) as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                            str(path / 'check.c'), '-o', str(path / 'check')],
                           check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)
