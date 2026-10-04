"""Compile actual ready-poll property/runtime helpers; no realize or guest."""
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class ReadyPollNativeTests(unittest.TestCase):
    def test_site_parser_and_owned_runtime(self):
        repo = Path(__file__).resolve().parents[1]
        source = (repo / 'experiments/qemu-tcg/msm5xxx-poc.c').read_text()

        def function(name):
            match = re.search(r'^static [^\n]*(?:\n[^\n]*)?\b' + name + r'\(',
                              source, re.M)
            self.assertIsNotNone(match, name)
            brace = source.index('{', match.end())
            depth, cursor = 1, brace + 1
            while depth:
                depth += (source[cursor] == '{') - (source[cursor] == '}')
                cursor += 1
            return source[match.start():cursor]

        def declaration(name):
            start = source.index('typedef ' + name + ' {')
            end = source.index('} ' + name.split()[-1] + ';', start)
            return source[start:end + len('} ' + name.split()[-1] + ';')]

        constants = '\n'.join(re.findall(
            r'^#define MSM5XXX_POC_(?:MSM_BASE|MSM_SIZE|READY_POLL_DELAY|'
            r'READY_POLL_MAX_SITES|UART_SR_IDLE) .+$', source, re.M))
        fields = source[source.index('    bool ready_poll_enabled;'):
                        source.index('    bool pause_timer_enabled;')]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#define MiB (1024 * 1024)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
typedef uint64_t hwaddr;
typedef struct { uint32_t pc; } CPUState;
typedef struct { CPUState parent; } ARMCPU;
typedef struct { uint64_t (*get_pc)(CPUState *); } CPUClass;
static uint64_t get_pc(CPUState *cpu) { return cpu->pc; }
static CPUClass cpu_class = {get_pc};
#define CPU(p) (&(p)->parent)
#define CPU_GET_CLASS(p) ((void)(p), &cpu_class)
typedef struct { int marker; } Error;
static Error failure;
static void error_setg(Error **errp, const char *format, ...) {
    (void)format; *errp = &failure;
}
static int qemu_strtoul(const char *text, const char **end, int base,
                       unsigned long *value) {
    char *tail;
    errno = 0;
    *value = strtoul(text, &tail, base);
    *end = tail;
    return errno ? -errno : tail == text ? -EINVAL : 0;
}
static uint64_t instructions;
static uint64_t icount_get_raw(void) { return instructions; }
''' + constants + '\n' + declaration('enum MSM5xxxPOCReadyPollStatus') + '\n' + declaration(
            'struct MSM5xxxPOCReadyPollSite') + r'''
typedef struct {
    ARMCPU *cpu;
    uint32_t primary_nor_size;
''' + fields + r'''
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
''' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_ready_reject', 'msm5xxx_poc_ready_site_for_pc',
            'msm5xxx_poc_ready_status_read', 'msm5xxx_poc_ready_pulse_write',
            'msm5xxx_poc_get_ready_poll_sites', 'msm5xxx_poc_set_ready_poll_sites')) + r'''
static ARMCPU cpu;
static MSM5xxxPOCMachineState fresh(void) {
    MSM5xxxPOCMachineState s = {0};
    s.cpu = &cpu;
    s.primary_nor_size = 0x4000;
    return s;
}
static void configure(MSM5xxxPOCMachineState *s, const char *wire) {
    Error *error = NULL;
    msm5xxx_poc_set_ready_poll_sites(s, wire, &error);
    assert(!error && s->ready_poll_enabled);
    char *roundtrip = msm5xxx_poc_get_ready_poll_sites(s, &error);
    assert(!error && strcmp(roundtrip, wire) == 0);
    g_free(roundtrip);
    s->ready_poll_status = MSM5XXX_POC_READY_OBSERVING;
}
static uint64_t read_at(MSM5xxxPOCMachineState *s, uint32_t pc) {
    cpu.parent.pc = pc;
    return msm5xxx_poc_ready_status_read(s, 0, 1);
}
static void pulse_at(MSM5xxxPOCMachineState *s, uint32_t pc, uint8_t value) {
    cpu.parent.pc = pc;
    msm5xxx_poc_ready_pulse_write(s, 0, value, 1);
}
int main(void) {
    const char *legacy = "30007b4:8:3000600:100;200";
    const char *explicit_sites = "30007b4:8:3000600:100,2,c,10,a0,a2;200,14,10,12";
    MSM5xxxPOCMachineState s = fresh();
    Error *error = NULL;
    char *empty = msm5xxx_poc_get_ready_poll_sites(&s, &error);
    assert(!error && !*empty); g_free(empty);
    configure(&s, legacy);
    assert(!s.ready_poll_sites_explicit && s.ready_poll_site_count == 2);
    instructions = 10;
    assert(read_at(&s, 0x102) == 0 && s.ready_poll_phase == 1);
    pulse_at(&s, 0x10c, 1); pulse_at(&s, 0x110, 0);
    assert(s.ready_poll_phase == 3 && s.ready_poll_cycles == 1);
    instructions += MSM5XXX_POC_READY_POLL_DELAY;
    assert(read_at(&s, 0x102) == 8);
    assert(s.ready_poll_status == MSM5XXX_POC_READY_ACCEPTED);
    assert(read_at(&s, 0x202) == 8 && read_at(&s, 0x204) == 0);

    s = fresh(); configure(&s, explicit_sites);
    assert(s.ready_poll_sites_explicit && s.ready_poll_site_count == 2);
    assert(s.ready_poll_sites[0].rx_empty_offset == 0xa0);
    assert(s.ready_poll_sites[0].rx_frame_offset == 0xa2);
    assert(s.ready_poll_sites[1].rx_empty_offset == 0);
    assert(s.ready_poll_sites[1].rx_frame_offset == 0);
    assert(s.ready_uart_rx_empty_enabled);
    s.ready_status_backing = 0x20;
    instructions = 100;
    assert(read_at(&s, 0x202) == 0x20); /* Legacy offset does not own site2. */
    assert(s.ready_poll_status == MSM5XXX_POC_READY_OBSERVING);
    assert(read_at(&s, 0x102) == 0x20 && s.ready_poll_phase == 1);
    pulse_at(&s, 0x210, 1); pulse_at(&s, 0x212, 0); /* Other site's pulses. */
    assert(s.ready_poll_phase == 1 && s.ready_poll_cycles == 0);
    instructions += MSM5XXX_POC_READY_POLL_DELAY;
    assert(read_at(&s, 0x102) == 0x20);
    assert(s.ready_poll_status == MSM5XXX_POC_READY_CANDIDATE);
    pulse_at(&s, 0x10c, 1); pulse_at(&s, 0x110, 0);
    assert(s.ready_poll_phase == 3);
    instructions++;
    assert(read_at(&s, 0x214) == 0x20); /* Switching restarts full qualification. */
    assert(s.ready_poll_active_entry == 0x200 && s.ready_poll_phase == 1);
    assert(s.ready_poll_active_set_offset == 0x10);
    assert(s.ready_poll_active_clear_offset == 0x12);
    uint64_t switch_count = instructions;
    pulse_at(&s, 0x20c, 1); pulse_at(&s, 0x210, 0); /* Wrong offsets for site2. */
    assert(s.ready_poll_status == MSM5XXX_POC_READY_REJECTED);

    s = fresh(); configure(&s, explicit_sites);
    instructions = switch_count;
    assert(read_at(&s, 0x214) == 0);
    pulse_at(&s, 0x210, 1); pulse_at(&s, 0x212, 0);
    instructions += MSM5XXX_POC_READY_POLL_DELAY - 1;
    assert(read_at(&s, 0x214) == 0);
    assert(s.ready_poll_status == MSM5XXX_POC_READY_CANDIDATE);
    pulse_at(&s, 0x210, 1); pulse_at(&s, 0x212, 0);
    instructions++;
    assert(read_at(&s, 0x214) & 8);
    assert(s.ready_poll_status == MSM5XXX_POC_READY_ACCEPTED);
    assert(read_at(&s, 0x1a0) == MSM5XXX_POC_UART_SR_IDLE);
    assert(read_at(&s, 0x1a2) == MSM5XXX_POC_UART_SR_IDLE);
    assert(read_at(&s, 0x333) == MSM5XXX_POC_UART_SR_IDLE); /* Existing allPC contract. */
    unsigned phase = s.ready_poll_phase;
    uint64_t responses = s.ready_poll_responses;
    assert(msm5xxx_poc_ready_status_read(&s, 1, 1) == 0);
    assert(msm5xxx_poc_ready_status_read(&s, 0, 2) == 0);
    assert(s.ready_poll_phase == phase && s.ready_poll_responses == responses);
    msm5xxx_poc_ready_pulse_write(&s, 0, 1, 2);
    assert(s.ready_poll_status == MSM5XXX_POC_READY_REJECTED);
    assert(read_at(&s, 0x214) == 0); /* Rejected qualification stays closed. */

    const char *invalid[] = {
        "", "30007b4:8:3000600:100", "30007b4:8:3000600:100;100",
        "30007b4:8:3000600:101;200", "30007b4:8:3000600:100;200;",
        "30007b4:8:3000600:100;100000000", "30007b4:8:3000600:100;-1",
        "30007b4:8:3000600:100;3ff0", "30007b4:8:3000600:100;200:extra",
        "30007b4:3:3000600:100;200", "30007b4:100:3000600:100;200",
        "30007b4:8:30007b4:100;200", "2ffffff:8:3000600:100;200",
        "30007b4:8:4000000:100;200", "30007b4:8:3000600:100,2,c,10;200",
        "30007b4:8:3000600:100;200,14,10,12",
        "30007b4:8:3000600:100,2,c;200,14,10,12",
        "30007b4:8:3000600:100,3,c,10;200,14,10,12",
        "30007b4:8:3000600:100,2,c,c;200,14,10,12",
        "30007b4:8:3000600:100,c,c,10;200,14,10,12",
        "30007b4:8:3000600:100,2,c,10,10;200,14,10,12",
        "30007b4:8:3000600:100,2,c,10,a0,a0;200,14,10,12",
        "30007b4:8:3000600:100,1002,c,10;200,14,10,12",
        "30007b4:8:3000600:100,2,c,10,100000000;200,14,10,12",
        "30007b4:8:3000600:100,2,c,10,a0,a2,aa;200,14,10,12",
        "30007b4:8:3000600:100,2,c,10;10e,2,4,6", /* Owned-PC collision110. */
        "30007b4:8:3000600:100;200;300;400;500;600;700;800;900",
    };
    for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
        MSM5xxxPOCMachineState rejected = fresh(), before;
        rejected.ready_status_backing = 0xa5;
        rejected.ready_poll_reads = 17;
        memcpy(&before, &rejected, sizeof(before));
        error = NULL;
        msm5xxx_poc_set_ready_poll_sites(&rejected, invalid[i], &error);
        assert(error && memcmp(&before, &rejected, sizeof(before)) == 0);
    }
    s = fresh(); configure(&s, explicit_sites);
    MSM5xxxPOCMachineState before;
    memcpy(&before, &s, sizeof(before)); error = NULL;
    msm5xxx_poc_set_ready_poll_sites(&s, legacy, &error);
    assert(error && memcmp(&before, &s, sizeof(before)) == 0);
    puts("ready-poll actual-C: legacy/heterogeneous/atomic/phase/UART PASS");
    return 0;
}
'''
        flags = shlex.split(subprocess.check_output(
            ['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True, timeout=10))
        with tempfile.TemporaryDirectory(prefix='.ready-poll-native-', dir=repo) as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', str(path / 'check.c'),
                            '-o', str(path / 'check'), *flags], check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
