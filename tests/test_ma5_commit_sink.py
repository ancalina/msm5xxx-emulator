"""Compile the actual C core; no QEMU guest or synthesis."""
import subprocess
import tempfile
import unittest
from pathlib import Path

HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "msm5xxx-ma5-audio.h"

typedef struct Log {
    MSM5xxxMA5Device *device;
    MSM5xxxMA5Commit rows[128];
    unsigned count;
} Log;
typedef struct Pair { MSM5xxxMA5Device on, off; Log log; } Pair;
static void sink(void *opaque, const MSM5xxxMA5Commit *c) {
    Log *log = opaque;
    MSM5xxxMA5Device *d = log->device;
    assert(log->count < 128);
    if (c->kind == MSM5XXX_MA5_COMMIT_CONTROL) {
        assert(d->backing.control[c->address] == c->value);
        assert(c->value == (c->raw & 127));
        if (c->address == 480 && (c->value & 1))
            assert(!d->counter_running);
    } else if (c->kind == MSM5XXX_MA5_COMMIT_SRAM) {
        assert(c->address >= 0x4000 && c->address < 0x6000);
        assert(d->backing.sram[c->address - 0x4000] == c->value);
        assert(c->raw == c->value);
    }
    log->rows[log->count++] = *c;
}
static void same(Pair *p) {
    MSM5xxxMA5Device a = p->on, b = p->off;
    a.commit_sink = b.commit_sink = 0;
    a.commit_opaque = b.commit_opaque = 0;
    assert(!memcmp(&a, &b, sizeof(a)));
}
static void init(Pair *p) {
    memset(p, 0, sizeof(*p));
    assert(msm5xxx_ma5_device_init(&p->on, 10));
    assert(msm5xxx_ma5_device_init(&p->off, 10));
    assert(!p->on.commit_sink && !p->on.commit_opaque);
    p->log.device = &p->on;
    p->on.commit_sink = sink; p->on.commit_opaque = &p->log;
    same(p);
}
static bool write(Pair *p, bool index, uint8_t v, uint64_t t) {
    bool a = msm5xxx_ma5_device_write(&p->on, index, v, t);
    bool b = msm5xxx_ma5_device_write(&p->off, index, v, t);
    assert(a == b); same(p); return a;
}
static void reg(Pair *p, uint8_t b, uint8_t v, uint64_t t) {
    assert(write(p, true, b, t)); assert(write(p, false, v, t));
}
static void advance(Pair *p, uint64_t t) {
    msm5xxx_ma5_device_advance(&p->on, t);
    msm5xxx_ma5_device_advance(&p->off, t); same(p);
}
static void bytes(Pair *p, uint8_t port, const uint8_t *data, unsigned n, uint64_t t) {
    assert(write(p, true, port, t));
    for (unsigned i = 0; i < n; i++) assert(write(p, false, data[i], t));
}
static void clocked(Pair *p) {
    assert(msm5xxx_ma5_device_set_clock(&p->on, 19660800));
    assert(msm5xxx_ma5_device_set_clock(&p->off, 19660800)); same(p);
    reg(p, 30, 0x14, 0); reg(p, 31, 0x4b, 0);
    reg(p, 35, 0, 0); reg(p, 36, 4, 0); reg(p, 38, 2, 0);
    MSM5xxxMA5Commit c = p->log.rows[p->log.count - 1];
    assert(c.kind == MSM5XXX_MA5_COMMIT_B && c.address == 38 &&
           c.value == 0 && c.raw == 2 && c.time_ns == 0);
    reg(p, 38, 1, 0);
}
static void logs_equal(Log *a, Log *b) {
    assert(a->count == b->count);
    for (unsigned i = 0; i < a->count; i++) {
        MSM5xxxMA5Commit *x = &a->rows[i], *y = &b->rows[i];
        assert(x->kind == y->kind && x->address == y->address &&
               x->value == y->value && x->raw == y->raw && x->time_ns == y->time_ns);
    }
}
static void immediate(Pair *p, bool fragmented) {
    const uint8_t c[] = {0x80, 0x81};
    const uint8_t ram[] = {0, 0, 0x81, 0x82, 0x80, 0xff};
    const uint8_t rom[] = {0, 0, 0x80, 0x81, 0xfe};
    const uint8_t read[] = {0x80, 0x80};
    bytes(p, 2, c, sizeof(c), 0);
    bytes(p, 2, ram, sizeof(ram), 0);
    bytes(p, 2, rom, sizeof(rom), 0);
    bytes(p, 3, read, sizeof(read), 0);
    const uint8_t fragment[] = {0x81};
    bytes(p, 2, fragment, 1, 0);
    if (fragmented) for (uint64_t t = 0; t <= 160; t++) advance(p, t);
    else advance(p, 160);
    assert(p->log.count == 3); /* C0 + two actual SRAM bytes; no header/ROM/read. */
    assert(p->log.rows[0].time_ns == 20 && p->log.rows[0].raw == 0x81);
    assert(p->log.rows[1].address == 0x4000 && p->log.rows[1].value == 0x80 &&
           p->log.rows[1].time_ns == 70);
    assert(p->log.rows[2].address == 0x4001 && p->log.rows[2].raw == 0xff &&
           p->log.rows[2].time_ns == 80); /* Address survives terminal cursor reset. */
    assert(write(p, false, 0xff, 160)); advance(p, 170);
    assert(p->log.rows[3].address == 1 && p->log.rows[3].value == 127 &&
           p->log.rows[3].raw == 255 && p->log.rows[3].time_ns == 170);
    reg(p, 37, 4, 200);
    assert(p->log.rows[4].kind == MSM5XXX_MA5_COMMIT_B && p->log.rows[4].time_ns == 200);
    uint8_t a, b;
    assert(write(p, true, 0x41, 200));
    assert(msm5xxx_ma5_device_read(&p->on, false, &a, 200));
    assert(msm5xxx_ma5_device_read(&p->off, false, &b, 200));
    assert(a == b && p->log.count == 5); same(p);
}
static void delayed(Pair *p, bool fragmented) {
    clocked(p); p->log.count = 0;
    const uint8_t data[] = {0x82, 0x80, 0x87, 0x80, 0x60, 0x83, 0x81,
                            0x81, 0x81, 0x88};
    bytes(p, 1, data, sizeof(data), 0);
    if (fragmented) for (uint64_t t = 0; t <= 3000; t++) advance(p, t);
    else advance(p, 3000);
    assert(p->log.count == 2 && !p->on.counter_running);
    assert(p->log.rows[0].address == 0 && p->log.rows[0].value == 7);
    assert(p->log.rows[0].time_ns == 2171);
    assert(p->log.rows[1].address == 480 && p->log.rows[1].value == 1);
    assert(p->log.rows[1].time_ns > p->log.rows[0].time_ns);
    reg(p, 38, 1, 5000); /* Same-clock resume keeps queued B1 deadline. */
    if (fragmented) for (uint64_t t = 5000; t <= 8000; t++) advance(p, t);
    else advance(p, 8000);
    assert(p->log.count == 4 && p->log.rows[2].kind == MSM5XXX_MA5_COMMIT_B);
    assert(p->log.rows[3].address == 1 && p->log.rows[3].value == 8 &&
           p->log.rows[3].time_ns > 5000);
}
int main(void) {
    Pair a, b;
    init(&a); init(&b); immediate(&a, false); immediate(&b, true);
    logs_equal(&a.log, &b.log);
    init(&a); init(&b); delayed(&a, false); delayed(&b, true);
    logs_equal(&a.log, &b.log);
    init(&a); clocked(&a); a.log.count = 0;
    const uint8_t control[] = {0x80, 0x81};
    bytes(&a, 2, control, 2, 0); assert(write(&a, true, 55, 0));
    assert(!write(&a, false, 1, 100)); /* Advance prior due commits before bad B55. */
    assert(a.log.count == 1 && a.log.rows[0].time_ns == 20);
    init(&a);
    const uint8_t invalid[] = {0, 0, 0}; bytes(&a, 2, invalid, 3, 0);
    advance(&a, 30); assert(a.on.reject && !a.log.count);
    init(&a);
    const uint8_t last[] = {0x7f, 0x3f, 0x81, 0x81, 0xff};
    bytes(&a, 2, last, sizeof(last), 0); advance(&a, 50);
    assert(a.log.count == 1 && a.log.rows[0].address == 0x5fff &&
           a.log.rows[0].raw == 0xff && !a.on.backing.immediate.address_bytes);
    init(&a); clocked(&a); a.log.count = 0;
    const uint8_t crossing[] = {0x80, 0x7f, 0x3f, 0x81, 0x82, 0x80, 0xff};
    bytes(&a, 1, crossing, sizeof(crossing), 0); advance(&a, 70);
    assert(a.on.reject == MSM5XXX_MA5_REJECT_PACKET && a.log.count == 1);
    assert(a.log.rows[0].kind == MSM5XXX_MA5_COMMIT_SRAM &&
           a.log.rows[0].address == 0x5fff && a.log.rows[0].raw == 0x80 &&
           a.log.rows[0].time_ns == 60); /* Out-of-range second byte never emits. */
    init(&a);
    uint64_t start = UINT64_MAX - 25;
    const uint8_t overflow[] = {0x80, 0x81, 0x80};
    bytes(&a, 2, overflow, 3, start); advance(&a, UINT64_MAX);
    assert(a.on.reject == MSM5XXX_MA5_REJECT_CLOCK && a.log.count == 1);
    assert(a.log.rows[0].time_ns == UINT64_MAX - 5 && a.log.rows[0].value == 1);
    assert(msm5xxx_ma5_device_init(&a.on, 10));
    assert(!a.on.commit_sink && !a.on.commit_opaque); /* Constructor clears opt-in. */
    return 0;
}
'''


class CommitSinkTests(unittest.TestCase):
    def test_actual_core_sink_contract(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        with tempfile.TemporaryDirectory(dir=native.parent) as directory:
            c = Path(directory) / 'sink.c'
            binary = Path(directory) / 'sink'
            c.write_text(HARNESS)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                            '-I' + str(native), str(c),
                            str(native / 'msm5xxx-ma5-audio.c'), '-o', str(binary)],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
