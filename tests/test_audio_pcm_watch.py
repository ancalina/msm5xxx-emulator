"""Actual stream retry/prepare/reset C with QEMU dependencies stubbed; no guest."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class AudioPCMWatchTests(unittest.TestCase):
    def test_partial_packet_writable_and_lifecycle(self):
        repo = Path(__file__).resolve().parents[1]
        native = repo / 'experiments/qemu-tcg'
        source = (native / 'msm5xxx-poc.c').read_text()

        def function(name):
            match = re.search(r'^static [^;\n]*\b' + name +
                              r'\([^;]*?\)\n\{', source, re.MULTILINE)
            self.assertIsNotNone(match, name)
            start = match.start()
            opening = source.index('{', start)
            depth = 1
            end = opening + 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[start:end]

        # Every original rejection keeps its telemetry but cancels the new watch.
        rejects = list(re.finditer(r'^\s*s->audio_stream_rejected = true;',
                                   source, re.MULTILINE))
        self.assertEqual(len(rejects), 11)
        for reject in rejects:
            self.assertTrue(source[:reject.start()].rstrip().endswith(
                'msm5xxx_poc_audio_pcm_cancel_watch(s);'))
        self.assertIn('.instance_finalize = msm5xxx_poc_instance_finalize,', source)
        constants = '\n'.join(re.findall(
            r'^#define MSM5XXX_POC_AUDIO_(?:PACKET_(?:HEADER|SIZE)|'
            r'STATUS_(?:RESET|NATIVE|REJECTED)) (?:[^\n]*\\\n)?[^\n]*',
            source, re.MULTILINE))
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "msm5xxx-audio-synth.h"
#include "msm5xxx-audio-request.h"
typedef uint64_t hwaddr;
typedef unsigned guint;
typedef int gboolean;
typedef unsigned GIOCondition;
#define G_IO_OUT 1u
#define G_IO_HUP 2u
#define G_IO_ERR 4u
#define G_IO_NVAL 8u
#define G_SOURCE_REMOVE 0
typedef int QemuMutex;
typedef int CharFrontend;
typedef gboolean (*FEWatchFunc)(void *, GIOCondition, void *);
''' + constants + r'''
typedef struct {
    CharFrontend audio_stream_chr;
    uint8_t audio_pcm_packet[MSM5XXX_POC_AUDIO_PACKET_SIZE];
    unsigned audio_pcm_length, audio_pcm_offset;
    guint audio_pcm_watch;
    bool audio_pcm_failed, audio_stream_rejected, audio_output_started;
    bool audio_reset_initialized, audio_core_lock_initialized;
    bool audio_synth_lock_initialized, audio_readback_rejection_reported;
    bool audio_stream_started, audio_irq_asserted, ma2_audio_timer_rejected;
    char *audio_stream_chardev;
    QemuMutex audio_core_lock, audio_synth_lock;
    MSM5xxxAudioSynth audio_synth;
    void *ma2_audio_timer, *audio_voice;
    uint8_t audio_index, audio_backing[4], audio_readback[4];
    MSM5xxxAudioPacketSink audio_packet_sink;
    uint8_t audio_packet_index, audio_packet_control;
    uint8_t audio_packet_mode, audio_packet_init[4][2];
    uint8_t audio_packet_init_valid;
    bool audio_packet_fault, audio_packet_reported, audio_packet_gate_reported;
    bool audio_packet_fifo_empty_known;
    bool audio_packet_ready, audio_packet_reset_armed, audio_packet_clear_armed;
    unsigned audio_packet_trace_count;
    uint8_t audio_stream_status_pending;
    unsigned audio_backend_pcm_length, audio_backend_pcm_offset;
    unsigned audio_stream_order, audio_stream_dropped, audio_stream_reject_code;
    unsigned audio_irq_gate_status, audio_irq_assertions;
    uint64_t audio_stream_reset_epoch, ma2_audio_events;
    uint64_t ma2_audio_gate_offs, ma2_audio_ends;
    int ma2_audio;
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
static MSM5xxxPOCMachineState s;
static unsigned core_held, synth_held;
static guint active_watch, next_watch;
static unsigned additions, removals, write_calls;
static bool watch_supported = true;
static FEWatchFunc callback;
static void *callback_data;
static int responses[16];
static unsigned response_count, response_index;
static uint8_t written_bytes[4 * MSM5XXX_POC_AUDIO_PACKET_SIZE];
static size_t written_length;
static void qemu_mutex_lock(QemuMutex *lock) {
    if (lock == &s.audio_core_lock) { assert(!core_held); core_held = 1; }
    else { assert(lock == &s.audio_synth_lock && core_held && !synth_held); synth_held = 1; }
}
static void qemu_mutex_unlock(QemuMutex *lock) {
    if (lock == &s.audio_core_lock) { assert(core_held && !synth_held); core_held = 0; }
    else { assert(lock == &s.audio_synth_lock && synth_held); synth_held = 0; }
}
static gboolean g_source_remove(guint id) {
    assert(id && active_watch == id); active_watch = 0; removals++; return true;
}
static guint qemu_chr_fe_add_watch(CharFrontend *chr, GIOCondition flags,
                                  FEWatchFunc cb, void *opaque) {
    assert(chr == &s.audio_stream_chr && core_held && !active_watch);
    assert(flags == (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL));
    additions++;
    if (!watch_supported) { return 0; }
    callback = cb; callback_data = opaque;
    return active_watch = ++next_watch;
}
static int qemu_chr_fe_write(CharFrontend *chr, const uint8_t *buf, int len) {
    assert(chr == &s.audio_stream_chr && core_held && len > 0);
    write_calls++;
    int result = response_index < response_count ? responses[response_index++] : len;
    if (result == -1) { errno = EAGAIN; return -1; }
    if (result == -2) { errno = EIO; return -1; }
    assert(result >= 0 && result <= len);
    memcpy(written_bytes + written_length, buf, (size_t)result);
    written_length += result;
    return result;
}
static void timer_del(void *timer) { (void)timer; assert(core_held); }
static void AUD_set_active_out(void *voice, bool active) {
    (void)voice; assert(!active && core_held);
}
static void msm5xxx_poc_ma2_pending_clear(MSM5xxxPOCMachineState *state) {
    assert(state == &s);
}
static void msm5xxx_ma2_reset(int *ma2) { assert(ma2 == &s.ma2_audio && core_held); }
static void msm5xxx_poc_audio_stream_status(MSM5xxxPOCMachineState *state) {
    assert(state == &s && !core_held);
}
static gboolean msm5xxx_poc_audio_pcm_writable(void *, GIOCondition, void *);
''' + '\n'.join(function(name) for name in (
            'msm5xxx_poc_backing_write',
            'msm5xxx_poc_audio_pcm_prepare',
            'msm5xxx_poc_audio_pcm_cancel_watch',
            'msm5xxx_poc_audio_pcm_reject',
            'msm5xxx_poc_audio_pcm_flush',
            'msm5xxx_poc_audio_pcm_writable',
            'msm5xxx_poc_audio_reset',
            'msm5xxx_poc_instance_finalize')) + r'''
static void setup(void) {
    assert(!active_watch && !core_held && !synth_held);
    memset(&s, 0, sizeof(s));
    s.audio_core_lock_initialized = s.audio_synth_lock_initialized = true;
    s.audio_stream_chardev = "stream";
    s.audio_output_started = true;
    msm5xxx_audio_synth_init(&s.audio_synth);
    s.audio_synth.ring_count = MSM5XXX_AUDIO_CHUNK_FRAMES;
    s.audio_synth.ring_write = MSM5XXX_AUDIO_CHUNK_FRAMES;
    s.audio_synth.generated_frame = MSM5XXX_AUDIO_CHUNK_FRAMES;
    s.audio_synth.clock_ns = 12345;
    for (unsigned i = 0; i < MSM5XXX_AUDIO_CHUNK_FRAMES; i++) {
        s.audio_synth.ring[i][0] = (int16_t)i;
        s.audio_synth.ring[i][1] = -(int16_t)i;
    }
    response_index = response_count = 0;
    written_length = write_calls = additions = removals = 0;
    watch_supported = true;
}
static int flush(void) {
    qemu_mutex_lock(&s.audio_core_lock);
    int result = msm5xxx_poc_audio_pcm_flush(&s);
    qemu_mutex_unlock(&s.audio_core_lock);
    return result;
}
static void block(void) {
    responses[0] = -1; response_count = 1;
    assert(flush() == 0 && s.audio_pcm_watch && active_watch);
}
static void fire(GIOCondition condition) {
    assert(active_watch && s.audio_pcm_watch == active_watch);
    /* The delivered one-shot is retired; a retry may register its successor. */
    active_watch = 0;
    assert(callback(NULL, condition, callback_data) == G_SOURCE_REMOVE);
    assert(!core_held && !synth_held && s.audio_pcm_watch == active_watch);
}
int main(void) {
    uint8_t packet[MSM5XXX_POC_AUDIO_PACKET_SIZE];
    setup();
    responses[0] = 17; responses[1] = -1; response_count = 2;
    assert(flush() == 0 && s.audio_pcm_offset == 17 && additions == 1);
    assert(written_length == 17 && s.audio_synth.ring_count == 0);
    memcpy(packet, s.audio_pcm_packet, sizeof(packet));
    guint first = s.audio_pcm_watch;
    responses[2] = -1; response_count = 3;
    assert(flush() == 0 && s.audio_pcm_watch == first && additions == 1);
    responses[3] = -1; response_count = 4;
    fire(G_IO_OUT); /* Repeated EAGAIN: exactly one successor. */
    assert(s.audio_pcm_watch && s.audio_pcm_watch != first && additions == 2);
    fire(G_IO_OUT);
    assert(!s.audio_pcm_watch && !s.audio_pcm_length && !s.audio_pcm_offset);
    assert(written_length == sizeof(packet) && !memcmp(packet, written_bytes, sizeof(packet)));
    assert(s.audio_synth.clock_ns == 12345 &&
           s.audio_synth.generated_frame == MSM5XXX_AUDIO_CHUNK_FRAMES);
    unsigned calls = write_calls;
    assert(flush() == 1 && write_calls == calls); /* No duplicate packet. */

    setup();
    s.audio_synth.ring_count = s.audio_synth.ring_write =
        s.audio_synth.generated_frame = 2 * MSM5XXX_AUDIO_CHUNK_FRAMES;
    for (unsigned i = MSM5XXX_AUDIO_CHUNK_FRAMES;
         i < 2 * MSM5XXX_AUDIO_CHUNK_FRAMES; i++) {
        s.audio_synth.ring[i][0] = 1000;
        s.audio_synth.ring[i][1] = -1000;
    }
    responses[0] = 17; responses[1] = -1; response_count = 2;
    assert(flush() == 0);
    memcpy(packet, s.audio_pcm_packet, sizeof(packet));
    fire(G_IO_OUT); /* Existing buffered packets drain in sequence, no synthesis. */
    assert(written_length == 2 * sizeof(packet));
    assert(!memcmp(written_bytes, packet, sizeof(packet)));
    const uint8_t *second = written_bytes + sizeof(packet);
    assert(!memcmp(second, "M5P2", 4) && second[16] == 2 &&
           second[24] == 0xb9 && second[25] == 1); /* start frame441 */
    assert(second[32] == 0xe8 && second[33] == 3 &&
           second[34] == 0x18 && second[35] == 0xfc);
    assert(!s.audio_synth.ring_count && s.audio_synth.clock_ns == 12345 &&
           s.audio_synth.generated_frame == 2 * MSM5XXX_AUDIO_CHUNK_FRAMES);

    setup(); block(); first = s.audio_pcm_watch;
    assert(flush() == 1 && !s.audio_pcm_watch && removals == 1);
    assert(!active_watch && written_length == sizeof(packet)); /* Timer wins race. */

    setup(); block();
    qemu_mutex_lock(&s.audio_core_lock);
    msm5xxx_poc_audio_pcm_reject(&s);
    qemu_mutex_unlock(&s.audio_core_lock);
    assert(!active_watch && !s.audio_pcm_watch && s.audio_stream_rejected);
    assert(!s.audio_pcm_length && !s.audio_pcm_offset && removals == 1);
    assert(flush() == 1 && !written_length);

    setup(); block();
    s.audio_packet_ready = s.audio_packet_reset_armed = s.audio_packet_clear_armed = true;
    msm5xxx_poc_audio_reset(&s);
    assert(!active_watch && !s.audio_pcm_watch && !s.audio_pcm_length);
    assert(!s.audio_output_started && !s.audio_pcm_failed && !s.audio_stream_rejected);
    assert(!s.audio_packet_ready && !s.audio_packet_reset_armed && !s.audio_packet_clear_armed);
    assert(!written_length && flush() == 1);

    setup(); block();
    msm5xxx_poc_instance_finalize(&s);
    assert(!active_watch && !s.audio_pcm_watch && removals == 1);

    const GIOCondition errors[] = {G_IO_HUP, G_IO_ERR, G_IO_NVAL};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
        setup(); block(); fire(errors[i]);
        assert(s.audio_pcm_failed && !active_watch && write_calls == 1);
        qemu_mutex_lock(&s.audio_core_lock);
        msm5xxx_poc_audio_pcm_reject(&s); /* Existing next-tick rejection. */
        qemu_mutex_unlock(&s.audio_core_lock);
        assert(!s.audio_pcm_length && s.audio_stream_rejected);
    }
    setup(); block(); responses[1] = -2; response_count = 2; fire(G_IO_OUT);
    assert(s.audio_pcm_failed && !active_watch && !s.audio_pcm_watch);
    setup(); block(); responses[1] = 0; response_count = 2;
    assert(flush() == -1 && !active_watch && removals == 1);

    setup(); watch_supported = false;
    responses[0] = -1; response_count = 1;
    assert(flush() == 0 && !s.audio_pcm_watch && s.audio_pcm_length);
    assert(flush() == 1 && written_length == sizeof(packet)); /* Old timer retry. */
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', '-I', str(native),
                            str(path / 'check.c'), str(native / 'msm5xxx-audio-synth.c'),
                            str(native / 'msm5xxx-audio-request.c'),
                            '-o', str(path / 'check')], check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
