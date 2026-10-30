"""Actual stream retry/prepare/reset C with QEMU dependencies stubbed; no guest."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class AudioPCMWatchTests(unittest.TestCase):
    def test_ma5_timer_consumes_without_followup_mmio(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        source = (native / "msm5xxx-poc.c").read_text()
        helpers = source[source.index("static void msm5xxx_poc_ma5_sram_observe("):
                         source.index("static bool msm5xxx_poc_audio_site_owned(")]
        harness = r'''#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>
#include "msm5xxx-ma5-audio.h"
#include "msm5xxx-audio-synth.h"
#include "msm5xxx-ma5-pcm-output.h"
#define QEMU_CLOCK_VIRTUAL 0
#define LOG_GUEST_ERROR 1
#define MSM5XXX_POC_AUDIO_STATUS_REJECTED 3
#define MSM5XXX_POC_AUDIO_STATUS_RESET 1
#define MIN(a,b) ((a) < (b) ? (a) : (b))
static uint64_t now, scheduled;
static unsigned cancels, warnings, read_logs;
typedef struct MA5WTEngine MA5WTEngine;
typedef struct { unsigned active; uint64_t timeline_gaps; } MA5WTStatus;
typedef struct {
    void *ma5_audio_timer;
    int audio_core_lock;
    MSM5xxxMA5Device ma5_device;
    bool audio_readback_rejection_reported;
    bool ma5_pcm_initialized, ma5_pcm_output_failed;
    bool audio_synth_lock_initialized, audio_stream_chardev;
    bool audio_output_started, audio_pcm_failed, ma5_pcm_output_reported;
    bool ma5_pcm_resync_pending;
    bool audio_stream_rejected;
    uint64_t ma5_pcm_timeline_gaps;
    unsigned audio_pcm_length, audio_pcm_offset;
    uint8_t audio_stream_status_pending;
    void *audio_voice;
    int audio_synth_lock;
    unsigned audio_backend_pcm_length, audio_backend_pcm_offset;
    uint64_t audio_stream_reset_epoch;
    MSM5xxxMA5PCMOutput ma5_pcm_output;
    MA5WTEngine *ma5_wt_engine;
} MSM5xxxPOCMachineState;
static void msm5xxx_poc_ma5_irq_update(MSM5xxxPOCMachineState *s) { (void)s; }
static void qemu_mutex_lock(int *lock) { (void)lock; }
static void qemu_mutex_unlock(int *lock) { (void)lock; }
static void msm5xxx_poc_audio_pcm_cancel_watch(MSM5xxxPOCMachineState *s) { (void)s; }
static int msm5xxx_poc_audio_pcm_flush(MSM5xxxPOCMachineState *s) { (void)s; return 0; }
static void AUD_set_active_out(void *voice, bool active) { (void)voice; (void)active; }
static MA5WTStatus ma5_wt_engine_status(const MA5WTEngine *engine) {
    (void)engine; return (MA5WTStatus){0};
}
static void ma5_wt_engine_advance(MA5WTEngine *engine, uint64_t time) {
    (void)engine; (void)time;
}
static void timer_del(void *timer) { assert(timer); cancels++; scheduled = 0; }
static void timer_mod_ns(void *timer, int64_t due) {
    assert(timer && due >= 0); scheduled = due;
}
static bool timer_pending(void *timer) { assert(timer); return scheduled > now; }
static uint64_t timer_expire_time_ns(void *timer) { assert(timer); return scheduled; }
static int64_t qemu_clock_get_ns(int clock) { (void)clock; return now; }
static void qemu_log_mask(int mask, const char *format, ...) {
    (void)mask;
    if (strstr(format, "MA5 read-complete")) read_logs++;
}
#define warn_report(...) (warnings++)
''' + helpers + r'''
static void wr(MSM5xxxMA5Device *d, unsigned reg, unsigned value) {
    assert(msm5xxx_ma5_device_write(d, true, reg, 0));
    assert(msm5xxx_ma5_device_write(d, false, value, 0));
}
int main(void) {
    MSM5xxxPOCMachineState s = {0};
    s.ma5_audio_timer = &s;
    assert(msm5xxx_ma5_device_init(&s.ma5_device, 10));
    assert(msm5xxx_ma5_device_write(&s.ma5_device, true, 2, 0));
    assert(msm5xxx_ma5_device_write(&s.ma5_device, false, 0x80, 0));
    assert(msm5xxx_ma5_device_write(&s.ma5_device, false, 0x81, 0));
    msm5xxx_poc_ma5_audio_kick(&s);
    assert(scheduled == 10 && !s.ma5_device.backing.control[0]);
    now = scheduled; msm5xxx_poc_ma5_audio_tick(&s);
    assert(scheduled == 20 && !s.ma5_device.backing.control[0]);
    now = scheduled; msm5xxx_poc_ma5_audio_tick(&s);
    assert(!scheduled && s.ma5_device.backing.control[0] == 1);
    assert(!s.ma5_device.count && s.ma5_device.backing.control_writes == 1);
    assert(!warnings && cancels);
    assert(msm5xxx_ma5_device_init(&s.ma5_device, 10));
    assert(msm5xxx_ma5_device_write(&s.ma5_device, true, 3, 0));
    const unsigned char request[] = {0x40, 0x81, 0x80};
    for (unsigned i = 0; i < sizeof(request); i++)
        assert(msm5xxx_ma5_device_write(&s.ma5_device, false, request[i], 0));
    now = 30; msm5xxx_poc_ma5_audio_tick(&s);
    assert(s.ma5_device.reads == 1 && read_logs == 1);
    msm5xxx_poc_ma5_audio_tick(&s);
    assert(read_logs == 1); /* No duplicate timer completion log. */
    assert(msm5xxx_ma5_device_init(&s.ma5_device, 10));
    assert(msm5xxx_ma5_device_write(&s.ma5_device, true, 2, 0));
    for (unsigned i = 0; i < 3; i++)
        assert(msm5xxx_ma5_device_write(&s.ma5_device, false, 0, 0));
    now = 30; msm5xxx_poc_ma5_audio_tick(&s);
    assert(s.ma5_device.reject == MSM5XXX_MA5_REJECT_PACKET);
    assert(warnings == 1 && !scheduled && s.audio_readback_rejection_reported);
    msm5xxx_poc_ma5_audio_tick(&s);
    assert(warnings == 1);
    s.audio_readback_rejection_reported = false;
    assert(msm5xxx_ma5_device_init(&s.ma5_device, 10));
    assert(msm5xxx_ma5_device_write(&s.ma5_device, true, 2, 0));
    assert(msm5xxx_ma5_device_write(&s.ma5_device, false, 0x80, 0));
    s.ma5_device.next_ns = UINT64_MAX;
    msm5xxx_poc_ma5_audio_kick(&s);
    assert(s.ma5_device.reject == MSM5XXX_MA5_REJECT_CLOCK && !scheduled);
    assert(msm5xxx_ma5_device_init(&s.ma5_device, 10));
    assert(msm5xxx_ma5_device_set_clock(&s.ma5_device, 19660800));
    wr(&s.ma5_device, 30, 20); wr(&s.ma5_device, 31, 75);
    wr(&s.ma5_device, 35, 14); wr(&s.ma5_device, 36, 0x68);
    wr(&s.ma5_device, 38, 2); wr(&s.ma5_device, 38, 1);
    wr(&s.ma5_device, 1, 0x82); /* delta2 */
    wr(&s.ma5_device, 1, 0x80); /* C0 */
    wr(&s.ma5_device, 1, 0x81); /* C0=1 */
    msm5xxx_poc_ma5_audio_kick(&s);
    assert(scheduled == 10);
    now = scheduled; msm5xxx_poc_ma5_audio_tick(&s);
    assert(scheduled == 20);
    now = scheduled; msm5xxx_poc_ma5_audio_tick(&s);
    assert(!s.ma5_device.count && !s.ma5_device.backing.control[0]);
    assert(scheduled == 2000869); /* Exact rational delta deadline. */
    now = scheduled; msm5xxx_poc_ma5_audio_tick(&s);
    assert(s.ma5_device.backing.control[0] == 1 && !scheduled);
    assert(!s.ma5_device.reject && !s.ma5_device.delayed_count);
    {
        int16_t storage[512 * 2], input[500 * 2];
        assert(msm5xxx_ma5_pcm_output_init(&s.ma5_pcm_output, storage, 512) ==
               MSM5XXX_MA5_PCM_OK);
        for (unsigned i = 0; i < 500; i++) {
            input[2 * i] = 1000;
            input[2 * i + 1] = -1000;
        }
        assert(msm5xxx_ma5_pcm_output_emit(&s.ma5_pcm_output, 1, 0, input, 500) ==
               MSM5XXX_MA5_PCM_OK);
        s.ma5_pcm_initialized = true;
        s.audio_synth_lock_initialized = true;
        s.audio_output_started = true;
        s.audio_pcm_length = 1796;
        s.audio_pcm_offset = 17;
        s.ma5_pcm_resync_pending = true;
        assert(msm5xxx_ma5_device_init(&s.ma5_device, 10));
        msm5xxx_poc_ma5_audio_tick(&s);
        assert(s.ma5_pcm_output.queue.epoch == 2 &&
               s.ma5_pcm_output.rate.epoch == 2 &&
               !s.ma5_pcm_resync_pending && !s.audio_output_started &&
               !s.audio_pcm_length && !s.audio_pcm_offset &&
               s.audio_stream_status_pending == MSM5XXX_POC_AUDIO_STATUS_RESET);
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            c = Path(temporary) / "ma5-timer.c"
            binary = Path(temporary) / "ma5-timer"
            c.write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-pedantic", "-I" + str(native), str(c),
                    str(native / "msm5xxx-ma5-audio.c"),
                    str(native / "msm5xxx-ma5-pcm-queue.c"),
                    str(native / "msm5xxx-ma5-rateconv.c"),
                    str(native / "msm5xxx-ma5-pcm-output.c"),
                    "-o", str(binary)],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_partial_packet_writable_and_lifecycle(self):
        repo = Path(__file__).resolve().parents[1]
        native = repo / 'native/qemu'
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
        self.assertEqual(len(rejects), 12)
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
#include "msm5xxx-ma5-audio.h"
#include "msm5xxx-ma5-pcm-output.h"
#include "msm5xxx-ma5-wt-engine.h"
#include "msm5xxx-small-page-nand.h"
typedef uint64_t hwaddr;
typedef unsigned guint;
typedef int gboolean;
typedef unsigned GIOCondition;
#define G_IO_OUT 1u
#define G_IO_HUP 2u
#define G_IO_ERR 4u
#define G_IO_NVAL 8u
#define G_SOURCE_REMOVE 0
#define QEMU_CLOCK_VIRTUAL 0
typedef int QemuMutex;
typedef int CharFrontend;
typedef gboolean (*FEWatchFunc)(void *, GIOCondition, void *);
''' + constants + r'''
typedef struct {
    bool uart_console_mapped;
    bool sbi_raw_input_registered;
    MSM5xxxSmallPageNand small_nand;
    void *small_nand_timer, *small_nand_blk;
    uint8_t *small_nand_raw;
    void *spi_nv_timer, *spi_nv_blk;
    struct { void *image; } spi_nv;
    struct { bool initialized; void *image; } protected_nor;
    void *protected_nor_blk;
    CharFrontend audio_stream_chr;
    uint8_t audio_pcm_packet[MSM5XXX_POC_AUDIO_PACKET_SIZE];
    unsigned audio_pcm_length, audio_pcm_offset;
    guint audio_pcm_watch;
    bool audio_pcm_failed, audio_stream_rejected, audio_output_started;
    bool audio_reset_initialized, audio_core_lock_initialized;
    bool audio_synth_lock_initialized, audio_readback_rejection_reported;
    bool audio_stream_started, audio_irq_asserted, ma2_audio_timer_rejected;
    bool ma5_pcm_initialized, ma5_pcm_output_failed, ma5_pcm_output_reported;
    bool ma5_pcm_resync_pending;
    uint64_t ma5_pcm_timeline_gaps;
    char *audio_stream_chardev;
    QemuMutex audio_core_lock, audio_synth_lock;
    MSM5xxxAudioSynth audio_synth;
    MSM5xxxMA5PCMOutput ma5_pcm_output;
    MA5WTEngine *ma5_wt_engine;
    uint64_t ma5_byte_ns, ma5_clki_hz, ma5_target_rate_hz;
    MSM5xxxMA5Device ma5_device;
    uint16_t ma5_gpio_pending[3], ma5_parent_pending;
    bool ma5_irq_configured, ma5_irq_qualified, ma5_irq_level;
    unsigned ma5_irq_gate_status, ma5_commit_traces;
    void *ma2_audio_timer, *ma5_audio_timer, *audio_voice;
    void *search1_timer;
    char *search1_description;
    char *finger_description;
    void *decoder_init_timer;
    void *tx_init_timer;
    char *tx_init_description;
    char *decoder_init_description;
    char *decoder_sync_description;
    char *decoder_paging_description;
    char *decoder_traffic_description;
    char *decoder_traffic_frame_description;
    char *traffic_service_description;
    void *search2_timer;
    char *search2_probe_description;
    char *search2_virtual_description;
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
    bool dmd5100_enabled;
    uint16_t *dmd5100_even, *dmd5100_odd;
    int ma2_audio;
    void *watchdog_timer;
} MSM5xxxPOCMachineState;
typedef MSM5xxxPOCMachineState Object;
#define MSM5XXX_POC_MACHINE(obj) (obj)
static MSM5xxxPOCMachineState s;
static unsigned core_held, synth_held;
static guint active_watch, next_watch;
static unsigned additions, removals, write_calls;
static unsigned timer_frees, description_frees;
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
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *state) { (void)state; }
#define LOG_GUEST_ERROR 1
static void qemu_log_mask(int mask, const char *format, ...) { (void)mask; (void)format; }
static void msm5xxx_poc_ma5_commit_trace(void *opaque, const MSM5xxxMA5Commit *commit) {
    (void)opaque; (void)commit;
}
static void msm5xxx_poc_ma5_commit_consume(void *opaque, const MSM5xxxMA5Commit *commit) {
    msm5xxx_poc_ma5_commit_trace(opaque, commit);
}
static uint64_t qemu_clock_get_ns(int clock) { (void)clock; return 0; }
/* This audio fixture keeps optional NAND, SPI, UART and SBI raw-input paths disabled. */
static void msm5xxx_poc_spi_nv_sync(MSM5xxxPOCMachineState *state) {
    (void)state; assert(false);
}
static void msm5xxx_poc_sbi_raw_input_reset(void *opaque) { assert(false); }
static void msm5xxx_poc_uart_console_reset(void *opaque) { assert(false); }
static void msm5xxx_poc_dmd5100_reset(void *opaque) { assert(false); }
static void msm5xxx_poc_small_nand_reset(void *opaque) { assert(false); }
static void msm5xxx_poc_protected_reset(void *opaque) { assert(false); }
static void msm5xxx_poc_watchdog_reset(void *opaque) { assert(false); }
static void qemu_unregister_reset(void (*reset)(void *), void *opaque) {
    assert(false);
}
static bool msm5xxx_poc_small_nand_sync(MSM5xxxPOCMachineState *state,
                                      uint64_t now) { assert(false); return false; }
static void msm5xxx_poc_small_nand_poison(MSM5xxxPOCMachineState *state,
                                        const char *reason) { assert(false); }
static void blk_unref(void *backend) { assert(false); }
void ma5_wt_engine_reset(MA5WTEngine *engine, uint64_t origin) {
    (void)engine; (void)origin;
}
void ma5_wt_engine_free(MA5WTEngine *engine) { (void)engine; }
static void timer_del(void *timer) { (void)timer; assert(core_held); }
static void timer_free(void *timer) {
    assert(timer == s.ma5_audio_timer || timer == s.search2_timer || timer == s.search1_timer || timer == s.decoder_init_timer || timer == s.tx_init_timer); timer_frees++;
}
static void g_free(void *value) {
    if (value) { assert(value == s.search2_probe_description || value == s.search2_virtual_description || value == s.search1_description || value == s.finger_description || value == s.decoder_init_description || value == s.decoder_sync_description || value == s.decoder_paging_description || value == s.decoder_traffic_description || value == s.decoder_traffic_frame_description || value == s.tx_init_description || value == s.traffic_service_description); description_frees++; }
}
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
    timer_frees = description_frees = 0;
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
    s.ma5_audio_timer = &s.ma5_audio_timer;
    s.search1_timer = &s.search1_timer;
    s.search1_description = "legacy";
    s.finger_description = "finger";
    s.decoder_init_timer = &s.decoder_init_timer;
    s.decoder_init_description = "decoder";
    s.decoder_sync_description = "sync";
    s.decoder_paging_description = "paging";
    s.decoder_traffic_description = "traffic";
    s.decoder_traffic_frame_description = "decoded-frame";
    s.traffic_service_description = "service";
    s.tx_init_timer = &s.tx_init_timer;
    s.tx_init_description = "tx-init";
    s.search2_timer = &s;
    s.search2_probe_description = "probe";
    s.search2_virtual_description = "virtual";
    msm5xxx_poc_instance_finalize(&s);
    assert(!active_watch && !s.audio_pcm_watch && removals == 1);
    assert(timer_frees == 5 && description_frees == 11);

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
    setup();
    int16_t ma5_packet_storage[512 * 2], ma5_input[500 * 2];
    assert(msm5xxx_ma5_pcm_output_init(&s.ma5_pcm_output, ma5_packet_storage, 512) ==
           MSM5XXX_MA5_PCM_OK);
    for (unsigned i = 0; i < 500; i++) {
        ma5_input[i * 2] = 1000;
        ma5_input[i * 2 + 1] = -1000;
    }
    assert(msm5xxx_ma5_pcm_output_emit(&s.ma5_pcm_output, 1, 0, ma5_input, 500) ==
           MSM5XXX_MA5_PCM_OK);
    s.ma5_pcm_initialized = true;
    assert(s.ma5_pcm_output.queue.count == 459);
    assert(flush() == 1 && written_length == MSM5XXX_POC_AUDIO_PACKET_SIZE);
    assert(!memcmp(written_bytes, "M5P2\x02\0\0\0", 8));
    assert(written_bytes[8] == 1 && written_bytes[16] == 1 &&
           written_bytes[24] == 0 && s.ma5_pcm_output.queue.count == 18);
    setup(); s.ma5_byte_ns = 10; s.ma5_clki_hz = 19660800;
    s.ma5_commit_traces = 19;
    msm5xxx_poc_audio_reset(&s);
    assert(!s.ma5_commit_traces && s.ma5_device.commit_opaque == &s);
    assert(s.ma5_device.commit_sink == msm5xxx_poc_ma5_commit_consume);
    setup();
    int16_t ma5_storage[32];
    assert(msm5xxx_ma5_pcm_output_init(&s.ma5_pcm_output, ma5_storage, 16) ==
           MSM5XXX_MA5_PCM_OK);
    s.ma5_pcm_initialized = true;
    s.ma5_byte_ns = 10;
    msm5xxx_poc_audio_reset(&s);
    assert(s.ma5_pcm_output.queue.epoch == 2 &&
           s.ma5_pcm_output.rate.epoch == 2 &&
           s.audio_stream_reset_epoch == 2 && !s.ma5_pcm_output_failed);
    msm5xxx_poc_instance_finalize(&s);
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
                            str(native / 'msm5xxx-ma5-audio.c'),
                            str(native / 'msm5xxx-ma5-pcm-queue.c'),
                            str(native / 'msm5xxx-ma5-rateconv.c'),
                            str(native / 'msm5xxx-ma5-pcm-output.c'),
                            '-o', str(path / 'check')], check=True, timeout=30)
            subprocess.run([str(path / 'check')], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
