"""Actual native callback/packet/timer helpers, with only QEMU I/O modeled."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


def native_function(source, name):
    match = re.search(r'^static [^;\n]*\b' + name + r'\([^;]*?\)\n\{',
                      source, re.MULTILINE)
    if match is None:
        raise AssertionError(name)
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def drain_harness(source, baseline=False):
    constants = '\n'.join(re.findall(
        r'^#define MSM5XXX_POC_AUDIO_(?:PACKET_(?:HEADER|SIZE)|'
        r'STATUS_REJECTED) (?:[^\n]*\\\n)?[^\n]*', source, re.MULTILINE))
    return ('#define BASELINE ' + str(int(baseline)) + '\n' + r'''
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "msm5xxx-audio-synth.h"
#include "msm5xxx-ma5-pcm-output.h"
#include "msm5xxx-ma5-wt-engine.h"
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define QEMU_CLOCK_VIRTUAL 0
#define G_IO_OUT 1u
#define G_IO_HUP 2u
#define G_IO_ERR 4u
#define G_IO_NVAL 8u
#define G_SOURCE_REMOVE 0
typedef unsigned guint;
typedef unsigned GIOCondition;
typedef int gboolean;
typedef int QemuMutex;
typedef int CharFrontend;
typedef uint64_t hwaddr;
typedef gboolean (*FEWatchFunc)(void *, GIOCondition, void *);
typedef struct { bool pending; uint64_t expiry; } QEMUTimer;
''' + constants + r'''
typedef struct {
    bool ma5_pcm_initialized, ma5_pcm_output_failed, ma5_pcm_resync_pending;
    bool audio_core_lock_initialized, audio_synth_lock_initialized;
    bool audio_pcm_failed, audio_stream_rejected, audio_output_started;
    QemuMutex audio_core_lock, audio_synth_lock;
    MSM5xxxMA5PCMOutput ma5_pcm_output;
    MSM5xxxAudioSynth audio_synth;
    char *audio_stream_chardev;
    CharFrontend audio_stream_chr;
    void *audio_voice;
    unsigned audio_pcm_length, audio_pcm_offset;
    uint8_t audio_pcm_packet[MSM5XXX_POC_AUDIO_PACKET_SIZE];
    guint audio_pcm_watch;
    QEMUTimer *ma5_audio_timer;
    MSM5xxxMA5Device ma5_device;
    MA5WTEngine *ma5_wt_engine;
} MSM5xxxPOCMachineState;
static MSM5xxxPOCMachineState s;
static unsigned core_held, synth_held, activation_count, callbacks;
static guint active_watch, next_watch, additions;
static FEWatchFunc writable;
static void *writable_opaque;
static bool blocked, watch_supported;
static int responses[4];
static unsigned response_count, response_index, writes;
static uint8_t wire[120 * MSM5XXX_POC_AUDIO_PACKET_SIZE];
static size_t wire_length, peak_queue;
static uint64_t now;
static int16_t storage[MSM5XXX_AUDIO_MAX_FRAMES * 2], input[256 * 2];
static void qemu_mutex_lock(QemuMutex *lock) {
    if (lock == &s.audio_core_lock) { assert(!core_held && !synth_held); core_held=1; }
    else { assert(lock == &s.audio_synth_lock && !synth_held);
           assert(BASELINE || core_held); synth_held=1; }
}
static void qemu_mutex_unlock(QemuMutex *lock) {
    if (lock == &s.audio_core_lock) { assert(core_held && !synth_held); core_held=0; }
    else { assert(lock == &s.audio_synth_lock && synth_held); synth_held=0;
           if (s.ma5_pcm_output.queue.count > peak_queue)
               peak_queue=s.ma5_pcm_output.queue.count; }
}
static gboolean g_source_remove(guint id) {
    assert(core_held && !synth_held && id && active_watch==id);
    active_watch=0; return true;
}
static guint qemu_chr_fe_add_watch(CharFrontend *chr, GIOCondition flags,
                                  FEWatchFunc cb, void *opaque) {
    assert(chr==&s.audio_stream_chr && core_held && !synth_held && !active_watch);
    assert(flags==(G_IO_OUT|G_IO_HUP|G_IO_ERR|G_IO_NVAL));
    additions++;
    if (!watch_supported) return 0;
    writable=cb; writable_opaque=opaque;
    return active_watch=++next_watch;
}
static int qemu_chr_fe_write(CharFrontend *chr, const uint8_t *buf, int len) {
    assert(chr==&s.audio_stream_chr && core_held && !synth_held && len>0);
    writes++;
    int result = response_index<response_count ? responses[response_index++] :
                 blocked ? -1 : len;
    if (result<0) { errno=result==-1 ? EAGAIN : EIO; return -1; }
    assert(result<=len && wire_length+(size_t)result<=sizeof(wire));
    memcpy(wire+wire_length,buf,(size_t)result); wire_length+=(size_t)result;
    return result;
}
static void AUD_set_active_out(void *voice, bool active) {
    assert(voice==&s && active && core_held && !synth_held); activation_count++;
}
static uint64_t qemu_clock_get_ns(int clock) { assert(clock==0); return now; }
static void timer_del(QEMUTimer *timer) { timer->pending=false; }
static void timer_mod_ns(QEMUTimer *timer, int64_t due) {
    assert(due>=0); timer->pending=true; timer->expiry=(uint64_t)due;
}
static bool timer_pending(const QEMUTimer *timer) { return timer->pending; }
static uint64_t timer_expire_time_ns(const QEMUTimer *timer) { return timer->expiry; }
static gboolean msm5xxx_poc_audio_pcm_writable(void *, GIOCondition, void *);
''' + '\n'.join(native_function(source, name) for name in (
        'msm5xxx_poc_backing_write',
        'msm5xxx_poc_audio_pcm_prepare',
        'msm5xxx_poc_audio_pcm_cancel_watch',
        'msm5xxx_poc_audio_pcm_flush',
        'msm5xxx_poc_audio_pcm_writable',
        'msm5xxx_poc_ma5_pcm_emit',
        'msm5xxx_poc_ma5_audio_kick')) + r'''
static void setup(void) {
    assert(!core_held && !synth_held);
    /* Each case has an independent frontend lifetime. */
    active_watch=next_watch=additions=0;
    memset(&s,0,sizeof(s));
    s.ma5_pcm_initialized=s.audio_core_lock_initialized=true;
    s.audio_synth_lock_initialized=true;
    s.audio_stream_chardev="stream";
    assert(msm5xxx_ma5_pcm_output_init(&s.ma5_pcm_output,storage,
                                     MSM5XXX_AUDIO_MAX_FRAMES)==MSM5XXX_MA5_PCM_OK);
    msm5xxx_audio_synth_init(&s.audio_synth);
    assert(msm5xxx_ma5_device_init(&s.ma5_device,10));
    for (unsigned i=0;i<256;i++) { input[i*2]=1000; input[i*2+1]=-1000; }
    response_count=response_index=writes=activation_count=callbacks=0;
    wire_length=peak_queue=now=0; blocked=false; watch_supported=true;
}
static bool emit(uint64_t first, size_t frames) {
    callbacks++;
    bool accepted=msm5xxx_poc_ma5_pcm_emit(&s,first,input,frames);
    assert(!core_held && !synth_held); return accepted;
}
static void feed(uint64_t first, uint64_t end) {
    while (first<end) {
        size_t frames=(size_t)MIN(end-first,256);
        if (!emit(first,frames)) {
            fprintf(stderr,"burst rejected first=%"PRIu64" dropped=%"PRIu64
                    " queue=%zu\n",first,s.ma5_pcm_output.dropped_frames,
                    s.ma5_pcm_output.queue.count);
            assert(false);
        }
        first+=frames;
    }
}
static uint64_t le(const uint8_t *p, unsigned bytes) {
    uint64_t value=0;
    for (unsigned i=0;i<bytes;i++) value|=(uint64_t)p[i]<<(8*i);
    return value;
}
static void packets(size_t count) {
    assert(wire_length==count*MSM5XXX_POC_AUDIO_PACKET_SIZE);
    for (size_t i=0;i<count;i++) {
        const uint8_t *p=wire+i*MSM5XXX_POC_AUDIO_PACKET_SIZE;
        assert(!memcmp(p,"M5P2",4) && le(p+4,4)==2 && le(p+8,8)==1);
        assert(le(p+16,8)==i+1 && le(p+24,8)==i*441);
        for (unsigned j=0;j<441;j++) {
            assert(le(p+32+j*4,2)==1000 && le(p+34+j*4,2)==(uint16_t)-1000);
        }
    }
}
static void fire(GIOCondition condition) {
    assert(active_watch && active_watch==s.audio_pcm_watch);
    active_watch=0;
    assert(writable(NULL,condition,writable_opaque)==G_SOURCE_REMOVE);
    assert(!core_held && !synth_held && active_watch==s.audio_pcm_watch);
}
static bool reset_emit(void *opaque, uint64_t first, const int16_t *pcm, size_t n) {
    (void)opaque; (void)first; (void)pcm; (void)n;
    callbacks++; assert(!core_held); return true;
}
int main(void) {
    setup(); feed(0,48000); packets(100);
    assert(!s.ma5_pcm_output.failed && !s.ma5_pcm_output.dropped_frames);
    assert(!s.ma5_pcm_output.underflow_frames && !s.ma5_pcm_output.queue.count);
    assert(!s.audio_pcm_length && !active_watch && s.audio_output_started);
    assert(peak_queue==3528 && peak_queue<MSM5XXX_AUDIO_MAX_FRAMES);
    printf("fast-sink: 44100 contiguous frames, peak=%zu dropped=0\n",peak_queue);

    setup(); s.audio_voice=&s; feed(0,3839);
    assert(s.ma5_pcm_output.queue.count==3527 && !s.audio_output_started);
    assert(!wire_length && !activation_count);
    assert(emit(3839,1)); packets(8);
    assert(s.audio_output_started && activation_count==1);
    setup(); s.audio_stream_chardev=NULL; s.audio_voice=&s; feed(0,5000);
    assert(!writes && s.audio_output_started && activation_count==1);
    assert(s.ma5_pcm_output.queue.count==4593);

    setup(); responses[0]=17; responses[1]=-1; response_count=2;
    feed(0,3840);
    assert(wire_length==17 && s.audio_pcm_offset==17 && active_watch && additions==1);
    uint8_t pending[MSM5XXX_POC_AUDIO_PACKET_SIZE];
    memcpy(pending,s.audio_pcm_packet,sizeof(pending));
    blocked=true; assert(emit(3840,256));
    assert(s.audio_pcm_offset==17 && additions==1 && !memcmp(pending,s.audio_pcm_packet,sizeof(pending)));
    blocked=false; fire(G_IO_OUT); packets(8);
    assert(!active_watch && !s.audio_pcm_length);
    feed(4096,48000); packets(100);
    assert(!s.ma5_pcm_output.dropped_frames && !s.audio_pcm_failed);

    setup(); blocked=true; watch_supported=false; feed(0,3840);
    assert(s.audio_pcm_length && !active_watch && !s.audio_pcm_failed);
    blocked=false; assert(emit(3840,256)); packets(8);

    setup(); blocked=true;
    uint64_t first=0;
    while (first<48000 && emit(first,256)) first+=256;
    assert(first<48000 && s.ma5_pcm_output_failed && s.ma5_pcm_output.failed);
    assert(s.ma5_pcm_output.dropped_frames>0 && s.ma5_pcm_output.queue.count<=11025);
    assert(active_watch && s.audio_pcm_length && !wire_length);
    unsigned old_writes=writes;
    assert(!emit(first+256,256) && writes==old_writes);
    printf("sustained-backpressure: rejected at=%"PRIu64" dropped=%"PRIu64"\n",
           first,s.ma5_pcm_output.dropped_frames);

    setup(); responses[0]=-2; response_count=1;
    feed(0,3839); assert(!emit(3839,1));
    assert(s.audio_pcm_failed && !active_watch && !wire_length);
    old_writes=writes; assert(!emit(3840,256) && writes==old_writes);
    setup(); blocked=true; feed(0,3840); fire(G_IO_HUP);
    assert(s.audio_pcm_failed && !emit(3840,256));

    setup(); s.ma5_pcm_resync_pending=true; assert(!emit(0,256));
    s.ma5_pcm_resync_pending=false; s.ma5_pcm_initialized=false;
    assert(!emit(0,256) && !writes);
    s.audio_core_lock_initialized=false; assert(!emit(0,256));

    setup(); MA5WTEngine *engine=ma5_wt_engine_new(0,reset_emit,&s);
    assert(engine && !callbacks);
    qemu_mutex_lock(&s.audio_core_lock);
    ma5_wt_engine_reset(engine,1000000);
    qemu_mutex_unlock(&s.audio_core_lock);
    assert(!callbacks && !core_held && !synth_held);
    QEMUTimer timer={0}; s.ma5_audio_timer=&timer; s.ma5_wt_engine=engine;
    s.ma5_pcm_resync_pending=true;
    msm5xxx_poc_ma5_audio_kick(&s); assert(timer.pending && timer.expiry==5000000);
    for (now=1000000;now<5000000;now+=1000000) {
        msm5xxx_poc_ma5_audio_kick(&s); assert(timer.expiry==5000000);
    }
    s.ma5_pcm_resync_pending=false; msm5xxx_poc_ma5_audio_kick(&s);
    assert(!timer.pending); /* No work cancels even an earlier pending timer. */
    timer.pending=true; timer.expiry=1;
    s.ma5_device.count=1; s.ma5_device.next_ns=(uint64_t)INT64_MAX+1;
    msm5xxx_poc_ma5_audio_kick(&s);
    assert(!timer.pending && s.ma5_device.reject==MSM5XXX_MA5_REJECT_CLOCK);
    ma5_wt_engine_free(engine);
    puts("threshold/AUD, partial/EAGAIN/watch retry, fatal, reset and timer guards: PASS");
    return 0;
}
''')


NATIVE_SOURCES = (
    'msm5xxx-audio-synth.c', 'msm5xxx-ma2-audio.c', 'msm5xxx-ma5-pcm-output.c',
    'msm5xxx-ma5-pcm-queue.c', 'msm5xxx-ma5-rateconv.c',
    'msm5xxx-ma5-audio.c', 'msm5xxx-ma5-wt-engine.c',
    'msm5xxx-ma5-gain.c', 'msm5xxx-ma5-fm-voice.c',
    'msm5xxx-ma5-operator.c', 'msm5xxx-ma5-waveform.c',
)


class MA5PCMDrainNativeTests(unittest.TestCase):
    def test_callback_drains_bursts_and_keeps_backpressure_bounded(self):
        native = Path(__file__).resolve().parents[1] / 'experiments/qemu-tcg'
        machine = (native / 'msm5xxx-poc.c').read_text()
        # Reset holds core, but its engine operation must never reenter emit.
        reset = native_function(machine, 'msm5xxx_poc_audio_reset')
        self.assertIn('ma5_wt_engine_reset(', reset)
        self.assertNotIn('ma5_wt_engine_advance(', reset)
        self.assertNotIn('ma5_wt_engine_commit(', reset)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'drain.c'
            binary = Path(temporary) / 'drain'
            source.write_text(drain_harness(machine))
            compile_result = subprocess.run([
                'cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                '-Wno-unused-parameter',
                '-fsanitize=undefined', '-fno-sanitize-recover=all', '-O1',
                '-I' + str(native), str(source),
                *(str(native / name) for name in NATIVE_SOURCES),
                '-lm', '-o', str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run([str(binary)], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stderr, '')
            self.assertIn('44100 contiguous frames, peak=3528 dropped=0', result.stdout)


if __name__ == '__main__':
    unittest.main()
