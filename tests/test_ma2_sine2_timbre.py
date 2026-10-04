"""Exercise the actual native descriptor adapter and live synthesis state."""
from pathlib import Path
import subprocess
import tempfile
import unittest

CORE = Path(__file__).resolve().parents[1] / 'experiments/qemu-tcg'


class Sine2TimbreTests(unittest.TestCase):
    def test_descriptor_fallback_and_feedback_lifetime(self):
        source = (CORE / 'msm5xxx-poc.c').read_text()
        start = source.index('static bool msm5xxx_poc_ma2_timbre(')
        adapter = source[start:source.index('\nstatic bool ', start + 1)]
        code = r'''
#include <assert.h>
#include <limits.h>
#include <math.h>
#include <string.h>
#include "msm5xxx-ma2-audio.h"
#include "msm5xxx-audio-synth.h"
typedef struct { MSM5xxxMA2Audio ma2_audio; } MSM5xxxPOCMachineState;
''' + adapter + r'''
static const uint8_t descriptor[42] = {
    16,0,0,1,1,0,
    0,0,0,0,10,1,6,6,25,2,2,0,2,0,1,0,0,6,
    0,0,0,0,10,15,7,0,0,0,2,0,2,0,1,0,0,0
};
static MSM5xxxAudioEvent candidate(void) {
    MSM5xxxPOCMachineState s = {0};
    MSM5xxxMA2FMChannel channel = {.key_on=true, .active_voice_slot=0};
    MSM5xxxMA2FMVoice *voice = &s.ma2_audio.fm_voice[0];
    MSM5xxxAudioEvent event = {0};
    voice->valid = true; voice->operator_count = 2;
    memcpy(voice->decoded, descriptor, sizeof(descriptor));
    assert(msm5xxx_poc_ma2_timbre(&s, &channel, &event));
    assert(event.timbre_valid && event.timbre_algorithm == 0 &&
           event.timbre_operator_count == 2 && event.timbre_feedback == 6);
    assert(event.timbre_level[0] == 25 && event.timbre_level[1] == 0);
    assert(event.timbre_decay_threshold_valid);
    assert(event.timbre_decay_factor[0] < 0x40000000u &&
           event.timbre_decay_factor[0] > event.timbre_decay_factor[1]);
    assert(event.timbre_decay_threshold[0] > 0u &&
           event.timbre_decay_threshold[0] < 0x80000000u &&
           event.timbre_decay_threshold[1] == 0x80000000u);
    for (unsigned i=0; i<sizeof(descriptor); i++) {
        MSM5xxxAudioEvent rejected = {0};
        voice->decoded[i] ^= 1;
        assert(!msm5xxx_poc_ma2_timbre(&s, &channel, &rejected));
        assert(!rejected.timbre_valid);
        voice->decoded[i] ^= 1;
    }
    voice->operator_count = 4;
    assert(!msm5xxx_poc_ma2_timbre(&s, &channel, &event));
    voice->operator_count = 2; voice->valid = false;
    assert(!msm5xxx_poc_ma2_timbre(&s, &channel, &event));
    voice->valid = true; channel.key_on = false;
    assert(!msm5xxx_poc_ma2_timbre(&s, &channel, &event));
    channel.key_on = true;
    channel.active_voice_slot = MSM5XXX_MA2_FM_VOICE_COUNT;
    assert(!msm5xxx_poc_ma2_timbre(&s, &channel, &event));
    event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
    event.voice_id = 1; event.note = 69;
    event.velocity = event.volume = event.expression = 127;
    event.pan = event.pitch_bend = 64;
    return event;
}
int main(void) {
    MSM5xxxAudioEvent event = candidate();
    MSM5xxxAudioSynth whole, split, plain, skipped;
    MSM5xxxAudioVoice before;
    int16_t a[441][2], b[441][2];
    msm5xxx_audio_synth_init(&whole);
    assert(msm5xxx_audio_synth_event(&whole, 0, &event));
    assert(whole.voice[0].timbre_decay_threshold_valid);
    assert(memcmp(whole.voice[0].timbre_decay_threshold,
                  event.timbre_decay_threshold,
                  sizeof(event.timbre_decay_threshold)) == 0);
    assert(whole.voice[0].timbre_envelope_state[2] == 0 &&
           whole.voice[0].timbre_envelope_state[3] == 0);
    split = plain = whole;
    plain.voice[0].timbre_feedback = 0;
    assert(msm5xxx_audio_synth_advance(&whole, 10000000));
    assert(msm5xxx_audio_synth_advance(&split, 4000000));
    assert(msm5xxx_audio_synth_advance(&split, 10000000));
    assert(memcmp(&whole.voice[0], &split.voice[0], sizeof(before)) == 0);
    assert(msm5xxx_audio_synth_read(&whole, a, 441, NULL, NULL, NULL) == 441);
    assert(msm5xxx_audio_synth_read(&split, b, 441, NULL, NULL, NULL) == 441);
    assert(memcmp(a, b, sizeof(a)) == 0);
    assert(msm5xxx_audio_synth_advance(&plain, 10000000));
    assert(msm5xxx_audio_synth_read(&plain, b, 441, NULL, NULL, NULL) == 441);
    assert(memcmp(a, b, sizeof(a)) != 0);

    /* Overflow discards PCM, but must evolve the same feedback history. */
    skipped = whole;
    assert(msm5xxx_audio_synth_advance(&skipped, 1010000000));
    for (unsigned i=1; i<=100; i++) {
        assert(msm5xxx_audio_synth_advance(&whole, 10000000 + (uint64_t)i*10000000));
        assert(msm5xxx_audio_synth_read(&whole, b, 441, NULL, NULL, NULL) == 441);
    }
    assert(memcmp(&whole.voice[0], &skipped.voice[0], sizeof(before)) == 0);

    before = whole.voice[0];
    msm5xxx_audio_synth_resync(&whole);
    assert(memcmp(&whole.voice[0], &before, sizeof(before)) == 0);
    event.kind = MSM5XXX_AUDIO_EVENT_CONTROL; event.volume = 60;
    assert(msm5xxx_audio_synth_event(&whole, 1010000000, &event));
    assert(memcmp(whole.voice[0].timbre_feedback_history,
                  before.timbre_feedback_history, sizeof(before.timbre_feedback_history)) == 0);
    event.kind = MSM5XXX_AUDIO_EVENT_NOTE_OFF;
    assert(msm5xxx_audio_synth_event(&whole, 1010000000, &event));
    assert(whole.voice[0].releasing);
    assert(memcmp(whole.voice[0].timbre_feedback_history,
                  before.timbre_feedback_history, sizeof(before.timbre_feedback_history)) == 0);
    split = skipped = whole;
    uint32_t release_start[2] = {whole.voice[0].timbre_envelope[0],
                                 whole.voice[0].timbre_envelope[1]};
    assert(msm5xxx_audio_synth_advance(&whole, 1040000000));
    assert(msm5xxx_audio_synth_advance(&split, 1020000000));
    assert(msm5xxx_audio_synth_advance(&split, 1040000000));
    assert(memcmp(&whole.voice[0], &split.voice[0], sizeof(before)) == 0);
    assert(msm5xxx_audio_synth_active(&whole));
    for (unsigned i=0; i<2; i++) {
        assert(whole.voice[0].timbre_envelope[i] > 0);
        assert(whole.voice[0].timbre_envelope[i] < release_start[i]);
    }
    assert(msm5xxx_audio_synth_advance(&skipped, 2010000000));
    for (unsigned tick=105; tick<=201; tick++) {
        assert(msm5xxx_audio_synth_advance(&whole,(uint64_t)tick*10000000));
        while (whole.ring_count>=441) {
            assert(msm5xxx_audio_synth_read(&whole,b,441,NULL,NULL,NULL)==441);
        }
    }
    assert(!msm5xxx_audio_synth_active(&whole));
    assert(memcmp(&whole.voice[0], &skipped.voice[0], sizeof(before)) == 0);

    event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
    assert(msm5xxx_audio_synth_event(&whole, 2010000000, &event));
    assert(whole.voice[0].timbre_feedback_history[0] == 0 &&
           whole.voice[0].timbre_feedback_history[1] == 0);
    /* Widen signed history arithmetic before multiplying phase units. */
    whole.voice[0].timbre_feedback_history[0] = INT32_MIN;
    whole.voice[0].timbre_feedback_history[1] = INT32_MIN;
    assert(msm5xxx_audio_synth_advance(&whole, 2010022676));
    whole.voice[0].timbre_feedback_history[0] = INT32_MAX;
    whole.voice[0].timbre_feedback_history[1] = INT32_MAX;
    assert(msm5xxx_audio_synth_advance(&whole, 2010045352));
    msm5xxx_audio_synth_reset(&whole);
    assert(!msm5xxx_audio_synth_active(&whole));
    assert(whole.voice[0].timbre_feedback_history[0] == 0 &&
           whole.voice[0].timbre_feedback_history[1] == 0);

    for (unsigned i=0; i<3; i++) {
        MSM5xxxAudioEvent bad = event;
        if (i == 0) bad.timbre_feedback = 7;
        if (i == 1) bad.timbre_operator_count = 4;
        if (i == 2) bad.timbre_algorithm = 1;
        assert(!msm5xxx_audio_synth_event(&whole, 0, &bad));
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            harness, binary = Path(directory) / 'check.c', Path(directory) / 'check'
            harness.write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', '-fno-sanitize-recover=all',
                            '-I', str(CORE), str(harness),
                            str(CORE / 'msm5xxx-audio-synth.c'), '-lm', '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_prepared_decay_threshold_boundaries(self):
        code = r'''
#include <assert.h>
#include <string.h>
#include "msm5xxx-audio-synth.c"
int main(void) {
    MSM5xxxAudioVoice voice = {0}, split;
    MSM5xxxAudioSynth synth, before;
    MSM5xxxAudioEvent event = {0};
    const uint32_t full = UINT32_C(0x80000000);
    voice.timbre_decay_threshold_valid = true;
    voice.timbre_envelope_state[0] = 4;
    voice.timbre_envelope[0] = full;
    voice.timbre_decay_factor[0] = UINT32_C(0x20000000);
    voice.timbre_decay_threshold[0] = full / 4;
    voice.timbre_sustain_factor[0] = UINT32_C(0x20000000);
    split = voice;
    audio_timbre_advance_envelope(&voice, 0, 1);
    assert(voice.timbre_envelope[0] == full/2 &&
           voice.timbre_envelope_state[0] == 4);
    audio_timbre_advance_envelope(&voice, 0, 1);
    assert(voice.timbre_envelope[0] == full/4 &&
           voice.timbre_envelope_state[0] == 5);
    audio_timbre_advance_envelope(&voice, 0, 1);
    audio_timbre_advance_envelope(&split, 0, 3);
    assert(voice.timbre_envelope[0] == full/8 &&
           memcmp(&voice, &split, sizeof(voice)) == 0);
    /* Crossing keeps the computed amplitude; no clamp up to threshold. */
    voice.timbre_envelope[0] = full;
    voice.timbre_envelope_state[0] = 4;
    voice.timbre_decay_threshold[0] = full/2 + 1;
    audio_timbre_advance_envelope(&voice, 0, 1);
    assert(voice.timbre_envelope[0] == full/2 &&
           voice.timbre_envelope_state[0] == 5);
    voice.timbre_envelope_state[0] = 4;
    voice.timbre_envelope[0] = full;
    voice.timbre_decay_threshold[0] = 0;
    audio_timbre_advance_envelope(&voice, 0, 32);
    assert(voice.timbre_envelope[0] == 0 &&
           voice.timbre_envelope_state[0] == 0);
    voice.timbre_envelope_state[0] = 4;
    voice.timbre_envelope[0] = full;
    voice.timbre_decay_threshold[0] = full/4;
    voice.timbre_decay_factor[0] = UINT32_C(0x40000000);
    audio_timbre_advance_envelope(&voice, 0, 100);
    assert(voice.timbre_envelope[0] == full &&
           voice.timbre_envelope_state[0] == 4);
    /* The legacy path still leaves decay after its first sample. */
    voice.timbre_decay_threshold_valid = false;
    audio_timbre_advance_envelope(&voice, 0, 1);
    assert(voice.timbre_envelope[0] == full &&
           voice.timbre_envelope_state[0] == 5);

    event.timbre_valid = event.timbre_decay_threshold_valid = true;
    event.timbre_algorithm = 0; event.timbre_operator_count = 2;
    event.note = 60;
    event.velocity = event.volume = event.expression = 127;
    event.pan = event.pitch_bend = 64;
    for (unsigned i=0; i<4; i++) {
        event.timbre_multiplier[i] = 1;
        event.timbre_attack_step[i] = 1;
        event.timbre_decay_factor[i] = UINT32_C(0x20000000);
        event.timbre_sustain_factor[i] = UINT32_C(0x40000000);
        event.timbre_release_factor[i] = UINT32_C(0x20000000);
    }
    assert(audio_timbre_valid(&event)); /* Zero threshold is valid. */
    msm5xxx_audio_synth_init(&synth);
    for (unsigned i=0; i<4; i++) {
        MSM5xxxAudioEvent bad = event;
        if (i==0) bad.timbre_decay_threshold[1] = full+1;
        if (i==1) { bad.timbre_algorithm=5; bad.timbre_operator_count=4; }
        if (i==2) bad.timbre_valid=false;
        if (i==3) bad.timbre_operator_count=4;
        before=synth;
        assert(!msm5xxx_audio_synth_event(&synth, 1000000000, &bad));
        assert(memcmp(&before, &synth, sizeof(synth)) == 0);
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            harness, binary = Path(directory) / 'check.c', Path(directory) / 'check'
            harness.write_text(code)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', '-fno-sanitize-recover=all',
                            '-I', str(CORE), str(harness), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    unittest.main()
