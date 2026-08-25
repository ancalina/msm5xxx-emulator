/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-audio-synth.h"

#include <limits.h>
#include <string.h>

#define MSM5XXX_AUDIO_ATTACK_STEP 149u
#define MSM5XXX_AUDIO_RELEASE_FRAMES 882u
#define MSM5XXX_AUDIO_TIMBRE_MODULATION_SCALE 65536

static void
audio_next_epoch(MSM5xxxAudioSynth *synth)
{
    synth->epoch = synth->epoch == UINT64_MAX ? 1u : synth->epoch + 1u;
}

static int16_t
audio_s16(int64_t value)
{
    if (value > INT16_MAX) {
        return INT16_MAX;
    }
    if (value < INT16_MIN) {
        return INT16_MIN;
    }
    return (int16_t)value;
}

static uint32_t
audio_note_step(uint8_t note)
{
    static const uint32_t base[12] = {
        796254u, 843601u, 893765u, 946911u,
        1003217u, 1062871u, 1126073u, 1193033u,
        1263974u, 1339134u, 1418763u, 1503127u,
    };
    unsigned octave = note / 12u;

    return base[note % 12u] << octave;
}

static uint32_t
audio_bent_step(uint32_t base, uint8_t bend)
{
    int32_t signed_bend = (int32_t)bend - 64;
    int64_t adjusted = (int64_t)base + (int64_t)base * signed_bend / 512;

    return adjusted > 0 ? (uint32_t)adjusted : 1u;
}

static int32_t
audio_triangle(uint32_t phase)
{
    uint32_t ramp = phase >> 16;

    return ramp < 32768u ? (int32_t)(ramp * 2u) - 32768 :
                           98303 - (int32_t)(ramp * 2u);
}

static int32_t
audio_sine(uint32_t phase)
{
    int32_t x = (int32_t)(phase >> 16u);
    int32_t absolute;
    int32_t sample;
    int32_t correction;

    if (x >= 32768) {
        x -= 65536;
    }
    absolute = x < 0 ? -x : x;
    sample = (int32_t)((int64_t)4 * x * (32768 - absolute) / 32768);
    correction = (int32_t)((int64_t)sample *
                           (sample < 0 ? -sample : sample) / 32768) - sample;
    sample += (int32_t)((int64_t)7373 * correction / 32768);
    return sample > 32767 ? 32767 : sample;
}

static uint32_t
audio_timbre_gain(uint8_t level)
{
    uint32_t gain = 32767u >> (level / 8u);

    return gain - (gain / 2u) * (level % 8u) / 8u;
}

static void
audio_timbre_advance_envelope(MSM5xxxAudioVoice *voice, size_t index,
                              uint64_t frames)
{
    uint32_t *envelope = &voice->timbre_envelope[index];
    uint8_t *state = &voice->timbre_envelope_state[index];
    uint64_t attack_frames;
    uint32_t factor;

    if (frames == 0u || *state == 0u) {
        return;
    }
    if (*state == 2u) {
        voice->timbre_phase[index] = 0u;
        *state = 3u;
        frames--;
    }
    if (*state == 3u && voice->timbre_attack_step[index] == 0u) {
        *state = 0u;
        return;
    }
    if (frames != 0u && *state == 3u &&
        voice->timbre_attack_step[index] != 0u) {
        attack_frames = (UINT64_C(0x80000000) - *envelope +
                         voice->timbre_attack_step[index] - 1u) /
                        voice->timbre_attack_step[index];
        if (frames < attack_frames) {
            *envelope += (uint32_t)(
                frames * voice->timbre_attack_step[index]);
            return;
        }
        *envelope = UINT32_C(0x80000000);
        *state = 4u;
        frames -= attack_frames;
    }
    if (frames == 0u || *state == 3u) {
        return;
    }
    if (*state == 4u) {
        *envelope = (uint32_t)((uint64_t)*envelope *
            voice->timbre_decay_factor[index] >> 30u);
        *state = *envelope == 0u ? 0u : 5u;
        if (--frames == 0u || *state == 0u) {
            return;
        }
    }
    factor = *state == 1u ? voice->timbre_release_factor[index] :
                            voice->timbre_sustain_factor[index];
    while (frames-- != 0u) {
        *envelope = (uint32_t)((uint64_t)*envelope * factor >> 30u);
        if (*envelope == 0u) {
            *state = 0u;
            return;
        }
    }
}

static int32_t
audio_timbre_operator(MSM5xxxAudioVoice *voice, size_t index,
                       int32_t modulation)
{
    uint32_t amplitude;
    uint32_t phase = voice->timbre_phase[index] +
                     (uint32_t)((int64_t)modulation *
                                MSM5XXX_AUDIO_TIMBRE_MODULATION_SCALE);
    int32_t sample;

    if (voice->timbre_envelope_state[index] == 0u) {
        return 0;
    }
    audio_timbre_advance_envelope(voice, index, 1u);
    amplitude = (uint32_t)((uint64_t)
        audio_timbre_gain(voice->timbre_level[index]) *
        (voice->timbre_envelope[index] >> 16u) >> 15u);
    sample = audio_sine(phase);

    sample = (int32_t)((int64_t)sample * amplitude >> 15u);
    voice->timbre_phase[index] +=
        voice->phase_step * voice->timbre_multiplier[index];
    return sample;
}

static int32_t
audio_timbre_sample(MSM5xxxAudioVoice *voice)
{
    int32_t first = audio_timbre_operator(voice, 0u, 0);
    int32_t second = audio_timbre_operator(voice, 2u, 0);
    size_t index;

    first = audio_timbre_operator(voice, 1u, first);
    second = audio_timbre_operator(voice, 3u, second);
    for (index = 0u; index < MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT; index++) {
        if (voice->timbre_envelope_state[index] != 0u) {
            return (first + second) / 2;
        }
    }
    voice->active = false;
    return (first + second) / 2;
}

static bool
audio_timbre_valid(const MSM5xxxAudioEvent *event)
{
    size_t index;

    if (!event->timbre_valid) {
        return true;
    }
    if (event->timbre_algorithm != 5u ||
        event->timbre_operator_count !=
            MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT) {
        return false;
    }
    for (index = 0u; index < MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT; index++) {
        if (event->timbre_multiplier[index] == 0u ||
            event->timbre_level[index] > 63u ||
            event->timbre_attack_step[index] > UINT32_C(0x80000000) ||
            event->timbre_decay_factor[index] == 0u ||
            event->timbre_decay_factor[index] > (UINT32_C(1) << 30u) ||
            event->timbre_sustain_factor[index] == 0u ||
            event->timbre_sustain_factor[index] > (UINT32_C(1) << 30u) ||
            event->timbre_release_factor[index] == 0u ||
            event->timbre_release_factor[index] >= (UINT32_C(1) << 30u)) {
            return false;
        }
    }
    return true;
}

static MSM5xxxAudioVoice *
audio_voice(MSM5xxxAudioSynth *synth, uint8_t voice_id, uint8_t channel,
            uint8_t note, bool allocate)
{
    MSM5xxxAudioVoice *free_voice = NULL;
    size_t index;

    for (index = 0u; index < MSM5XXX_AUDIO_VOICE_COUNT; index++) {
        MSM5xxxAudioVoice *voice = &synth->voice[index];

        if (voice->active && voice_id != 0u &&
            voice->voice_id == voice_id) {
            return voice;
        }
        if (voice->active && voice_id == 0u && !allocate &&
            voice->channel == channel && voice->note == note) {
            return voice;
        }
        if (!voice->active && free_voice == NULL) {
            free_voice = voice;
        }
    }
    return allocate ? free_voice : NULL;
}

static void
audio_release(MSM5xxxAudioVoice *voice)
{
    if (voice != NULL && voice->active && !voice->releasing) {
        size_t index;

        voice->releasing = true;
        if (voice->timbre_valid) {
            for (index = 0u; index < MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT;
                 index++) {
                if (voice->timbre_envelope_state[index] != 0u) {
                    voice->timbre_envelope_state[index] = 1u;
                }
            }
            return;
        }
        voice->release_step = (voice->envelope +
                               MSM5XXX_AUDIO_RELEASE_FRAMES - 1u) /
                              MSM5XXX_AUDIO_RELEASE_FRAMES;
        if (voice->release_step == 0u) {
            voice->release_step = 1u;
        }
    }
}

static void
audio_advance_envelope(MSM5xxxAudioVoice *voice, uint64_t frames)
{
    uint64_t change;

    if (!voice->active || frames == 0u) {
        return;
    }
    if (voice->timbre_valid) {
        return;
    }
    if (voice->releasing) {
        change = (uint64_t)voice->release_step * frames;
        if (change >= voice->envelope) {
            voice->active = false;
            voice->envelope = 0u;
        } else {
            voice->envelope -= (uint32_t)change;
        }
        return;
    }
    change = (uint64_t)MSM5XXX_AUDIO_ATTACK_STEP * frames;
    if (change >= 32767u - voice->envelope) {
        voice->envelope = 32767u;
    } else {
        voice->envelope += (uint32_t)change;
    }
}

static void
audio_drop(MSM5xxxAudioSynth *synth, size_t frames)
{
    frames = frames < synth->ring_count ? frames : synth->ring_count;
    synth->ring_read = (synth->ring_read + frames) % MSM5XXX_AUDIO_MAX_FRAMES;
    synth->ring_count -= frames;
    synth->ring_start_frame += frames;
}

static void
audio_make_room(MSM5xxxAudioSynth *synth, size_t frames)
{
    size_t dropped;

    if (synth->ring_count + frames <= MSM5XXX_AUDIO_MAX_FRAMES) {
        return;
    }
    dropped = synth->ring_count + frames - MSM5XXX_AUDIO_TARGET_FRAMES;
    audio_drop(synth, dropped);
    synth->overflow_frames += dropped;
    synth->output_frame = synth->ring_start_frame;
    audio_next_epoch(synth);
    synth->sequence = 0u;
}

static void
audio_skip_voice(MSM5xxxAudioVoice *voice, uint64_t frames)
{
    uint64_t frame;
    size_t index;

    if (!voice->active) {
        return;
    }
    if (voice->timbre_valid) {
        for (frame = 0u; frame < frames && voice->active; frame++) {
            bool active = false;

            for (index = 0u; index < MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT;
                 index++) {
                if (voice->timbre_envelope_state[index] == 0u) {
                    continue;
                }
                audio_timbre_advance_envelope(voice, index, 1u);
                voice->timbre_phase[index] +=
                    voice->phase_step * voice->timbre_multiplier[index];
                active = active ||
                         voice->timbre_envelope_state[index] != 0u;
            }
            voice->active = active;
        }
    } else {
        voice->phase += (uint32_t)((uint64_t)voice->phase_step * frames);
        audio_advance_envelope(voice, frames);
    }
}

static void
audio_skip(MSM5xxxAudioSynth *synth, uint64_t frames)
{
    size_t index;

    for (index = 0u; index < MSM5XXX_AUDIO_VOICE_COUNT; index++) {
        audio_skip_voice(&synth->voice[index], frames);
    }
    synth->generated_frame += frames;
}

static void
audio_render(MSM5xxxAudioSynth *synth, size_t frames)
{
    size_t frame;

    audio_make_room(synth, frames);
    for (frame = 0u; frame < frames; frame++) {
        int64_t left = 0;
        int64_t right = 0;
        size_t index;

        for (index = 0u; index < MSM5XXX_AUDIO_VOICE_COUNT; index++) {
            MSM5xxxAudioVoice *voice = &synth->voice[index];
            int32_t waveform;
            int64_t sample;

            if (!voice->active) {
                continue;
            }
            if (voice->timbre_valid) {
                waveform = audio_timbre_sample(voice);
            } else {
                waveform = audio_triangle(voice->phase);
                voice->phase += voice->phase_step;
            }
            sample = waveform;
            if (!voice->timbre_valid) {
                sample = sample * voice->envelope / 32767;
            }
            sample = sample * voice->velocity / 127;
            sample = sample * voice->volume / 127;
            sample = sample * voice->expression / 127;
            left += sample * (127u - voice->pan) / 127;
            right += sample * voice->pan / 127;
            audio_advance_envelope(voice, 1u);
        }
        synth->ring[synth->ring_write][0] = audio_s16(left);
        synth->ring[synth->ring_write][1] = audio_s16(right);
        synth->ring_write = (synth->ring_write + 1u) %
                            MSM5XXX_AUDIO_MAX_FRAMES;
        synth->ring_count++;
    }
    synth->generated_frame += frames;
}

void
msm5xxx_audio_synth_init(MSM5xxxAudioSynth *synth)
{
    if (synth == NULL) {
        return;
    }
    memset(synth, 0, sizeof(*synth));
    synth->epoch = 1u;
}

void
msm5xxx_audio_synth_reset(MSM5xxxAudioSynth *synth)
{
    uint64_t epoch;

    if (synth == NULL) {
        return;
    }
    epoch = synth->epoch == UINT64_MAX ? 1u : synth->epoch + 1u;
    memset(synth, 0, sizeof(*synth));
    synth->epoch = epoch;
}

void
msm5xxx_audio_synth_resync(MSM5xxxAudioSynth *synth)
{
    if (synth == NULL) {
        return;
    }
    synth->ring_read = 0u;
    synth->ring_write = 0u;
    synth->ring_count = 0u;
    synth->ring_start_frame = synth->generated_frame;
    synth->output_frame = synth->generated_frame;
    audio_next_epoch(synth);
    synth->sequence = 0u;
}

bool
msm5xxx_audio_synth_active(const MSM5xxxAudioSynth *synth)
{
    size_t index;

    if (synth == NULL) {
        return false;
    }
    for (index = 0u; index < MSM5XXX_AUDIO_VOICE_COUNT; index++) {
        if (synth->voice[index].active) {
            return true;
        }
    }
    return false;
}

bool
msm5xxx_audio_synth_advance(MSM5xxxAudioSynth *synth, uint64_t timestamp_ns)
{
    uint64_t delta;
    uint64_t frames;
    uint64_t fractional;

    if (synth == NULL) {
        return false;
    }
    if (!synth->clock_initialized) {
        synth->clock_initialized = true;
        synth->clock_ns = timestamp_ns;
        return true;
    }
    if (timestamp_ns < synth->clock_ns) {
        return false;
    }
    delta = timestamp_ns - synth->clock_ns;
    synth->clock_ns = timestamp_ns;
    frames = (delta / 1000000000u) * MSM5XXX_AUDIO_SAMPLE_RATE;
    fractional = (delta % 1000000000u) * MSM5XXX_AUDIO_SAMPLE_RATE +
                 synth->clock_remainder;
    frames += fractional / 1000000000u;
    synth->clock_remainder = fractional % 1000000000u;
    if (synth->generated_frame < synth->output_frame) {
        audio_skip(synth, synth->output_frame - synth->generated_frame);
    }
    /* M5P2 needs contiguous idle PCM; desktop callbacks do not. */
    if (!msm5xxx_audio_synth_active(synth) && synth->sequence == 0u &&
        synth->ring_count == 0u) {
        audio_skip(synth, frames);
        synth->ring_start_frame = synth->generated_frame;
        synth->output_frame = synth->generated_frame;
        return true;
    }
    if (frames > MSM5XXX_AUDIO_TARGET_FRAMES &&
        frames > MSM5XXX_AUDIO_MAX_FRAMES - synth->ring_count) {
        size_t dropped = synth->ring_count;

        audio_drop(synth, dropped);
        synth->overflow_frames += dropped +
                                  frames - MSM5XXX_AUDIO_TARGET_FRAMES;
        audio_next_epoch(synth);
        synth->sequence = 0u;
        audio_skip(synth, frames - MSM5XXX_AUDIO_TARGET_FRAMES);
        frames = MSM5XXX_AUDIO_TARGET_FRAMES;
        synth->ring_start_frame = synth->generated_frame;
        synth->output_frame = synth->ring_start_frame;
    }
    audio_render(synth, (size_t)frames);
    return true;
}

uint64_t
msm5xxx_audio_synth_clamp_event_timestamp(MSM5xxxAudioSynth *synth,
                                           uint64_t timestamp_ns)
{
    uint64_t lateness;

    if (synth == NULL || !synth->clock_initialized ||
        timestamp_ns >= synth->clock_ns) {
        if (synth != NULL) {
            synth->last_late_valid = false;
        }
        return timestamp_ns;
    }
    lateness = synth->clock_ns - timestamp_ns;
    synth->late_events++;
    if (synth->last_late_valid &&
        synth->last_late_target_ns == synth->clock_ns &&
        synth->last_late_timestamp_ns != timestamp_ns) {
        synth->collapsed_events++;
    }
    synth->max_lateness_ns = lateness > synth->max_lateness_ns ?
                             lateness : synth->max_lateness_ns;
    synth->last_late_timestamp_ns = timestamp_ns;
    synth->last_late_target_ns = synth->clock_ns;
    synth->last_late_valid = true;
    return synth->clock_ns;
}

bool
msm5xxx_audio_synth_event(MSM5xxxAudioSynth *synth,
                          uint64_t timestamp_ns,
                          const MSM5xxxAudioEvent *event)
{
    MSM5xxxAudioVoice *voice;
    size_t index;

    if (synth == NULL || event == NULL || event->channel >= 32u ||
        event->note >= 128u || event->velocity > 127u ||
        event->volume > 127u || event->pan > 127u ||
        event->expression > 127u || event->pitch_bend > 127u ||
        !audio_timbre_valid(event) ||
        !msm5xxx_audio_synth_advance(synth, timestamp_ns)) {
        return false;
    }
    if (event->kind == MSM5XXX_AUDIO_EVENT_ALL_OFF) {
        for (index = 0u; index < MSM5XXX_AUDIO_VOICE_COUNT; index++) {
            audio_release(&synth->voice[index]);
        }
        return true;
    }
    voice = audio_voice(synth, event->voice_id, event->channel, event->note,
                        event->kind == MSM5XXX_AUDIO_EVENT_NOTE_ON);
    switch (event->kind) {
    case MSM5XXX_AUDIO_EVENT_NOTE_ON:
        if (voice == NULL || event->velocity == 0u) {
            return voice != NULL;
        }
        memset(voice, 0, sizeof(*voice));
        voice->active = true;
        voice->voice_id = event->voice_id;
        voice->channel = event->channel;
        voice->note = event->note;
        voice->velocity = event->velocity;
        voice->volume = event->volume;
        voice->pan = event->pan;
        voice->expression = event->expression;
        voice->pitch_bend = event->pitch_bend;
        voice->timbre_valid = event->timbre_valid;
        voice->timbre_algorithm = event->timbre_algorithm;
        voice->timbre_operator_count = event->timbre_operator_count;
        memcpy(voice->timbre_multiplier, event->timbre_multiplier,
               sizeof(voice->timbre_multiplier));
        memcpy(voice->timbre_level, event->timbre_level,
               sizeof(voice->timbre_level));
        memcpy(voice->timbre_attack_step, event->timbre_attack_step,
               sizeof(voice->timbre_attack_step));
        memcpy(voice->timbre_decay_factor, event->timbre_decay_factor,
               sizeof(voice->timbre_decay_factor));
        memcpy(voice->timbre_sustain_factor,
               event->timbre_sustain_factor,
               sizeof(voice->timbre_sustain_factor));
        memcpy(voice->timbre_release_factor,
               event->timbre_release_factor,
               sizeof(voice->timbre_release_factor));
        if (voice->timbre_valid) {
            memset(voice->timbre_envelope_state, 2,
                   sizeof(voice->timbre_envelope_state));
        }
        voice->base_step = audio_note_step(event->note);
        voice->phase_step = audio_bent_step(voice->base_step,
                                            voice->pitch_bend);
        return true;
    case MSM5XXX_AUDIO_EVENT_NOTE_OFF:
        if (voice != NULL && voice->note == event->note) {
            audio_release(voice);
        }
        return true;
    case MSM5XXX_AUDIO_EVENT_CONTROL:
        for (index = 0u; index < MSM5XXX_AUDIO_VOICE_COUNT; index++) {
            voice = &synth->voice[index];
            if (!voice->active || voice->channel != event->channel) {
                continue;
            }
            voice->volume = event->volume;
            voice->pan = event->pan;
            voice->expression = event->expression;
            voice->pitch_bend = event->pitch_bend;
            voice->phase_step = audio_bent_step(voice->base_step,
                                                voice->pitch_bend);
        }
        return true;
    case MSM5XXX_AUDIO_EVENT_ALL_OFF:
        return true;
    }
    return false;
}

size_t
msm5xxx_audio_synth_read(MSM5xxxAudioSynth *synth, int16_t (*pcm)[2],
                         size_t frames, uint64_t *epoch, uint64_t *sequence,
                         uint64_t *start_frame)
{
    size_t frame;

    if (synth == NULL || pcm == NULL || frames == 0u ||
        frames > MSM5XXX_AUDIO_MAX_FRAMES) {
        return 0u;
    }
    if (synth->ring_start_frame < synth->output_frame) {
        uint64_t stale = synth->output_frame - synth->ring_start_frame;

        audio_drop(synth, stale > SIZE_MAX ? SIZE_MAX : (size_t)stale);
    }
    if (epoch != NULL) {
        *epoch = synth->epoch;
    }
    if (sequence != NULL) {
        *sequence = ++synth->sequence;
    }
    if (start_frame != NULL) {
        *start_frame = synth->output_frame;
    }
    for (frame = 0u; frame < frames; frame++) {
        if (synth->ring_count != 0u &&
            synth->ring_start_frame == synth->output_frame) {
            pcm[frame][0] = synth->ring[synth->ring_read][0];
            pcm[frame][1] = synth->ring[synth->ring_read][1];
            audio_drop(synth, 1u);
        } else {
            pcm[frame][0] = 0;
            pcm[frame][1] = 0;
            synth->underflow_frames++;
        }
        synth->output_frame++;
    }
    if (synth->ring_count == 0u) {
        synth->ring_start_frame = synth->output_frame;
    }
    return frames;
}
