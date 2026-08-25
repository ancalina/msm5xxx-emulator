/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_AUDIO_SYNTH_H
#define MSM5XXX_AUDIO_SYNTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSM5XXX_AUDIO_SAMPLE_RATE 44100u
#define MSM5XXX_AUDIO_CHUNK_FRAMES 441u
#define MSM5XXX_AUDIO_TARGET_FRAMES \
    (MSM5XXX_AUDIO_SAMPLE_RATE * 80u / 1000u)
#define MSM5XXX_AUDIO_MAX_FRAMES 11025u
#define MSM5XXX_AUDIO_VOICE_COUNT 32u
#define MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT 4u

typedef enum MSM5xxxAudioEventKind {
    MSM5XXX_AUDIO_EVENT_NOTE_ON = 0,
    MSM5XXX_AUDIO_EVENT_NOTE_OFF,
    MSM5XXX_AUDIO_EVENT_CONTROL,
    MSM5XXX_AUDIO_EVENT_ALL_OFF,
} MSM5xxxAudioEventKind;

typedef struct MSM5xxxAudioEvent {
    MSM5xxxAudioEventKind kind;
    uint8_t voice_id;
    uint8_t channel;
    uint8_t note;
    uint8_t velocity;
    uint8_t volume;
    uint8_t pan;
    uint8_t expression;
    uint8_t pitch_bend;
    uint8_t timbre_algorithm;
    uint8_t timbre_operator_count;
    uint8_t timbre_multiplier[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint8_t timbre_level[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_attack_step[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_decay_factor[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_sustain_factor[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_release_factor[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    bool timbre_valid;
} MSM5xxxAudioEvent;

typedef struct MSM5xxxAudioVoice {
    uint32_t phase;
    uint32_t base_step;
    uint32_t phase_step;
    uint32_t envelope;
    uint32_t release_step;
    uint8_t voice_id;
    uint8_t channel;
    uint8_t note;
    uint8_t velocity;
    uint8_t volume;
    uint8_t pan;
    uint8_t expression;
    uint8_t pitch_bend;
    uint8_t timbre_algorithm;
    uint8_t timbre_operator_count;
    uint8_t timbre_multiplier[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint8_t timbre_level[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_phase[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_envelope[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_attack_step[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_decay_factor[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_sustain_factor[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint32_t timbre_release_factor[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    uint8_t timbre_envelope_state[MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT];
    bool active;
    bool releasing;
    bool timbre_valid;
} MSM5xxxAudioVoice;

typedef struct MSM5xxxAudioSynth {
    MSM5xxxAudioVoice voice[MSM5XXX_AUDIO_VOICE_COUNT];
    int16_t ring[MSM5XXX_AUDIO_MAX_FRAMES][2];
    size_t ring_read;
    size_t ring_write;
    size_t ring_count;
    uint64_t ring_start_frame;
    uint64_t generated_frame;
    uint64_t output_frame;
    uint64_t clock_ns;
    uint64_t clock_remainder;
    uint64_t underflow_frames;
    uint64_t overflow_frames;
    uint64_t epoch;
    uint64_t sequence;
    uint64_t late_events;
    uint64_t collapsed_events;
    uint64_t max_lateness_ns;
    uint64_t last_late_timestamp_ns;
    uint64_t last_late_target_ns;
    bool clock_initialized;
    bool last_late_valid;
} MSM5xxxAudioSynth;

void msm5xxx_audio_synth_init(MSM5xxxAudioSynth *synth);
void msm5xxx_audio_synth_reset(MSM5xxxAudioSynth *synth);
void msm5xxx_audio_synth_resync(MSM5xxxAudioSynth *synth);
bool msm5xxx_audio_synth_active(const MSM5xxxAudioSynth *synth);
bool msm5xxx_audio_synth_event(MSM5xxxAudioSynth *synth,
                               uint64_t timestamp_ns,
                               const MSM5xxxAudioEvent *event);
bool msm5xxx_audio_synth_advance(MSM5xxxAudioSynth *synth,
                                 uint64_t timestamp_ns);
uint64_t msm5xxx_audio_synth_clamp_event_timestamp(
    MSM5xxxAudioSynth *synth, uint64_t timestamp_ns);
size_t msm5xxx_audio_synth_read(MSM5xxxAudioSynth *synth,
                                int16_t (*pcm)[2], size_t frames,
                                uint64_t *epoch, uint64_t *sequence,
                                uint64_t *start_frame);

#endif
