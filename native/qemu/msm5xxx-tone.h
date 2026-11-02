/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_TONE_H
#define MSM5XXX_TONE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSM5XXX_TONE_CHANNELS 2u
#define MSM5XXX_TONE_REGISTER_BYTES 40u
#define MSM5XXX_TONE_SAMPLE_RATE 44100u
#define MSM5XXX_TONE_MAX_FRAMES 11025u

typedef struct MSM5xxxToneChannel {
    uint32_t phase;
    uint32_t clock_hz;
    uint16_t period;
    uint16_t high_ticks;
    uint32_t duty_q16;
    bool enabled;
} MSM5xxxToneChannel;

typedef struct MSM5xxxTone {
    uint8_t registers[MSM5XXX_TONE_REGISTER_BYTES];
    MSM5xxxToneChannel channel[MSM5XXX_TONE_CHANNELS];
    int16_t ring[MSM5XXX_TONE_MAX_FRAMES][2];
    size_t ring_read;
    size_t ring_write;
    size_t ring_count;
    uint64_t generated_frame;
    uint64_t output_frame;
    uint64_t clock_ns;
    uint64_t clock_remainder;
    uint64_t underflow_frames;
    uint64_t overflow_frames;
    uint64_t epoch;
    uint64_t sequence;
    bool clock_initialized;
} MSM5xxxTone;

typedef struct MSM5xxxToneMetadata {
    uint64_t epoch;
    uint64_t sequence;
    uint64_t start_frame;
} MSM5xxxToneMetadata;

void msm5xxx_tone_init(MSM5xxxTone *tone);
void msm5xxx_tone_reset(MSM5xxxTone *tone);
void msm5xxx_tone_resync(MSM5xxxTone *tone);
bool msm5xxx_tone_read_register(const MSM5xxxTone *tone, uint32_t offset,
                                unsigned size, uint8_t *value);
bool msm5xxx_tone_write(MSM5xxxTone *tone, uint32_t offset,
                        unsigned size, uint8_t value);
bool msm5xxx_tone_active(const MSM5xxxTone *tone);
bool msm5xxx_tone_advance(MSM5xxxTone *tone, uint64_t timestamp_ns);
bool msm5xxx_tone_fill_silence(MSM5xxxTone *tone, size_t frames);
size_t msm5xxx_tone_read_pcm(MSM5xxxTone *tone, int16_t (*pcm)[2],
                             size_t frames, MSM5xxxToneMetadata *metadata);

#endif
