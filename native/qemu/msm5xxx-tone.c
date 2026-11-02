/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-tone.h"

#include <limits.h>
#include <string.h>

#define TONE_BASE_CLOCK_HZ 307500u
#define TONE_ENABLE 0x40u
#define TONE_AMPLITUDE 7000

static int16_t tone_saturate(int32_t sample)
{
    if (sample > INT16_MAX) {
        return INT16_MAX;
    }
    if (sample < INT16_MIN) {
        return INT16_MIN;
    }
    return (int16_t)sample;
}

static uint16_t tone_word(const MSM5xxxTone *tone, unsigned channel,
                          unsigned reg)
{
    unsigned base = channel * 20u + reg * 4u;

    return (uint16_t)tone->registers[base] |
           (uint16_t)((uint16_t)tone->registers[base + 4u] << 8u);
}

static void tone_update_channel(MSM5xxxTone *tone, unsigned channel)
{
    MSM5xxxToneChannel *state = &tone->channel[channel];
    unsigned base = channel * 20u;
    uint8_t control = tone->registers[base + 16u];
    unsigned selector = control & 0x3fu;
    uint16_t q = tone_word(tone, channel, 0u);
    uint16_t reload = tone_word(tone, channel, 2u);
    uint32_t period = (uint16_t)~reload + selector;
    bool enabled = (control & TONE_ENABLE) && selector && period;
    bool was_enabled = state->enabled;

    if (!enabled) {
        state->enabled = false;
        state->clock_hz = 0u;
        state->period = 0u;
        state->high_ticks = 0u;
        state->duty_q16 = 0u;
        return;
    }
    state->clock_hz = TONE_BASE_CLOCK_HZ * selector;
    state->period = period;
    state->high_ticks = q >= period ? period : q;
    state->duty_q16 = q >= period ? 65536u :
                      (uint32_t)(((uint64_t)q << 16u) / period);
    state->enabled = true;
    if (!was_enabled) {
        state->phase = 0u;
    }
}

void msm5xxx_tone_init(MSM5xxxTone *tone)
{
    if (tone) {
        memset(tone, 0, sizeof(*tone));
        tone->epoch = 1u;
    }
}

void msm5xxx_tone_reset(MSM5xxxTone *tone)
{
    msm5xxx_tone_init(tone);
}

void msm5xxx_tone_resync(MSM5xxxTone *tone)
{
    if (!tone) {
        return;
    }
    tone->ring_read = 0u;
    tone->ring_write = 0u;
    tone->ring_count = 0u;
    tone->output_frame = tone->generated_frame;
    tone->epoch = tone->epoch == UINT64_MAX ? 1u : tone->epoch + 1u;
    tone->sequence = 0u;
}

bool msm5xxx_tone_read_register(const MSM5xxxTone *tone, uint32_t offset,
                                unsigned size, uint8_t *value)
{
    if (!tone || !value || size != 1u || offset >= MSM5XXX_TONE_REGISTER_BYTES ||
        (offset & 3u)) {
        return false;
    }
    *value = tone->registers[offset];
    return true;
}

bool msm5xxx_tone_write(MSM5xxxTone *tone, uint32_t offset,
                        unsigned size, uint8_t value)
{
    unsigned channel;
    unsigned reg;

    if (!tone || size != 1u || offset >= MSM5XXX_TONE_REGISTER_BYTES ||
        (offset & 3u)) {
        return false;
    }
    tone->registers[offset] = value;
    channel = offset / 20u;
    reg = offset % 20u;
    if (channel >= MSM5XXX_TONE_CHANNELS || (reg & 3u) || reg > 16u) {
        return false;
    }
    tone_update_channel(tone, channel);
    return true;
}

bool msm5xxx_tone_active(const MSM5xxxTone *tone)
{
    return tone && (tone->channel[0].enabled || tone->channel[1].enabled);
}

static void tone_render(MSM5xxxTone *tone, size_t frames)
{
    size_t requested = frames;
    size_t available = MSM5XXX_TONE_MAX_FRAMES - tone->ring_count;
    size_t frame;

    if (frames > available) {
        size_t skip = frames > MSM5XXX_TONE_MAX_FRAMES ?
                      frames - MSM5XXX_TONE_MAX_FRAMES : 0u;
        unsigned channel;

        tone->overflow_frames += tone->ring_count + skip;
        tone->output_frame = tone->generated_frame + skip;
        tone->ring_read = 0u;
        tone->ring_write = 0u;
        tone->ring_count = 0u;
        tone->epoch = tone->epoch == UINT64_MAX ? 1u : tone->epoch + 1u;
        tone->sequence = 0u;
        for (channel = 0; channel < MSM5XXX_TONE_CHANNELS; channel++) {
            MSM5xxxToneChannel *state = &tone->channel[channel];

            if (state->enabled && state->period) {
                uint64_t advance = ((uint64_t)state->clock_hz << 32u) /
                    ((uint64_t)state->period * MSM5XXX_TONE_SAMPLE_RATE);

                state->phase += (uint32_t)(advance * skip);
            }
        }
        frames -= skip;
    }
    for (frame = 0; frame < frames; frame++) {
        int32_t sample = 0;
        unsigned channel;

        for (channel = 0; channel < MSM5XXX_TONE_CHANNELS; channel++) {
            MSM5xxxToneChannel *state = &tone->channel[channel];
            uint64_t advance;

            if (!state->enabled || !state->period) {
                continue;
            }
            sample += (uint64_t)state->phase * state->period <
                      ((uint64_t)state->high_ticks << 32u) ?
                      TONE_AMPLITUDE : -TONE_AMPLITUDE;
            advance = ((uint64_t)state->clock_hz << 32u) /
                      ((uint64_t)state->period * MSM5XXX_TONE_SAMPLE_RATE);
            state->phase += (uint32_t)advance;
        }
        tone->ring[tone->ring_write][0] = tone_saturate(sample);
        tone->ring[tone->ring_write][1] = tone_saturate(sample);
        tone->ring_write = (tone->ring_write + 1u) % MSM5XXX_TONE_MAX_FRAMES;
        tone->ring_count++;
    }
    tone->generated_frame += requested;
}

bool msm5xxx_tone_advance(MSM5xxxTone *tone, uint64_t timestamp_ns)
{
    uint64_t delta;
    uint64_t frames;
    uint64_t fractional;

    if (!tone) {
        return false;
    }
    if (!tone->clock_initialized) {
        tone->clock_initialized = true;
        tone->clock_ns = timestamp_ns;
        return true;
    }
    if (timestamp_ns < tone->clock_ns) {
        return false;
    }
    delta = timestamp_ns - tone->clock_ns;
    tone->clock_ns = timestamp_ns;
    frames = (delta / UINT64_C(1000000000)) * MSM5XXX_TONE_SAMPLE_RATE;
    fractional = (delta % UINT64_C(1000000000)) * MSM5XXX_TONE_SAMPLE_RATE +
                 tone->clock_remainder;
    frames += fractional / UINT64_C(1000000000);
    tone->clock_remainder = fractional % UINT64_C(1000000000);
    if (msm5xxx_tone_active(tone)) {
        tone_render(tone, frames);
    } else {
        tone->generated_frame += frames;
        if (!tone->ring_count) {
            tone->output_frame = tone->generated_frame;
        }
    }
    return true;
}

size_t msm5xxx_tone_read_pcm(MSM5xxxTone *tone, int16_t (*pcm)[2],
                             size_t frames, MSM5xxxToneMetadata *metadata)
{
    size_t count;
    size_t frame;

    if (!tone || !pcm) {
        return 0u;
    }
    count = frames < tone->ring_count ? frames : tone->ring_count;
    if (metadata) {
        metadata->epoch = tone->epoch;
        metadata->sequence = ++tone->sequence;
        metadata->start_frame = tone->output_frame;
    }
    for (frame = 0; frame < count; frame++) {
        pcm[frame][0] = tone->ring[tone->ring_read][0];
        pcm[frame][1] = tone->ring[tone->ring_read][1];
        tone->ring_read = (tone->ring_read + 1u) % MSM5XXX_TONE_MAX_FRAMES;
    }
    tone->ring_count -= count;
    tone->output_frame += count;
    tone->underflow_frames += frames - count;
    return count;
}

bool msm5xxx_tone_fill_silence(MSM5xxxTone *tone, size_t frames)
{
    size_t frame;

    if (!tone || frames > MSM5XXX_TONE_MAX_FRAMES - tone->ring_count) {
        return false;
    }
    for (frame = 0; frame < frames; frame++) {
        tone->ring[tone->ring_write][0] = 0;
        tone->ring[tone->ring_write][1] = 0;
        tone->ring_write = (tone->ring_write + 1u) % MSM5XXX_TONE_MAX_FRAMES;
        tone->ring_count++;
    }
    tone->generated_frame += frames;
    return true;
}
