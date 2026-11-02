/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma3-stream.h"

#include <math.h>
#include <string.h>

#define MA3_STREAM_BLOCK 1024u
#define MA3_STREAM_SAMPLE_OFFSET 0x20u
#define MA3_STREAM_SAMPLE_BYTES (MA3_STREAM_BLOCK - MA3_STREAM_SAMPLE_OFFSET)
#define MA3_STREAM_DESC_BYTES 13u

static uint64_t ma3_ns_to_frame(uint64_t ns)
{
    return (uint64_t)(((__uint128_t)ns * MSM5XXX_MA3_STREAM_OUTPUT_RATE) /
                      UINT64_C(1000000000));
}

static uint16_t ma3_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static bool ma3_stream_rate(uint16_t pitch, uint32_t *rate)
{
    unsigned fnum;
    unsigned block;
    double decoded;

    if (rate == NULL) {
        return false;
    }
    fnum = (unsigned)(pitch & 0x007fu) |
           (unsigned)((pitch >> 3) & 0x0380u);
    block = (unsigned)(pitch >> 7) & 7u;
    decoded = ldexp((double)(1024u + fnum), (int)block + 1) /
              (4096.0 * 4096.0 / (48000.0 * 256.0));
    if (!isfinite(decoded) || decoded < 1.0 ||
        decoded > (double)MSM5XXX_MA3_STREAM_INPUT_RATE_MAX + 1.0) {
        return false;
    }
    if (decoded > MSM5XXX_MA3_STREAM_INPUT_RATE_MAX) {
        decoded = MSM5XXX_MA3_STREAM_INPUT_RATE_MAX;
    }
    *rate = (uint32_t)floor(decoded + 0.5);
    return *rate != 0u;
}

void msm5xxx_ma3_stream_init(MSM5xxxMA3StreamEngine *engine,
                             MSM5xxxMA3StreamEmit emit, void *opaque)
{
    if (engine != NULL) {
        memset(engine, 0, sizeof(*engine));
        engine->emit = emit;
        engine->emit_opaque = opaque;
    }
}

void msm5xxx_ma3_stream_reset(MSM5xxxMA3StreamEngine *engine,
                              uint64_t epoch)
{
    MSM5xxxMA3StreamEmit emit;
    void *opaque;

    if (engine == NULL) {
        return;
    }
    emit = engine->emit;
    opaque = engine->emit_opaque;
    memset(engine, 0, sizeof(*engine));
    engine->emit = emit;
    engine->emit_opaque = opaque;
    engine->epoch = epoch;
}

static bool ma3_stream_start(MSM5xxxMA3StreamEngine *engine,
                             const MSM5xxxMA3Audio *device,
                             unsigned slot, uint8_t channel,
                             uint64_t timestamp_ns)
{
    MSM5xxxMA3StreamVoice *voice;
    unsigned reg_base;
    uint16_t descriptor_address;
    uint16_t start_address;
    uint16_t pitch;
    const uint8_t *descriptor;
    uint8_t mode;

    reg_base = 96u + slot * 6u;
    descriptor_address = (uint16_t)(
        (((uint16_t)(device->reg[reg_base] & 0x7fu) << 7) |
         (device->reg[reg_base + 1u] & 0x7fu)) * 2u);
    if (descriptor_address < 0x4000u ||
        descriptor_address + MA3_STREAM_DESC_BYTES >
            MSM5XXX_MA3_ADDRESS_SPACE) {
        engine->reject_reason = MSM5XXX_MA3_STREAM_BAD_DESCRIPTOR;
        engine->bad_descriptor_count++;
        return false;
    }
    descriptor = device->memory + descriptor_address;
    if (!(descriptor[0] & 0x02u)) {
        engine->reject_reason = MSM5XXX_MA3_STREAM_BAD_DESCRIPTOR;
        engine->bad_descriptor_count++;
        return false;
    }
    mode = descriptor[1] & 3u;
    if (mode != 0u && mode != 2u && mode != 3u) {
        engine->reject_reason = MSM5XXX_MA3_STREAM_UNSUPPORTED_FORMAT;
        engine->unsupported_format_count++;
        return false;
    }
    start_address = ma3_be16(descriptor + 7u);
    if (start_address < 0x4000u ||
        (uint32_t)start_address + MA3_STREAM_SAMPLE_BYTES >
            MSM5XXX_MA3_ADDRESS_SPACE) {
        engine->reject_reason = MSM5XXX_MA3_STREAM_BAD_DESCRIPTOR;
        engine->bad_descriptor_count++;
        return false;
    }
    pitch = (uint16_t)(((uint16_t)(device->reg[reg_base + 3u] & 0x7fu) << 7) |
                       (device->reg[reg_base + 4u] & 0x7fu));
    voice = &engine->voice[slot];
    memset(voice, 0, sizeof(*voice));
    if (!ma3_stream_rate(pitch, &voice->rate_hz)) {
        engine->reject_reason = MSM5XXX_MA3_STREAM_BAD_RATE;
        engine->bad_descriptor_count++;
        return false;
    }
    voice->slot = (uint8_t)slot;
    voice->channel = channel;
    voice->format = mode;
    voice->sample_start = start_address;
    voice->pan = (!(descriptor[0] & 0x01u) || (descriptor[1] & 4u)) ? 64u :
        (uint8_t)(((unsigned)((descriptor[0] >> 1) & 0x7cu) * 127u) / 124u);
    voice->active = true;
    if (mode == 0u) {
        msm5xxx_ma2_adpcm_decoder_reset(&voice->decoder);
    }
    if (!engine->clock_initialized) {
        engine->output_frame = ma3_ns_to_frame(timestamp_ns);
        engine->clock_initialized = true;
    }
    engine->reject_reason = MSM5XXX_MA3_STREAM_OK;
    return true;
}

bool msm5xxx_ma3_stream_operation(MSM5xxxMA3StreamEngine *engine,
                                  const MSM5xxxMA3Audio *device,
                                  const MSM5xxxMA3Operation *operation)
{
    unsigned address;
    unsigned relative;
    unsigned slot;

    if (engine == NULL || device == NULL || operation == NULL ||
        operation->kind != MSM5XXX_MA3_OP_REGISTER_WRITE) {
        return false;
    }
    address = operation->address;
    if (address < 96u || address >= 144u) {
        return true;
    }
    relative = address - 96u;
    if (relative % 6u != 5u) {
        return true;
    }
    slot = relative / 6u;
    if (slot >= MSM5XXX_MA3_STREAM_COUNT) {
        return true;
    }
    if (operation->value & 0x40u) {
        return ma3_stream_start(engine, device, slot,
                                operation->value & 0x0fu,
                                operation->timestamp_ns);
    }
    engine->voice[slot].active = false;
    return true;
}

static bool ma3_next_sample(MSM5xxxMA3StreamVoice *voice,
                            const MSM5xxxMA3Audio *device,
                            int16_t *sample)
{
    size_t address = 0;

    if (voice->byte_position >= MA3_STREAM_SAMPLE_BYTES) {
        voice->byte_position = 0;
    }
    for (;;) {
        uint8_t byte;
        if (voice->format == 2u || voice->format == 3u) {
            address = (size_t)voice->sample_start + voice->byte_position;
            if (address >= MSM5XXX_MA3_ADDRESS_SPACE) {
                return false;
            }
            byte = device->memory[address];
            if (voice->format == 2u) {
                *sample = (int16_t)(((int)byte - 128) * 256);
            } else {
                *sample = (int16_t)((int)(int8_t)byte * 256);
            }
            voice->byte_position++;
            return true;
        }

        address = (size_t)voice->sample_start + voice->byte_position;
        if (address >= MSM5XXX_MA3_ADDRESS_SPACE) {
            return false;
        }
        if (!voice->decoded_valid) {
            int16_t decoded[2];
            byte = device->memory[address];
            if (!msm5xxx_ma2_adpcm_decode_byte(&voice->decoder, byte,
                                               decoded)) {
                return false;
            }
            voice->decoded[0] = decoded[0];
            voice->decoded[1] = decoded[1];
            voice->decoded_valid = true;
            voice->nibble = 0u;
        }
        *sample = voice->decoded[voice->nibble];
        if (voice->nibble == 0u) {
            voice->nibble = 1u;
        } else {
            voice->nibble = 0u;
            voice->decoded_valid = false;
            voice->byte_position++;
        }
        return true;
    }
}

static int16_t ma3_sat16(int32_t value)
{
    if (value > INT16_MAX) {
        return INT16_MAX;
    }
    if (value < INT16_MIN) {
        return INT16_MIN;
    }
    return (int16_t)value;
}

static void ma3_stream_frame(MSM5xxxMA3StreamEngine *engine,
                             MSM5xxxMA3Audio *device,
                             int16_t output[2])
{
    int32_t left = 0;
    int32_t right = 0;
    unsigned slot;

    for (slot = 0u; slot < MSM5XXX_MA3_STREAM_COUNT; slot++) {
        MSM5xxxMA3StreamVoice *voice = &engine->voice[slot];
        int16_t sample;
        unsigned reg_base = 96u + slot * 6u;
        unsigned channel_volume;
        unsigned voice_volume;
        unsigned pan;

        if (!voice->active) {
            continue;
        }
        voice->phase += voice->rate_hz;
        while (voice->phase >= MSM5XXX_MA3_STREAM_OUTPUT_RATE) {
            voice->phase -= MSM5XXX_MA3_STREAM_OUTPUT_RATE;
            if (!ma3_next_sample(voice, device, &sample)) {
                voice->active = false;
                break;
            }
            voice->current_sample = sample;
            voice->played_samples++;
        }
        if (!voice->active) {
            continue;
        }
        sample = voice->current_sample;
        voice_volume = device->reg[reg_base + 2u] & 0x7cu;
        channel_volume = device->reg[144u + voice->channel] & 0x7cu;
        if (voice_volume > 124u) {
            voice_volume = 124u;
        }
        if (channel_volume > 124u) {
            channel_volume = 124u;
        }
        pan = voice->pan;
        sample = (int16_t)((int32_t)sample * (int32_t)voice_volume *
                           (int32_t)channel_volume / (124 * 124));
        left += (int32_t)sample * (int32_t)(127u - pan) / 127;
        right += (int32_t)sample * (int32_t)pan / 127;
        if (voice->format == 0u && voice->nibble == 0u &&
            !voice->decoded_valid) {
            voice->byte_position = (uint16_t)(voice->byte_position %
                                               MA3_STREAM_SAMPLE_BYTES);
        }
        if (voice->format == 2u || voice->format == 3u) {
            voice->byte_position = (uint16_t)(voice->byte_position %
                                               MA3_STREAM_SAMPLE_BYTES);
        }
        if (voice->format == 0u) {
            device->reg[330u + slot] =
                (uint8_t)(((voice->byte_position >> 4) & 0x3eu));
        } else {
            device->reg[330u + slot] =
                (uint8_t)(((voice->byte_position >> 5) & 0x1fu));
        }
    }
    output[0] = ma3_sat16(left);
    output[1] = ma3_sat16(right);
}

bool msm5xxx_ma3_stream_advance(MSM5xxxMA3StreamEngine *engine,
                                MSM5xxxMA3Audio *device,
                                uint64_t now_ns)
{
    uint64_t target;
    unsigned voice;
    bool active = false;

    if (engine == NULL || device == NULL) {
        return false;
    }
    target = ma3_ns_to_frame(now_ns);
    if (!engine->clock_initialized) {
        engine->output_frame = target;
        engine->clock_initialized = true;
        return true;
    }
    if (target < engine->output_frame) {
        return false;
    }
    for (voice = 0u; voice < MSM5XXX_MA3_STREAM_COUNT; voice++) {
        active |= engine->voice[voice].active;
    }
    if (!active) {
        engine->output_frame = target;
        return true;
    }
    while (engine->output_frame < target) {
        size_t frames = (size_t)(target - engine->output_frame);
        size_t index;

        if (frames > MSM5XXX_MA3_STREAM_CHUNK) {
            frames = MSM5XXX_MA3_STREAM_CHUNK;
        }
        for (index = 0u; index < frames; index++) {
            ma3_stream_frame(engine, device, engine->chunk[index]);
        }
        if (engine->emit != NULL) {
            if (!engine->emit(engine->emit_opaque, engine->output_frame,
                              (const int16_t *)engine->chunk, frames)) {
                engine->output_failures++;
                engine->reject_reason = MSM5XXX_MA3_STREAM_OUTPUT_FAILED;
            }
        }
        engine->output_frame += frames;
    }
    return true;
}
