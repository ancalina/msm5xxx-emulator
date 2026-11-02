/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma3-render.h"
#include "msm5xxx-ma5-fm-voice.h"

#include <math.h>
#include <string.h>

#define MA3_FM_SLOT_COUNT 32u
#define MA3_WT_SLOT_FIRST 32u
#define MA3_REGISTER_FM_FIRST 0u
#define MA3_REGISTER_FM_EXT 224u
#define MA3_REGISTER_WT 96u

static uint8_t ma3_scale_7bit(uint8_t value)
{
    unsigned scaled = (unsigned)(value & 0x7cu) * 127u / 124u;

    return (uint8_t)(scaled > 127u ? 127u : scaled);
}

static bool ma3_pitch_to_note(uint16_t pitch, unsigned base_octave,
                              uint8_t *note)
{
    unsigned fnum;
    unsigned block;
    double freq;
    double midi;
    long rounded;

    if (note == NULL) {
        return false;
    }
    fnum = (unsigned)(pitch & 0x007fu) |
           (unsigned)((pitch >> 3) & 0x0380u);
    block = (unsigned)(pitch >> 7) & 7u;
    /* Firmware pitch words encode (1024 + fnum) * 2^(block + 1)
     * in the sequencer's 48 kHz fixed-point scale. */
    freq = ldexp((double)(1024u + fnum),
                 (int)block + 1 - (int)base_octave) /
           (4096.0 * 4096.0 / (48000.0 * 256.0));
    if (!isfinite(freq) || freq <= 0.0) {
        return false;
    }
    midi = 69.0 + 12.0 * log2(freq / 440.0);
    rounded = lround(midi);
    if (rounded < 0) {
        rounded = 0;
    } else if (rounded > 127) {
        rounded = 127;
    }
    *note = (uint8_t)rounded;
    return true;
}

static uint32_t ma3_eg_factor_q30(unsigned setting, unsigned offset)
{
    static const double base_ms[4] = {5.25, 4.2, 3.5, 3.0};
    unsigned rate;
    double milliseconds;
    double factor;

    if (setting == 0u) {
        return UINT32_C(1) << 30u;
    }
    rate = 4u * setting + offset;
    if (rate > 63u) {
        rate = 63u;
    }
    if (rate < 4u) {
        return UINT32_C(1) << 30u;
    }
    milliseconds = rate >= 60u ? 2.625 :
        base_ms[rate & 3u] * ldexp(1.0, (int)(59u - rate) / 4);
    factor = pow(10.0, -96.0 /
                 (20.0 * milliseconds * MSM5XXX_AUDIO_SAMPLE_RATE / 1000.0));
    return (uint32_t)floor(factor * (UINT32_C(1) << 30u) + 0.5);
}

static uint32_t ma3_sustain_threshold(unsigned level)
{
    double attenuation = level == 15u ? 93.0 : 3.0 * level;
    double threshold = pow(10.0, -attenuation / 20.0) * 2147483648.0;

    return (uint32_t)floor(threshold + 0.5);
}

static bool ma3_decode_voice(const MSM5xxxMA3Audio *device,
                             uint16_t voice_address,
                             uint16_t pitch,
                             MSM5xxxAudioEvent *event,
                             MSM5xxxMA3Renderer *renderer)
{
    size_t address;
    unsigned operator_count;
    unsigned algorithm;
    unsigned index;
    unsigned fnum;
    unsigned block;
    unsigned key_scale;
    bool half_multiplier = false;
    const uint8_t *patch;

    address = (size_t)voice_address * 2u;
    if (address < 0x4000u || address + 30u > MSM5XXX_MA3_ADDRESS_SPACE) {
        renderer->reject_reason =
            MSM5XXX_MA3_RENDER_UNSUPPORTED_ROM_VOICE;
        renderer->unsupported_rom_voices++;
        return false;
    }
    patch = device->memory + address;
    if ((patch[0] & 0x80u) == 0u) {
        renderer->reject_reason =
            MSM5XXX_MA3_RENDER_UNSUPPORTED_ROM_VOICE;
        renderer->unsupported_rom_voices++;
        return false;
    }
    algorithm = patch[1] & 7u;
    operator_count = algorithm < 2u ? 2u : 4u;

    fnum = (unsigned)(pitch & 0x007fu) |
           (unsigned)((pitch >> 3) & 0x0380u);
    block = (unsigned)(pitch >> 7) & 7u;
    key_scale = 2u * block + (fnum >> 9);
    if (!ma3_pitch_to_note(pitch, patch[0] & 3u, &event->note)) {
        renderer->reject_reason = MSM5XXX_MA3_RENDER_INVALID_PITCH;
        renderer->invalid_pitches++;
        return false;
    }

    event->timbre_valid = true;
    event->timbre_algorithm = (uint8_t)algorithm;
    event->timbre_operator_count = (uint8_t)operator_count;
    event->timbre_operator_feedback_valid = true;
    event->timbre_decay_threshold_valid = operator_count == 2u;
    for (index = 0u; index < operator_count; index++) {
        const uint8_t *op = patch + 2u + index * 7u;
        unsigned sustain_level = op[2] & 0x0fu;
        unsigned attack_rate = op[2] >> 4;
        unsigned decay_rate = op[1] & 0x0fu;
        unsigned release_rate = op[1] >> 4;
        unsigned sustain_rate = op[0] >> 4;
        unsigned rate_offset = (op[0] & 1u) ? key_scale : key_scale >> 2;
        unsigned raw_multiplier = op[5] >> 4;
        unsigned waveform = op[6] >> 3;
        unsigned feedback = op[6] & 7u;
        unsigned ksl = op[3] & 3u;
        uint16_t ksl_gain;
        double ksl_db;
        unsigned ksl_steps;
        unsigned total_level = (op[3] >> 2) & 0x3fu;

        if (waveform > 7u) {
            renderer->reject_reason = MSM5XXX_MA3_RENDER_UNSUPPORTED_WAVEFORM;
            renderer->unsupported_waveforms++;
            return false;
        }
        if (feedback != 0u && index != 0u &&
            !(algorithm == 5u && index == 2u)) {
            renderer->reject_reason = MSM5XXX_MA3_RENDER_UNSUPPORTED_ALGORITHM;
            renderer->unsupported_algorithms++;
            return false;
        }
        event->timbre_waveform[index] = (uint8_t)waveform;
        event->timbre_operator_feedback[index] = (uint8_t)feedback;
        half_multiplier |= raw_multiplier == 0u;
        event->timbre_multiplier[index] =
            (uint8_t)(raw_multiplier == 0u ? 1u : raw_multiplier);

        ksl_gain = msm5xxx_ma5_fm_ksl_gain(ksl, fnum >> 6, block);
        if (ksl_gain == 0u) {
            renderer->reject_reason = MSM5XXX_MA3_RENDER_UNSUPPORTED_ALGORITHM;
            renderer->unsupported_algorithms++;
            return false;
        }
        ksl_db = -20.0 * log10((double)ksl_gain / 32768.0);
        ksl_steps = (unsigned)floor(ksl_db / 0.75 + 0.5);
        event->timbre_level[index] = (uint8_t)(
            total_level + ksl_steps > 63u ? 63u : total_level + ksl_steps);
        event->timbre_attack_step[index] =
            msm5xxx_ma5_fm_attack_step(attack_rate, rate_offset,
                                       MSM5XXX_AUDIO_SAMPLE_RATE);
        event->timbre_decay_factor[index] =
            ma3_eg_factor_q30(decay_rate, rate_offset);
        event->timbre_sustain_factor[index] =
            ma3_eg_factor_q30(sustain_rate, rate_offset);
        event->timbre_release_factor[index] =
            ma3_eg_factor_q30(release_rate, rate_offset);
        if (operator_count == 2u) {
            event->timbre_decay_threshold[index] =
                ma3_sustain_threshold(sustain_level);
        }
    }
    if (half_multiplier) {
        if (event->note < 12u) {
            renderer->reject_reason = MSM5XXX_MA3_RENDER_INVALID_PITCH;
            renderer->invalid_pitches++;
            return false;
        }
        event->note = (uint8_t)(event->note - 12u);
        for (index = 0u; index < operator_count; index++) {
            event->timbre_multiplier[index] =
                (uint8_t)(event->timbre_multiplier[index] * 2u);
        }
    }
    return true;
}

void msm5xxx_ma3_renderer_init(MSM5xxxMA3Renderer *renderer)
{
    if (renderer != NULL) {
        memset(renderer, 0, sizeof(*renderer));
    }
}

static int ma3_slot_from_address(uint16_t address, unsigned *offset)
{
    if (address < 96u) {
        unsigned relative = address - MA3_REGISTER_FM_FIRST;
        if (relative % 6u == 5u) {
            *offset = 5u;
            return (int)(relative / 6u);
        }
    }
    if (address >= MA3_REGISTER_FM_EXT && address < 320u) {
        unsigned relative = address - MA3_REGISTER_FM_EXT;
        if (relative % 6u == 5u) {
            *offset = 5u;
            return 16 + (int)(relative / 6u);
        }
    }
    if (address >= MA3_REGISTER_WT && address < 144u) {
        unsigned relative = address - MA3_REGISTER_WT;
        if (relative % 6u == 5u) {
            *offset = 5u;
            return (int)(MA3_WT_SLOT_FIRST + relative / 6u);
        }
    }
    return -1;
}

static void ma3_fill_channel_event(const MSM5xxxMA3Audio *device,
                                   MSM5xxxAudioEvent *event,
                                   uint8_t channel)
{
    unsigned bend = 8192u;

    event->channel = channel;
    event->volume = ma3_scale_7bit(device->reg[144u + channel]);
    event->pan = ma3_scale_7bit(device->reg[160u + channel]);
    event->expression = 127u;
    bend = ((unsigned)(device->reg[192u + channel * 2u] & 0x7fu) << 7) |
           (unsigned)(device->reg[193u + channel * 2u] & 0x7fu);
    event->pitch_bend = (uint8_t)(bend >> 7);
}

static bool ma3_emit_note(MSM5xxxMA3Renderer *renderer,
                          const MSM5xxxMA3Audio *device,
                          const MSM5xxxMA3Operation *operation,
                          MSM5xxxAudioSynth *synth, unsigned slot,
                          uint8_t channel)
{
    uint16_t base;
    uint16_t address;
    uint16_t pitch;
    MSM5xxxAudioEvent event;

    if (slot >= MA3_FM_SLOT_COUNT) {
        renderer->reject_reason = MSM5XXX_MA3_RENDER_UNSUPPORTED_WAVE_SLOT;
        renderer->unsupported_wave_slots++;
        return false;
    }
    base = slot < 16u ? (uint16_t)(slot * 6u) :
           (uint16_t)(MA3_REGISTER_FM_EXT + (slot - 16u) * 6u);
    address = (uint16_t)(((uint16_t)(device->reg[base] & 0x7fu) << 7) |
                         (device->reg[base + 1u] & 0x7fu));
    pitch = (uint16_t)(((uint16_t)(device->reg[base + 3u] & 0x7fu) << 7) |
                       (device->reg[base + 4u] & 0x7fu));
    memset(&event, 0, sizeof(event));
    event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
    event.voice_id = (uint8_t)slot;
    event.velocity = ma3_scale_7bit(device->reg[base + 2u]);
    if (event.velocity == 0u) {
        event.velocity = 1u;
    }
    ma3_fill_channel_event(device, &event, channel);
    if (!ma3_decode_voice(device, address, pitch, &event, renderer)) {
        return false;
    }
    if (!msm5xxx_audio_synth_event(synth, operation->timestamp_ns, &event)) {
        renderer->reject_reason = MSM5XXX_MA3_RENDER_SYNTH_REJECTED;
        return false;
    }
    renderer->voice[slot].channel = channel;
    renderer->voice[slot].note = event.note;
    renderer->voice[slot].active = true;
    renderer->reject_reason = MSM5XXX_MA3_RENDER_OK;
    return true;
}

static bool ma3_emit_note_off(MSM5xxxMA3Renderer *renderer,
                              const MSM5xxxMA3Operation *operation,
                              MSM5xxxAudioSynth *synth, unsigned slot)
{
    MSM5xxxAudioEvent event;
    MSM5xxxMA3RenderVoice *voice;

    if (slot >= MA3_FM_SLOT_COUNT) {
        renderer->reject_reason = MSM5XXX_MA3_RENDER_UNSUPPORTED_WAVE_SLOT;
        renderer->unsupported_wave_slots++;
        return false;
    }
    voice = &renderer->voice[slot];
    if (!voice->active) {
        return true;
    }
    memset(&event, 0, sizeof(event));
    event.kind = MSM5XXX_AUDIO_EVENT_NOTE_OFF;
    event.voice_id = (uint8_t)slot;
    event.channel = voice->channel;
    event.note = voice->note;
    event.volume = 127u;
    event.pan = 64u;
    event.expression = 127u;
    event.pitch_bend = 64u;
    if (!msm5xxx_audio_synth_event(synth, operation->timestamp_ns, &event)) {
        renderer->reject_reason = MSM5XXX_MA3_RENDER_SYNTH_REJECTED;
        return false;
    }
    voice->active = false;
    renderer->reject_reason = MSM5XXX_MA3_RENDER_OK;
    return true;
}

static bool ma3_emit_control(MSM5xxxMA3Renderer *renderer,
                             const MSM5xxxMA3Audio *device,
                             const MSM5xxxMA3Operation *operation,
                             MSM5xxxAudioSynth *synth, uint8_t channel)
{
    MSM5xxxAudioEvent event;

    memset(&event, 0, sizeof(event));
    event.kind = MSM5XXX_AUDIO_EVENT_CONTROL;
    ma3_fill_channel_event(device, &event, channel);
    event.note = 0u;
    event.velocity = 0u;
    event.pitch_bend = event.pitch_bend > 127u ? 127u : event.pitch_bend;
    if (!msm5xxx_audio_synth_event(synth, operation->timestamp_ns, &event)) {
        renderer->reject_reason = MSM5XXX_MA3_RENDER_SYNTH_REJECTED;
        return false;
    }
    renderer->reject_reason = MSM5XXX_MA3_RENDER_OK;
    return true;
}

bool msm5xxx_ma3_renderer_operation(
    MSM5xxxMA3Renderer *renderer, const MSM5xxxMA3Audio *device,
    const MSM5xxxMA3Operation *operation, MSM5xxxAudioSynth *synth)
{
    unsigned offset;
    int slot;
    uint8_t value;

    if (renderer == NULL || device == NULL || operation == NULL ||
        synth == NULL || operation->kind != MSM5XXX_MA3_OP_REGISTER_WRITE) {
        return false;
    }
    value = operation->value;
    slot = ma3_slot_from_address(operation->address, &offset);
    if (slot >= 0) {
        if ((unsigned)slot >= MA3_WT_SLOT_FIRST) {
            renderer->reject_reason = MSM5XXX_MA3_RENDER_UNSUPPORTED_WAVE_SLOT;
            renderer->unsupported_wave_slots++;
            return false;
        }
        if (value & 0x40u) {
            return ma3_emit_note(renderer, device, operation, synth,
                                 (unsigned)slot, value & 0x0fu);
        }
        if (value & 0x30u) {
            uint8_t channel = value & 0x0fu;
            if (renderer->voice[slot].active &&
                renderer->voice[slot].channel != channel) {
                return true;
            }
            return ma3_emit_note_off(renderer, operation, synth,
                                     (unsigned)slot);
        }
        if (renderer->voice[slot].active &&
            renderer->voice[slot].channel != (value & 0x0fu)) {
            return true;
        }
        return ma3_emit_note_off(renderer, operation, synth, (unsigned)slot);
    }
    if (operation->address >= 144u && operation->address < 160u) {
        return ma3_emit_control(renderer, device, operation, synth,
                                (uint8_t)(operation->address - 144u));
    }
    if (operation->address >= 160u && operation->address < 176u) {
        return ma3_emit_control(renderer, device, operation, synth,
                                (uint8_t)(operation->address - 160u));
    }
    if (operation->address >= 192u && operation->address < 224u) {
        return ma3_emit_control(renderer, device, operation, synth,
                                (uint8_t)((operation->address - 192u) / 2u));
    }
    return true;
}
