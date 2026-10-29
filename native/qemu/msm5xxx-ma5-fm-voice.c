/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-fm-voice.h"
#include <math.h>
#include <string.h>

uint32_t msm5xxx_ma5_fm_attack_step(unsigned setting, unsigned offset,
                                    unsigned sample_rate)
{
    static const double high_rate_scale[6] = {
        6566.4048, -19.8140, -43.5497, -93.7996, -80.2857, -43.0104
    };
    double x, b1=0.0, b2=0.0, scale, shape, step;
    unsigned rate;

    if (setting == 0 || sample_rate == 0) {
        return 0;
    }
    rate = setting > 15u ? 60u : setting * 4u;
    if (offset > 63u - rate) {
        rate = 63u;
    } else {
        rate += offset;
    }
    if (rate < 4u) {
        return 0;
    }
    if (rate >= 60u) {
        return UINT32_C(0x80000000);
    }

    /* shortcut: degree-5 normalized high-rate fit; upgrade after independent
     * runtime vectors close the law (0.986% at32/44.1/48k;4.071% at22.05k). */
    if (rate <= 51u) {
        scale=3639.9;
    } else {
        x=(2.0*rate-111.0)/7.0;
        for (int i=5;i>=1;i--) {
            double b=2.0*x*b1-b2+high_rate_scale[i];
            b2=b1; b1=b;
        }
        scale=x*b1-b2+high_rate_scale[0];
    }
    shape=ldexp(1.0,(rate-4u)/4u)*(4u+(rate&3u));
    step=floor(scale*48000.0*shape/(double)sample_rate+0.5);
    return step>UINT32_C(0x80000000) ? UINT32_C(0x80000000) : (uint32_t)step;
}

uint16_t msm5xxx_ma5_fm_ksl_gain(unsigned raw_ksl, unsigned fnum_group,
                                 unsigned octave)
{
    static const uint16_t base_3db_x16[16] = {
        0, 144, 192, 222, 240, 258, 270, 282,
        288, 300, 306, 312, 318, 324, 330, 336
    };
    int attenuation_x16;
    unsigned per_octave_x16;

    if (raw_ksl == 0u) {
        return 32768;
    }
    if (raw_ksl > 3u || fnum_group >= 16u || octave >= 8u) {
        return 0;
    }
    attenuation_x16 = base_3db_x16[fnum_group];
    per_octave_x16 = 48;
    if (raw_ksl == 2u) {
        attenuation_x16 /= 2;
        per_octave_x16 = 24;
    } else if (raw_ksl == 3u) {
        attenuation_x16 *= 2;
        per_octave_x16 = 96;
    }
    attenuation_x16 -= (int)(7u - octave) * (int)per_octave_x16;
    if (attenuation_x16 <= 0) {
        return 32512;
    }
    return (uint16_t)floor(32768.0 *
        pow(10.0, -(double)attenuation_x16 / 320.0) + 0.5);
}

static uint32_t fm_detune_coefficient(unsigned group, unsigned key_index)
{
    /* shortcut: exact MA5 table; key-index/base-octave mapping remains inferred. */
    static const uint32_t coefficient_q16[4][32] = {
    {
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
    },
    {
        0u, 0u, 0u, 0u, 3277u, 3277u, 3277u, 3277u,
        3277u, 3277u, 3277u, 3277u, 5898u, 5898u, 5898u, 5898u,
        5898u, 9175u, 9175u, 9175u, 11796u, 11796u, 11796u, 15073u,
        15073u, 17695u, 17695u, 20971u, 24248u, 24248u, 24248u, 24248u
    },
    {
        3277u, 3277u, 3277u, 3277u, 5898u, 5898u, 5898u, 5898u,
        5898u, 9175u, 9175u, 9175u, 11796u, 11796u, 11796u, 15073u,
        15073u, 17695u, 17695u, 20971u, 24248u, 24248u, 26870u, 30147u,
        32768u, 36045u, 38666u, 41943u, 47841u, 47841u, 47841u, 47841u
    },
    {
        5898u, 5898u, 5898u, 5898u, 9175u, 9175u, 9175u, 9175u,
        11796u, 11796u, 11796u, 15073u, 15073u, 18350u, 18350u, 20972u,
        24248u, 24248u, 26870u, 30147u, 32768u, 36045u, 38666u, 41943u,
        47841u, 51118u, 57016u, 59638u, 65536u, 65536u, 65536u, 65536u
    }
    };

    return coefficient_q16[group][key_index];
}

uint32_t msm5xxx_ma5_fm_detune_step(uint32_t base_step, unsigned raw_detune,
                                    unsigned key_index, unsigned sample_rate)
{
    unsigned group = raw_detune & 3u;
    uint32_t detune_q16;
    uint64_t native_step;
    uint64_t scale;
    uint64_t correction;
    uint64_t delta;
    uint64_t adjusted_step;

    if (raw_detune > 7u || key_index >= 32u || base_step == 0u) {
        return 0;
    }
    if (raw_detune == 0u) {
        return base_step;
    }
    if (sample_rate == 0u) {
        return 0;
    }

    detune_q16 = fm_detune_coefficient(group, key_index);
    native_step = base_step >> 16;
    scale = native_step * sample_rate;
    if (scale < 0x10000u) {
        scale = 0x10000u;
    }
    correction = (uint64_t)detune_q16 * base_step;
    delta = correction / scale;
    if (raw_detune & 4u) {
        delta += correction % scale != 0u;
        if (delta > base_step) {
            return 0;
        }
        adjusted_step = base_step - delta;
    } else {
        if (delta > UINT32_MAX - base_step) {
            return 0;
        }
        adjusted_step = base_step + delta;
    }
    return adjusted_step > UINT32_MAX ? 0 : (uint32_t)adjusted_step;
}

bool msm5xxx_ma5_fm_voice_decode(const uint8_t *data, size_t size,
                                MSM5xxxMA5FMVoice *voice)
{
    MSM5xxxMA5FMVoice decoded;
    if (data == NULL || voice == NULL || size < 2) {
        return false;
    }
    memset(&decoded, 0, sizeof(decoded));
    decoded.algorithm = data[1] & 7u;
    decoded.operator_count = decoded.algorithm < 2u ? 2u : 4u;
    decoded.record_size = 2u + 7u * decoded.operator_count;
    if (size < decoded.record_size) {
        return false;
    }
    decoded.pan = data[0] >> 3;
    decoded.base_octave = data[0] & 3u;
    decoded.lfo = data[1] >> 6;
    decoded.pan_enable = (data[1] >> 5) & 1u;
    decoded.pan_off = (data[1] >> 4) & 1u;
    decoded.reserved = ((data[0] >> 2) & 1u) | (((data[1] >> 3) & 1u) << 1);
    for (unsigned i = 0; i < decoded.operator_count; i++) {
        const uint8_t *p = data + 2u + i * 7u;
        MSM5xxxMA5FMOperatorParams *op = &decoded.operators[i];
        op->sustain_rate = p[0] >> 4;
        op->xof = (p[0] >> 3) & 1u;
        op->sustain = (p[0] >> 1) & 1u;
        op->key_scale_rate = p[0] & 1u;
        op->release_rate = p[1] >> 4;
        op->decay_rate = p[1] & 15u;
        op->attack_rate = p[2] >> 4;
        op->sustain_level = p[2] & 15u;
        op->total_level = p[3] >> 2;
        op->key_scale_level = p[3] & 3u;
        op->amplitude_depth = (p[4] >> 5) & 3u;
        op->amplitude_enable = (p[4] >> 4) & 1u;
        op->vibrato_depth = (p[4] >> 1) & 3u;
        op->vibrato_enable = p[4] & 1u;
        op->multiplier = p[5] >> 4;
        op->detune = p[5] & 7u;
        op->waveform = p[6] >> 3;
        op->feedback = p[6] & 7u;
        op->reserved = ((p[0] >> 2) & 1u) | (((p[4] >> 3) & 1u) << 1) |
                       (((p[4] >> 7) & 1u) << 2) | (((p[5] >> 3) & 1u) << 3);
    }
    *voice = decoded;
    return true;
}
