/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-gain.h"

#include <math.h>
#include <stddef.h>

static uint32_t ma5_log_index(double gain)
{
    double index = ceil(1024.0 + (20.0 * 1024.0 / 48.0) * log10(gain));

    if (index < 1.0) {
        return 1;
    }
    if (index > 1024.0) {
        return 1024;
    }
    return (uint32_t)index;
}

bool msm5xxx_ma5_gain_init(MSM5xxxMA5GainTables *tables)
{
    if (tables == NULL) {
        return false;
    }
    for (unsigned i = 0; i < 32; i++) {
        unsigned code = 4u * i + 3u;

        tables->g32[i] = i ? UINT32_C(32768) * code * code / (127u * 127u) : 0;
        tables->cv[i] = i ? ma5_log_index(tables->g32[i] / 32768.0) << 16 : 0;
        if (i == 31u) {
            tables->cp_l[i] = 0;
        } else {
            unsigned position = i <= 15u ? i : i - 1u;
            double gain = cos(acos(-1.0) * position / 60.0);

            tables->cp_l[i] = ma5_log_index(gain) << 16;
        }
    }
    for (unsigned i = 0; i < 32; i++) {
        tables->cp_r[i] = tables->cp_l[31u - i];
    }
    for (unsigned i = 0; i < 64; i++) {
        double gain = trunc(32768.0 * pow(10.0, -0.75 * i / 20.0) + 0.5);

        tables->tl[i] = (uint16_t)(gain > 32767.0 ? 32767.0 : gain);
    }
    for (unsigned i = 0; i < 193; i++) {
        tables->att[i] = i == 192u ? 0 :
            (uint16_t)trunc(32768.0 * pow(10.0, -0.5 * i / 20.0) + 0.5);
    }
    tables->v[0] = 192;
    for (unsigned i = 1; i < 128; i++) {
        double value = trunc(-80.0 * log10(i / 127.0) + 0.5);

        tables->v[i] = (uint8_t)(value < 0.0 ? 0.0 :
                                value > 192.0 ? 192.0 : value);
    }
    for (unsigned i = 0; i < 1025; i++) {
        tables->a[i] = i ? (uint16_t)floor(32768.0 *
            pow(10.0, ((double)i - 1024.0) * 48.0 / (1024.0 * 20.0))) : 0;
    }
    for (unsigned i = 0; i < 16; i++) {
        double attenuation = i == 15u ? 93.0 : 3.0 * i;

        tables->sl[i] = (uint32_t)trunc(2147483648.0 *
                                       pow(10.0, -attenuation / 20.0) + 0.5);
    }
    for (unsigned i = 0; i < 32; i++) {
        tables->slotgain[i] = tables->att[tables->v[4u * i + 3u]];
    }
    return true;
}

static bool ma5_channel_gain_valid(const MSM5xxxMA5ChannelGain *state)
{
    return state != NULL && state->current <= MSM5XXX_MA5_GAIN_MAX_Q16 &&
           state->target <= MSM5XXX_MA5_GAIN_MAX_Q16 &&
           (state->smooth || state->current == state->target);
}

bool msm5xxx_ma5_channel_gain_configure(MSM5xxxMA5ChannelGain *state,
                                       uint32_t target, bool smooth)
{
    if (!ma5_channel_gain_valid(state) || target > MSM5XXX_MA5_GAIN_MAX_Q16) {
        return false;
    }
    state->target = target;
    state->smooth = smooth;
    if (!smooth) {
        state->current = target;
    }
    return true;
}

bool msm5xxx_ma5_channel_gain_step(const MSM5xxxMA5GainTables *tables,
                                  MSM5xxxMA5ChannelGain *state,
                                  uint32_t step, uint16_t *out)
{
    uint32_t current, index;

    if (tables == NULL || out == NULL || !ma5_channel_gain_valid(state) ||
        (step != 65536u && step != 262144u)) {
        return false;
    }
    current = index = state->current;
    if (current < state->target) {
        if (state->target - current <= step) {
            current = index = state->target;
        } else {
            current += step;
        }
    } else if (current > state->target) {
        if (current - state->target <= step) {
            current = index = state->target;
        } else {
            current -= step;
        }
    }
    *out = tables->a[index >> 16];
    state->current = current;
    return true;
}
