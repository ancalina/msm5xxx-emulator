/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-rateconv.h"

static bool valid(const MSM5xxxMA5RateConv *r)
{
    if (!r || !r->epoch || r->credit >= 160 ||
        r->have_previous != (r->input_frames != 0)) {
        return false;
    }
    return r->credit == (r->input_frames % 160) * 147 % 160 &&
        r->output_frames == (r->input_frames / 160) * 147 +
                            (r->input_frames % 160) * 147 / 160;
}

MSM5xxxMA5RateResult msm5xxx_ma5_rateconv_init(MSM5xxxMA5RateConv *r)
{
    if (!r) { return MSM5XXX_MA5_RATE_ARGUMENT; }
    *r = (MSM5xxxMA5RateConv){.epoch = 1};
    return MSM5XXX_MA5_RATE_OK;
}

MSM5xxxMA5RateResult msm5xxx_ma5_rateconv_reset(MSM5xxxMA5RateConv *r)
{
    if (!valid(r)) { return MSM5XXX_MA5_RATE_ARGUMENT; }
    if (r->epoch == UINT64_MAX) { return MSM5XXX_MA5_RATE_LIMIT; }
    *r = (MSM5xxxMA5RateConv){.epoch = r->epoch + 1};
    return MSM5XXX_MA5_RATE_OK;
}

static int32_t floor147(int32_t x)
{
    return x >= 0 ? x / 147 : -((-x + 146) / 147);
}

MSM5xxxMA5RateResult msm5xxx_ma5_rateconv_process(MSM5xxxMA5RateConv *r,
    uint64_t epoch, const int16_t *input, size_t input_frames,
    int16_t *output, size_t output_capacity, size_t *consumed, size_t *produced)
{
    size_t used = 0, made = 0;
    if (!valid(r) || !consumed || !produced || (input_frames && !input) ||
        (output_capacity && !output) ||
        input_frames > SIZE_MAX / (2 * sizeof(int16_t)) ||
        output_capacity > SIZE_MAX / (2 * sizeof(int16_t))) {
        return MSM5XXX_MA5_RATE_ARGUMENT;
    }
    if (epoch != r->epoch) { return MSM5XXX_MA5_RATE_EPOCH; }
    if (input_frames > UINT64_MAX - r->input_frames) {
        return MSM5XXX_MA5_RATE_LIMIT;
    }
    while (used < input_frames) {
        unsigned credit = r->credit + 147;
        if (credit >= 160) {
            if (made == output_capacity) { break; }
            credit -= 160;
            /* shortcut: linear transport only; add a filter after calibration. */
            for (unsigned side = 0; side < 2; side++) {
                int32_t old = r->previous[side];
                int32_t delta = (int32_t)input[2 * used + side] - old;
                output[2 * made + side] = (int16_t)(old +
                    floor147(delta * (147 - (int32_t)credit)));
            }
            made++;
            r->output_frames++;
        }
        r->previous[0] = input[2 * used];
        r->previous[1] = input[2 * used + 1];
        r->have_previous = true;
        r->credit = (uint16_t)credit;
        r->input_frames++;
        used++;
    }
    *consumed = used;
    *produced = made;
    return used == input_frames ? MSM5XXX_MA5_RATE_OK :
                                 MSM5XXX_MA5_RATE_OUTPUT_FULL;
}
