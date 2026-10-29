/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_GAIN_H
#define MSM5XXX_MA5_GAIN_H

#include <stdbool.h>
#include <stdint.h>

#define MSM5XXX_MA5_GAIN_MAX_Q16 (UINT32_C(1024) << 16)

typedef struct MSM5xxxMA5GainTables {
    uint32_t g32[32];
    uint16_t tl[64], att[193];
    uint8_t v[128];
    uint16_t a[1025];
    uint32_t cv[32], cp_l[32], cp_r[32], sl[16];
    uint16_t slotgain[32];
} MSM5xxxMA5GainTables;

typedef struct MSM5xxxMA5ChannelGain {
    uint32_t current, target;
    bool smooth;
} MSM5xxxMA5ChannelGain;

bool msm5xxx_ma5_gain_init(MSM5xxxMA5GainTables *tables);
/* State starts zeroed or valid; rejected arguments leave state/output intact. */
bool msm5xxx_ma5_channel_gain_configure(MSM5xxxMA5ChannelGain *state,
                                       uint32_t target, bool smooth);
/* Tables must be initialized. Only Q16 steps 65536/262144 are supported. */
bool msm5xxx_ma5_channel_gain_step(const MSM5xxxMA5GainTables *tables,
                                  MSM5xxxMA5ChannelGain *state,
                                  uint32_t step, uint16_t *out);

#endif
