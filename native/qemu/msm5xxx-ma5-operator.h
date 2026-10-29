/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_OPERATOR_H
#define MSM5XXX_MA5_OPERATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct MSM5xxxMA5Operator {
    uint32_t env_state;
    uint32_t phase;
    uint32_t phase_step;
    uint32_t attack;
    uint32_t decay;
    uint32_t sr_mul;
    uint32_t rr_mul;
    uint32_t sustain_level;
    uint32_t level;
    uint32_t released_use_sr;
    uint32_t gain;
} MSM5xxxMA5Operator;

/* Caller supplies 1024 signed samples. Invalid input changes neither state nor out.
 * One step models a bounded integer operator contract, not a physical chip clock. */
bool msm5xxx_ma5_operator_step(MSM5xxxMA5Operator *op,
                               const int16_t *wave, size_t capacity,
                               bool phase_modulated, int32_t phase_mod,
                               int32_t *out);

#endif
