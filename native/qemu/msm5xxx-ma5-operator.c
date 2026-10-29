/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-operator.h"

#define MA5_FULL UINT32_C(0x80000000)
#define MA5_UNITY UINT32_C(0x40000000)

/* Arithmetic right shift with defined negative rounding in C11. */
static int64_t ma5_floor_shift(int64_t value, unsigned bits)
{
    int64_t divisor = INT64_C(1) << bits;
    int64_t quotient = value / divisor;

    return quotient - (value < 0 && value % divisor != 0);
}

static uint32_t ma5_decay(uint32_t level, uint32_t factor)
{
    return (uint32_t)(((uint64_t)level * factor) >> 30);
}

bool msm5xxx_ma5_operator_step(MSM5xxxMA5Operator *op,
                               const int16_t *wave, size_t capacity,
                               bool phase_modulated, int32_t phase_mod,
                               int32_t *out)
{
    uint32_t index;
    uint32_t amplitude;
    int64_t product;

    if (op == NULL || wave == NULL || out == NULL || capacity < 1024 ||
        op->env_state > 6 || op->attack > MA5_FULL ||
        op->decay > MA5_UNITY || op->sr_mul > MA5_UNITY ||
        op->rr_mul > MA5_UNITY || op->sustain_level > MA5_FULL ||
        op->level > MA5_FULL || op->released_use_sr > 1 ||
        op->gain > UINT32_C(0x8000)) {
        return false;
    }
    if (op->env_state == 0) {
        *out = 0;
        return true;
    }
    switch (op->env_state) {
    case 1:
        op->level = ma5_decay(op->level,
            op->released_use_sr ? op->sr_mul : op->rr_mul);
        if (op->level == 0) {
            op->env_state = 0;
        }
        break;
    case 2:
        op->phase = 0;
        op->env_state = 3;
        break;
    case 3:
    case 6:
        /* Addition wraps before the unsigned saturation test. */
        op->level = (uint32_t)((uint64_t)op->level + op->attack);
        if (op->level >= MA5_FULL) {
            op->level = MA5_FULL;
        }
        if (op->env_state == 6) {
            op->phase = 0;
            op->env_state = 1;
        } else if (op->level == MA5_FULL) {
            op->env_state = 4;
        }
        break;
    case 4:
        op->level = ma5_decay(op->level, op->decay);
        if (op->level == 0) {
            op->env_state = 0;
        } else if (op->level <= op->sustain_level) {
            op->env_state = 5;
        }
        break;
    case 5:
        op->level = ma5_decay(op->level, op->sr_mul);
        if (op->level == 0) {
            op->env_state = 0;
        }
        break;
    default:
        return false;
    }
    if (op->gain == 0) {
        *out = 0;
    } else {
        if (phase_modulated) {
            uint32_t shifted = (uint32_t)phase_mod << 14;
            int64_t signed_shifted = shifted <= INT32_MAX ?
                (int64_t)shifted : (int64_t)shifted - INT64_C(4294967296);
            uint32_t modulation = (uint32_t)ma5_floor_shift(signed_shifted, 15);

            index = ((uint32_t)(modulation + (op->phase >> 20)) >> 2) & 1023;
        } else {
            index = op->phase >> 22;
        }
        amplitude = (uint32_t)(((uint64_t)(op->level >> 16) *
                                op->gain) >> 15);
        product = (int64_t)wave[index] * amplitude;
        *out = (int32_t)ma5_floor_shift(product, 15);
    }
    /* Becoming inactive during this step still advances phase; state0 entry does not. */
    op->phase = (uint32_t)((uint64_t)op->phase + op->phase_step);
    return true;
}
