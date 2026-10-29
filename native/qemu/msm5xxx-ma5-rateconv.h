/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_RATECONV_H
#define MSM5XXX_MA5_RATECONV_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    MSM5XXX_MA5_RATE_OK, MSM5XXX_MA5_RATE_ARGUMENT,
    MSM5XXX_MA5_RATE_EPOCH, MSM5XXX_MA5_RATE_OUTPUT_FULL,
    MSM5XXX_MA5_RATE_LIMIT
} MSM5xxxMA5RateResult;

typedef struct {
    uint64_t epoch, input_frames, output_frames;
    uint16_t credit;
    bool have_previous;
    int16_t previous[2];
} MSM5xxxMA5RateConv;

/* Private uncalibrated 48000 -> 44100 stereo signed-host-S16 experiment.
 * Integer linear interpolation, signed floor, no filter, no allocation/locking.
 * Input sample n starts at time (n+1)/48000, output m at (m+1)/44100.
 * Thus N input frames produce floor(N*147/160) frames without EOF padding.
 * State is caller-owned but must not be edited; init is for a new lifetime.
 * Buffers, state and out-parameters must all be mutually disjoint.
 */
MSM5xxxMA5RateResult msm5xxx_ma5_rateconv_init(MSM5xxxMA5RateConv *r);
/* Advances epoch; clears history, fractional phase and frame counters. */
MSM5xxxMA5RateResult msm5xxx_ma5_rateconv_reset(MSM5xxxMA5RateConv *r);
/* Caller supplies input_frames*2 readable and output_capacity*2 writable samples.
 * NULL buffers are permitted only for zero corresponding count/capacity.
 * OK consumes all input. OUTPUT_FULL may consume a prefix: retry the unconsumed
 * suffix with the same epoch; consumed/produced always describe exact progress.
 * No input requiring unavailable output space is consumed. No tail flush or
 * extrapolation occurs on empty input. Other errors change nothing, including
 * buffers and out-parameters. Capacity/counts are checked before any mutation.
 */
MSM5xxxMA5RateResult msm5xxx_ma5_rateconv_process(MSM5xxxMA5RateConv *r,
    uint64_t epoch, const int16_t *input, size_t input_frames,
    int16_t *output, size_t output_capacity, size_t *consumed, size_t *produced);
#endif
