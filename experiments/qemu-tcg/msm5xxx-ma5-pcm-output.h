/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_PCM_OUTPUT_H
#define MSM5XXX_MA5_PCM_OUTPUT_H

#include "msm5xxx-ma5-pcm-queue.h"
#include "msm5xxx-ma5-rateconv.h"

typedef struct {
    MSM5xxxMA5RateConv rate;
    MSM5xxxMA5PCMQueue queue;
    uint64_t dropped_frames;
    uint64_t underflow_frames;
    uint64_t origin_frame;
    bool started;
    bool failed;
} MSM5xxxMA5PCMOutput;

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_output_init(
    MSM5xxxMA5PCMOutput *output, int16_t *storage, size_t capacity);
MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_output_reset(
    MSM5xxxMA5PCMOutput *output);
/* Accept one explicit 48 kHz renderer chunk on its absolute frame timeline.
 * Leading zero-only output is ignored and the first nonzero sample establishes
 * frame zero, so boot-time idle silence cannot fill the bounded queue. Later
 * gaps are queued as silence; PCM older than the consumer cursor or occupied
 * queue tail is dropped. A full queue fails only this output epoch; callers
 * must not propagate that result into firmware/MMIO acceptance. dropped_frames
 * records PCM discarded before failure. Caller serializes all functions and
 * owns the supplied queue storage.
 */
MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_output_emit(
    MSM5xxxMA5PCMOutput *output, uint64_t epoch, uint64_t first_frame,
    const int16_t *stereo_48000, size_t frames);
MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_output_read(
    MSM5xxxMA5PCMOutput *output, int16_t *stereo_44100, size_t frames,
    size_t *provided_frames, MSM5xxxMA5PCMMetadata *metadata);

#endif
