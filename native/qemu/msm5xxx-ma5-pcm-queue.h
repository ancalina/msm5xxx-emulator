/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_PCM_QUEUE_H
#define MSM5XXX_MA5_PCM_QUEUE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define MSM5XXX_MA5_PCM_RATE 44100u

typedef enum {
    MSM5XXX_MA5_PCM_OK, MSM5XXX_MA5_PCM_ARGUMENT,
    MSM5XXX_MA5_PCM_OVERFLOW, MSM5XXX_MA5_PCM_EPOCH,
    MSM5XXX_MA5_PCM_LATE, MSM5XXX_MA5_PCM_OVERLAP,
    MSM5XXX_MA5_PCM_GAP, MSM5XXX_MA5_PCM_LIMIT
} MSM5xxxMA5PCMResult;
typedef struct {
    uint64_t epoch, sequence, start_frame;
    uint32_t frames;
} MSM5xxxMA5PCMMetadata;
typedef struct {
    int16_t *storage;
    size_t capacity, head, count;
    uint64_t epoch, sequence, cursor;
} MSM5xxxMA5PCMQueue;

/* Caller owns capacity*2 interleaved stereo s16 samples at host44100.
 * No allocation, rendering, resampling, clock conversion or locking. One logical
 * consumer (AUD or M5P2); caller serializes all operations. Inputs/outputs must
 * not alias storage or queue; all input/output buffers and out-parameters must
 * be mutually disjoint. Failed operations leave all state,
 * storage, outputs and metadata unchanged. Queue structure is not caller-edited.
 * Init is for a new lifetime only; use reset on a live queue to advance epoch.
 */
MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_queue_init(MSM5xxxMA5PCMQueue *q,
                                              int16_t *storage, size_t capacity);
/* New epoch, sequence0, cursor0. No stale samples are readable after reset. */
MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_queue_reset(MSM5xxxMA5PCMQueue *q);
/* Only contiguous append is accepted. Whole late chunks reject, including
 * partially stale chunks. A producer must explicitly resume at cursor after
 * underflow; no stale sound is replayed and no future gaps are guessed. */
MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_queue_enqueue(MSM5xxxMA5PCMQueue *q,
    uint64_t epoch, uint64_t start_frame, const int16_t *stereo, size_t frames);
/* Exactly frames written, missing frames are zero. Cursor advances by requested
 * frames, including silence. provided_frames reports queued frames (not padded
 * silence), even if the queued samples themselves are zero. Metadata describes
 * this read; sequence starts at1 each epoch (M5P2), while queue.sequence
 * stores the last issued sequence (init/reset0)
 * and increments once per nonempty read. Empty reads reject. Caller supplies
 * frames*2 writable samples. Samples are signed host values, not wire encoding.
 */
MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_queue_read(MSM5xxxMA5PCMQueue *q,
    int16_t *stereo, size_t frames, size_t *provided_frames,
    MSM5xxxMA5PCMMetadata *metadata);
#endif
