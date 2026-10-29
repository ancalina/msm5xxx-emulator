/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-pcm-queue.h"
#include <string.h>

static bool valid(const MSM5xxxMA5PCMQueue *q)
{
    return q && q->storage && q->capacity && q->capacity <= UINT32_MAX &&
        q->capacity <= SIZE_MAX / (2 * sizeof(int16_t)) &&
        q->head < q->capacity && q->count <= q->capacity && q->epoch &&
        q->count <= UINT64_MAX - q->cursor;
}

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_queue_init(MSM5xxxMA5PCMQueue *q,
                                              int16_t *storage, size_t capacity)
{
    if (!q || !storage || !capacity || capacity > UINT32_MAX ||
        capacity > SIZE_MAX / (2 * sizeof(int16_t))) {
        return MSM5XXX_MA5_PCM_ARGUMENT;
    }
    *q = (MSM5xxxMA5PCMQueue){.storage=storage, .capacity=capacity, .epoch=1};
    return MSM5XXX_MA5_PCM_OK;
}

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_queue_reset(MSM5xxxMA5PCMQueue *q)
{
    if (!valid(q)) { return MSM5XXX_MA5_PCM_ARGUMENT; }
    if (q->epoch == UINT64_MAX) { return MSM5XXX_MA5_PCM_LIMIT; }
    q->epoch++;
    q->head = q->count = 0;
    q->sequence = q->cursor = 0;
    return MSM5XXX_MA5_PCM_OK;
}

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_queue_enqueue(MSM5xxxMA5PCMQueue *q,
    uint64_t epoch, uint64_t start_frame, const int16_t *stereo, size_t frames)
{
    uint64_t tail;
    if (!valid(q) || !frames || !stereo) { return MSM5XXX_MA5_PCM_ARGUMENT; }
    if (epoch != q->epoch) { return MSM5XXX_MA5_PCM_EPOCH; }
    if (start_frame < q->cursor) { return MSM5XXX_MA5_PCM_LATE; }
    tail = q->cursor + q->count;
    if (start_frame < tail) { return MSM5XXX_MA5_PCM_OVERLAP; }
    if (start_frame > tail) { return MSM5XXX_MA5_PCM_GAP; }
    if (frames > q->capacity - q->count) { return MSM5XXX_MA5_PCM_OVERFLOW; }
    if (frames > UINT64_MAX - tail) { return MSM5XXX_MA5_PCM_LIMIT; }
    /* All possible rejection checks precede storage changes. */
    size_t remaining = q->capacity - q->head;
    size_t position = q->count >= remaining ? q->count - remaining : q->head + q->count;
    for (size_t i = 0; i < frames; i++) {
        q->storage[2 * position] = stereo[2 * i];
        q->storage[2 * position + 1] = stereo[2 * i + 1];
        if (++position == q->capacity) { position = 0; }
    }
    q->count += frames;
    return MSM5XXX_MA5_PCM_OK;
}

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_queue_read(MSM5xxxMA5PCMQueue *q,
    int16_t *stereo, size_t frames, size_t *provided_frames,
    MSM5xxxMA5PCMMetadata *metadata)
{
    size_t available;
    MSM5xxxMA5PCMMetadata next;
    if (!valid(q) || !stereo || !provided_frames || !metadata || !frames || frames > UINT32_MAX ||
        frames > SIZE_MAX / (2 * sizeof(int16_t))) {
        return MSM5XXX_MA5_PCM_ARGUMENT;
    }
    if (frames > UINT64_MAX - q->cursor || q->sequence == UINT64_MAX) {
        return MSM5XXX_MA5_PCM_LIMIT;
    }
    next = (MSM5xxxMA5PCMMetadata){q->epoch, q->sequence + 1, q->cursor, (uint32_t)frames};
    available = frames < q->count ? frames : q->count;
    size_t position = q->head;
    for (size_t i = 0; i < available; i++) {
        stereo[2 * i] = q->storage[2 * position];
        stereo[2 * i + 1] = q->storage[2 * position + 1];
        if (++position == q->capacity) { position = 0; }
    }
    memset(stereo + 2 * available, 0, (frames - available) * 2 * sizeof(int16_t));
    q->head = position;
    q->count -= available;
    q->cursor += frames;
    q->sequence++;
    *provided_frames = available;
    *metadata = next;
    return MSM5XXX_MA5_PCM_OK;
}
