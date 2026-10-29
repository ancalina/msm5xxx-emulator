/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-pcm-output.h"
#include <string.h>

enum { MA5_PCM_INPUT_CHUNK = 256, MA5_PCM_OUTPUT_CHUNK = 236 };

static void add_dropped(MSM5xxxMA5PCMOutput *output, uint64_t frames)
{
    output->dropped_frames = frames > UINT64_MAX - output->dropped_frames ?
                             UINT64_MAX : output->dropped_frames + frames;
}

static MSM5xxxMA5PCMResult append_timeline(MSM5xxxMA5PCMOutput *output,
    uint64_t first_frame, const int16_t *samples, size_t frames)
{
    MSM5xxxMA5PCMQueue *queue = &output->queue;
    uint64_t tail = queue->cursor + queue->count;
    size_t skip = 0;
    static const int16_t silence[MA5_PCM_INPUT_CHUNK * 2] = {0};

    if (first_frame < queue->cursor) {
        uint64_t late = queue->cursor - first_frame;
        skip = late >= frames ? frames : (size_t)late;
        add_dropped(output, skip);
        first_frame += skip;
    }
    if (skip == frames) {
        return MSM5XXX_MA5_PCM_OK;
    }
    if (first_frame < tail) {
        uint64_t overlap = tail - first_frame;
        skip = overlap >= frames - skip ? frames - skip : (size_t)overlap;
        add_dropped(output, skip);
        first_frame += skip;
    }
    if (skip == frames) {
        return MSM5XXX_MA5_PCM_OK;
    }
    tail = queue->cursor + queue->count;
    while (first_frame > tail) {
        size_t free_frames = queue->capacity - queue->count;
        size_t gap = first_frame - tail > SIZE_MAX ? SIZE_MAX :
                     (size_t)(first_frame - tail);
        size_t fill = gap < free_frames ? gap : free_frames;
        if (!fill) {
            add_dropped(output, frames - skip);
            return MSM5XXX_MA5_PCM_OVERFLOW;
        }
        if (fill > MA5_PCM_INPUT_CHUNK) {
            fill = MA5_PCM_INPUT_CHUNK;
        }
        if (msm5xxx_ma5_pcm_queue_enqueue(queue, queue->epoch, tail,
                silence, fill) != MSM5XXX_MA5_PCM_OK) {
            return MSM5XXX_MA5_PCM_OVERFLOW;
        }
        tail += fill;
    }
    {
        size_t free_frames = queue->capacity - queue->count;
        size_t remaining = frames - skip;
        size_t accepted = remaining < free_frames ? remaining : free_frames;
        if (accepted && msm5xxx_ma5_pcm_queue_enqueue(queue, queue->epoch,
                tail, samples + skip * 2, accepted) != MSM5XXX_MA5_PCM_OK) {
            return MSM5XXX_MA5_PCM_OVERFLOW;
        }
        add_dropped(output, remaining - accepted);
        if (accepted != remaining) {
            return MSM5XXX_MA5_PCM_OVERFLOW;
        }
    }
    return MSM5XXX_MA5_PCM_OK;
}

static MSM5xxxMA5PCMResult convert_and_append(MSM5xxxMA5PCMOutput *output,
    const int16_t *input, size_t frames)
{
    int16_t converted[MA5_PCM_OUTPUT_CHUNK * 2];
    uint64_t start = output->rate.output_frames;
    size_t consumed = 0, produced = 0;
    MSM5xxxMA5RateResult result = msm5xxx_ma5_rateconv_process(
        &output->rate, output->queue.epoch, input, frames,
        converted, MA5_PCM_OUTPUT_CHUNK, &consumed, &produced);

    if (result != MSM5XXX_MA5_RATE_OK || consumed != frames) {
        return MSM5XXX_MA5_PCM_LIMIT;
    }
    if (produced) {
        MSM5xxxMA5PCMResult appended = append_timeline(output, start,
                                                       converted, produced);
        if (appended != MSM5XXX_MA5_PCM_OK) {
            output->failed = true;
        }
        return appended;
    }
    return MSM5XXX_MA5_PCM_OK;
}

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_output_init(
    MSM5xxxMA5PCMOutput *output, int16_t *storage, size_t capacity)
{
    if (!output) {
        return MSM5XXX_MA5_PCM_ARGUMENT;
    }
    memset(output, 0, sizeof(*output));
    if (msm5xxx_ma5_pcm_queue_init(&output->queue, storage, capacity) !=
            MSM5XXX_MA5_PCM_OK ||
        msm5xxx_ma5_rateconv_init(&output->rate) != MSM5XXX_MA5_RATE_OK) {
        memset(output, 0, sizeof(*output));
        return MSM5XXX_MA5_PCM_ARGUMENT;
    }
    return MSM5XXX_MA5_PCM_OK;
}

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_output_reset(
    MSM5xxxMA5PCMOutput *output)
{
    MSM5xxxMA5PCMResult queued;
    MSM5xxxMA5RateResult converted;

    if (!output || output->rate.epoch != output->queue.epoch) {
        return MSM5XXX_MA5_PCM_ARGUMENT;
    }
    if (output->queue.epoch == UINT64_MAX) {
        return MSM5XXX_MA5_PCM_LIMIT;
    }
    queued = msm5xxx_ma5_pcm_queue_reset(&output->queue);
    converted = msm5xxx_ma5_rateconv_reset(&output->rate);
    if (queued != MSM5XXX_MA5_PCM_OK || converted != MSM5XXX_MA5_RATE_OK ||
        output->queue.epoch != output->rate.epoch) {
        return MSM5XXX_MA5_PCM_LIMIT;
    }
    output->dropped_frames = 0;
    output->origin_frame = 0;
    output->started = false;
    output->failed = false;
    output->underflow_frames = 0;
    return MSM5XXX_MA5_PCM_OK;
}

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_output_emit(
    MSM5xxxMA5PCMOutput *output, uint64_t epoch, uint64_t first_frame,
    const int16_t *stereo_48000, size_t frames)
{
    int16_t silence[MA5_PCM_INPUT_CHUNK * 2] = {0};
    uint64_t input_end;
    size_t skipped = 0;

    if (!output || output->queue.epoch != output->rate.epoch ||
        (frames && !stereo_48000) ||
        frames > SIZE_MAX / (2 * sizeof(int16_t)) ||
        epoch != output->queue.epoch) {
        return epoch != (output ? output->queue.epoch : 0) ?
               MSM5XXX_MA5_PCM_EPOCH : MSM5XXX_MA5_PCM_ARGUMENT;
    }
    if (!frames) {
        return MSM5XXX_MA5_PCM_ARGUMENT;
    }
    if (output->failed) {
        return MSM5XXX_MA5_PCM_OVERFLOW;
    }
    if (frames > UINT64_MAX - first_frame) {
        return MSM5XXX_MA5_PCM_LIMIT;
    }
    if (!output->started) {
        size_t first = 0;
        while (first < frames && stereo_48000[2 * first] == 0 &&
               stereo_48000[2 * first + 1] == 0) {
            first++;
        }
        if (first == frames) {
            return MSM5XXX_MA5_PCM_OK;
        }
        output->origin_frame = first_frame + first;
        output->started = true;
        first_frame += first;
        stereo_48000 += first * 2;
        frames -= first;
    }
    if (first_frame < output->origin_frame) {
        uint64_t before_origin = output->origin_frame - first_frame;
        size_t trim = before_origin >= frames ? frames : (size_t)before_origin;
        first_frame += trim;
        stereo_48000 += trim * 2;
        frames -= trim;
        if (!frames) {
            return MSM5XXX_MA5_PCM_OK;
        }
    }
    first_frame -= output->origin_frame;
    input_end = first_frame + frames;
    if (first_frame < output->rate.input_frames) {
        uint64_t overlap = output->rate.input_frames - first_frame;
        skipped = overlap >= frames ? frames : (size_t)overlap;
        add_dropped(output, skipped);
    }
    while (output->rate.input_frames < input_end) {
        uint64_t gap = first_frame > output->rate.input_frames ?
                       first_frame - output->rate.input_frames : 0;
        size_t count = gap ?
                       (gap < MA5_PCM_INPUT_CHUNK ? (size_t)gap :
                                                    MA5_PCM_INPUT_CHUNK) :
                       (size_t)(input_end - output->rate.input_frames);
        if (count > MA5_PCM_INPUT_CHUNK) {
            count = MA5_PCM_INPUT_CHUNK;
        }
        if (!count) {
            return MSM5XXX_MA5_PCM_LIMIT;
        }
        if (gap) {
            MSM5xxxMA5PCMResult result = convert_and_append(output, silence, count);
            if (result != MSM5XXX_MA5_PCM_OK) {
                return result;
            }
        } else {
            size_t source_offset = (size_t)(output->rate.input_frames - first_frame);
            MSM5xxxMA5PCMResult result = convert_and_append(
                output, stereo_48000 + source_offset * 2, count);
            if (result != MSM5XXX_MA5_PCM_OK) {
                return result;
            }
        }
    }
    return MSM5XXX_MA5_PCM_OK;
}

MSM5xxxMA5PCMResult msm5xxx_ma5_pcm_output_read(
    MSM5xxxMA5PCMOutput *output, int16_t *stereo_44100, size_t frames,
    size_t *provided_frames, MSM5xxxMA5PCMMetadata *metadata)
{
    size_t provided;
    MSM5xxxMA5PCMResult result;

    if (!output || output->rate.epoch != output->queue.epoch) {
        return MSM5XXX_MA5_PCM_ARGUMENT;
    }
    if (!provided_frames) {
        return MSM5XXX_MA5_PCM_ARGUMENT;
    }
    result = msm5xxx_ma5_pcm_queue_read(&output->queue, stereo_44100, frames,
                                        &provided, metadata);
    if (result == MSM5XXX_MA5_PCM_OK) {
        uint64_t missing = frames - provided;

        output->underflow_frames = missing >
            UINT64_MAX - output->underflow_frames ? UINT64_MAX :
            output->underflow_frames + missing;
        *provided_frames = provided;
    }
    return result;
}
