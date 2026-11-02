/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA3_STREAM_H
#define MSM5XXX_MA3_STREAM_H

#include "msm5xxx-ma2-audio.h"
#include "msm5xxx-ma3-audio.h"

#define MSM5XXX_MA3_STREAM_COUNT 8u
#define MSM5XXX_MA3_STREAM_OUTPUT_RATE 44100u
#define MSM5XXX_MA3_STREAM_INPUT_RATE_MAX 48000u
#define MSM5XXX_MA3_STREAM_CHUNK 128u

typedef bool (*MSM5xxxMA3StreamEmit)(void *opaque, uint64_t first_frame,
                                     const int16_t *stereo,
                                     size_t frames);

typedef enum MSM5xxxMA3StreamReject {
    MSM5XXX_MA3_STREAM_OK = 0,
    MSM5XXX_MA3_STREAM_BAD_DESCRIPTOR,
    MSM5XXX_MA3_STREAM_UNSUPPORTED_FORMAT,
    MSM5XXX_MA3_STREAM_BAD_RATE,
    MSM5XXX_MA3_STREAM_OUTPUT_FAILED,
} MSM5xxxMA3StreamReject;

typedef struct MSM5xxxMA3StreamVoice {
    uint64_t phase;
    uint32_t rate_hz;
    uint32_t played_samples;
    uint16_t byte_position;
    uint16_t sample_start;
    int16_t decoded[2];
    int16_t current_sample;
    uint8_t slot;
    uint8_t channel;
    uint8_t format;
    uint8_t nibble;
    uint8_t pan;
    bool active;
    bool decoded_valid;
    MSM5xxxMA2AdpcmDecoder decoder;
} MSM5xxxMA3StreamVoice;

typedef struct MSM5xxxMA3StreamEngine {
    MSM5xxxMA3StreamVoice voice[MSM5XXX_MA3_STREAM_COUNT];
    int16_t chunk[MSM5XXX_MA3_STREAM_CHUNK][2];
    uint64_t output_frame;
    uint64_t epoch;
    uint64_t unsupported_format_count;
    uint64_t bad_descriptor_count;
    uint64_t output_failures;
    MSM5xxxMA3StreamReject reject_reason;
    bool clock_initialized;
    MSM5xxxMA3StreamEmit emit;
    void *emit_opaque;
} MSM5xxxMA3StreamEngine;

void msm5xxx_ma3_stream_init(MSM5xxxMA3StreamEngine *engine,
                             MSM5xxxMA3StreamEmit emit, void *opaque);
void msm5xxx_ma3_stream_reset(MSM5xxxMA3StreamEngine *engine,
                              uint64_t epoch);
bool msm5xxx_ma3_stream_operation(MSM5xxxMA3StreamEngine *engine,
                                  const MSM5xxxMA3Audio *device,
                                  const MSM5xxxMA3Operation *operation);
bool msm5xxx_ma3_stream_advance(MSM5xxxMA3StreamEngine *engine,
                                MSM5xxxMA3Audio *device,
                                uint64_t now_ns);

#endif
