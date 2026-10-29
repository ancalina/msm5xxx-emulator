/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MA5_PRIVATE_WT_ENGINE_H
#define MA5_PRIVATE_WT_ENGINE_H
#include "msm5xxx-ma5-audio.h"

#define MA5_WT_RATE 48000u
#define MA5_WT_CHUNK 256u
#define MA5_WT_SLOTS 32u

typedef struct MA5WTEngine MA5WTEngine;
typedef bool (*MA5WTEmit)(void *opaque, uint64_t first_frame,
                          const int16_t *stereo, size_t frames);
typedef enum MA5WTSkip {
    MA5_WT_SKIP_NONE, MA5_WT_SKIP_UPLOAD, MA5_WT_SKIP_DESCRIPTOR,
    MA5_WT_SKIP_CONTROL, MA5_WT_SKIP_MUTATION, MA5_WT_SKIP_MODE,
    MA5_WT_SKIP_TIMELINE, MA5_WT_SKIP_ROM
} MA5WTSkip;
typedef struct MA5WTStatus {
    uint64_t frame, commits, admitted, skipped, fm_admitted, fm_skipped;
    uint64_t fm_skip_upload, fm_skip_rom, fm_skip_descriptor;
    uint64_t fm_skip_control, fm_skip_mutation, fm_skip_mode, fm_skip_timeline;
    uint64_t fm_wave_uploads, fm_wave_upload_rejects;
    uint64_t invalid, pcm_dropped;
    uint64_t timeline_gaps;
    unsigned active;
} MA5WTStatus;
typedef struct MA5WTVoiceInfo {
    bool active, held, muted;
    unsigned envelope;
    uint32_t phase, step, endpoint;
    int32_t saved, last_sample;
    uint64_t crossed_frame;
    MA5WTSkip skip;
} MA5WTVoiceInfo;

/* Private experimental PC-model arithmetic, not physical clock calibration.
 * Caller feeds every ordered consumed commit, using raw for C/S/B semantics.
 * No core backing pointer is retained. Emit is bounded and must not reenter.
 * PCM sink failure is diagnostic only; later chip commits still apply.
 * Frame boundary = ceil((event_ns-origin_ns)*48000/1e9); same-time order stays.
 * One advance is bounded to 48000 frames; larger gaps skip local voices.
 */
MA5WTEngine *ma5_wt_engine_new(uint64_t origin_ns, MA5WTEmit emit, void *opaque);
void ma5_wt_engine_free(MA5WTEngine *engine);
void ma5_wt_engine_reset(MA5WTEngine *engine, uint64_t origin_ns);
void ma5_wt_engine_commit(MA5WTEngine *engine, const MSM5xxxMA5Commit *commit);
void ma5_wt_engine_advance(MA5WTEngine *engine, uint64_t time_ns);
MA5WTStatus ma5_wt_engine_status(const MA5WTEngine *engine);
MA5WTVoiceInfo ma5_wt_engine_voice(const MA5WTEngine *engine, unsigned slot);
uint32_t ma5_wt_engine_channel_q16(const MA5WTEngine *engine, unsigned channel);
#endif
