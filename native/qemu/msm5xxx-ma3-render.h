/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA3_RENDER_H
#define MSM5XXX_MA3_RENDER_H

#include "msm5xxx-ma3-audio.h"
#include "msm5xxx-audio-synth.h"

typedef enum MSM5xxxMA3RenderReject {
    MSM5XXX_MA3_RENDER_OK = 0,
    MSM5XXX_MA3_RENDER_UNSUPPORTED_ROM_VOICE,
    MSM5XXX_MA3_RENDER_UNSUPPORTED_ALGORITHM,
    MSM5XXX_MA3_RENDER_UNSUPPORTED_WAVEFORM,
    MSM5XXX_MA3_RENDER_UNSUPPORTED_WAVE_SLOT,
    MSM5XXX_MA3_RENDER_INVALID_PITCH,
    MSM5XXX_MA3_RENDER_SYNTH_REJECTED,
} MSM5xxxMA3RenderReject;

typedef struct MSM5xxxMA3RenderVoice {
    uint8_t channel;
    uint8_t note;
    bool active;
} MSM5xxxMA3RenderVoice;

typedef struct MSM5xxxMA3Renderer {
    MSM5xxxMA3RenderVoice voice[40];
    MSM5xxxMA3RenderReject reject_reason;
    uint64_t unsupported_rom_voices;
    uint64_t unsupported_algorithms;
    uint64_t unsupported_waveforms;
    uint64_t unsupported_wave_slots;
    uint64_t invalid_pitches;
} MSM5xxxMA3Renderer;

void msm5xxx_ma3_renderer_init(MSM5xxxMA3Renderer *renderer);
bool msm5xxx_ma3_renderer_operation(
    MSM5xxxMA3Renderer *renderer, const MSM5xxxMA3Audio *device,
    const MSM5xxxMA3Operation *operation, MSM5xxxAudioSynth *synth);

#endif
