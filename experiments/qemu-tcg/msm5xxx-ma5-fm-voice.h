/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_FM_VOICE_H
#define MSM5XXX_MA5_FM_VOICE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct MSM5xxxMA5FMOperatorParams {
    uint8_t sustain_rate, release_rate, decay_rate, attack_rate, sustain_level;
    uint8_t total_level, key_scale_rate, key_scale_level, sustain, xof;
    uint8_t multiplier, detune, waveform, feedback;
    uint8_t amplitude_depth, amplitude_enable, vibrato_depth, vibrato_enable;
    uint8_t reserved;
} MSM5xxxMA5FMOperatorParams;
typedef struct MSM5xxxMA5FMVoice {
    uint8_t pan, base_octave, lfo, pan_enable, pan_off, algorithm, reserved;
    uint8_t operator_count, record_size;
    MSM5xxxMA5FMOperatorParams operators[4];
} MSM5xxxMA5FMVoice;
/* Parsing does not admit an asset, waveform or synthesis mode. */
bool msm5xxx_ma5_fm_voice_decode(const uint8_t *data, size_t size,
                                MSM5xxxMA5FMVoice *voice);
uint32_t msm5xxx_ma5_fm_attack_step(unsigned setting, unsigned offset,
                                    unsigned sample_rate);
uint16_t msm5xxx_ma5_fm_ksl_gain(unsigned raw_ksl, unsigned fnum_group,
                                 unsigned octave);
uint32_t msm5xxx_ma5_fm_detune_step(uint32_t base_step, unsigned raw_detune,
                                    unsigned key_index, unsigned sample_rate);
#endif
