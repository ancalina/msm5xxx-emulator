/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_WAVEFORM_H
#define MSM5XXX_MA5_WAVEFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSM5XXX_MA5_WAVEFORM_BINS 1024u

/* Builds WS0/8/13/24/27; invalid arguments leave the output untouched. */
bool msm5xxx_ma5_waveform_build(uint8_t ws, int16_t *out, size_t capacity);
/* Ordinary FB0 carrier indexing only; no feedback state or renderer admission. */
uint16_t msm5xxx_ma5_phase_index(uint32_t phase, int16_t modulation);

#endif
