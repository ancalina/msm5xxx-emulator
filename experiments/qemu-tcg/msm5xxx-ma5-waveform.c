/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-waveform.h"

#include <math.h>

static int16_t ma5_quantize(double value)
{
    double rounded = trunc(value + 0.5);

    if (rounded > 32767.0) {
        return 32767;
    }
    if (rounded < -32767.0) {
        return -32767;
    }
    return (int16_t)rounded;
}

static double ma5_triangle(unsigned index, unsigned cycles)
{
    double phase = fmod((double)index * cycles /
                        MSM5XXX_MA5_WAVEFORM_BINS + 0.25, 1.0);

    return 1.0 - 4.0 * fabs(phase - 0.5);
}

bool msm5xxx_ma5_waveform_build(uint8_t ws, int16_t *out, size_t capacity)
{
    double cycle = 2.0 * acos(-1.0);

    if (out == NULL || capacity < MSM5XXX_MA5_WAVEFORM_BINS ||
        ws > 30u || ws == 15u || ws == 23u) {
        return false;
    }
    for (unsigned i = 0; i < MSM5XXX_MA5_WAVEFORM_BINS; i++) {
        double phase = cycle * i / MSM5XXX_MA5_WAVEFORM_BINS;
        double sine = sin(phase);
        double triangle = ma5_triangle(i, 1);

        switch (ws) {
        case 0:
            out[i] = ma5_quantize(32768.0 * sine);
            break;
        case 1:
            out[i] = ma5_quantize(32768.0 * fmax(0.0, sine));
            break;
        case 2:
            out[i] = ma5_quantize(32768.0 * fabs(sine));
            break;
        case 3:
            out[i] = (i / 256u) % 2u == 0u ?
                ma5_quantize(32768.0 * fabs(sine)) : 0;
            break;
        case 4:
            out[i] = i < 512u ?
                ma5_quantize(32768.0 * sin(2.0 * phase)) : 0;
            break;
        case 5:
            out[i] = i < 512u ?
                ma5_quantize(32768.0 * fabs(sin(2.0 * phase))) : 0;
            break;
        case 6:
            out[i] = i < 512u ? 32767 : -32767;
            break;
        case 7:
            out[i] = i < 512u ?
                ma5_quantize(32768.0 * pow(2.0, -(double)i / 32.0)) :
                ma5_quantize(-32768.0 * pow(2.0,
                    -((double)(1024u - i) - 0.5) / 32.0));
            break;
        case 8:
            out[i] = ma5_quantize(32768.0 * sqrt(2.0) * sine);
            break;
        case 9:
            out[i] = ma5_quantize(32768.0 * sqrt(2.0) * fmax(0.0, sine));
            break;
        case 10:
            out[i] = ma5_quantize(32768.0 * sqrt(2.0) * fabs(sine));
            break;
        case 11:
            out[i] = (i / 256u) % 2u == 0u ?
                ma5_quantize(32768.0 * sqrt(2.0) * fabs(sine)) : 0;
            break;
        case 12:
            out[i] = i < 512u ?
                ma5_quantize(32768.0 * sqrt(2.0) * sin(2.0 * phase)) : 0;
            break;
        case 13:
            out[i] = i < 512u ?
                ma5_quantize(32768.0 * sqrt(2.0) * fabs(sin(2.0 * phase))) : 0;
            break;
        case 14:
            out[i] = i < 512u ? 32767 : 0;
            break;
        case 16:
            out[i] = ma5_quantize(32768.0 * triangle);
            break;
        case 17:
            out[i] = ma5_quantize(32768.0 * fmax(0.0, triangle));
            break;
        case 18:
            out[i] = ma5_quantize(32768.0 * fabs(triangle));
            break;
        case 19:
            out[i] = (i / 256u) % 2u == 0u ?
                ma5_quantize(32768.0 * fabs(triangle)) : 0;
            break;
        case 20:
            out[i] = i < 512u ?
                ma5_quantize(32768.0 * ma5_triangle(i, 2)) : 0;
            break;
        case 21:
            out[i] = i < 512u ?
                ma5_quantize(32768.0 * fabs(ma5_triangle(i, 2))) : 0;
            break;
        case 22:
            out[i] = i % 512u < 256u ? 32767 : 0;
            break;
        case 24:
            out[i] = ma5_quantize(32768.0 *
                ((double)i / 512.0 - (i < 512u ? 0.0 : 2.0)));
            break;
        case 25:
            out[i] = i < 512u ? ma5_quantize(32768.0 * (double)i / 512.0) : 0;
            break;
        case 26:
            out[i] = ma5_quantize(32768.0 * (double)(i % 512u) / 512.0);
            break;
        case 27:
            out[i] = i < 128u ? (int16_t)(64u * i) :
                (i >= 512u && i < 768u ? (int16_t)(128u * (i - 512u)) : 0);
            break;
        case 28:
            out[i] = i < 256u ? (int16_t)(128u * i) :
                (i < 512u ? (int16_t)(-32767 + (int32_t)128 * (i - 256u)) : 0);
            break;
        case 29:
            out[i] = i < 256u ? (int16_t)(128u * i) :
                (i < 512u ? (int16_t)(128u * (i - 256u)) : 0);
            break;
        case 30:
            out[i] = i < 256u ? 32767 : 0;
            break;
        }
    }
    return true;
}

uint16_t msm5xxx_ma5_phase_index(uint32_t phase, int16_t modulation)
{
    int32_t half = (int32_t)modulation / 2;
    uint32_t sum;

    if (modulation < 0 && modulation % 2 != 0) {
        half--;
    }
    sum = (phase >> 20) + (uint32_t)half;
    return (uint16_t)((sum >> 2) & 1023u);
}
