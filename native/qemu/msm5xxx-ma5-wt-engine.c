/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-wt-engine.h"
#include "msm5xxx-ma2-audio.h"
#include "msm5xxx-ma5-gain.h"
#include "msm5xxx-ma5-fm-voice.h"
#include "msm5xxx-ma5-operator.h"
#include "msm5xxx-ma5-waveform.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

typedef struct Voice {
    MA5WTVoiceInfo info;
    uint8_t descriptor[13], payload[8192], b[64];
    int16_t decoded[16384];
    uint32_t descriptor_address, sample_address, bytes, loop;
    uint32_t side[2], level, dr, sr, rr, sustain, silence;
    unsigned channel;
    unsigned pending_edges;
    uint64_t pending_frame;
    bool descriptor_ok, pitch_ok, xof;
} Voice;

typedef struct FMVoice {
    MSM5xxxMA5FMVoice descriptor;
    MSM5xxxMA5Operator op[4];
    uint32_t base_phase_step[4], base_gain[4];
    uint32_t side[2];
    uint32_t descriptor_address;
    int32_t history[2][2];
    unsigned channel, pending_edges;
    uint64_t pending_frame;
    bool descriptor_ok, pitch_ok, active, muted;
    MA5WTSkip skip, descriptor_skip;
} FMVoice;

#define MA5_FM_LFO_PHASES 4096u

static const uint8_t fm_multiplier[16] = {
    0,1,2,3,4,5,6,7,8,9,10,10,12,12,15,15
};

struct MA5WTEngine {
    MA5WTEmit emit;
    void *opaque;
    uint64_t origin, last_time;
    MA5WTStatus stats;
    uint8_t c[564], sram[8192], b[64];
    bool ck[564], sk[8192], bk[64], bend_ok[16];
    MSM5xxxMA5GainTables gain;
    MSM5xxxMA5ChannelGain volume[16];
    uint16_t channel_gain[16];
    Voice voice[MA5_WT_SLOTS];
    FMVoice fm[32];
    uint32_t fm_lfo_phase[16], fm_lfo_step[16];
    uint8_t fm_lfo_rate[16];
    bool fm_lfo_known[16];
    uint32_t fm_pm_q20[4][MA5_FM_LFO_PHASES];
    uint16_t fm_am_q15[4][MA5_FM_LFO_PHASES];
    int16_t fm_wave[32][MSM5XXX_MA5_WAVEFORM_BINS];
    bool fm_wave_ready[32];
};

static void fm_lfo_tables_build(MA5WTEngine *e)
{
    static const double pm_log[4][3] = {
        {0.00159066887387, -0.000177280987369, 0.0000634309311738},
        {0.00313455020800, -0.000349350774479, 0.0001249967218180},
        {0.00631588300205, -0.000703947184998, 0.0002518263622080},
        {0.01253820416930, -0.001397409585010, 0.0004999974255970},
    };
    static const double am_triangle_log[4][2] = {
        {-0.0748339256470, 0.0748339922454},
        {-0.1611803206490, 0.1611812164610},
        {-0.3338745953280, 0.3338747989560},
        {-0.6792626331060, 0.6792634007960},
    };
    const double tau = 2.0 * acos(-1.0);

    for (unsigned i = 0; i < MA5_FM_LFO_PHASES; i++) {
        double phase = tau * i / MA5_FM_LFO_PHASES;
        double pitch_sine = sin(phase);
        double pitch_log_3 = sin(3.0 * phase);
        double pitch_log_5 = sin(5.0 * phase);
        double fraction = (double)i / MA5_FM_LFO_PHASES;
        double triangle = fraction < 0.5 ? 1.0 - 4.0 * fraction :
                                                   4.0 * fraction - 3.0;

        for (unsigned depth = 0; depth < 4; depth++) {
            double pm = exp(pm_log[depth][0] * pitch_sine +
                            pm_log[depth][1] * pitch_log_3 +
                            pm_log[depth][2] * pitch_log_5) * 1048576.0;
            /* shortcut: log-linear AM triangle fits within 1 Q15 count;
             * upgrade only if an independent device vector disagrees. */
            double am = exp(am_triangle_log[depth][0] +
                            am_triangle_log[depth][1] * triangle) * 32768.0;
            e->fm_pm_q20[depth][i] = (uint32_t)floor(pm + 0.5);
            if (am > 32768.0) am = 32768.0;
            e->fm_am_q15[depth][i] = (uint16_t)floor(am + 0.5);
        }
    }
}

static uint32_t fm_lfo_phase_step(unsigned rate)
{
    static const uint8_t rate_tenths_hz[4] = {19, 42, 61, 72};
    uint64_t denominator = UINT64_C(10) * MA5_WT_RATE;

    if (rate >= 4u) return 0;
    return (uint32_t)(((uint64_t)rate_tenths_hz[rate] *
                       (UINT64_C(1) << 32) + denominator / 2u) /
                      denominator);
}

static int64_t floor_div64(int64_t value, int64_t divisor)
{
    return value / divisor - (value < 0 && value % divisor != 0);
}

static int32_t floor_div(int64_t value, int64_t divisor)
{
    return (int32_t)floor_div64(value, divisor);
}

static uint32_t bend_factor_q16(unsigned high, unsigned low)
{
    return ((((uint32_t)high&31u)<<7) | (low&126u)) << 6;
}

static uint32_t eg_rate_q30(unsigned setting, unsigned offset)
{
    static const double base_ms[4] = {5.25,4.2,3.5,3.0};
    unsigned rate;
    double ms;

    if (!setting) return UINT32_C(1) << 30;
    rate=4*setting+offset;
    if (rate>63) rate=63;
    if (rate<4) return UINT32_C(1) << 30;
    ms=rate>=60 ? 2.625 : base_ms[rate&3] * ldexp(1.0,(59-rate)/4);
    return (uint32_t)floor((double)(UINT32_C(1)<<30) *
        pow(10.0,-96.0/(20.0*ms*MA5_WT_RATE/1000.0))+0.5);
}

static void skip(MA5WTEngine *e, Voice *v, MA5WTSkip reason)
{
    v->info.active = false;
    v->info.skip = reason;
    e->stats.skipped++;
}

static void skip_all(MA5WTEngine *e, MA5WTSkip reason)
{
    for (unsigned i = 0; i < MA5_WT_SLOTS; i++) {
        if (e->voice[i].info.active) skip(e, &e->voice[i], reason);
    }
}

static void fm_skip(MA5WTEngine *e, FMVoice *v, MA5WTSkip reason)
{
    v->active = false;
    v->skip = reason;
    e->stats.fm_skipped++;
    switch (reason) {
    case MA5_WT_SKIP_UPLOAD: e->stats.fm_skip_upload++; break;
    case MA5_WT_SKIP_ROM: e->stats.fm_skip_rom++; break;
    case MA5_WT_SKIP_DESCRIPTOR: e->stats.fm_skip_descriptor++; break;
    case MA5_WT_SKIP_CONTROL: e->stats.fm_skip_control++; break;
    case MA5_WT_SKIP_MUTATION: e->stats.fm_skip_mutation++; break;
    case MA5_WT_SKIP_MODE: e->stats.fm_skip_mode++; break;
    case MA5_WT_SKIP_TIMELINE: e->stats.fm_skip_timeline++; break;
    case MA5_WT_SKIP_NONE: break;
    }
}

static void fm_skip_all(MA5WTEngine *e, MA5WTSkip reason)
{
    for (unsigned i = 0; i < 32; i++) {
        if (e->fm[i].active) fm_skip(e, &e->fm[i], reason);
    }
}

static bool known_span(const MA5WTEngine *e, uint32_t address, uint32_t count)
{
    if (address < 0x4000u || address >= 0x6000u || count > 0x6000u-address)
        return false;
    for (uint32_t i = 0; i < count; i++) {
        if (!e->sk[address-0x4000u+i]) return false;
    }
    return true;
}

static unsigned fm_slot_base(unsigned slot)
{
    return slot < 16 ? 6 * slot : 272 + 6 * (slot - 16);
}

static unsigned fm_slot_from_address(unsigned address)
{
    return address < 96 ? address / 6 : 16 + (address - 272) / 6;
}

static void fm_descriptor(MA5WTEngine *e, FMVoice *v, unsigned base)
{
    v->descriptor_ok = false;
    v->descriptor_skip = MA5_WT_SKIP_UPLOAD;
    if (!e->ck[base] || !e->ck[base + 1]) {
        v->descriptor_skip = MA5_WT_SKIP_CONTROL;
        return;
    }
    uint32_t address = ((uint32_t)e->c[base] << 8) |
                       ((uint32_t)e->c[base + 1] << 1);
    v->descriptor_address = address;
    if (address < 0x4000u) {
        v->descriptor_skip = MA5_WT_SKIP_ROM;
        return;
    }
    if (address >= 0x6000u || !known_span(e, address, 2)) return;
    const uint8_t *source = e->sram + address - 0x4000u;
    unsigned algorithm = source[1] & 7u;
    unsigned size = algorithm < 2u ? 16u : 30u;
    if (!known_span(e, address, size)) return;
    if (!msm5xxx_ma5_fm_voice_decode(source, size, &v->descriptor)) {
        v->descriptor_skip = MA5_WT_SKIP_DESCRIPTOR;
        return;
    }
    v->descriptor_ok = true;
    v->descriptor_skip = MA5_WT_SKIP_NONE;
}

static bool fm_phase_step(unsigned fnum, unsigned block, unsigned octave,
                          unsigned multiplier, uint32_t bend_q16,
                          uint32_t *step)
{
    int shift = (int)block - (int)octave + 13;
    uint64_t value = fnum;
    if (shift >= 0) {
        if (shift >= 32 || value > (UINT32_MAX >> shift)) return false;
        value <<= shift;
    } else {
        value >>= (unsigned)-shift;
    }
    value = multiplier ? value * fm_multiplier[multiplier & 15u] : value / 2u;
    value = (value * bend_q16) >> 16;
    if (!value || value > UINT32_MAX) return false;
    *step = (uint32_t)value;
    return true;
}

static bool fm_apply_multiplier(uint32_t base, unsigned multiplier,
                                uint32_t *step)
{
    uint64_t value = multiplier ?
        (uint64_t)base * fm_multiplier[multiplier & 15u] : base / 2u;

    if (value == 0u || value > UINT32_MAX) {
        return false;
    }
    *step = (uint32_t)value;
    return true;
}

static bool fm_mode_ok(const MA5WTEngine *e)
{
    return e->bk[39] && e->bk[40] && e->bk[41] && e->bk[55] && e->bk[56] &&
        (e->b[55] == 0 || e->b[55] == 0xbc) &&
        e->b[56] <= 2u;
}

static void fm_side_gain(MA5WTEngine *e, FMVoice *v, unsigned base)
{
    unsigned channel = v->channel;
    unsigned pan = e->c[208 + channel] >> 2;
    unsigned level = e->c[base + 2] >> 2;
    unsigned master = e->b[41] >> 3;
    uint32_t gain = (e->gain.slotgain[level] * e->channel_gain[channel]) >> 15;
    for (unsigned lane = 0; lane < 2; lane++) {
        uint32_t pan_gain = e->gain.a[(lane ? e->gain.cp_r[pan] :
                                                e->gain.cp_l[pan]) >> 16];
        uint32_t side = (gain * pan_gain) >> 15;
        v->side[lane] = (side * e->gain.g32[master]) >> 15;
    }
}

static int32_t wrap_i32(int64_t value)
{
    uint32_t wrapped = (uint32_t)value;
    return wrapped <= INT32_MAX ? (int32_t)wrapped :
           (int32_t)((int64_t)wrapped - INT64_C(0x100000000));
}

static int32_t arithmetic_shift(int32_t value, unsigned shift)
{
    if (!shift) return value;
    int64_t divisor = INT64_C(1) << shift;
    return (int32_t)(value / divisor - (value < 0 && value % divisor != 0));
}

static int32_t fm_feedback(const FMVoice *v, unsigned op)
{
    static const uint8_t shift[8] = {0, 8, 7, 6, 5, 4, 3, 2};
    unsigned pair = op == 2 ? 1 : 0;
    unsigned amount = shift[v->descriptor.operators[op].feedback & 7u];
    int32_t sum = wrap_i32((int64_t)v->history[pair][0] +
                           v->history[pair][1]);
    return amount ? arithmetic_shift(sum, amount) : 0;
}

static void fm_history(FMVoice *v, unsigned op, int32_t output)
{
    unsigned pair = op == 2 ? 1 : 0;
    v->history[pair][1] = v->history[pair][0];
    v->history[pair][0] = output;
}

static MA5WTSkip fm_start(MA5WTEngine *e, FMVoice *v, unsigned slot)
{
    unsigned base = fm_slot_base(slot);
    unsigned channel = e->c[base + 5] & 15u;
    unsigned bend = 240u + 2u * channel;
    const MSM5xxxMA5FMVoice *d = &v->descriptor;

    if (!v->descriptor_ok) {
        return v->descriptor_skip == MA5_WT_SKIP_NONE ?
               MA5_WT_SKIP_UPLOAD : v->descriptor_skip;
    }
    if (!fm_mode_ok(e) || (slot>=16 && !(e->b[56]&1u)) ||
        ((e->b[56]&1u) && d->operator_count!=2u))
        return MA5_WT_SKIP_MODE;
    if (!e->ck[base + 2] || !e->ck[base + 3] || !e->ck[base + 4] ||
        !e->ck[192 + channel] || !e->ck[208 + channel] ||
        !e->ck[224 + channel] ||
        !e->bend_ok[channel] || !e->ck[bend] || !e->ck[bend + 1] ||
        (e->c[base + 3] & 0x40u) || (e->c[bend] & 0x60u) ||
        (e->c[bend + 1] & 1u) || (e->c[208 + channel] & 1u)) {
        return MA5_WT_SKIP_CONTROL;
    }
    if (d->operator_count != (d->algorithm < 2u ? 2u : 4u) ||
        d->reserved || d->pan_enable || d->pan_off) {
        return MA5_WT_SKIP_DESCRIPTOR;
    }
    /* Manual and ROM descriptor mapping both make raw BO=1 neutral; the
     * other raw values disagree, so keep those descriptors on native fallback. */
    if (d->base_octave != 1u) return MA5_WT_SKIP_DESCRIPTOR;
    unsigned fnum = ((unsigned)(e->c[base + 3] & 7u) << 7) |
                    e->c[base + 4];
    unsigned block = (e->c[base + 3] >> 3) & 7u;
    unsigned octave = block;
    unsigned key_scale = 2u * octave + (fnum >> 9);
    static const uint8_t key_class[16] = {
        0,0,0,0,0,0,0,1,2,3,3,3,3,3,3,3
    };
    unsigned detune_key = 4u * block + key_class[(fnum >> 6) & 15u];
    uint32_t bend_q16 = bend_factor_q16(e->c[bend], e->c[bend + 1]);

    for (unsigned i = 0; i < d->operator_count; i++) {
        const MSM5xxxMA5FMOperatorParams *p = &d->operators[i];
        uint32_t step;
        bool feedback_op = i == 0 || (d->algorithm == 5u && i == 2);
        if (p->reserved || p->xof ||
            (p->feedback && !feedback_op) ||
            !e->fm_wave_ready[p->waveform]) {
            return MA5_WT_SKIP_DESCRIPTOR;
        }
        if (p->detune == 0u) {
            if (!fm_phase_step(fnum, block, d->base_octave, p->multiplier,
                               bend_q16, &step)) {
                return MA5_WT_SKIP_DESCRIPTOR;
            }
        } else {
            if (!fm_phase_step(fnum, block, d->base_octave, 1u,
                               bend_q16, &step)) {
                return MA5_WT_SKIP_DESCRIPTOR;
            }
            step = msm5xxx_ma5_fm_detune_step(step, p->detune, detune_key,
                                              MA5_WT_RATE);
            if (step == 0u || !fm_apply_multiplier(step, p->multiplier,
                                                   &step)) {
                return MA5_WT_SKIP_DESCRIPTOR;
            }
        }
        unsigned rate_offset = p->key_scale_rate ? key_scale : key_scale >> 2;
        uint16_t ksl = msm5xxx_ma5_fm_ksl_gain(p->key_scale_level,
                                               fnum >> 6, octave);
        uint32_t gain = (e->gain.tl[p->total_level] * (uint32_t)ksl) >> 15;
        v->op[i] = (MSM5xxxMA5Operator){
            .env_state = 2,
            .phase = 0,
            .phase_step = step,
            .attack = msm5xxx_ma5_fm_attack_step(p->attack_rate, rate_offset,
                                                  MA5_WT_RATE),
            .decay = eg_rate_q30(p->decay_rate, rate_offset),
            .sr_mul = eg_rate_q30(p->sustain_rate, rate_offset),
            .rr_mul = eg_rate_q30(p->release_rate, rate_offset),
            .sustain_level = e->gain.sl[p->sustain_level],
            .level = 0,
            .released_use_sr = p->sustain &&
                               (e->c[224 + channel] & 0x10u),
            .gain = gain,
        };
        v->base_phase_step[i] = step;
        v->base_gain[i] = gain;
    }
    v->channel = channel;
    if (!e->fm_lfo_known[channel] || e->fm_lfo_rate[channel] != d->lfo) {
        e->fm_lfo_rate[channel] = d->lfo;
        e->fm_lfo_step[channel] = fm_lfo_phase_step(d->lfo);
        e->fm_lfo_known[channel] = true;
    }
    v->muted = !!(e->c[base + 5] & 0x20u);
    v->active = true;
    v->pending_edges = 0;
    memset(v->history, 0, sizeof(v->history));
    fm_side_gain(e, v, base);
    e->stats.fm_admitted++;
    return MA5_WT_SKIP_NONE;
}

static int32_t fm_operator(MA5WTEngine *e, FMVoice *v, unsigned index,
                           bool modulated, int32_t phase_mod)
{
    unsigned waveform = v->descriptor.operators[index].waveform;
    const MSM5xxxMA5FMOperatorParams *params = &v->descriptor.operators[index];
    unsigned lfo_phase = e->fm_lfo_phase[v->channel] >> 20;
    uint32_t phase_step = v->base_phase_step[index];
    uint32_t gain = v->base_gain[index];
    int32_t output = 0;

    if (waveform >= 32u || !e->fm_wave_ready[waveform]) return 0;
    if (params->vibrato_enable) {
        static const uint8_t modulation_level[8] = {0, 1, 2, 2, 3, 3, 4, 4};
        unsigned modulation = modulation_level[e->c[224u + v->channel] & 7u];
        if (modulation != 0u) {
            unsigned depth = modulation + params->vibrato_depth - 1u;
            if (depth > 3u) depth = 3u;
            phase_step = (uint32_t)(((uint64_t)phase_step *
                           e->fm_pm_q20[depth][lfo_phase]) >> 20);
        }
    }
    if (params->amplitude_enable) {
        gain = (uint32_t)(((uint64_t)gain *
                e->fm_am_q15[params->amplitude_depth][lfo_phase]) >> 15);
    }
    v->op[index].phase_step = phase_step;
    v->op[index].gain = gain;
    if (!msm5xxx_ma5_operator_step(&v->op[index], e->fm_wave[waveform],
                                   MSM5XXX_MA5_WAVEFORM_BINS, modulated,
                                   phase_mod, &output)) {
        return 0;
    }
    return output;
}

static int32_t fm_sample(MA5WTEngine *e, FMVoice *v)
{
    int32_t y0, y1, y2, y3;
    y0 = fm_operator(e, v, 0, v->descriptor.operators[0].feedback != 0,
                     fm_feedback(v, 0));
    fm_history(v, 0, y0);
    if (v->descriptor.algorithm == 0u) {
        y1 = fm_operator(e, v, 1, true, y0);
        return y1;
    }
    if (v->descriptor.algorithm == 1u) {
        y1 = fm_operator(e, v, 1, false, 0);
        return wrap_i32((int64_t)y0 + y1);
    }
    if (v->descriptor.algorithm == 2u) {
        y1 = fm_operator(e, v, 1, false, 0);
        y2 = fm_operator(e, v, 2, false, 0);
        y3 = fm_operator(e, v, 3, false, 0);
        return wrap_i32((int64_t)y0 + y1 + y2 + y3);
    }
    if (v->descriptor.algorithm == 3u) {
        y1 = fm_operator(e, v, 1, false, 0);
        y2 = fm_operator(e, v, 2, true, y1);
        y3 = fm_operator(e, v, 3, true, wrap_i32((int64_t)y0 + y2));
        return y3;
    }
    if (v->descriptor.algorithm == 4u) {
        y1 = fm_operator(e, v, 1, true, y0);
        y2 = fm_operator(e, v, 2, true, y1);
        return fm_operator(e, v, 3, true, y2);
    }
    if (v->descriptor.algorithm == 5u) {
        y1 = fm_operator(e, v, 1, true, y0);
        y2 = fm_operator(e, v, 2,
                         v->descriptor.operators[2].feedback != 0,
                         fm_feedback(v, 2));
        fm_history(v, 2, y2);
        y3 = fm_operator(e, v, 3, true, y2);
        return wrap_i32((int64_t)y1 + y3);
    }
    if (v->descriptor.algorithm == 6u) {
        y1 = fm_operator(e, v, 1, false, 0);
        y2 = fm_operator(e, v, 2, true, y1);
        y3 = fm_operator(e, v, 3, true, y2);
        return wrap_i32((int64_t)y0 + y3);
    }
    y1 = fm_operator(e, v, 1, false, 0);
    y2 = fm_operator(e, v, 2, true, y1);
    y3 = fm_operator(e, v, 3, false, 0);
    return wrap_i32((int64_t)y0 + y2 + y3);
}

static void fm_release(FMVoice *v, unsigned channel_esus)
{
    for (unsigned i = 0; i < v->descriptor.operator_count; i++) {
        MSM5xxxMA5FMOperatorParams *p = &v->descriptor.operators[i];
        if (v->op[i].env_state && !p->xof) {
            v->op[i].released_use_sr = p->sustain && channel_esus;
            v->op[i].env_state = 1;
        }
    }
}

static void apply_fm_control(MA5WTEngine *e, unsigned address, uint8_t value,
                             uint8_t old, bool known)
{
    unsigned slot = fm_slot_from_address(address);
    unsigned base = fm_slot_base(slot);
    unsigned field = address - base;
    FMVoice *v = &e->fm[slot];

    if (field < 5u && v->active && (!known || old != value)) {
        fm_skip(e,v,MA5_WT_SKIP_MUTATION);
    }
    if (field == 0u && (!known || old != value)) v->descriptor_ok = false;
    if (field == 1u) fm_descriptor(e,v,base);
    if (field == 3u && (!known || old != value)) v->pitch_ok = false;
    if (field == 4u) v->pitch_ok = e->ck[base + 3];
    if (field != 5u) return;

    if (v->active && (value & 15u) != v->channel) {
        fm_skip(e,v,MA5_WT_SKIP_CONTROL);
        return;
    }
    bool rise = known && !(old & 0x40u) && (value & 0x40u);
    bool fall = known && (old & 0x40u) && !(value & 0x40u);
    if (v->pending_frame != e->stats.frame) v->pending_edges = 0;
    v->pending_frame = e->stats.frame;
    v->pending_edges |= rise ? 1u : fall ? 2u : 0u;
    if (v->pending_edges == 3u) {
        fm_skip(e,v,MA5_WT_SKIP_CONTROL);
        return;
    }
    if ((value & 0x10u) != 0u) {
        v->active = false;
        if (value & 0x40u) fm_skip(e,v,MA5_WT_SKIP_CONTROL);
        return;
    }
    if (!known && (value & 0x40u)) {
        fm_skip(e,v,MA5_WT_SKIP_CONTROL);
        return;
    }
    if (rise) {
        MA5WTSkip reason = !v->pitch_ok ? MA5_WT_SKIP_CONTROL :
                           fm_start(e,v,slot);
        if (reason != MA5_WT_SKIP_NONE) {
            fm_skip(e,v,reason);
            return;
        }
    } else if (fall && v->active) {
        fm_release(v,e->c[224 + v->channel] & 0x10u);
    }
    if (v->active) v->muted = !!(value & 0x20u);
}

static uint32_t be16(const uint8_t *p)
{
    return ((uint32_t)p[0] << 8) | p[1];
}

static void descriptor(MA5WTEngine *e, Voice *v, unsigned base)
{
    v->descriptor_ok = false;
    if (!e->ck[base]) return;
    v->descriptor_address = ((uint32_t)e->c[base] << 8) | (e->c[base+1] << 1);
    if (!known_span(e, v->descriptor_address, 13)) return;
    memcpy(v->descriptor, e->sram + v->descriptor_address-0x4000u, 13);
    v->descriptor_ok = true;
}

static bool mode_ok(const MA5WTEngine *e)
{
    return e->bk[39] && e->bk[40] && e->bk[42] && e->bk[55] && e->bk[56] &&
        e->b[39] == 0xf8 && e->b[40] == 0xf8 && !(e->b[42] & 4) &&
        (e->b[55] == 0 || e->b[55] == 0xbc) &&
        (e->b[56] == 0 || e->b[56] == 2);
}

static void side_gain(MA5WTEngine *e, Voice *v, unsigned base)
{
    uint32_t gain = (e->gain.slotgain[e->c[base+2] >> 2] *
                     (uint32_t)e->channel_gain[v->channel]) >> 15;
    unsigned pan = e->c[208+v->channel] >> 2;
    unsigned tl = v->descriptor[5] >> 2;
    if (tl) gain=(gain*e->gain.tl[tl])>>15;
    v->side[0] = (gain * e->gain.a[e->gain.cp_l[pan] >> 16]) >> 15;
    v->side[1] = (gain * e->gain.a[e->gain.cp_r[pan] >> 16]) >> 15;
    for (unsigned i = 0; i < 2; i++)
        v->side[i] = (v->side[i] * e->gain.g32[e->b[42] >> 3]) >> 15;
}

static unsigned slot_base(unsigned slot)
{
    return slot < 16 ? 96+6*slot : 368+6*(slot-16);
}

static void start(MA5WTEngine *e, Voice *v, unsigned base)
{
    uint8_t *d = v->descriptor;
    unsigned ch = e->c[base+5] & 15;
    if (!v->descriptor_ok) { skip(e,v,MA5_WT_SKIP_UPLOAD); return; }
    uint32_t ep = be16(d+11), lp = be16(d+9), sa = be16(d+7);
    /* shortcut: AR15, no PE/PANOFF/EAM and channel vibrato disabled; active modulation stays closed. */
    if (d[0] != 0x78 || (d[1] & 0x3f) || (d[2] & 5) || (d[4] >> 4) != 15 ||
        (d[5] & 3) || (d[6] & 0x10) || !ep || ep > 16384 || lp > ep) {
        skip(e,v,MA5_WT_SKIP_DESCRIPTOR); return;
    }
    uint32_t bytes = (ep+1)/2;
    if (!known_span(e,sa,bytes)) { skip(e,v,MA5_WT_SKIP_UPLOAD); return; }
    if (!mode_ok(e)) { skip(e,v,MA5_WT_SKIP_MODE); return; }
    if ((base==422 || base==428) && (e->b[56]&2)) {
        skip(e,v,MA5_WT_SKIP_MODE); return;
    }
    for (unsigned i = 0; i < 6; i++) {
        if (!e->ck[base+i]) { skip(e,v,MA5_WT_SKIP_CONTROL); return; }
    }
    unsigned bend = 240+2*ch;
    if ((e->c[base+2]&3) || (e->c[base+3]&64) ||
        !v->pitch_ok || !e->ck[192+ch] || !e->ck[208+ch] || !e->ck[224+ch] ||
        e->c[224+ch] || !e->bend_ok[ch] ||
        (e->c[bend]&0x60) || (e->c[bend+1]&1) || (e->c[208+ch]&3) ||
        ((e->c[192+ch]&3) && (e->b[55] != 0 || (e->c[192+ch]&3) != 1))) {
        skip(e,v,MA5_WT_SKIP_CONTROL); return;
    }
    uint32_t fnum = ((e->c[base+3]&7u)<<7) | e->c[base+4];
    unsigned block = (e->c[base+3] >> 3)&7;
    unsigned rof=2*block+(fnum>>9);
    uint64_t step=((uint64_t)(1024+fnum)<<(block+1))*
        bend_factor_q16(e->c[bend],e->c[bend+1])>>16;
    v->info = (MA5WTVoiceInfo){.active=true, .envelope=2,
        .muted=!!(e->c[base+5]&32), .step=(uint32_t)step,
        .endpoint=ep, .crossed_frame=UINT64_MAX};
    v->sample_address=sa; v->bytes=bytes; v->loop=lp;
    v->channel=ch; v->level=0; v->xof=!!(d[2]&8);
    v->dr=eg_rate_q30(d[3]&15,rof);
    v->sr=eg_rate_q30(d[2]>>4,rof);
    v->rr=eg_rate_q30(d[3]>>4,rof);
    v->sustain=e->gain.sl[d[4]&15];
    v->silence=(uint32_t)floor((double)(UINT32_C(1)<<31)*pow(10.0,-96.0/20.0)+0.5);
    memcpy(v->payload,e->sram+sa-0x4000u,bytes);
    memcpy(v->b,e->b,sizeof(v->b));
    MSM5xxxMA2AdpcmDecoder decoder;
    msm5xxx_ma2_adpcm_decoder_reset(&decoder);
    for (uint32_t i=0;i<bytes;i++) {
        int16_t pair[2];
        (void)msm5xxx_ma2_adpcm_decode_byte(&decoder,v->payload[i],pair);
        v->decoded[2*i]=pair[0];
        if (2*i+1<ep) v->decoded[2*i+1]=pair[1];
    }
    /* Immutable predecode reuses the verified loop-point decoder state. */
    side_gain(e,v,base);
    e->stats.admitted++;
}

static int32_t sample(Voice *v, uint64_t frame)
{
    MA5WTVoiceInfo *s=&v->info;
    if (!s->envelope) return 0;
    if (s->envelope == 2) {
        /* KEY reset and admitted AR15 attack occupy independent sample frames. */
        s->phase=0; v->level=0; s->envelope=3;
    } else if (s->envelope == 3) {
        v->level=UINT32_C(0x80000000); s->envelope=4;
    } else if (s->envelope == 4) {
        v->level=(uint32_t)(((uint64_t)v->level*v->dr)>>30);
        if (v->level<=v->sustain) s->envelope=5;
    } else if (s->envelope == 5) {
        v->level=(uint32_t)(((uint64_t)v->level*v->sr)>>30);
        if (v->level<=v->silence) s->envelope=0;
    } else if (s->envelope == 1) {
        v->level=(uint32_t)(((uint64_t)v->level*v->rr)>>30);
        if (v->level<=v->silence) s->envelope=0;
    }
    uint32_t amp=((v->level>>16)*32767u)>>15;
    if (s->held) return floor_div((int64_t)s->saved*amp,32768);
    uint32_t index=s->phase>>16;
    uint32_t next=index+1<s->endpoint ? index+1 : v->loop<s->endpoint ? v->loop : index;
    int32_t a=v->decoded[index], b=v->decoded[next];
    int32_t raw=a+floor_div((int64_t)(b-a)*(s->phase&65535u),65536);
    int32_t out=floor_div((int64_t)raw*amp,32768);
    s->phase+=s->step;
    if ((uint64_t)s->phase >= (uint64_t)s->endpoint*65536u) {
        if (v->loop < s->endpoint) {
            uint64_t loop_phase=(uint64_t)v->loop*65536u;
            uint64_t end_phase=(uint64_t)s->endpoint*65536u;
            uint64_t loop_length=end_phase-loop_phase;
            s->phase=(uint32_t)(loop_phase+((s->phase-loop_phase)%loop_length));
        }
        else { s->held=true; s->crossed_frame=frame; }
    }
    s->saved=out;
    return out;
}

static void render(MA5WTEngine *e, uint64_t target)
{
    int16_t pcm[MA5_WT_CHUNK*2];
    while (e->stats.frame<target) {
        uint64_t first=e->stats.frame;
        size_t count=target-first>MA5_WT_CHUNK ? MA5_WT_CHUNK : (size_t)(target-first);
        for (size_t j=0;j<count;j++,e->stats.frame++) {
            int64_t mix[2]={0,0};
            int64_t fm_mix[2]={0,0};
            for (unsigned ch=0;ch<16;ch++)
                (void)msm5xxx_ma5_channel_gain_step(&e->gain,&e->volume[ch],
                    (e->b[55]&32) ? 65536 : 262144,&e->channel_gain[ch]);
            for (unsigned i=0;i<MA5_WT_SLOTS;i++) {
                Voice *v=&e->voice[i];
                if (!v->info.active) continue;
                if (!(e->stats.frame%32)) side_gain(e,v,slot_base(i));
                int32_t out=sample(v,e->stats.frame);
                v->info.last_sample=out;
                v->pending_edges=0;
                if (v->info.muted) continue;
                for (unsigned lane=0;lane<2;lane++)
                    mix[lane]+=(int64_t)floor_div((int64_t)out*v->side[lane],32768)*
                        (1u<<(v->b[42]&3));
            }
            for (unsigned i=0;i<32;i++) {
                FMVoice *v=&e->fm[i];
                if (!v->active) continue;
                if (!(e->stats.frame%32))
                    fm_side_gain(e,v,fm_slot_base(i));
                int32_t out=fm_sample(e,v);
                bool envelope_active=false;
                for (unsigned op=0;op<v->descriptor.operator_count;op++)
                    envelope_active |= v->op[op].env_state != 0;
                if (!envelope_active) v->active=false;
                if (v->muted) continue;
                unsigned shift=e->b[41]&3u;
                for (unsigned lane=0;lane<2;lane++) {
                    int32_t scaled=(int32_t)floor_div64(
                        (int64_t)out*v->side[lane],32768);
                    uint32_t shifted=(uint32_t)scaled<<shift;
                    fm_mix[lane]+=wrap_i32(shifted);
                }
            }
            for (unsigned ch=0;ch<16;ch++) {
                if (e->fm_lfo_known[ch]) e->fm_lfo_phase[ch] += e->fm_lfo_step[ch];
            }
            for (unsigned lane=0;lane<2;lane++) {
                unsigned master_reg=39u+lane;
                uint32_t master=e->gain.g32[e->b[master_reg]>>3] <<
                                (e->b[master_reg]&3u);
                fm_mix[lane]=floor_div64(fm_mix[lane]*master,32768);
                mix[lane]+=fm_mix[lane];
                int64_t out=mix[lane];
                if (out>32767) out=32767;
                if (out<-32767) out=-32767;
                pcm[j*2+lane]=(int16_t)floor_div(out*32767,32768);
            }
        }
        if (!e->emit(e->opaque,first,pcm,count)) e->stats.pcm_dropped+=count;
    }
}

MA5WTEngine *ma5_wt_engine_new(uint64_t origin, MA5WTEmit emit, void *opaque)
{
    if (!emit) return NULL;
    MA5WTEngine *e=calloc(1,sizeof(*e));
    if (e) { e->emit=emit; e->opaque=opaque; ma5_wt_engine_reset(e,origin); }
    return e;
}

void ma5_wt_engine_free(MA5WTEngine *e) { free(e); }

void ma5_wt_engine_reset(MA5WTEngine *e, uint64_t origin)
{
    if (!e) return;
    MA5WTEmit emit=e->emit; void *opaque=e->opaque;
    memset(e,0,sizeof(*e));
    e->emit=emit; e->opaque=opaque; e->origin=e->last_time=origin;
    (void)msm5xxx_ma5_gain_init(&e->gain);
    for (unsigned waveform = 0; waveform < 32; waveform++) {
        e->fm_wave_ready[waveform] = msm5xxx_ma5_waveform_build(
            waveform, e->fm_wave[waveform], MSM5XXX_MA5_WAVEFORM_BINS);
    }
    fm_lfo_tables_build(e);
    for (unsigned ch=0;ch<16;ch++) {
        e->volume[ch]=(MSM5xxxMA5ChannelGain){e->gain.cv[24],e->gain.cv[24],false};
        e->channel_gain[ch]=e->gain.a[e->gain.cv[24]>>16];
    }
}

void ma5_wt_engine_advance(MA5WTEngine *e, uint64_t time)
{
    if (!e) return;
    if (time<e->last_time) {
        e->stats.invalid++;
        skip_all(e,MA5_WT_SKIP_TIMELINE);
        fm_skip_all(e,MA5_WT_SKIP_TIMELINE);
        return;
    }
    uint64_t delta=time-e->origin;
    uint64_t target=(delta/1000000000u)*MA5_WT_RATE+
        ((delta%1000000000u)*MA5_WT_RATE+999999999u)/1000000000u;
    if (target-e->stats.frame>MA5_WT_RATE) {
        e->stats.invalid++; e->stats.timeline_gaps++;
        skip_all(e,MA5_WT_SKIP_TIMELINE);
        fm_skip_all(e,MA5_WT_SKIP_TIMELINE);
        e->stats.frame=target;
    } else render(e,target);
    e->last_time=time;
}

static void load_uploaded_waveform(MA5WTEngine *e, unsigned address,
                                   uint8_t low_address)
{
    static const uint8_t waveform_by_control[3] = {15, 23, 31};
    unsigned slot;
    unsigned high_address;
    uint32_t source_address;
    unsigned source_offset;

    if (address == 465u) {
        slot = 0;
    } else if (address == 467u) {
        slot = 1;
    } else if (address == 469u) {
        slot = 2;
    } else {
        return;
    }
    if (!e->ck[address - 1u]) {
        e->stats.fm_wave_upload_rejects++;
        return;
    }
    high_address = e->c[address - 1u] & 0x7fu;
    source_address = 2u * ((low_address & 0x7fu) | (high_address << 7));
    if (source_address < 0x4000u || source_address >= 0x5800u ||
        source_address + 0x800u > 0x6000u) {
        e->stats.fm_wave_upload_rejects++;
        return;
    }
    source_offset = source_address - 0x4000u;
    for (unsigned i = 0; i < 0x800u; i++) {
        if (!e->sk[source_offset + i]) {
            e->stats.fm_wave_upload_rejects++;
            return;
        }
    }
    for (unsigned i = 0; i < MSM5XXX_MA5_WAVEFORM_BINS; i++) {
        uint16_t sample = ((uint16_t)e->sram[source_offset + 2u * i] << 8) |
                          e->sram[source_offset + 2u * i + 1u];
        if (sample > 0x7fffu) {
            sample = (uint16_t)(0u - sample);
        }
        e->fm_wave[waveform_by_control[slot]][i] = (int16_t)sample;
    }
    e->fm_wave_ready[waveform_by_control[slot]] = true;
    e->stats.fm_wave_uploads++;
}

static void apply_control(MA5WTEngine *e, unsigned address, uint8_t raw)
{
    uint8_t value=raw&127, old=e->c[address];
    bool known=e->ck[address];
    e->c[address]=value; e->ck[address]=true;
    load_uploaded_waveform(e, address, value);
    bool wt=(address>=96 && address<192) || (address>=368 && address<464);
    if (wt) {
        unsigned slot=address<192 ? (address-96)/6 : 16+(address-368)/6;
        unsigned base=slot_base(slot), field=address-base;
        Voice *v=&e->voice[slot];
        if (field<5 && v->info.active && (!known || old!=value)) skip(e,v,MA5_WT_SKIP_MUTATION);
        if (field==0 && (!known || old!=value)) v->descriptor_ok=false;
        if (field==1) descriptor(e,v,base);
        if (field==3 && (!known || old!=value)) v->pitch_ok=false;
        if (field==4) v->pitch_ok=e->ck[base+3];
        if (field!=5) return;
        if (v->info.active && (value&15)!=v->channel) skip(e,v,MA5_WT_SKIP_CONTROL);
        bool rise=known && !(old&64) && (value&64);
        bool fall=known && (old&64) && !(value&64);
        if (v->pending_frame!=e->stats.frame) v->pending_edges=0;
        v->pending_frame=e->stats.frame;
        v->pending_edges |= rise ? 1u : fall ? 2u : 0u;
        if (v->pending_edges==3) { skip(e,v,MA5_WT_SKIP_CONTROL); return; }
        if (!known && (value&64) && !(value&16)) {
            skip(e,v,MA5_WT_SKIP_CONTROL); return;
        }
        if (value&16) {
            v->info.active=false; v->info.envelope=0;
            if (value&64) start(e,v,base);
        } else if (rise) start(e,v,base);
        else if (fall && v->info.active && !v->xof) v->info.envelope=1;
        if (v->info.active) v->info.muted=!!(value&32);
        return;
    }
    if (address<96 || (address>=272 && address<368)) {
        apply_fm_control(e,address,value,old,known);
        return;
    }
    if (address>=192 && address<272) {
        unsigned ch=address<240 ? (address-192)%16 : (address-240)/2;
        if (address<208) {
            (void)msm5xxx_ma5_channel_gain_configure(&e->volume[ch],e->gain.cv[value>>2],!!(value&1));
            if (!(value&1)) e->channel_gain[ch]=e->gain.a[e->gain.cv[value>>2]>>16];
        }
        if (address>=240) {
            if (address&1) e->bend_ok[ch]=e->ck[address-1];
            else if (!known || old!=value) e->bend_ok[ch]=false;
        }
        if (!known || old!=value) for (unsigned i=0;i<MA5_WT_SLOTS;i++) {
            Voice *v=&e->voice[i];
            if (v->info.active && v->channel==ch) skip(e,v,MA5_WT_SKIP_MUTATION);
        }
        /* Direct volume/pan use the existing gain refresh; interpolated controls stay closed. */
        if ((!known || old!=value) && !(address>=224 && address<240) &&
            !(address>=192 && address<208 && !(value&3)) &&
            !(address>=208 && address<224 && !(value&3)))
          for (unsigned i=0;i<32;i++) {
            FMVoice *v=&e->fm[i];
            if (v->active && v->channel==ch) fm_skip(e,v,MA5_WT_SKIP_MUTATION);
        }
    }
}

void ma5_wt_engine_commit(MA5WTEngine *e, const MSM5xxxMA5Commit *c)
{
    if (!e || !c) return;
    e->stats.commits++;
    if (c->time_ns<e->last_time) {
        e->stats.invalid++;
        skip_all(e,MA5_WT_SKIP_TIMELINE);
        fm_skip_all(e,MA5_WT_SKIP_TIMELINE);
        return;
    }
    ma5_wt_engine_advance(e,c->time_ns);
    if ((c->kind==MSM5XXX_MA5_COMMIT_CONTROL && (c->address>=564 || c->value!=(c->raw&127))) ||
        (c->kind==MSM5XXX_MA5_COMMIT_SRAM && (c->address<0x4000 || c->address>=0x6000 || c->value!=c->raw)) ||
        (c->kind==MSM5XXX_MA5_COMMIT_B && (c->address>=64 || c->value!=c->raw)) ||
        c->kind>MSM5XXX_MA5_COMMIT_B || c->kind<MSM5XXX_MA5_COMMIT_CONTROL) {
        e->stats.invalid++;
        skip_all(e,MA5_WT_SKIP_CONTROL);
        fm_skip_all(e,MA5_WT_SKIP_CONTROL);
        return;
    }
    if (c->kind==MSM5XXX_MA5_COMMIT_CONTROL) apply_control(e,c->address,c->raw);
    else if (c->kind==MSM5XXX_MA5_COMMIT_SRAM) {
        unsigned a=c->address-0x4000;
        if (!e->sk[a] || e->sram[a]!=c->raw) {
            for (unsigned i=0;i<MA5_WT_SLOTS;i++) {
                Voice *v=&e->voice[i];
                bool desc=c->address>=v->descriptor_address && c->address-v->descriptor_address<13;
                bool data=c->address>=v->sample_address && c->address-v->sample_address<v->bytes;
                if (v->info.active && (desc || data)) skip(e,v,MA5_WT_SKIP_MUTATION);
                if (desc) v->descriptor_ok=false;
            }
        }
        e->sram[a]=c->raw; e->sk[a]=true;
    } else {
        unsigned a=c->address;
        if (a==4 && (c->raw&128)) {
            /* Core reset semantics stay external; discard renderer coverage only. */
            skip_all(e,MA5_WT_SKIP_CONTROL);
            fm_skip_all(e,MA5_WT_SKIP_CONTROL);
            memset(e->ck,0,sizeof(e->ck)); memset(e->sk,0,sizeof(e->sk));
            memset(e->bk,0,sizeof(e->bk));
            memset(e->bend_ok,0,sizeof(e->bend_ok));
            memset(e->volume,0,sizeof(e->volume));
            memset(e->channel_gain,0,sizeof(e->channel_gain));
            for (unsigned i=0;i<MA5_WT_SLOTS;i++) e->voice[i].descriptor_ok=false;
            for (unsigned i=0;i<32;i++) e->fm[i].descriptor_ok=false;
        }
        if (!e->bk[a] || e->b[a]!=c->raw) {
            const unsigned relevant[]={4,30,31,35,36,38,39,40,42,55,56};
            for (unsigned i=0;i<sizeof(relevant)/sizeof(relevant[0]);i++)
                if (a==relevant[i]) {
                    skip_all(e,MA5_WT_SKIP_MUTATION);
                    fm_skip_all(e,MA5_WT_SKIP_MUTATION);
                }
        }
        e->b[a]=c->raw; e->bk[a]=true;
    }
}

MA5WTStatus ma5_wt_engine_status(const MA5WTEngine *e)
{
    MA5WTStatus status=e ? e->stats : (MA5WTStatus){0};
    if (e) {
        for (unsigned i=0;i<MA5_WT_SLOTS;i++)
            status.active+=e->voice[i].info.active && e->voice[i].info.envelope;
        for (unsigned i=0;i<32;i++) {
            if (!e->fm[i].active) continue;
            bool active=false;
            for (unsigned op=0;op<e->fm[i].descriptor.operator_count;op++)
                active |= e->fm[i].op[op].env_state != 0;
            status.active += active;
        }
    }
    return status;
}

MA5WTVoiceInfo ma5_wt_engine_voice(const MA5WTEngine *e, unsigned slot)
{ return e && slot<MA5_WT_SLOTS ? e->voice[slot].info : (MA5WTVoiceInfo){0}; }

uint32_t ma5_wt_engine_channel_q16(const MA5WTEngine *e, unsigned channel)
{ return e && channel<16 ? e->volume[channel].current : 0; }
