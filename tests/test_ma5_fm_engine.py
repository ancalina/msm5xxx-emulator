from __future__ import annotations

import hashlib
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "native/qemu"

HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "msm5xxx-ma2-audio.c"
#include "msm5xxx-ma5-wt-engine.h"

static uint64_t emitted, nonzero, pcm_hash;
static uint64_t lane_nonzero[2];
static bool emit(void *opaque, uint64_t first, const int16_t *pcm, size_t frames) {
    (void)opaque;
    assert(first==emitted);
    for (size_t i=0;i<frames*2;i++) {
        nonzero += pcm[i] != 0;
        lane_nonzero[i%2] += pcm[i] != 0;
        pcm_hash=(pcm_hash ^ (uint16_t)pcm[i]) * UINT64_C(1099511628211);
    }
    emitted += frames;
    return true;
}
static void commit(MA5WTEngine *e, MSM5xxxMA5CommitKind kind,
                   uint32_t address, uint8_t raw, uint64_t ns) {
    MSM5xxxMA5Commit c={kind,address,kind==MSM5XXX_MA5_COMMIT_CONTROL ?
                        (uint8_t)(raw&0x7f) : raw,raw,ns};
    ma5_wt_engine_commit(e,&c);
}
static void start_uploaded_voice_size(MA5WTEngine *e, const uint8_t *voice,
                                     unsigned voice_size) {
    commit(e,MSM5XXX_MA5_COMMIT_B,39,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,40,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,41,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,55,0xbc,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,56,2,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x51,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x40,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224,0,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240,8,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241,0,0);
    for (unsigned i=0;i<voice_size;i++)
        commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,voice[i],1000+i);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,0,0x40,40000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,1,0,41000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,2,0x7c,42000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,3,0x1f,43000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,4,4,44000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0,45000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0xc0,46000);
}
static void start_uploaded_voice(MA5WTEngine *e, const uint8_t *voice) {
    start_uploaded_voice_size(e,voice,30);
}
int main(void) {
    uint8_t voice[30]={
        0x79,0x43,0x02,0x64,0xff,0x9d,0x00,0x10,0x40,
        0x13,0x32,0xe2,0x67,0x00,0x50,0x00,0x02,0x41,0xd2,0x54,
        0x01,0x10,0x00,0x23,0x62,0xd4,0x02,0x01,0x10,0x00};
    uint8_t voice_template[30];
    memcpy(voice_template,voice,sizeof(voice_template));
    const uint8_t detuned_voice[30]={
        0x79,0x45,0x23,0x25,0xa0,0x56,0x00,0x70,0x00,0x33,
        0x34,0xf0,0x22,0x01,0x43,0x00,0x23,0x24,0xa1,0x78,
        0x00,0x70,0x08,0x13,0x22,0xf0,0x00,0x01,0x17,0x00};
    MA5WTEngine *e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    commit(e,MSM5XXX_MA5_COMMIT_B,39,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,40,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,41,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,55,0xbc,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,56,0x02,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x51,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x40,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224,0,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240,8,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241,0,0);
    for (unsigned i=0;i<sizeof(voice);i++)
        commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,voice[i],1000+i);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,0,0x40,40000); /* Voice address 0x4000. */
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,1,0x00,41000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,2,0x7c,42000); /* VOVOL31. */
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,3,0x1f,43000); /* BLOCK3, FNUM high7. */
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,4,4,44000);    /* FNUM900. */
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0,45000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0xc0,46000); /* Raw terminal KEY-on. */
    MA5WTStatus status=ma5_wt_engine_status(e);
    assert(status.fm_admitted==1 && status.fm_skipped==0 && status.active==1);
    ma5_wt_engine_advance(e,100000000);
    status=ma5_wt_engine_status(e);
    assert(status.frame==4800 && emitted==4800 && nonzero>100);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0x80,101000000); /* Release. */
    ma5_wt_engine_advance(e,300000000);
    assert(ma5_wt_engine_status(e).frame==14400);
    ma5_wt_engine_free(e);

    emitted=nonzero=0;
    e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    commit(e,MSM5XXX_MA5_COMMIT_B,39,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,40,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,41,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,55,0xbc,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,56,0x02,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x51,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x40,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224,0,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240,8,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241,0,0);
    for (unsigned i=0;i<sizeof(detuned_voice);i++)
        commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,detuned_voice[i],1000+i);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,0,0x40,40000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,1,0x00,41000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,2,0x7c,42000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,3,0x1f,43000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,4,4,44000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0,45000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0xc0,46000);
    status=ma5_wt_engine_status(e);
    assert(status.fm_admitted==1 && status.fm_skipped==0);
    ma5_wt_engine_advance(e,100000000);
    assert(emitted==4800 && nonzero>0);
    ma5_wt_engine_free(e);

    const uint8_t alg5[30]={
        0x79,0x45,
        0x02,0xff,0xff,0x00,0x00,0x10,0x00,
        0x02,0xff,0xff,0x00,0x00,0x10,0x00,
        0x02,0xff,0xff,0x00,0x00,0x10,0x00,
        0x02,0xff,0xff,0x00,0x00,0x10,0x00};
    emitted=nonzero=0;
    e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    commit(e,MSM5XXX_MA5_COMMIT_B,39,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,40,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,41,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,55,0,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,56,0,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x60,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x3c,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224,0,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240,8,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241,0,0);
    for (unsigned i=0;i<sizeof(alg5);i++)
        commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,alg5[i],1000+i);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,0,0x40,40000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,1,0x00,41000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,2,0x7c,42000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,3,0x1f,43000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,4,4,44000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0,45000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0xc0,46000);
    status=ma5_wt_engine_status(e);
    assert(status.fm_admitted==1 && status.fm_skipped==0);
    ma5_wt_engine_advance(e,100000000);
    assert(emitted==4800 && nonzero>100);
    ma5_wt_engine_free(e);

    const uint8_t alg01[2][16]={
        {0x79,0x40,0x02,0xff,0xff,0x00,0x00,0x10,0x00,
         0x02,0xff,0xff,0x00,0x00,0x10,0x00},
        {0x79,0x41,0x02,0xff,0xff,0x00,0x00,0x10,0x00,
         0x02,0xff,0xff,0x00,0x00,0x10,0x00}
    };
    uint64_t alg_pcm_hash[2];
    for (unsigned algorithm=0;algorithm<2;algorithm++) {
        emitted=nonzero=0;
        pcm_hash=UINT64_C(14695981039346656037);
        e=ma5_wt_engine_new(0,emit,NULL);
        assert(e);
        start_uploaded_voice_size(e,alg01[algorithm],sizeof(alg01[algorithm]));
        status=ma5_wt_engine_status(e);
        assert(status.fm_admitted==1 && status.fm_skipped==0 && status.active==1);
        ma5_wt_engine_advance(e,100000000);
        assert(emitted==4800 && nonzero>0);
        alg_pcm_hash[algorithm]=pcm_hash;
        ma5_wt_engine_free(e);
    }
    assert(alg_pcm_hash[0]!=alg_pcm_hash[1]);

    emitted=nonzero=0;
    e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    const uint8_t pan_voice[16]={
        0x79,0x41,0x00,0xf0,0xf0,0x20,0x00,0x10,0x00,
        0x00,0xf0,0xf0,0x20,0x00,0x10,0x00};
    start_uploaded_voice_size(e,pan_voice,sizeof(pan_voice));
    ma5_wt_engine_advance(e,100000000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x00,100000000);
    status=ma5_wt_engine_status(e);
    assert(status.active==1 && status.fm_skipped==0);
    lane_nonzero[0]=lane_nonzero[1]=0;
    ma5_wt_engine_advance(e,150000000);
    assert(lane_nonzero[0]>100 && lane_nonzero[1]==0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x7c,150000000);
    lane_nonzero[0]=lane_nonzero[1]=0;
    ma5_wt_engine_advance(e,200000000);
    assert(lane_nonzero[0]==0 && lane_nonzero[1]>100);
    status=ma5_wt_engine_status(e);
    assert(status.active==1 && status.fm_admitted==1 && status.fm_skipped==0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x01,200000000);
    status=ma5_wt_engine_status(e);
    assert(status.active==0 && status.fm_skip_mutation==1);
    ma5_wt_engine_free(e);

    emitted=nonzero=0;
    e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    start_uploaded_voice_size(e,pan_voice,sizeof(pan_voice));
    ma5_wt_engine_advance(e,100000000);
    assert(nonzero>100);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x00,100000000);
    status=ma5_wt_engine_status(e);
    assert(status.active==1 && status.fm_admitted==1 && status.fm_skipped==0);
    nonzero=0;
    ma5_wt_engine_advance(e,150000000);
    assert(nonzero==0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x7c,150000000);
    nonzero=0;
    ma5_wt_engine_advance(e,200000000);
    status=ma5_wt_engine_status(e);
    assert(nonzero>100 && status.active==1 && status.fm_admitted==1 && status.fm_skipped==0);
    ma5_wt_engine_free(e);
    const uint8_t unsupported_volume_modes[]={0x7d,0x7e};
    for (unsigned mode=0;mode<sizeof(unsupported_volume_modes);mode++) {
        emitted=nonzero=0;
        e=ma5_wt_engine_new(0,emit,NULL);
        assert(e);
        start_uploaded_voice_size(e,pan_voice,sizeof(pan_voice));
        ma5_wt_engine_advance(e,100000000);
        commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,unsupported_volume_modes[mode],100000000);
        status=ma5_wt_engine_status(e);
        assert(status.active==0 && status.fm_skip_mutation==1);
        ma5_wt_engine_free(e);
    }

    uint8_t alg0_feedback[16];
    memcpy(alg0_feedback,alg01[0],sizeof(alg0_feedback));
    alg0_feedback[8]=3; /* Op0 FB3, waveform0. */
    emitted=nonzero=0;
    pcm_hash=UINT64_C(14695981039346656037);
    e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    start_uploaded_voice_size(e,alg0_feedback,sizeof(alg0_feedback));
    status=ma5_wt_engine_status(e);
    assert(status.fm_admitted==1 && status.fm_skipped==0);
    ma5_wt_engine_advance(e,100000000);
    assert(emitted==4800 && nonzero>0 && pcm_hash!=alg_pcm_hash[0]);
    ma5_wt_engine_free(e);

    alg0_feedback[15]=4; /* Op1 feedback remains outside this closed class. */
    emitted=nonzero=0;
    e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    start_uploaded_voice_size(e,alg0_feedback,sizeof(alg0_feedback));
    status=ma5_wt_engine_status(e);
    assert(status.fm_admitted==0 && status.fm_skipped==1);
    assert(status.fm_skip_descriptor==1);
    ma5_wt_engine_free(e);

    emitted=nonzero=0;
    e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    commit(e,MSM5XXX_MA5_COMMIT_B,39,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,40,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,41,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,55,0xbc,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,56,0x12,0); /* Reject unknown B56 upper bits. */
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x51,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x40,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224,0,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240,8,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241,0,0);
    for (unsigned i=0;i<sizeof(voice);i++)
        commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,voice[i],1000+i);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,0,0x40,40000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,1,0x00,41000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,2,0x7c,42000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,3,0x1f,43000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,4,4,44000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0,45000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0xc0,46000);
    status=ma5_wt_engine_status(e);
    assert(status.fm_admitted==0 && status.fm_skipped==1);
    assert(status.fm_skip_mode==1 && status.fm_skip_descriptor==0);
    ma5_wt_engine_free(e);
    const uint8_t extra_waves[]={1,2,3,4,5,6,7,9,10,11,12,13,14,
        16,17,18,19,20,21,22,24,25,26,27,28,29,30};
    for (unsigned w=0;w<sizeof(extra_waves);w++) {
        for (unsigned op=0;op<4;op++) voice[2+op*7+6]=extra_waves[w]<<3;
        emitted=nonzero=0;
        e=ma5_wt_engine_new(0,emit,NULL);
        assert(e);
        start_uploaded_voice(e,voice);
        status=ma5_wt_engine_status(e);
        assert(status.fm_admitted==1 && status.fm_skipped==0);
        ma5_wt_engine_advance(e,100000000);
        assert(emitted==4800 && nonzero>0);
        ma5_wt_engine_free(e);
    }
    const uint8_t unsupported_waves[]={15,23,31};
    for (unsigned w=0;w<sizeof(unsupported_waves);w++) {
        for (unsigned op=0;op<4;op++)
            voice[2+op*7+6]=(uint8_t)(unsupported_waves[w]<<3);
        emitted=nonzero=0;
        e=ma5_wt_engine_new(0,emit,NULL);
        assert(e);
        start_uploaded_voice(e,voice);
        status=ma5_wt_engine_status(e);
        assert(status.fm_admitted==0 && status.fm_skipped==1);
        assert(status.fm_skip_descriptor==1);
        ma5_wt_engine_advance(e,100000000);
        assert(nonzero==0);
        ma5_wt_engine_free(e);
    }
    const uint8_t ambiguous_bo[]={0,2,3};
    for (unsigned b=0;b<sizeof(ambiguous_bo);b++) {
        voice[0]=(uint8_t)(0x78|ambiguous_bo[b]);
        emitted=nonzero=0;
        e=ma5_wt_engine_new(0,emit,NULL);
        assert(e);
        start_uploaded_voice(e,voice);
        status=ma5_wt_engine_status(e);
        assert(status.fm_admitted==0 && status.fm_skipped==1);
        assert(status.fm_skip_descriptor==1);
        ma5_wt_engine_advance(e,100000000);
        assert(nonzero==0);
        ma5_wt_engine_free(e);
    }
    const uint8_t dynamic_ids[]={15,23,31};
    const unsigned dynamic_ports[]={465,467,469};
    for (unsigned w=0;w<sizeof(dynamic_ids);w++) {
        uint8_t dynamic_voice[30];
        memcpy(dynamic_voice,voice_template,sizeof(dynamic_voice));
        e=ma5_wt_engine_new(0,emit,NULL);
        assert(e);
        for (unsigned i=0;i<1024;i++) {
            uint16_t sample=(uint16_t)(32u*i);
            commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4800+2*i,
                   (uint8_t)(sample>>8),0);
            commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4801+2*i,
                   (uint8_t)sample,0);
        }
        commit(e,MSM5XXX_MA5_COMMIT_CONTROL,dynamic_ports[w]-1,0x48,0);
        commit(e,MSM5XXX_MA5_COMMIT_CONTROL,dynamic_ports[w],0,0);
        for (unsigned op=0;op<4;op++)
            dynamic_voice[2+op*7+6]=(uint8_t)((dynamic_ids[w]<<3)|
                (dynamic_voice[2+op*7+6]&7u));
        emitted=nonzero=0;
        start_uploaded_voice(e,dynamic_voice);
        status=ma5_wt_engine_status(e);
        assert(status.fm_wave_uploads==1 && status.fm_wave_upload_rejects==0);
        assert(status.fm_admitted==1 && status.fm_skipped==0);
        ma5_wt_engine_advance(e,100000000);
        assert(emitted==4800 && nonzero>0);
        ma5_wt_engine_free(e);
    }
    uint8_t incomplete_voice[30];
    memcpy(incomplete_voice,voice_template,sizeof(incomplete_voice));
    e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,464,0x48,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,465,0,0);
    for (unsigned op=0;op<4;op++)
        incomplete_voice[2+op*7+6]=(uint8_t)((15u<<3)|
            (incomplete_voice[2+op*7+6]&7u));
    emitted=nonzero=0;
    start_uploaded_voice(e,incomplete_voice);
    status=ma5_wt_engine_status(e);
    assert(status.fm_wave_uploads==0 && status.fm_wave_upload_rejects==1);
    assert(status.fm_admitted==0 && status.fm_skipped==1);
    ma5_wt_engine_advance(e,100000000);
    assert(nonzero==0);
    ma5_wt_engine_free(e);

    uint32_t b55_gain_delta[2];
    const uint8_t b55_modes[]={0,0xbc};
    for (unsigned i=0;i<2;i++) {
        emitted=nonzero=0;
        e=ma5_wt_engine_new(0,emit,NULL);
        assert(e);
        commit(e,MSM5XXX_MA5_COMMIT_B,55,b55_modes[i],0);
        commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x51,0);
        uint32_t before=ma5_wt_engine_channel_q16(e,0);
        ma5_wt_engine_advance(e,20833); /* One 48 kHz synthesis frame. */
        uint32_t after=ma5_wt_engine_channel_q16(e,0);
        assert(before>after && emitted==1);
        b55_gain_delta[i]=before-after;
        ma5_wt_engine_free(e);
    }
    assert(b55_gain_delta[0]>b55_gain_delta[1]);
    return 0;
}
"""

TWO_OP_PCM_HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msm5xxx-ma2-audio.c"
#include "msm5xxx-ma5-wt-engine.h"

static bool emit(void *opaque, uint64_t first, const int16_t *pcm, size_t frames) {
    uint64_t *next=opaque;
    assert(first==*next);
    assert(fwrite(pcm,sizeof(*pcm),frames*2,stdout)==frames*2);
    *next+=frames;
    return true;
}
static void commit(MA5WTEngine *e, MSM5xxxMA5CommitKind kind,
                   uint32_t address, uint8_t raw) {
    MSM5xxxMA5Commit c={kind,address,kind==MSM5XXX_MA5_COMMIT_CONTROL ?
                        (uint8_t)(raw&0x7f) : raw,raw,0};
    ma5_wt_engine_commit(e,&c);
}
int main(int argc, char **argv) {
    assert(argc==3 || argc==4);
    unsigned algorithm=(unsigned)strtoul(argv[1],NULL,10);
    unsigned slot=(unsigned)strtoul(argv[2],NULL,10);
    assert(algorithm<8 && slot<32);
    uint8_t voice[30]={0x79,(uint8_t)algorithm};
    const uint8_t op[7]={0x00,0xf0,0xf0,0x20,0x00,0x10,0x00};
    unsigned operators=algorithm<2 ? 2 : 4;
    for (unsigned i=0;i<operators;i++) memcpy(voice+2+i*7,op,sizeof(op));
    unsigned base=slot<16 ? slot*6 : 272+(slot-16)*6;
    uint64_t next=0;
    MA5WTEngine *e=ma5_wt_engine_new(0,emit,&next);
    assert(e);
    commit(e,MSM5XXX_MA5_COMMIT_B,39,0xf8);
    commit(e,MSM5XXX_MA5_COMMIT_B,40,0xf8);
    commit(e,MSM5XXX_MA5_COMMIT_B,41,0xf8);
    commit(e,MSM5XXX_MA5_COMMIT_B,55,0);
    unsigned mode=argc==4 ? (unsigned)strtoul(argv[3],NULL,0) : slot<16 ? 0 : 1;
    commit(e,MSM5XXX_MA5_COMMIT_B,56,(uint8_t)mode);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x7d);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x3c);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240,8);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241,0);
    for (unsigned i=0;i<2+operators*7;i++)
        commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,voice[i]);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base,0x40);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+1,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+2,0x7c);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+3,0x24);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+4,89);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+5,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+5,0xc0);
    MA5WTStatus status=ma5_wt_engine_status(e);
    bool enabled=mode<=2 && (slot<16 || (mode&1)) &&
                 (!(mode&1) || algorithm<2);
    if (enabled) assert(status.fm_admitted==1 && status.fm_skipped==0);
    else assert(status.fm_admitted==0 && status.fm_skip_mode==1 && status.active==0);
    ma5_wt_engine_advance(e,50000000);
    assert(next==2400);
    ma5_wt_engine_free(e);
    return 0;
}
"""


LFO_HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "msm5xxx-ma2-audio.c"
#include "msm5xxx-ma5-wt-engine.h"

static uint64_t frames, pcm_hash;
static bool emit(void *opaque, uint64_t first, const int16_t *pcm, size_t count) {
    (void)opaque;
    assert(first==frames);
    for (size_t i=0;i<count*2;i++)
        pcm_hash=(pcm_hash ^ (uint16_t)pcm[i]) * UINT64_C(1099511628211);
    frames+=count;
    return true;
}
static void commit(MA5WTEngine *e, MSM5xxxMA5CommitKind kind,
                   uint32_t address, uint8_t raw, uint64_t ns) {
    MSM5xxxMA5Commit c={kind,address,kind==MSM5XXX_MA5_COMMIT_CONTROL ?
                        (uint8_t)(raw&0x7f) : raw,raw,ns};
    ma5_wt_engine_commit(e,&c);
}
static const uint8_t base_voice[30]={
    0x79,0x43, 0x02,0x64,0xff,0x9d,0x00,0x10,0x40,
    0x13,0x32,0xe2,0x67,0x00,0x50,0x00,0x02,0x41,0xd2,0x54,
    0x01,0x10,0x00,0x23,0x62,0xd4,0x02,0x01,0x10,0x00};
static uint64_t run_voice(uint8_t op4, uint8_t modulation, int update_live,
                          uint64_t *skipped) {
    uint8_t voice[30];
    memcpy(voice,base_voice,sizeof(voice));
    voice[6]=voice[13]=voice[20]=0;
    voice[27]=op4;
    frames=0; pcm_hash=UINT64_C(14695981039346656037);
    MA5WTEngine *e=ma5_wt_engine_new(0,emit,NULL);
    assert(e);
    commit(e,MSM5XXX_MA5_COMMIT_B,39,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,40,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,41,0xf8,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,55,0xbc,0);
    commit(e,MSM5XXX_MA5_COMMIT_B,56,2,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192,0x51,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208,0x40,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224,update_live ? 0 : modulation,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240,8,0);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241,0,0);
    for (unsigned i=0;i<sizeof(voice);i++)
        commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,voice[i],1000+i);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,0,0x40,40000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,1,0,41000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,2,0x7c,42000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,3,0x1f,43000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,4,4,44000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0,45000);
    commit(e,MSM5XXX_MA5_COMMIT_CONTROL,5,0xc0,46000);
    assert(ma5_wt_engine_status(e).fm_admitted==1);
    if (update_live) {
        ma5_wt_engine_advance(e,10000000);
        commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224,modulation,10001000);
    }
    ma5_wt_engine_advance(e,100000000);
    MA5WTStatus status=ma5_wt_engine_status(e);
    assert(status.fm_skipped==0 && status.fm_admitted==1 && frames==4800);
    *skipped=status.fm_skipped;
    ma5_wt_engine_free(e);
    return pcm_hash;
}
int main(void) {
    uint64_t skipped=0;
    uint64_t disabled=run_voice(0x03,0,false,&skipped);
    uint64_t shallow=run_voice(0x03,1,false,&skipped);
    uint64_t deep=run_voice(0x03,4,false,&skipped);
    uint64_t no_vib=run_voice(0x00,1,false,&skipped);
    uint64_t am=run_voice(0x11,0,false,&skipped);
    uint64_t live=run_voice(0x03,1,true,&skipped);
    assert(disabled!=shallow && shallow!=deep);
    assert(disabled==no_vib);
    assert(disabled!=am);
    assert(disabled!=live && skipped==0);
    return 0;
}
"""


class MA5FMEngineTests(unittest.TestCase):
    def test_lfo_vibrato_am_and_live_channel_modulation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ma5-fm-lfo-") as directory:
            root = Path(directory)
            source = root / "fm-lfo.c"
            binary = root / "fm-lfo"
            source.write_text(textwrap.dedent(LFO_HARNESS), encoding="utf-8")
            compile_result = subprocess.run(
                [
                    "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", "-fsanitize=undefined",
                    "-fno-sanitize-recover=all", f"-I{CORE}", str(source),
                    str(CORE / "msm5xxx-ma5-wt-engine.c"),
                    str(CORE / "msm5xxx-ma5-gain.c"),
                    str(CORE / "msm5xxx-ma5-fm-voice.c"),
                    str(CORE / "msm5xxx-ma5-operator.c"),
                    str(CORE / "msm5xxx-ma5-waveform.c"), "-lm", "-o", str(binary),
                ], capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_uploaded_alg3_voice_emits_experimental_pcm(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ma5-fm-engine-") as directory:
            root = Path(directory)
            source = root / "fm-engine.c"
            binary = root / "fm-engine"
            source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
            compile_result = subprocess.run(
                [
                    "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", "-fsanitize=undefined",
                    "-fno-sanitize-recover=all", f"-I{CORE}", str(source),
                    str(CORE / "msm5xxx-ma5-wt-engine.c"),
                    str(CORE / "msm5xxx-ma5-gain.c"),
                    str(CORE / "msm5xxx-ma5-fm-voice.c"),
                    str(CORE / "msm5xxx-ma5-operator.c"),
                    str(CORE / "msm5xxx-ma5-waveform.c"), "-lm", "-o", str(binary),
                ], capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_all_fm_algorithms_and_bank1_match_pcm_vectors(self) -> None:
        expected = {
            (0, 0): "0eade7384a9eff1ce86a44e42df29491f2b9965ad63e74162233583642420ba2",
            (1, 0): "d0bd45745c22676316440852c988811c8e151e49ceabf638531e91a49fd0c607",
            (2, 0): "8a8d6dec32192a39a4e279c5955b18e7d331b669f4a8816f5631d90738b12a59",
            (3, 0): "5f47b501bb45b7ee6a4c098544670ec77615ea32af5c1fc3f24301a7bf955fa8",
            (4, 0): "2c26c30f7ee7fc2b71defec50aaaa77859a2fd490c8449cb02aa76a87dc3751d",
            (5, 0): "da838d378f79d4e1b476e8809f335a825af3b76cdb92293a784619a4ab36dc84",
            (6, 0): "e33251d6ba2950e0f3fde1eb038f6bb508fb4e7ac0518e8ef3a56026c143beb0",
            (7, 0): "8cd2947c8c4f429eccb23e1d5bd12f9161d23d39e5285a1136a8d268ecbe387b",
            (1, 31): "d0bd45745c22676316440852c988811c8e151e49ceabf638531e91a49fd0c607",
        }
        with tempfile.TemporaryDirectory(prefix="ma5-two-op-pcm-") as directory:
            root = Path(directory)
            source = root / "fm-algorithm-pcm.c"
            binary = root / "fm-algorithm-pcm"
            source.write_text(textwrap.dedent(TWO_OP_PCM_HARNESS), encoding="utf-8")
            compile_result = subprocess.run(
                [
                    "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", "-fsanitize=undefined",
                    "-fno-sanitize-recover=all", f"-I{CORE}", str(source),
                    str(CORE / "msm5xxx-ma5-wt-engine.c"),
                    str(CORE / "msm5xxx-ma5-gain.c"),
                    str(CORE / "msm5xxx-ma5-fm-voice.c"),
                    str(CORE / "msm5xxx-ma5-operator.c"),
                    str(CORE / "msm5xxx-ma5-waveform.c"), "-lm", "-o", str(binary),
                ], capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            for (algorithm, slot), digest in expected.items():
                result = subprocess.run(
                    [str(binary), str(algorithm), str(slot)], capture_output=True
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(len(result.stdout), 2400 * 4)
                self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), digest)
            rejected = [(1, 31, 0), (1, 31, 2), (1, 31, 3), (1, 0, 3), (1, 31, 0x12)]
            rejected += [(algorithm, slot, 1) for algorithm in range(2, 8) for slot in (0, 31)]
            for algorithm, slot, mode in rejected:
                with self.subTest(algorithm=algorithm, slot=slot, mode=mode):
                    result = subprocess.run(
                        [str(binary), str(algorithm), str(slot), str(mode)], capture_output=True
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertEqual(result.stdout, bytes(2400 * 4))


if __name__ == "__main__":
    unittest.main()
