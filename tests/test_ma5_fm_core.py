from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "experiments/qemu-tcg"

HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "msm5xxx-ma5-fm-voice.h"
#include "msm5xxx-ma5-operator.h"
#include "msm5xxx-ma5-waveform.h"

int main(void) {
    const uint8_t x850_alg3[30] = {
        0x79,0x43,0x02,0x64,0xff,0x9d,0x00,0x10,0x40,
        0x13,0x32,0xe2,0x67,0x00,0x50,0x00,0x02,0x41,0xd2,0x54,
        0x01,0x10,0x00,0x23,0x62,0xd4,0x02,0x01,0x10,0x00
    };
    const uint8_t x850_alg5[30] = {
        0x79,0x45,0x31,0x3f,0xf0,0x98,0x44,0x70,0x0d,0x40,
        0x47,0xf0,0x2e,0x44,0x50,0x00,0x00,0x11,0x60,0x62,
        0x03,0x17,0x0e,0x00,0x51,0x81,0x02,0x03,0x10,0x00
    };
    MSM5xxxMA5FMVoice voice, before;
    static const uint32_t detune_reference_q16[4][32] = {
        {
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
        },
        {
            0u, 0u, 0u, 0u, 3277u, 3277u, 3277u, 3277u,
            3277u, 3277u, 3277u, 3277u, 5898u, 5898u, 5898u, 5898u,
            5898u, 9175u, 9175u, 9175u, 11796u, 11796u, 11796u, 15073u,
            15073u, 17695u, 17695u, 20971u, 24248u, 24248u, 24248u, 24248u
        },
        {
            3277u, 3277u, 3277u, 3277u, 5898u, 5898u, 5898u, 5898u,
            5898u, 9175u, 9175u, 9175u, 11796u, 11796u, 11796u, 15073u,
            15073u, 17695u, 17695u, 20971u, 24248u, 24248u, 26870u, 30147u,
            32768u, 36045u, 38666u, 41943u, 47841u, 47841u, 47841u, 47841u
        },
        {
            5898u, 5898u, 5898u, 5898u, 9175u, 9175u, 9175u, 9175u,
            11796u, 11796u, 11796u, 15073u, 15073u, 18350u, 18350u, 20972u,
            24248u, 24248u, 26870u, 30147u, 32768u, 36045u, 38666u, 41943u,
            47841u, 51118u, 57016u, 59638u, 65536u, 65536u, 65536u, 65536u
        }
    };
    memset(&voice,0xa5,sizeof(voice)); before=voice;
    assert(!msm5xxx_ma5_fm_voice_decode(NULL,30,&voice));
    assert(!msm5xxx_ma5_fm_voice_decode(x850_alg3,29,&voice));
    assert(!memcmp(&voice,&before,sizeof(voice)));
    assert(msm5xxx_ma5_fm_voice_decode(x850_alg3,30,&voice));
    assert(voice.pan==15 && voice.base_octave==1 && voice.lfo==1);
    assert(voice.algorithm==3 && voice.operator_count==4 && voice.record_size==30);
    assert(voice.operators[0].attack_rate==15 && voice.operators[0].waveform==8);
    assert(voice.operators[0].feedback==0 && voice.operators[0].total_level==39);
    assert(msm5xxx_ma5_fm_voice_decode(x850_alg5,30,&voice));
    assert(voice.algorithm==5 && voice.operator_count==4 && voice.record_size==30);
    assert(msm5xxx_ma5_fm_attack_step(1,0,48000)==14560);
    assert(msm5xxx_ma5_fm_attack_step(1,0,32000)==21839);
    assert(msm5xxx_ma5_fm_attack_step(10,0,48000)==7454515);
    assert(msm5xxx_ma5_fm_attack_step(11,1,48000)==18636288);
    assert(msm5xxx_ma5_fm_attack_step(13,0,48000)==108121185);
    assert(msm5xxx_ma5_fm_attack_step(14,2,48000)==330683425);
    assert(msm5xxx_ma5_fm_attack_step(14,3,48000)==360461253);
    assert(msm5xxx_ma5_fm_attack_step(14,3,1)==0x80000000u);
    assert(msm5xxx_ma5_fm_attack_step(0,63,48000)==0);
    assert(msm5xxx_ma5_fm_attack_step(1,0,0)==0);
    assert(msm5xxx_ma5_fm_attack_step(15,0,48000)==0x80000000u);
    assert(msm5xxx_ma5_fm_ksl_gain(0,15,7)==32768);
    assert(msm5xxx_ma5_fm_ksl_gain(1,3,3)==26406); /* 1.875 dB. */
    assert(msm5xxx_ma5_fm_ksl_gain(1,15,7)==2920);  /* 21 dB. */
    assert(msm5xxx_ma5_fm_ksl_gain(2,15,7)==9783);  /* 10.5 dB. */
    assert(msm5xxx_ma5_fm_ksl_gain(3,15,7)==260);   /* 42 dB. */
    assert(msm5xxx_ma5_fm_ksl_gain(1,0,7)==32512);
    assert(msm5xxx_ma5_fm_ksl_gain(4,15,7)==0);
    assert(msm5xxx_ma5_fm_detune_step(0x06000000,0,19,48000)==0x06000000);
    assert(msm5xxx_ma5_fm_detune_step(0x06001234,0,19,48000)==0x06001234);
    assert(msm5xxx_ma5_fm_detune_step(0x06001234,4,19,48000)==0x06001234);
    assert(msm5xxx_ma5_fm_detune_step(0x06000000,4,19,48000)==0x06000000);
    assert(msm5xxx_ma5_fm_detune_step(0x06000000,3,19,48000)==0x0600a0c8);
    assert(msm5xxx_ma5_fm_detune_step(0x06000000,7,19,48000)==0x05ff5f37);
    assert(msm5xxx_ma5_fm_detune_step(0x06000000,8,19,48000)==0);
    assert(msm5xxx_ma5_fm_detune_step(0x06000000,3,32,48000)==0);
    assert(msm5xxx_ma5_fm_detune_step(0x06000000,3,19,0)==0);
    {
        const uint32_t bases[]={0x00010000,0x06000000,0x40000000,UINT32_MAX};
        const unsigned rates[]={22050,32000,44100,48000,96000};
        for (unsigned bi=0;bi<sizeof(bases)/sizeof(bases[0]);bi++)
            for (unsigned ri=0;ri<sizeof(rates)/sizeof(rates[0]);ri++)
                for (unsigned group=0;group<4;group++)
                    for (unsigned key=0;key<32;key++) {
                        uint32_t base=bases[bi];
                        uint64_t scale=(uint64_t)(base>>16)*rates[ri];
                        uint64_t correction=(uint64_t)detune_reference_q16[group][key]*base;
                        if (scale<0x10000u) scale=0x10000u;
                        uint64_t plus_delta=correction/scale;
                        uint64_t minus_delta=plus_delta+(correction%scale!=0u);
                        uint32_t plus=plus_delta>UINT32_MAX-base ? 0u :
                            base+(uint32_t)plus_delta;
                        uint32_t minus=minus_delta>base ? 0u :
                            base-(uint32_t)minus_delta;
                        assert(msm5xxx_ma5_fm_detune_step(base,group,key,rates[ri])==plus);
                        assert(msm5xxx_ma5_fm_detune_step(base,group|4u,key,rates[ri])==minus);
                    }
    }

    static const uint8_t supported_waveforms[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
        16,17,18,19,20,21,22,24,25,26,27,28,29,30};
    static const uint8_t unsupported_waveforms[]={15,23,31};
    int16_t wave[1024], unchanged[1024];
    for (unsigned i=0;i<1024;i++) wave[i]=unchanged[i]=1234;
    for (unsigned i=0;i<sizeof(unsupported_waveforms);i++) {
        assert(!msm5xxx_ma5_waveform_build(unsupported_waveforms[i],wave,1024));
        assert(!memcmp(wave,unchanged,sizeof(wave)));
    }
    for (unsigned i=0;i<sizeof(supported_waveforms);i++)
        assert(msm5xxx_ma5_waveform_build(supported_waveforms[i],wave,1024));
    assert(msm5xxx_ma5_waveform_build(1,wave,1024));
    assert(wave[0]==0 && wave[256]==32767 && wave[512]==0);
    assert(msm5xxx_ma5_waveform_build(8,wave,1024));

    MSM5xxxMA5Operator op={.env_state=3,.phase=0xffffffffu,
        .phase_step=2,.attack=0x80000000u,.decay=0x40000000u,
        .sr_mul=0x40000000u,.rr_mul=0x40000000u,
        .sustain_level=0,.level=0,.gain=0x8000};
    int32_t sample=0;
    assert(msm5xxx_ma5_operator_step(&op,wave,1024,false,0,&sample));
    assert(op.level==0x80000000u && op.phase==1u);
    assert(sample==wave[1023]);
    return 0;
}
"""


class MA5FMCoreTests(unittest.TestCase):
    def test_uploaded_x850_voice_decode_and_operator_primitives(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ma5-fm-core-") as directory:
            root = Path(directory)
            source = root / "fm-core.c"
            binary = root / "fm-core"
            source.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
            result = subprocess.run(
                [
                    "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", "-fsanitize=undefined",
                    "-fno-sanitize-recover=all", f"-I{CORE}", str(source),
                    str(CORE / "msm5xxx-ma5-fm-voice.c"),
                    str(CORE / "msm5xxx-ma5-operator.c"),
                    str(CORE / "msm5xxx-ma5-waveform.c"), "-lm", "-o", str(binary),
                ], capture_output=True, text=True, check=True,
            )
            self.assertEqual(result.stderr, "")
            subprocess.run([str(binary)], capture_output=True, text=True, check=True)


if __name__ == "__main__":
    unittest.main()
