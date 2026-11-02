import subprocess
import tempfile
import unittest
from pathlib import Path


class TestMA3RendererNative(unittest.TestCase):
    def test_register_driven_ram_voice_rendering_and_rejection(self):
        repo = Path(__file__).resolve().parents[1]
        native = repo / "native" / "qemu"
        harness = r"""
#include <assert.h>
#include <math.h>
#include <string.h>
#include "msm5xxx-ma3-audio.h"
#include "msm5xxx-ma3-render.h"
#include "msm5xxx-ma5-fm-voice.h"

static void make_patch(MSM5xxxMA3Audio *device, unsigned algorithm,
                       unsigned feedback)
{
    unsigned op;
    uint8_t *patch = device->memory + 0x4000;
    memset(patch, 0, 30);
    patch[0] = 0x80;
    patch[1] = (uint8_t)algorithm;
    for (op = 0; op < (algorithm < 2 ? 2u : 4u); op++) {
        uint8_t *p = patch + 2 + op * 7;
        p[0] = 0xf0;
        p[1] = 0x7f;
        p[2] = 0xf1;
        p[3] = 0;
        p[5] = 0x20;
        p[6] = op == 0 ? (uint8_t)feedback : 0;
    }
    device->reg[0] = 0x40; /* uploaded address 0x2000, scaled by two */
    device->reg[1] = 0;
    device->reg[2] = 0x7c;
    device->reg[3] = 0x08;
    device->reg[4] = 0x33;
    device->reg[144] = 0x7c;
    device->reg[160] = 0x3c;
}

static void check_algorithm(unsigned algorithm, unsigned feedback)
{
    MSM5xxxMA3Audio device;
    MSM5xxxMA3Renderer renderer;
    MSM5xxxAudioSynth synth;
    MSM5xxxMA3Operation operation = {
        .kind = MSM5XXX_MA3_OP_REGISTER_WRITE,
        .timestamp_ns = 0,
        .address = 5,
        .value = 0x40,
    };
    int16_t pcm[MSM5XXX_AUDIO_MAX_FRAMES][2];
    uint64_t epoch, sequence, frame;
    size_t got;
    size_t i;
    bool nonzero = false;

    memset(&device, 0, sizeof(device));
    make_patch(&device, algorithm, feedback);
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    assert(msm5xxx_ma3_renderer_operation(&renderer, &device, &operation,
                                          &synth));
    assert(renderer.voice[0].active);
    assert(synth.voice[0].active);
    assert(synth.voice[0].note == 93);
    assert(synth.voice[0].timbre_attack_step[0] ==
           msm5xxx_ma5_fm_attack_step(15, 0, MSM5XXX_AUDIO_SAMPLE_RATE));
    assert(synth.voice[0].timbre_decay_factor[0] == 975968195u);
    assert(synth.voice[0].timbre_release_factor[0] == 1073341448u);
    if (algorithm == 0) {
        assert(synth.voice[0].timbre_decay_threshold[0] == 1520301996u);
    }
    assert(msm5xxx_audio_synth_advance(&synth, 20000000));
    got = msm5xxx_audio_synth_read(&synth, pcm, 441, &epoch, &sequence,
                                   &frame);
    assert(got == 441);
    for (i = 0; i < got; i++) {
        nonzero |= pcm[i][0] != 0 || pcm[i][1] != 0;
    }
    assert(nonzero);
}

int main(void)
{
    MSM5xxxMA3Audio device;
    MSM5xxxMA3Renderer renderer;
    MSM5xxxAudioSynth synth;
    MSM5xxxMA3Operation operation = {
        .kind = MSM5XXX_MA3_OP_REGISTER_WRITE,
        .timestamp_ns = 0,
        .address = 5,
        .value = 0x40,
    };

    for (unsigned algorithm = 0; algorithm < 8; algorithm++) {
        check_algorithm(algorithm, algorithm < 2 ? 6 : 0);
    }

    memset(&device, 0, sizeof(device));
    device.reg[0] = 0x40;
    device.reg[2] = 0x7c;
    device.reg[3] = 0x08;
    device.reg[4] = 0x33;
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    assert(!msm5xxx_ma3_renderer_operation(&renderer, &device, &operation,
                                           &synth));
    assert(renderer.unsupported_rom_voices == 1);

    memset(&device, 0, sizeof(device));
    make_patch(&device, 1, 0);
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    assert(msm5xxx_ma3_renderer_operation(&renderer, &device, &operation,
                                          &synth));
    assert(synth.voice[0].timbre_operator_count == 2);

    memset(&device, 0, sizeof(device));
    make_patch(&device, 0, 6);
    device.memory[0x4000] = 0x82; /* base octave lowers pitch two octaves */
    device.memory[0x4002] = 0xa1; /* AR 10, key-scale rate enabled */
    device.memory[0x4003] = 0xa6; /* RR 10, DR 6 */
    device.memory[0x4004] = 0xa4; /* AR 10, sustain level 4 */
    device.memory[0x4005] = 34;   /* TL 8, KSL 2 */
    device.reg[3] = 0x23;
    device.reg[4] = 0x58;         /* fnum 600, block 3 */
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    assert(msm5xxx_ma3_renderer_operation(&renderer, &device, &operation,
                                          &synth));
    assert(synth.voice[0].note == 110);
    assert(synth.voice[0].timbre_attack_step[0] ==
           msm5xxx_ma5_fm_attack_step(10, 7, MSM5XXX_AUDIO_SAMPLE_RATE));
    assert(synth.voice[0].timbre_attack_step[0] !=
           msm5xxx_ma5_fm_attack_step(10, 1, MSM5XXX_AUDIO_SAMPLE_RATE));
    {
        uint16_t gain = msm5xxx_ma5_fm_ksl_gain(2, 9, 3);
        unsigned adjustment = (unsigned)floor(
            -20.0 * log10((double)gain / 32768.0) / 0.75 + 0.5);
        assert(synth.voice[0].timbre_level[0] == 8u + adjustment);
        assert(synth.voice[0].timbre_decay_factor[0] == 1073041264u);
        assert(synth.voice[0].timbre_release_factor[0] == 1062587549u);
    }

    memset(&device, 0, sizeof(device));
    make_patch(&device, 0, 6);
    device.memory[0x4008] = 0x0e; /* standard waveform 1 */
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    assert(msm5xxx_ma3_renderer_operation(&renderer, &device, &operation,
                                          &synth));
    assert(synth.voice[0].timbre_waveform[0] == 1);

    memset(&device, 0, sizeof(device));
    make_patch(&device, 0, 6);
    device.memory[0x4008] = 0x7e; /* custom waveform 15 remains unsupported */
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    assert(!msm5xxx_ma3_renderer_operation(&renderer, &device, &operation,
                                           &synth));
    assert(renderer.unsupported_waveforms == 1);

    memset(&device, 0, sizeof(device));
    make_patch(&device, 0, 6);
    device.memory[0x4000] = 0x82;
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    assert(msm5xxx_ma3_renderer_operation(&renderer, &device, &operation,
                                          &synth));
    assert(synth.voice[0].note == 69);

    memset(&device, 0, sizeof(device));
    make_patch(&device, 0, 6);
    device.memory[0x4007] = 0x00; /* multiplier zero is one half */
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    assert(msm5xxx_ma3_renderer_operation(&renderer, &device, &operation,
                                          &synth));
    assert(synth.voice[0].note == 81);
    assert(synth.voice[0].timbre_multiplier[0] == 2);
    assert(synth.voice[0].timbre_multiplier[1] == 4);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test_ma3_renderer.c"
            binary = Path(directory) / "test_ma3_renderer"
            source.write_text(harness, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-I", str(native), str(source),
                 str(native / "msm5xxx-ma3-render.c"),
                 str(native / "msm5xxx-ma5-fm-voice.c"),
                 str(native / "msm5xxx-audio-synth.c"),
                 str(native / "msm5xxx-ma5-waveform.c"), "-lm", "-o",
                 str(binary)],
                check=True,
                timeout=30,
            )
            subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
