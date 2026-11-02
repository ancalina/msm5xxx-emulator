import subprocess
import tempfile
import unittest
from pathlib import Path


class TestMA3EndToEndNative(unittest.TestCase):
    def test_register_packets_upload_patch_and_timed_fifo_render_pcm(self):
        repo = Path(__file__).resolve().parents[1]
        native = repo / "native" / "qemu"
        harness = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "msm5xxx-ma3-audio.h"
#include "msm5xxx-ma3-render.h"
#include "msm5xxx-audio-synth.h"

static void drain_operations(MSM5xxxMA3Audio *device,
                             MSM5xxxMA3Renderer *renderer,
                             MSM5xxxAudioSynth *synth)
{
    MSM5xxxMA3Operation operation;
    while (msm5xxx_ma3_pop_operation(device, &operation)) {
        if (operation.address == 5 && operation.value == 0x40) {
            assert(operation.timestamp_ns == 2001000);
        }
        assert(msm5xxx_ma3_renderer_operation(renderer, device, &operation,
                                               synth));
    }
}

static void write_register(MSM5xxxMA3Audio *device,
                           MSM5xxxMA3Renderer *renderer,
                           MSM5xxxAudioSynth *synth,
                           uint16_t address, uint8_t value,
                           uint64_t timestamp_ns)
{
    assert(msm5xxx_ma3_status_write(device, 2, timestamp_ns));
    assert(msm5xxx_ma3_data_write(device, address & 0x7f, timestamp_ns));
    assert(msm5xxx_ma3_data_write(device,
                                  ((address >> 7) & 0x7f) | 0x80,
                                  timestamp_ns));
    assert(msm5xxx_ma3_data_write(device, value | 0x80, timestamp_ns));
    drain_operations(device, renderer, synth);
}

static void upload_test_patch(MSM5xxxMA3Audio *device, uint64_t timestamp_ns)
{
    uint8_t patch[30] = {0};
    unsigned op;

    /* A synthetic two-operator patch in device RAM, encoded through the
     * immediate host port. No firmware-derived data is used. */
    patch[0] = 0x80;
    patch[1] = 0;
    for (op = 0; op < 2; op++) {
        uint8_t *p = patch + 2 + op * 7;
        p[0] = 0x70;
        p[1] = 0x7f;
        p[2] = 0xf1;
        p[3] = 0x04;
        p[5] = 0x20;
        p[6] = op == 0 ? 0x06 : 0;
    }

    assert(msm5xxx_ma3_status_write(device, 2, timestamp_ns));
    assert(msm5xxx_ma3_data_write(device, 0x00, timestamp_ns));
    assert(msm5xxx_ma3_data_write(device, 0x00, timestamp_ns));
    assert(msm5xxx_ma3_data_write(device, 0x81, timestamp_ns)); /* 0x4000 */
    assert(msm5xxx_ma3_data_write(device, 0x9e, timestamp_ns)); /* 30 bytes */
    for (op = 0; op < sizeof(patch); op++) {
        assert(msm5xxx_ma3_data_write(device, patch[op], timestamp_ns));
    }
    assert(memcmp(device->memory + 0x4000, patch, sizeof(patch)) == 0);
}

int main(void)
{
    MSM5xxxMA3Audio device;
    MSM5xxxMA3Renderer renderer;
    MSM5xxxAudioSynth synth;
    MSM5xxxMA3Operation operation;
    int16_t pcm[MSM5XXX_AUDIO_MAX_FRAMES][2];
    uint64_t epoch, sequence, frame, deadline;
    size_t got, i;
    bool nonzero = false;

    msm5xxx_ma3_reset(&device);
    msm5xxx_ma3_renderer_init(&renderer);
    msm5xxx_audio_synth_init(&synth);
    upload_test_patch(&device, 0);

    /* Select RAM word address 0x2000 and set pitch/level by packets. */
    write_register(&device, &renderer, &synth, 0, 0x40, 0);
    write_register(&device, &renderer, &synth, 1, 0x00, 0);
    write_register(&device, &renderer, &synth, 2, 0x7c, 0);
    write_register(&device, &renderer, &synth, 3, 0x08, 0);
    write_register(&device, &renderer, &synth, 4, 0x33, 0);
    write_register(&device, &renderer, &synth, 144, 0x7c, 0);
    write_register(&device, &renderer, &synth, 160, 0x3c, 0);
    write_register(&device, &renderer, &synth, 350, 0x06, 0);
    write_register(&device, &renderer, &synth, 351, 0x60, 0);
    write_register(&device, &renderer, &synth, 353, 0x01, 0);

    /* Delayed FIFO packet: two sequencer ticks, then a key-on for slot 0. */
    assert(msm5xxx_ma3_status_write(&device, 1, 1000));
    assert(msm5xxx_ma3_data_write(&device, 0x82, 1000));
    assert(msm5xxx_ma3_data_write(&device, 0x05, 1000));
    assert(msm5xxx_ma3_data_write(&device, 0x80, 1000));
    assert(msm5xxx_ma3_data_write(&device, 0xc0, 1000));
    assert(msm5xxx_ma3_next_deadline(&device, &deadline));
    assert(deadline == 1000);
    assert(msm5xxx_ma3_advance(&device, deadline, &operation));
    drain_operations(&device, &renderer, &synth);
    assert(msm5xxx_ma3_next_deadline(&device, &deadline));
    assert(deadline == 2001000);

    /* Drive the same deadline/operation queue path used by the QEMU timer. */
    assert(msm5xxx_ma3_advance(&device, deadline, &operation));
    drain_operations(&device, &renderer, &synth);
    assert(msm5xxx_ma3_advance(&device, deadline, &operation));
    drain_operations(&device, &renderer, &synth);
    assert(msm5xxx_ma3_advance(&device, deadline, &operation));
    drain_operations(&device, &renderer, &synth);
    assert(renderer.voice[0].active && synth.voice[0].active);
    assert(synth.clock_ns == deadline && synth.late_events == 0);
    assert(synth.voice[0].note == 93);

    assert(msm5xxx_audio_synth_advance(&synth, 20000000));
    got = msm5xxx_audio_synth_read(&synth, pcm, 441, &epoch, &sequence,
                                   &frame);
    assert(got == 441);
    for (i = 0; i < got; i++) {
        nonzero |= pcm[i][0] != 0 || pcm[i][1] != 0;
    }
    assert(nonzero);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test_ma3_end_to_end.c"
            binary = Path(directory) / "test_ma3_end_to_end"
            source.write_text(harness, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-I", str(native), str(source),
                 str(native / "msm5xxx-ma3-audio.c"),
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
