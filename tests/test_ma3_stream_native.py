import subprocess
import tempfile
import unittest
from pathlib import Path


class TestMA3StreamNative(unittest.TestCase):
    def test_guest_ram_pcm_adpcm_and_page_readback(self):
        repo = Path(__file__).resolve().parents[1]
        native = repo / "native" / "qemu"
        harness = r"""
#include <assert.h>
#include <string.h>
#include "msm5xxx-ma3-stream.h"

typedef struct Capture {
    uint64_t next_frame;
    size_t frames;
    bool have_chunk;
    bool nonzero;
} Capture;

static bool capture(void *opaque, uint64_t first_frame,
                    const int16_t *pcm, size_t frames)
{
    Capture *c = opaque;
    size_t i;
    if (c->have_chunk) assert(first_frame == c->next_frame);
    else c->have_chunk = true;
    for (i = 0; i < frames * 2; i++) c->nonzero |= pcm[i] != 0;
    c->frames += frames;
    c->next_frame = first_frame + frames;
    return true;
}

static void run_format(unsigned format, uint16_t pitch,
                       unsigned expected_page, uint64_t duration_ns,
                       size_t expected_frames)
{
    MSM5xxxMA3Audio device;
    MSM5xxxMA3StreamEngine engine;
    MSM5xxxMA3Operation op = {
        .kind = MSM5XXX_MA3_OP_REGISTER_WRITE,
        .timestamp_ns = 0,
        .address = 101,
        .value = 0x40,
    };
    Capture captured = {0};
    uint8_t *descriptor;
    unsigned i;

    memset(&device, 0, sizeof(device));
    descriptor = device.memory + 0x4000;
    descriptor[0] = 0x83; /* stream and pan enabled */
    descriptor[1] = (uint8_t)format;
    descriptor[7] = 0x40;
    descriptor[8] = 0x20;
    descriptor[11] = 0x03;
    descriptor[12] = 0xe0;
    device.reg[96] = 0x40;
    device.reg[97] = 0;
    device.reg[98] = 0x7c;
    device.reg[99] = (uint8_t)(pitch >> 7);
    device.reg[100] = (uint8_t)(pitch & 0x7f);
    device.reg[144] = 0x60;
    for (i = 0; i < 992; i++) {
        device.memory[0x4020 + i] = format == 3 ? 0x40 : 0xff;
    }
    msm5xxx_ma3_stream_init(&engine, capture, &captured);
    assert(msm5xxx_ma3_stream_operation(&engine, &device, &op));
    assert(engine.voice[0].active);
    assert(msm5xxx_ma3_stream_advance(&engine, &device, duration_ns));
    assert(captured.frames == expected_frames);
    assert(captured.nonzero);
    assert(device.reg[330] == expected_page);
}

int main(void)
{
    MSM5xxxMA3Audio device;
    MSM5xxxMA3StreamEngine engine;
    MSM5xxxMA3Operation op = {
        .kind = MSM5XXX_MA3_OP_REGISTER_WRITE,
        .timestamp_ns = 0,
        .address = 101,
        .value = 0x40,
    };
    Capture captured = {0};
    run_format(2, 0x08d5, 2, 20000000, 882); /* 4 kHz offset-binary PCM */
    run_format(3, 0x08d5, 2, 20000000, 882); /* 4 kHz signed PCM */
    run_format(0, 0x0955, 4, 20000000, 882); /* 8 kHz nibble ADPCM */
    run_format(2, 0x0280, 14, 30000000, 1323); /* wraps a full PCM ring */

    memset(&device, 0, sizeof(device));
    device.memory[0x4000] = 0xfa; /* STM set, PE clear (default pan=255) */
    device.memory[0x4001] = 2;   /* offset-binary PCM */
    device.memory[0x4007] = 0x40;
    device.memory[0x4008] = 0x20;
    device.reg[96] = 0x40;
    device.reg[98] = 0x7c;
    device.reg[99] = 0x11;
    device.reg[100] = 0x55;
    msm5xxx_ma3_stream_init(&engine, capture, &captured);
    assert(msm5xxx_ma3_stream_operation(&engine, &device, &op));
    assert(engine.voice[0].active && engine.voice[0].pan == 64);

    memset(&device, 0, sizeof(device));
    device.memory[0x4000] = 0x83;
    device.memory[0x4001] = 1; /* format 1 is not modeled */
    device.memory[0x4007] = 0x40;
    device.memory[0x4008] = 0x20;
    device.reg[96] = 0x40;
    device.reg[99] = 0x11;
    device.reg[100] = 0x55;
    msm5xxx_ma3_stream_init(&engine, capture, &captured);
    assert(!msm5xxx_ma3_stream_operation(&engine, &device, &op));
    assert(engine.unsupported_format_count == 1);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test_ma3_stream.c"
            binary = Path(directory) / "test_ma3_stream"
            source.write_text(harness, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-I", str(native), str(source),
                 str(native / "msm5xxx-ma3-stream.c"),
                 str(native / "msm5xxx-ma2-audio.c"), "-lm", "-o",
                 str(binary)],
                check=True,
                timeout=30,
            )
            subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
