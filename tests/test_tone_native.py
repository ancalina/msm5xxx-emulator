"""Exercise the register map and guest-clock PCM ring in the native tone core."""
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "msm5xxx-tone.h"

static void reg(MSM5xxxTone *tone, unsigned offset, unsigned value) {
    assert(msm5xxx_tone_write(tone, offset, 1, value));
}

static void program(MSM5xxxTone *tone, unsigned base, unsigned selector,
                    unsigned frequency, unsigned duty_basis_points) {
    unsigned period = (307500u * selector) / frequency;
    unsigned high = period * duty_basis_points / 10000u;
    unsigned reload = (uint16_t)~(period - selector);

    reg(tone, base, high & 0xff);
    reg(tone, base + 4, high >> 8);
    reg(tone, base + 8, reload & 0xff);
    reg(tone, base + 12, reload >> 8);
    reg(tone, base + 16, 0x40 | selector);
}

static unsigned rising_edges(const int16_t (*pcm)[2], unsigned frames) {
    unsigned edges = 0;
    for (unsigned i = 1; i < frames; i++) {
        if (pcm[i - 1][0] < 0 && pcm[i][0] >= 0) edges++;
    }
    return edges;
}

int main(void) {
    MSM5xxxTone tone;
    MSM5xxxToneMetadata meta;
    int16_t pcm[4410][2];
    uint8_t value = 0xff;

    msm5xxx_tone_init(&tone);
    assert(tone.epoch == 1 && !msm5xxx_tone_active(&tone));
    assert(msm5xxx_tone_read_register(&tone, 0, 1, &value) && value == 0);
    assert(!msm5xxx_tone_read_register(&tone, 1, 1, &value));
    assert(!msm5xxx_tone_read_register(&tone, 0, 2, &value));
    assert(!msm5xxx_tone_write(&tone, 0, 2, 1));
    assert(msm5xxx_tone_advance(&tone, 0));

    /* 500 Hz, selector 7, 25% high time: K/period is the guest clock. */
    program(&tone, 0, 7, 500, 2500);
    assert(msm5xxx_tone_active(&tone));
    assert(tone.channel[0].clock_hz == 2152500u);
    assert(tone.channel[0].period == 4305u);
    assert(tone.channel[0].high_ticks == 1076u);
    assert(msm5xxx_tone_advance(&tone, 100000000));
    assert(tone.ring_count == 4410);
    assert(msm5xxx_tone_read_pcm(&tone, pcm, 4410, &meta) == 4410);
    assert(meta.epoch == 1 && meta.sequence == 1 && meta.start_frame == 0);
    assert(rising_edges((const int16_t (*)[2])pcm, 4410) >= 49 &&
           rising_edges((const int16_t (*)[2])pcm, 4410) <= 50);
    unsigned high = 0;
    for (unsigned i = 0; i < 4410; i++) {
        assert(pcm[i][0] == pcm[i][1]);
        high += pcm[i][0] > 0;
    }
    assert(high > 1080 && high < 1110);

    /* Stop, idle guest time, and a second note do not synthesize host-time PCM. */
    reg(&tone, 16, 0);
    assert(!msm5xxx_tone_active(&tone));
    assert(msm5xxx_tone_advance(&tone, 500000000));
    assert(tone.ring_count == 0);
    msm5xxx_tone_resync(&tone);
    program(&tone, 20, 14, 1000, 5000);
    assert(tone.channel[1].clock_hz == 4305000u);
    assert(msm5xxx_tone_advance(&tone, 600000000));
    assert(tone.ring_count == 4410);
    assert(msm5xxx_tone_read_pcm(&tone, pcm, 4410, &meta) == 4410);
    assert(meta.epoch == 2 && meta.sequence == 1 && meta.start_frame == 22050);
    assert(rising_edges((const int16_t (*)[2])pcm, 4410) >= 99 &&
           rising_edges((const int16_t (*)[2])pcm, 4410) <= 100);

    /* A long guest interval drops old PCM safely and advertises a new epoch. */
    assert(msm5xxx_tone_advance(&tone, 1100000000));
    assert(tone.ring_count == MSM5XXX_TONE_MAX_FRAMES);
    assert(tone.overflow_frames > 0 && tone.epoch == 3);
    assert(msm5xxx_tone_read_pcm(&tone, pcm, 4410, &meta) == 4410);
    assert(meta.epoch == 3 && meta.sequence == 1);

    msm5xxx_tone_reset(&tone);
    assert(!msm5xxx_tone_active(&tone) && tone.ring_count == 0);
    assert(msm5xxx_tone_read_register(&tone, 36, 1, &value) && value == 0);
    return 0;
}
'''


class NativeToneTests(unittest.TestCase):
    def test_register_programming_and_virtual_pcm(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "tone-check.c"
            executable = Path(directory) / "tone-check"
            source.write_text(HARNESS)
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT / "native/qemu"), str(source),
                str(ROOT / "native/qemu/msm5xxx-tone.c"), "-o", str(executable),
            ], check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
