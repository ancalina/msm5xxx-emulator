import subprocess
import tempfile
import unittest
from pathlib import Path


class MA2PCMTest(unittest.TestCase):
    def test_wave_fifo_reaches_pcm(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        source = r'''
#include <assert.h>
#include <string.h>
#include "msm5xxx-ma2-audio.h"
static unsigned count, nonzero;
static void emit(void *opaque, uint64_t frame, int16_t sample) {
    (void)opaque; assert(frame == count++); nonzero += sample != 0;
}
int main(void) {
    MSM5xxxMA2Audio audio;
    MSM5xxxMA2PCM pcm = {0};
    memset(&audio, 0, sizeof(audio));
    msm5xxx_ma2_reset(&audio);
    audio.control = MSM5XXX_MA2_SAMPLE_RATE_8KHZ;
    audio.index = MSM5XXX_MA2_ADPCM_WAVE_DATA;
    for (unsigned i = 0; i < 128; i++) assert(msm5xxx_ma2_data_write(&audio, 0x21));
    msm5xxx_ma2_pcm_start(&pcm, 0);
    assert(msm5xxx_ma2_pcm_advance(&pcm, &audio, 32000000, emit, 0));
    assert(count == 1411 && nonzero > 1000);
    assert(msm5xxx_ma2_fifo_occupancy(&audio, MSM5XXX_MA2_FIFO_ADPCM_WAVE) == 0);
    audio.control |= MSM5XXX_MA2_ADPCM_START;
    audio.adpcm_irq_ctrl = 0x40;
    assert(msm5xxx_ma2_wave_status(&audio) == 5);
    assert(msm5xxx_ma2_irq_pending(&audio));
    audio.adpcm_irq_ctrl = 0;
    assert(!msm5xxx_ma2_irq_pending(&audio));
    audio.page = 1; audio.index = MSM5XXX_MA2_FM_CHANNEL_ASSIGN;
    assert(msm5xxx_ma2_data_write(&audio, 0));
    audio.index = 0xd0; assert(msm5xxx_ma2_data_write(&audio, 1));
    audio.page = 0; audio.index = 0xd0; assert(msm5xxx_ma2_data_write(&audio, 0));
    for (unsigned op = 0; op < 2; op++) for (unsigned plane = 0; plane < 5; plane++) {
        audio.index = 0x10 + 4 * op + 0x20 * plane;
        assert(msm5xxx_ma2_data_write(&audio, 0x11 + plane + op));
    }
    audio.index = 0xb0; assert(msm5xxx_ma2_data_write(&audio, 0x34));
    audio.index = 0xc0; assert(msm5xxx_ma2_data_write(&audio, 0x31));
    audio.index = 0xe0; assert(msm5xxx_ma2_data_write(&audio, 31));
    assert(audio.fm_channel[0].key_on && audio.fm_channel[0].direct_fnum == 0x134);
    assert(audio.fm_channel[0].direct_block == 4 && audio.fm_channel[0].volume == 127);
    assert(audio.fm_voice[0].valid && audio.fm_voice[0].operator_count == 2);
    assert(audio.fm_voice[0].operation[1].data[4] == 0x16);
    audio.page = 1; audio.index = MSM5XXX_MA2_FIFO_CONTROL;
    assert(msm5xxx_ma2_data_write(&audio, MSM5XXX_MA2_FM_SOFT_RESET));
    assert(!audio.fm_channel[0].key_on);
    msm5xxx_ma2_reset(&audio);
    const uint8_t legacy[] = {0, 0xff, 0xf0, 19, 0x43, 2, 1, 0, 42, 0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf7};
    audio.index = 0;
    for (unsigned i = 0; i < sizeof(legacy); i++) assert(msm5xxx_ma2_data_write(&audio, legacy[i]));
    audio.page = 1; audio.index = MSM5XXX_MA2_CONTROL;
    assert(msm5xxx_ma2_data_write(&audio, MSM5XXX_MA2_FM_START));
    MSM5xxxMA2Output output;
    assert(msm5xxx_ma2_scheduler_step(&audio, 0, &output));
    assert(output.timestamp_ns == 0 && output.unhandled_reason == MSM5XXX_MA2_UNHANDLED_NONE);
    assert(audio.fm_voice[1].valid && audio.fm_voice[1].legacy);
    assert(audio.fm_voice[1].decoded[6 + 18 + 4] == 9);
    assert(audio.fm_voice[1].decoded[6 + 18 + 2] == 1);
    audio.page = 0; audio.index = 0;
    const uint8_t program[] = {0, 0xff, 0xf0, 6, 0x43, 2, 0x90, 0xc0, 42, 0xf7};
    for (unsigned i = 0; i < sizeof(program); i++) assert(msm5xxx_ma2_data_write(&audio, program[i]));
    assert(msm5xxx_ma2_scheduler_step(&audio, 0, &output));
    assert(output.unhandled_reason == MSM5XXX_MA2_UNHANDLED_NONE);
    assert(audio.fm_channel[0].program == 42);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            c, binary = Path(d) / 'pcm.c', Path(d) / 'pcm'
            c.write_text(source)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I', str(native), str(c), str(native / 'msm5xxx-ma2-audio.c'),
                            '-lm', '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
