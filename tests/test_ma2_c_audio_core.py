import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


class TestMA2CAudioCore(unittest.TestCase):
    def test_qemu_bus_keeps_unowned_accesses_on_lcd_path(self):
        repo = Path(__file__).resolve().parents[1]
        source = (repo / "experiments" / "qemu-tcg" /
                  "msm5xxx-poc.c").read_text(encoding="utf-8")
        self.assertIn("static bool msm5xxx_poc_audio_read_owned", source)
        start = source.index("static uint64_t msm5xxx_poc_lcd_aperture_read")
        end = source.index("\nstatic ", start + 1)
        body = source[start:end]
        self.assertIn("s->lcd_aperture_backing", body)
        self.assertIn("msm5xxx_poc_audio_read_owned", body)
        read_start = source.index("static bool msm5xxx_poc_audio_read_owned")
        read_end = source.index("\nstatic ", read_start + 1)
        read = source[read_start:read_end]
        self.assertIn("msm5xxx_poc_audio_site_owned", read)
        self.assertIn("msm5xxx_poc_audio_site_owned(s, false", read)
        self.assertIn("MSM5XXX_MA2_ADPCM_WAVE_DATA", read)
        self.assertIn("MSM5XXX_MA2_STATUS1", read)
        self.assertIn("MSM5XXX_MA2_WAVE_STATUS", read)
        self.assertIn("msm5xxx_ma2_data_read", read)
        write_start = source.index("static bool msm5xxx_poc_audio_write_owned")
        write_end = source.index("\nstatic ", write_start + 1)
        write = source[write_start:write_end]
        self.assertIn("msm5xxx_poc_audio_site_owned(s, true", write)
        self.assertIn("msm5xxx_poc_ma2_audio_kick(s);", write)
        site = write.index("msm5xxx_poc_audio_site_owned")
        backing = write.index("s->audio_backing[offset] = value;")
        index_write = write.index("msm5xxx_ma2_index_write")
        data_write = write.index("msm5xxx_ma2_data_write")
        self.assertLess(site, index_write)
        self.assertLess(site, data_write)
        self.assertLess(backing, index_write)
        self.assertLess(backing, data_write)
        self.assertIn("if (!native_site)", write)
        self.assertIn("if (s->audio_ma2", write)
        self.assertIn("msm5xxx_ma2_take_fm_stop", write)
        self.assertIn("msm5xxx_poc_ma2_synth_stop", write)
        stop_start = source.index("static bool msm5xxx_poc_ma2_synth_stop")
        stop_end = source.index("\nstatic ", stop_start + 1)
        stop = source[stop_start:stop_end]
        self.assertIn("MSM5XXX_AUDIO_EVENT_ALL_OFF", stop)
        self.assertIn("int16_t audio_backend_pcm", source)
        self.assertNotIn("(int16_t (*)[2])s->audio_backend_pcm", source)
        self.assertIn("qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)", stop)
        stream = write.index("s->audio_stream_started = true;")
        self.assertLess(write.index("if (!native_site)"), stream)
        self.assertLess(
            write.index("return false;", write.index("if (!native_site)")),
            stream,
        )
        aperture_start = source.index(
            "static void msm5xxx_poc_lcd_aperture_write"
        )
        aperture_end = source.index("\nstatic ", aperture_start + 1)
        aperture = source[aperture_start:aperture_end]
        owned = aperture.index("msm5xxx_poc_audio_write_owned")
        self.assertLess(owned, aperture.index("s->lcd_aperture_writes++"))
        self.assertIn("return;", aperture[owned:])
        self.assertNotIn("memory_region_init_io(&s->audio", source)
        tick_start = source.index("static void msm5xxx_poc_ma2_audio_tick")
        tick_end = source.index("\nstatic ", tick_start + 1)
        tick = source[tick_start:tick_end]
        self.assertIn("msm5xxx_ma2_scheduler_step", tick)
        self.assertIn("msm5xxx_ma2_scheduler_next_deadline", tick)
        self.assertRegex(
            tick,
            r"msm5xxx_audio_synth_active\(&s->audio_synth\) \|\|\s+"
            r"\(s->audio_output_started && s->audio_stream_chardev\)",
        )
        callback_start = source.index(
            "static void msm5xxx_poc_audio_backend_callback"
        )
        callback_end = source.index("\nstatic ", callback_start + 1)
        callback = source[callback_start:callback_end]
        self.assertRegex(
            callback,
            r"!msm5xxx_audio_synth_active\(&s->audio_synth\) &&\s+"
            r"s->audio_synth\.ring_count < frames",
        )
        self.assertIn("frames = s->audio_synth.ring_count", callback)
        self.assertIn("memset(&s->audio_backend_pcm[frames]", callback)
        self.assertIn("MSM5XXX_POC_AUDIO_STATUS_REJECTED", tick)
        self.assertIn("if (s->audio_pcm_enabled)", tick)
        self.assertIn("msm5xxx_ma2_scheduler_step", tick)
        self.assertLess(tick.index("msm5xxx_ma2_scheduler_step"),
                        tick.index("if (s->audio_pcm_enabled)"))
        self.assertNotIn("qemu_set_irq", tick)
        synth_start = source.index("static bool msm5xxx_poc_ma2_synth_output")
        synth_end = source.index("\nstatic ", synth_start + 1)
        synth = source[synth_start:synth_end]
        self.assertIn("msm5xxx_poc_ma2_timbre(s, channel, &event)", synth)
        timbre_start = source.index("static bool msm5xxx_poc_ma2_timbre")
        timbre_end = source.index("\nstatic ", timbre_start + 1)
        timbre = source[timbre_start:timbre_end]
        self.assertIn("memcmp(voice->decoded, descriptor", timbre)
        self.assertIn("one proven descriptor", timbre)
        self.assertIn("event->timbre_algorithm = 5u;", timbre)
        self.assertIn("UINT32_C(0x0094f20a)", timbre)
        self.assertIn("UINT32_C(0x3eb1aa70)", timbre)
        reset_start = source.index("static void msm5xxx_poc_audio_reset")
        reset_end = source.index("\nstatic ", reset_start + 1)
        reset = source[reset_start:reset_end]
        self.assertIn("s->audio_stream_rejected = false;", reset)
        self.assertIn("bool warm_reset = s->audio_reset_initialized;", reset)
        self.assertIn("s->audio_reset_initialized = true;", reset)
        self.assertIn("s->audio_pcm_length = 0u;", reset)
        self.assertIn("s->audio_pcm_offset = 0u;", reset)
        self.assertIn("s->audio_output_started = false;", reset)
        self.assertNotIn("pcm_partial", reset)
        self.assertIn("qemu_mutex_lock(&s->audio_core_lock);", reset)
        self.assertIn("msm5xxx_poc_audio_stream_status(s);", reset)
        self.assertIn("s->audio_stream_reset_epoch = s->audio_synth.epoch;",
                      reset)
        prepare_start = source.index("static void msm5xxx_poc_audio_pcm_prepare")
        prepare_end = source.index("\nstatic ", prepare_start + 1)
        prepare = source[prepare_start:prepare_end]
        self.assertIn("s->audio_stream_rejected", prepare)
        flush_start = source.index(
            "static int msm5xxx_poc_audio_pcm_flush"
        )
        flush_end = source.index("\nstatic ", flush_start + 1)
        flush = source[flush_start:flush_end]
        self.assertIn("qemu_chr_fe_write", flush)
        self.assertIn("written < 0 && errno == EAGAIN", flush)
        self.assertIn(
            "while (s->audio_pcm_offset < s->audio_pcm_length)", flush
        )
        self.assertEqual(flush.count("msm5xxx_poc_audio_pcm_prepare(s);"), 1)
        self.assertIn("return 0;", flush)
        self.assertIn("return -1;", flush)
        self.assertNotIn("audio_pcm_reset_tail", source)
        self.assertIn("while (true)", flush)
        self.assertNotIn("overflow_frames += dropped", flush)
        self.assertNotIn("msm5xxx_audio_synth_resync", flush)
        reject_start = source.index(
            "static void msm5xxx_poc_audio_pcm_reject"
        )
        reject_end = source.index("\nstatic ", reject_start + 1)
        reject = source[reject_start:reject_end]
        self.assertIn("s->audio_output_started = false;", reject)
        self.assertIn("if (s->audio_pcm_failed)", tick)
        self.assertIn("!stream_rejected", source)
        self.assertNotIn("qemu_chr_fe_add_watch", flush)
        self.assertNotIn("audio_pcm_watch", source)
        self.assertIn("msm5xxx_poc_audio_pcm_flush(s)", tick)
        self.assertLess(tick.index("msm5xxx_audio_synth_advance"),
                        tick.index("msm5xxx_poc_audio_pcm_flush(s)"))
        self.assertIn("s->audio_pcm_failed = true;", tick)
        self.assertNotIn("static void msm5xxx_poc_audio_pcm_tick", source)
        self.assertNotIn("audio_pcm_timer", source)
        self.assertNotIn("audio_pcm_deadline_ns", source)
        self.assertNotIn("MSM5XXX_POC_AUDIO_PACKET_PERIOD_NS", source)
        self.assertIn(
            "s->audio_synth.ring_count < MSM5XXX_AUDIO_CHUNK_FRAMES",
            prepare,
        )
        setter = source[source.index("static void msm5xxx_poc_set_audio_aperture"):]
        setter = setter[:setter.index("\nstatic ", 1)]
        self.assertIn("ma2_valid =", setter)
        self.assertIn("data_offset == 2", setter)
        self.assertIn('object_class_property_add_str(oc, "audio-sites"',
                      source)
        self.assertIn('object_class_property_add_bool(oc, "audio-pcm"',
                      source)
        self.assertIn("s->audio_pcm_enabled = true;", source)

    def test_protocol_contract(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "experiments" / "qemu-tcg" / "msm5xxx-ma2-audio.c"
        include_dir = core.parent
        harness = textwrap.dedent(
            r"""
            #include <assert.h>
            #include <stdint.h>
            #include <string.h>

            #include "msm5xxx-ma2-audio.h"

            static void write_register(MSM5xxxMA2Audio *audio, uint8_t page,
                                       uint8_t index, uint8_t value)
            {
                assert(msm5xxx_ma2_index_write(audio,
                                               MSM5XXX_MA2_PAGE_SELECT));
                assert(msm5xxx_ma2_data_write(audio, page));
                assert(msm5xxx_ma2_index_write(audio, index));
                assert(msm5xxx_ma2_data_write(audio, value));
            }

            static void write_stream(MSM5xxxMA2Audio *audio, uint8_t index,
                                     const uint8_t *bytes, size_t length)
            {
                size_t position;

                assert(msm5xxx_ma2_index_write(audio,
                                               MSM5XXX_MA2_PAGE_SELECT));
                assert(msm5xxx_ma2_data_write(audio, MSM5XXX_MA2_PAGE_REG0));
                assert(msm5xxx_ma2_index_write(audio, index));
                for (position = 0u; position < length; position++) {
                    assert(msm5xxx_ma2_data_write(audio, bytes[position]));
                }
            }

            static void enable_voice(MSM5xxxMA2Audio *audio, uint8_t channel,
                                     uint8_t slot)
            {
                audio->fm_voice[slot].valid = true;
                audio->fm_channel[channel].voice_slot = slot;
                audio->fm_channel[channel].voice_slot_valid = true;
            }

            int main(void)
            {
                MSM5xxxMA2Audio audio;
                MSM5xxxMA2CompactParser parser;
                MSM5xxxMA2CompactEvent event;
                MSM5xxxMA2CompactResult result;
                MSM5xxxMA2AdpcmDecoder decoder;
                MSM5xxxMA2Output output;
                int16_t samples[2];
                uint64_t nanoseconds;
                uint64_t deadline;
                uint8_t value;
                unsigned i;
                unsigned events;
                static const uint8_t compact[] = {
                    0x00u, 0xffu, 0xf0u, 0x02u, 0x12u, 0x34u,
                    0x00u, 0x01u, 0x01u,
                    0x64u, 0x02u, 0x01u,
                    0x00u, 0x00u, 0x00u, 0x00u,
                };
                static const uint8_t lookahead[] = {
                    0x00u, 0x00u, 0x00u, 0x64u, 0x02u, 0x01u,
                };
                static const uint8_t wide_values[] = {
                    0x80u, 0x80u, 0x01u, 0x81u, 0x80u,
                };
                static const uint8_t adpcm_event[] = {0x02u, 0x3eu, 0x03u};
                static const uint8_t invalid_adpcm[] = {0x00u, 0x41u, 0x01u};
                static const uint8_t timed_fm[] = {
                    0x02u, 0x01u, 0x03u,
                    0x00u, 0x02u, 0x01u,
                    0x00u, 0x00u, 0x00u, 0x00u,
                };
                static const uint8_t state_fm[] = {
                    0x00u, 0xffu, 0xf0u, 0x06u,
                    0x43u, 0x03u, 0x91u, 0x18u, 0x21u, 0xf7u,
                    0x00u, 0xffu, 0xf0u, 0x1cu,
                    0x43u, 0x03u, 0x00u, 0x02u, 0x07u, 0x45u, 0x01u,
                    0x71u, 0x35u, 0x50u, 0x62u, 0xa0u,
                    0x10u, 0x34u, 0xf0u, 0x01u, 0xa0u,
                    0xd1u, 0x25u, 0xa0u, 0x90u, 0xa0u,
                    0x10u, 0x35u, 0xf0u, 0x14u, 0xa0u, 0xf7u,
                    0x00u, 0x00u, 0x30u, 0x07u,
                    0x00u, 0x00u, 0x31u, 0x02u,
                    0x00u, 0x00u, 0x37u, 0x55u,
                    0x00u, 0x00u, 0x33u, 0x51u,
                    0x00u, 0x00u, 0x07u,
                    0x00u, 0x00u, 0x12u,
                    0x00u, 0x00u, 0x2fu,
                    0x00u, 0x37u, 0x02u,
                    0x00u, 0x00u, 0x00u, 0x00u,
                };
                static const uint8_t shifted_fm[] = {
                    0x00u, 0x00u, 0x32u, 0x7fu,
                    0x00u, 0x3cu, 0x01u,
                    0x00u, 0x00u, 0x32u, 0xffu,
                    0x00u, 0x01u, 0x01u,
                    0x00u, 0x00u, 0x00u, 0x00u,
                };
                static const uint8_t invalid_voice_fm[] = {
                    0x00u, 0xffu, 0xf0u, 0x12u,
                    0x43u, 0x03u, 0x00u, 0x01u, 0x0au, 0x45u, 0x01u,
                    0x71u, 0x35u, 0x50u, 0x62u, 0xa0u,
                    0x10u, 0x34u, 0xf0u, 0x01u, 0xa0u, 0xf7u,
                    0x00u, 0x00u, 0x00u, 0x00u,
                };
                static const uint8_t paused_fm[] = {0x0au, 0x01u, 0x02u};
                static const uint8_t unresolved_fm[] = {
                    0x00u, 0xffu, 0xf0u, 0x06u,
                    0x43u, 0x03u, 0x91u, 0x18u, 0x01u, 0xf7u,
                    0x00u, 0x01u, 0x01u,
                    0x00u, 0x00u, 0x00u, 0x00u,
                };
                static const uint8_t max_deadline_fm[] = {
                    0x01u, 0x01u, 0x00u,
                    0x00u, 0x00u, 0x00u, 0x00u,
                };
                static const uint8_t timed_adpcm[] = {0x02u, 0x01u, 0x03u};
                static const uint8_t adpcm[] = {
                    0x10u, 0x98u, 0x32u, 0xbau,
                };
                static const int16_t decoded[] = {
                    15, 61, 46, 0, 78, 187, 109, 0,
                };
                static const uint8_t adpcm_growth[] = {0x77u, 0x77u};
                static const int16_t decoded_growth[] = {
                    236, 806, 2172, 5449,
                };
                static const uint8_t decoded_voice[] = {
                    0x10u, 0x00u, 0x00u, 0x01u, 0x01u, 0x05u,
                    0x03u, 0x00u, 0x00u, 0x01u, 0x03u, 0x05u,
                    0x05u, 0x00u, 0x18u, 0x02u, 0x02u, 0x00u,
                    0x02u, 0x00u, 0x07u, 0x00u, 0x00u, 0x00u,
                    0x03u, 0x00u, 0x00u, 0x00u, 0x03u, 0x04u,
                    0x0fu, 0x00u, 0x00u, 0x01u, 0x02u, 0x00u,
                    0x02u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u,
                    0x02u, 0x00u, 0x00u, 0x01u, 0x02u, 0x05u,
                    0x0au, 0x00u, 0x24u, 0x00u, 0x02u, 0x00u,
                    0x02u, 0x00u, 0x0du, 0x00u, 0x00u, 0x00u,
                    0x03u, 0x00u, 0x00u, 0x00u, 0x03u, 0x05u,
                    0x0fu, 0x00u, 0x05u, 0x00u, 0x02u, 0x00u,
                    0x02u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u,
                };

                msm5xxx_ma2_reset(&audio);

                /* Direct assignment registers own two channel nibbles. */
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_FM_CHANNEL_ASSIGN, 0x21u);
                assert(audio.fm_assignment[0] == 0x21u);
                assert(audio.fm_channel[0].voice_slot_valid);
                assert(audio.fm_channel[0].voice_slot == 1u);
                assert(audio.fm_channel[1].voice_slot_valid);
                assert(audio.fm_channel[1].voice_slot == 2u);
                assert(msm5xxx_ma2_data_read(&audio, &value) &&
                       value == 0x21u);
                msm5xxx_ma2_reset(&audio);

                assert(msm5xxx_ma2_timebase_ns(
                    0x72u, false, &nanoseconds));
                assert(nanoseconds == 50000000u);
                assert(msm5xxx_ma2_timebase_ns(
                    0x72u, true, &nanoseconds));
                assert(nanoseconds == 4000000u);
                assert(!msm5xxx_ma2_timebase_ns(
                    0x88u, false, &nanoseconds));

                /* Page select works while the other page is selected. */
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_PAGE_SELECT));
                assert(msm5xxx_ma2_data_write(&audio, MSM5XXX_MA2_PAGE_REG1));
                assert(audio.page == MSM5XXX_MA2_PAGE_REG1);
                assert(msm5xxx_ma2_index_write(&audio, 0x80u));
                assert(msm5xxx_ma2_data_write(&audio, 0x5au));
                assert(msm5xxx_ma2_data_read(&audio, &value) && value == 0x5au);
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_PAGE_SELECT));
                assert(msm5xxx_ma2_data_read(&audio, &value) &&
                       value == MSM5XXX_MA2_PAGE_REG1);
                assert(msm5xxx_ma2_data_write(&audio, MSM5XXX_MA2_PAGE_REG0));

                /* Unknown page-0 registers mirror through the shadow. */
                assert(msm5xxx_ma2_index_write(&audio, 0xb0u));
                assert(msm5xxx_ma2_data_write(&audio, 0xa5u));
                assert(msm5xxx_ma2_data_read(&audio, &value) && value == 0xa5u);

                /* FM0: exact capacity plus unproven status fail-closed. */
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_FM_IRQ_CTRL));
                assert(msm5xxx_ma2_data_write(&audio, 0x13u));
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_FM_DATA0));
                for (i = 0u; i < MSM5XXX_MA2_FM_FIFO_CAPACITY; ++i) {
                    assert(msm5xxx_ma2_data_write(&audio, (uint8_t)i));
                }
                assert(msm5xxx_ma2_fifo_occupancy(&audio,
                                                  MSM5XXX_MA2_FIFO_FM0) ==
                       MSM5XXX_MA2_FM_FIFO_CAPACITY);
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_FULL_STATUS));
                assert(msm5xxx_ma2_data_read(&audio, &value) &&
                       (value & 0x01u) != 0u);
                for (i = 0u; i < MSM5XXX_MA2_FM_FIFO_CAPACITY / 2u; ++i) {
                    assert(msm5xxx_ma2_chip_fifo_pop(
                        &audio, MSM5XXX_MA2_FIFO_FM0, &value));
                }
                assert(msm5xxx_ma2_index_write(&audio, MSM5XXX_MA2_STATUS1));
                assert(!msm5xxx_ma2_data_read(&audio, &value));
                assert(msm5xxx_ma2_reject_reason(&audio) ==
                       MSM5XXX_MA2_REJECT_UNSUPPORTED_READ);
                msm5xxx_ma2_clear_rejection(&audio);
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_PAGE_SELECT));
                assert(msm5xxx_ma2_data_write(&audio, MSM5XXX_MA2_PAGE_REG1));
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_FIFO_CONTROL));
                assert(msm5xxx_ma2_data_write(&audio,
                                              MSM5XXX_MA2_FM_FIFO_CLEAR));
                assert(msm5xxx_ma2_fifo_occupancy(
                    &audio, MSM5XXX_MA2_FIFO_FM0) == 0u);
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_PAGE_SELECT));
                assert(msm5xxx_ma2_data_write(&audio, MSM5XXX_MA2_PAGE_REG0));

                /* Start edges are one-shot; held bits and FS are not starts. */
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_PAGE_SELECT));
                assert(msm5xxx_ma2_data_write(&audio, MSM5XXX_MA2_PAGE_REG1));
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_CONTROL));
                assert(msm5xxx_ma2_data_write(&audio, 0u));
                assert(!msm5xxx_ma2_take_fm_start(&audio));
                assert(!msm5xxx_ma2_take_adpcm_start(&audio));
                assert(msm5xxx_ma2_data_write(&audio,
                                               MSM5XXX_MA2_ADPCM_START));
                assert(msm5xxx_ma2_take_adpcm_start(&audio));
                assert(!msm5xxx_ma2_take_adpcm_start(&audio));
                assert(msm5xxx_ma2_data_write(&audio,
                                               MSM5XXX_MA2_ADPCM_START));
                assert(!msm5xxx_ma2_take_adpcm_start(&audio));
                assert(msm5xxx_ma2_data_write(
                    &audio, MSM5XXX_MA2_ADPCM_START |
                            MSM5XXX_MA2_SAMPLE_RATE_8KHZ));
                assert(!msm5xxx_ma2_take_adpcm_start(&audio));
                assert(msm5xxx_ma2_data_write(
                    &audio, MSM5XXX_MA2_SAMPLE_RATE_8KHZ));
                assert(msm5xxx_ma2_data_write(
                    &audio, MSM5XXX_MA2_FM_START |
                            MSM5XXX_MA2_ADPCM_START |
                            MSM5XXX_MA2_SAMPLE_RATE_8KHZ));
                assert(msm5xxx_ma2_take_fm_start(&audio));
                assert(msm5xxx_ma2_take_adpcm_start(&audio));
                assert(!msm5xxx_ma2_take_fm_stop(&audio));
                assert(msm5xxx_ma2_data_write(
                    &audio, MSM5XXX_MA2_ADPCM_START |
                            MSM5XXX_MA2_SAMPLE_RATE_8KHZ));
                assert(msm5xxx_ma2_take_fm_stop(&audio));
                assert(!msm5xxx_ma2_take_fm_stop(&audio));
                assert(msm5xxx_ma2_data_write(
                    &audio, MSM5XXX_MA2_ADPCM_START |
                            MSM5XXX_MA2_SAMPLE_RATE_8KHZ));
                assert(!msm5xxx_ma2_take_fm_stop(&audio));
                assert(msm5xxx_ma2_data_write(
                    &audio, MSM5XXX_MA2_FM_START |
                            MSM5XXX_MA2_ADPCM_START |
                            MSM5XXX_MA2_SAMPLE_RATE_8KHZ));
                assert(msm5xxx_ma2_take_fm_start(&audio));
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_PAGE_SELECT));
                assert(msm5xxx_ma2_data_write(&audio, MSM5XXX_MA2_PAGE_REG0));

                /* ADPCM sequence: exact capacity; flags fail closed. */
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_ADPCM_IRQ_CTRL));
                assert(msm5xxx_ma2_data_write(&audio, 0x90u));
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_ADPCM_SEQ_DATA));
                for (i = 0u; i < MSM5XXX_MA2_ADPCM_SEQUENCE_CAPACITY; ++i) {
                    assert(msm5xxx_ma2_data_write(&audio, (uint8_t)i));
                }
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_FULL_STATUS));
                assert(msm5xxx_ma2_data_read(&audio, &value) &&
                       (value & MSM5XXX_MA2_ADPCM_FULL) != 0u);
                for (i = 0u; i < MSM5XXX_MA2_ADPCM_SEQUENCE_CAPACITY / 2u;
                     ++i) {
                    assert(msm5xxx_ma2_chip_fifo_pop(
                        &audio, MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE, &value));
                }
                assert(msm5xxx_ma2_index_write(&audio, MSM5XXX_MA2_STATUS1));
                assert(!msm5xxx_ma2_data_read(&audio, &value));
                assert(msm5xxx_ma2_reject_reason(&audio) ==
                       MSM5XXX_MA2_REJECT_UNSUPPORTED_READ);
                msm5xxx_ma2_clear_rejection(&audio);
                for (i = 0u; i < MSM5XXX_MA2_ADPCM_SEQUENCE_CAPACITY / 2u;
                     ++i) {
                    assert(msm5xxx_ma2_chip_fifo_pop(
                        &audio, MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE, &value));
                }
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_EMPTY_STATUS));
                assert(msm5xxx_ma2_data_read(&audio, &value) &&
                       (value & MSM5XXX_MA2_ADPCM_EMPTY) != 0u);

                /* ADPCM wave occupancy is exact; combined status is not. */
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_ADPCM_IRQ_CTRL));
                assert(msm5xxx_ma2_data_write(&audio, 0x44u));
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_ADPCM_WAVE_DATA));
                for (i = 0u; i < MSM5XXX_MA2_ADPCM_WAVE_CAPACITY; ++i) {
                    assert(msm5xxx_ma2_data_write(&audio, (uint8_t)i));
                }
                assert(msm5xxx_ma2_fifo_occupancy(
                    &audio, MSM5XXX_MA2_FIFO_ADPCM_WAVE) ==
                       MSM5XXX_MA2_ADPCM_WAVE_CAPACITY);
                for (i = 0u; i < MSM5XXX_MA2_ADPCM_WAVE_CAPACITY / 2u;
                     ++i) {
                    assert(msm5xxx_ma2_chip_fifo_pop(
                        &audio, MSM5XXX_MA2_FIFO_ADPCM_WAVE, &value));
                }
                assert(msm5xxx_ma2_fifo_occupancy(
                    &audio, MSM5XXX_MA2_FIFO_ADPCM_WAVE) ==
                       MSM5XXX_MA2_ADPCM_WAVE_CAPACITY / 2u);
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_WAVE_STATUS));
                assert(!msm5xxx_ma2_data_read(&audio, &value));
                assert(msm5xxx_ma2_reject_reason(&audio) ==
                       MSM5XXX_MA2_REJECT_UNSUPPORTED_READ);
                msm5xxx_ma2_clear_rejection(&audio);
                for (i = 0u; i < MSM5XXX_MA2_ADPCM_WAVE_CAPACITY / 2u;
                     ++i) {
                    assert(msm5xxx_ma2_chip_fifo_pop(
                        &audio, MSM5XXX_MA2_FIFO_ADPCM_WAVE, &value));
                }
                assert(msm5xxx_ma2_fifo_occupancy(
                    &audio, MSM5XXX_MA2_FIFO_ADPCM_WAVE) == 0u);

                /* GEND is the only writable status bit and is W1C. */
                audio.gend_status = 0x20u;
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_STATUS2));
                assert(msm5xxx_ma2_data_write(&audio, 0x20u));
                assert(audio.gend_status == 0u);
                assert(msm5xxx_ma2_data_read(&audio, &value) && value == 0u);

                /* Unsupported IRQ point encodings fail closed. */
                msm5xxx_ma2_clear_rejection(&audio);
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_FM_IRQ_CTRL));
                assert(!msm5xxx_ma2_data_write(&audio, 0x01u));
                assert(msm5xxx_ma2_reject_reason(&audio) ==
                       MSM5XXX_MA2_REJECT_INVALID_ENCODING);
                msm5xxx_ma2_clear_rejection(&audio);
                assert(msm5xxx_ma2_index_write(&audio,
                                               MSM5XXX_MA2_ADPCM_IRQ_CTRL));
                assert(!msm5xxx_ma2_data_write(&audio, 0x08u));
                assert(msm5xxx_ma2_reject_reason(&audio) ==
                       MSM5XXX_MA2_REJECT_INVALID_ENCODING);

                /* Compact events commit only after every fragmented byte. */
                msm5xxx_ma2_compact_parser_reset(&parser);
                events = 0u;
                for (i = 0u; i < sizeof(compact); ++i) {
                    result = msm5xxx_ma2_compact_parser_feed(
                        &parser, compact[i], &event);
                    if (result == MSM5XXX_MA2_COMPACT_EVENT) {
                        if (events == 0u) {
                            assert(event.kind == MSM5XXX_MA2_COMPACT_SYSEX);
                            assert(event.delta_ticks == 0u);
                            assert(event.sysex_length == 2u);
                            assert(event.sysex[0] == 0x12u);
                            assert(event.sysex[1] == 0x34u);
                        } else if (events == 1u) {
                            assert(event.kind == MSM5XXX_MA2_COMPACT_NOTE);
                            assert(event.delta_ticks == 0u);
                            assert(event.local_channel == 0u);
                            assert(event.octave == 0u);
                            assert(event.note_id == 1u);
                            assert(event.gate_ticks == 1u);
                        } else {
                            assert(events == 2u);
                            assert(event.kind == MSM5XXX_MA2_COMPACT_NOTE);
                            assert(event.delta_ticks == 100u);
                            assert(event.note_id == 2u);
                            assert(event.gate_ticks == 1u);
                        }
                        events++;
                    } else if (i + 1u == sizeof(compact)) {
                        assert(result == MSM5XXX_MA2_COMPACT_END);
                    } else {
                        assert(result == MSM5XXX_MA2_COMPACT_NEED_MORE);
                    }
                }
                assert(events == 3u);
                assert(parser.length == 0u);

                /* Three zero bytes need lookahead; the fourth is retained. */
                msm5xxx_ma2_compact_parser_reset(&parser);
                for (i = 0u; i < sizeof(lookahead); ++i) {
                    result = msm5xxx_ma2_compact_parser_feed(
                        &parser, lookahead[i], &event);
                    if (i < 3u) {
                        assert(result == MSM5XXX_MA2_COMPACT_NEED_MORE);
                    } else if (i == 3u) {
                        assert(result == MSM5XXX_MA2_COMPACT_EVENT);
                        assert(event.kind == MSM5XXX_MA2_COMPACT_CONTROL);
                        assert(event.control_family == 0u);
                        assert(event.control_code == 0u);
                        assert(parser.length == 1u);
                    } else if (i == 4u) {
                        assert(result == MSM5XXX_MA2_COMPACT_NEED_MORE);
                    } else {
                        assert(result == MSM5XXX_MA2_COMPACT_EVENT);
                        assert(event.kind == MSM5XXX_MA2_COMPACT_NOTE);
                        assert(event.delta_ticks == 100u);
                        assert(event.note_id == 2u);
                    }
                }

                /* Handy two-byte values mask bit 7 in the second byte. */
                msm5xxx_ma2_compact_parser_reset(&parser);
                for (i = 0u; i < sizeof(wide_values); ++i) {
                    result = msm5xxx_ma2_compact_parser_feed(
                        &parser, wide_values[i], &event);
                }
                assert(result == MSM5XXX_MA2_COMPACT_EVENT);
                assert(event.kind == MSM5XXX_MA2_COMPACT_NOTE);
                assert(event.delta_ticks == 128u);
                assert(event.gate_ticks == 256u);

                /* Only closed FM state transitions mutate native state. */
                msm5xxx_ma2_reset(&audio);
                write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                             state_fm, sizeof(state_fm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.event.kind == MSM5XXX_MA2_COMPACT_SYSEX);
                assert(audio.fm_assignment[0] == 0x21u);
                assert(audio.fm_channel[0].voice_slot == 1u);
                assert(audio.fm_channel[1].voice_slot == 2u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_voice[0].valid);
                assert(audio.fm_voice[0].bank == 2u);
                assert(audio.fm_voice[0].program == 7u);
                assert(audio.fm_voice[0].info == 0x45u);
                assert(audio.fm_voice[0].basic_octave == 1u);
                assert(audio.fm_voice[0].operator_count == 4u);
                assert(audio.fm_voice[0].operation[0].data[0] == 0x71u);
                assert(audio.fm_voice[0].operation[0].data[4] == 0xa0u);
                assert(memcmp(audio.fm_voice[0].decoded, decoded_voice,
                              sizeof(decoded_voice)) == 0);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].program == 7u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].bank == 2u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].volume == 0x55u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].modulation == 0x0cu);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].expression == 0x48u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].pitch_bend == 0x10u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].modulation == 0x0fu);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.event.kind == MSM5XXX_MA2_COMPACT_NOTE);
                assert(output.note == 79u);
                assert(audio.fm_channel[0].key_on);
                assert(audio.fm_channel[0].note_octave == 3u);
                assert(audio.fm_channel[0].note_id == 7u);
                assert(audio.fm_channel[0].note == 79u);
                assert(audio.fm_channel[0].active_voice_slot == 0u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_END);
                assert(msm5xxx_ma2_scheduler_step(&audio, 2000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_GATE_OFF);
                assert(output.note == 79u);
                assert(!audio.fm_channel[0].key_on);
                assert(audio.fm_state_unhandled == 0u);

                /* Octave shift is signed magnitude and note output clamps. */
                msm5xxx_ma2_reset(&audio);
                enable_voice(&audio, 0u, 0u);
                write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                             shifted_fm, sizeof(shifted_fm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].octave_shift == 127);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].note == 127u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].octave_shift == -127);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(audio.fm_channel[0].note == 0u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_END);

                /* Mismatched voice length/algorithm remains observable. */
                msm5xxx_ma2_reset(&audio);
                write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                             invalid_voice_fm, sizeof(invalid_voice_fm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.event.kind == MSM5XXX_MA2_COMPACT_SYSEX);
                assert(audio.fm_state_unhandled == 1u);
                assert(!audio.fm_voice[0].valid);

                /* A later AD parse error rolls back earlier FM staging. */
                {
                    MSM5xxxMA2SequenceState before_fm0;
                    MSM5xxxMA2SequenceState before_ad;
                    size_t before_fm0_count;
                    size_t before_ad_count;
                    uint64_t before_now;
                    bool before_clock_initialized;

                    msm5xxx_ma2_reset(&audio);
                    enable_voice(&audio, 0u, 0u);
                    write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                                 max_deadline_fm, sizeof(max_deadline_fm));
                    write_stream(&audio, MSM5XXX_MA2_ADPCM_SEQ_DATA,
                                 invalid_adpcm, sizeof(invalid_adpcm));
                    write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                                   MSM5XXX_MA2_CONTROL,
                                   MSM5XXX_MA2_FM_START |
                                   MSM5XXX_MA2_ADPCM_START);
                    before_fm0 = audio.sequence[0];
                    before_ad = audio.sequence[4];
                    before_fm0_count = msm5xxx_ma2_fifo_occupancy(
                        &audio, MSM5XXX_MA2_FIFO_FM0);
                    before_ad_count = msm5xxx_ma2_fifo_occupancy(
                        &audio, MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE);
                    before_now = audio.scheduler_now_ns;
                    before_clock_initialized = audio.scheduler_clock_initialized;
                    assert(!msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                    assert(msm5xxx_ma2_rejected(&audio));
                    assert(msm5xxx_ma2_reject_reason(&audio) ==
                           MSM5XXX_MA2_REJECT_INVALID_ENCODING);
                    assert(msm5xxx_ma2_fifo_occupancy(
                        &audio, MSM5XXX_MA2_FIFO_FM0) == before_fm0_count);
                    assert(msm5xxx_ma2_fifo_occupancy(
                        &audio, MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE) ==
                           before_ad_count);
                    assert(memcmp(&audio.sequence[0], &before_fm0,
                                  sizeof(before_fm0)) == 0);
                    assert(memcmp(&audio.sequence[4], &before_ad,
                                  sizeof(before_ad)) == 0);
                    assert(audio.scheduler_now_ns == before_now);
                    assert(audio.scheduler_clock_initialized ==
                           before_clock_initialized);
                    assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                }

                /* Unresolved notes follow the native Nop path. */
                msm5xxx_ma2_reset(&audio);
                write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                             unresolved_fm, sizeof(unresolved_fm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.event.kind == MSM5XXX_MA2_COMPACT_NOTE);
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                assert(output.note == 37u);
                assert(!audio.fm_channel[0].key_on);
                assert(!audio.fm_gate[0].active);
                assert(audio.fm_state_unhandled == 1u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_END);
                assert(msm5xxx_ma2_scheduler_step(
                    &audio, 4000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);

                /* AD sequence events use a six-bit wave id, not FM notes. */
                msm5xxx_ma2_compact_parser_reset(&parser);
                for (i = 0u; i < sizeof(adpcm_event); ++i) {
                    result = msm5xxx_ma2_adpcm_parser_feed(
                        &parser, adpcm_event[i], &event);
                }
                assert(result == MSM5XXX_MA2_COMPACT_EVENT);
                assert(event.kind == MSM5XXX_MA2_COMPACT_WAVE);
                assert(event.delta_ticks == 2u);
                assert(event.wave_id == 0x3eu);
                assert(event.gate_ticks == 3u);
                msm5xxx_ma2_compact_parser_reset(&parser);
                for (i = 0u; i < sizeof(invalid_adpcm); ++i) {
                    result = msm5xxx_ma2_adpcm_parser_feed(
                        &parser, invalid_adpcm[i], &event);
                }
                assert(result == MSM5XXX_MA2_COMPACT_ERROR);
                assert(parser.rejected);

                /* Sequencer time is chip time; equal-time events keep order. */
                msm5xxx_ma2_reset(&audio);
                enable_voice(&audio, 0u, 0u);
                write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                             timed_fm, sizeof(timed_fm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_FM_TIMEBASE, 0u);
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 1000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                assert(msm5xxx_ma2_scheduler_next_deadline(&audio, &deadline));
                assert(deadline == 3000000u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 2999999u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                assert(msm5xxx_ma2_scheduler_step(&audio, 3000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_EVENT);
                assert(output.timestamp_ns == 3000000u);
                assert(output.stream == MSM5XXX_MA2_FIFO_FM0);
                assert(output.channel == 0u && output.event.note_id == 1u);
                assert(output.voice_id == 1u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 3000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_EVENT);
                assert(output.timestamp_ns == 3000000u);
                assert(output.event.note_id == 2u);
                assert(output.voice_id == 2u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 3000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_END);
                assert(output.stream == MSM5XXX_MA2_FIFO_FM0);
                assert(msm5xxx_ma2_scheduler_step(&audio, 4000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_GATE_OFF);
                assert(output.channel == 0u);
                assert(output.voice_id == 2u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 6000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_GATE_OFF);
                assert(output.channel == 0u);
                assert(output.voice_id == 1u);

                /* CONTROL stop preserves parser state and remaining duration. */
                msm5xxx_ma2_reset(&audio);
                enable_voice(&audio, 0u, 0u);
                write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                             paused_fm, sizeof(paused_fm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                assert(msm5xxx_ma2_scheduler_step(&audio, 4000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, 0u);
                assert(msm5xxx_ma2_take_fm_stop(&audio));
                assert(!msm5xxx_ma2_take_fm_stop(&audio));
                assert(msm5xxx_ma2_scheduler_step(&audio, 4000000u, &output));
                assert(!msm5xxx_ma2_scheduler_next_deadline(&audio, &deadline));
                assert(msm5xxx_ma2_scheduler_step(&audio, 100000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 100000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                assert(msm5xxx_ma2_scheduler_next_deadline(&audio, &deadline));
                assert(deadline == 106000000u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 105999999u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                assert(msm5xxx_ma2_scheduler_step(&audio, 106000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_EVENT);
                assert(output.event.note_id == 1u);

                /* UINT64_MAX is a valid event and gate deadline. */
                msm5xxx_ma2_reset(&audio);
                enable_voice(&audio, 0u, 0u);
                write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                             max_deadline_fm, sizeof(max_deadline_fm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(
                    &audio, UINT64_MAX - 1000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                assert(msm5xxx_ma2_scheduler_next_deadline(&audio, &deadline));
                assert(deadline == UINT64_MAX);
                assert(msm5xxx_ma2_scheduler_step(
                    &audio, UINT64_MAX, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_EVENT);
                assert(msm5xxx_ma2_scheduler_step(
                    &audio, UINT64_MAX, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_GATE_OFF);

                /* AD sequence uses its own clock and wave event semantics. */
                msm5xxx_ma2_reset(&audio);
                write_stream(&audio, MSM5XXX_MA2_ADPCM_SEQ_DATA,
                             timed_adpcm, sizeof(timed_adpcm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_ADPCM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                assert(msm5xxx_ma2_scheduler_step(&audio, 2000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_EVENT);
                assert(output.event.kind == MSM5XXX_MA2_COMPACT_WAVE);
                assert(output.event.wave_id == 1u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 5000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_GATE_OFF);
                assert(output.stream == MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE);
                assert(!msm5xxx_ma2_scheduler_step(&audio, 4999999u, &output));
                assert(msm5xxx_ma2_reject_reason(&audio) ==
                       MSM5XXX_MA2_REJECT_CLOCK_ROLLBACK);

                /* One byte produces low-nibble then high-nibble PCM. */
                msm5xxx_ma2_adpcm_decoder_reset(&decoder);
                for (i = 0u; i < sizeof(adpcm); ++i) {
                    assert(msm5xxx_ma2_adpcm_decode_byte(
                        &decoder, adpcm[i], samples));
                    assert(samples[0] == decoded[i * 2u]);
                    assert(samples[1] == decoded[i * 2u + 1u]);
                }
                assert(decoder.accumulator == 0);
                msm5xxx_ma2_adpcm_decoder_reset(&decoder);
                for (i = 0u; i < sizeof(adpcm_growth); ++i) {
                    assert(msm5xxx_ma2_adpcm_decode_byte(
                        &decoder, adpcm_growth[i], samples));
                    assert(samples[0] == decoded_growth[i * 2u]);
                    assert(samples[1] == decoded_growth[i * 2u + 1u]);
                }
                assert(decoder.accumulator == 5449);
                msm5xxx_ma2_adpcm_decoder_reset(&decoder);
                assert(decoder.accumulator == 0);
                assert(decoder.step == 127u);
                return 0;
            }
            """
        )

        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            harness_path = temporary / "ma2_harness.c"
            binary_path = temporary / "ma2_harness"
            harness_path.write_text(harness, encoding="utf-8")
            compile_command = [
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                f"-I{include_dir}",
                str(core),
                str(harness_path),
                "-o",
                str(binary_path),
            ]
            subprocess.run(compile_command, check=True, capture_output=True,
                           text=True)
            subprocess.run([str(binary_path)], check=True,
                           capture_output=True, text=True)

    def test_fm_renderer_core(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "experiments" / "qemu-tcg" / "msm5xxx-ma2-audio.c"
        include_dir = core.parent
        harness = textwrap.dedent(
            r"""
            #include <assert.h>
            #include <math.h>
            #include <stdint.h>
            #include <string.h>

            #include "msm5xxx-ma2-audio.h"

            static void init_operator(MSM5xxxMA2FMRenderOperator *operation,
                                      const int16_t *wave, uint32_t attack,
                                      uint32_t decay, uint32_t sustain,
                                      uint32_t phase_step, uint32_t gain)
            {
                memset(operation, 0, sizeof(*operation));
                operation->wave = wave;
                operation->attack_step = attack;
                operation->decay_factor = decay;
                operation->sustain_factor = sustain;
                operation->release_factor = sustain;
                operation->threshold = 0x80000000u;
                operation->phase_step = phase_step;
                operation->output_gain = gain;
                operation->envelope_state = 2u;
            }

            int main(void)
            {
                MSM5xxxMA2FMRenderVoice voice;
                int16_t wave[4][MSM5XXX_MA2_FM_WAVE_SAMPLES];
                int16_t sine[MSM5XXX_MA2_FM_WAVE_SAMPLES];
                int32_t sample;
                int32_t samples[32];
                size_t algorithm;
                size_t operation;
                size_t index;
                static const int32_t topology[] = {
                    170, 240, 800, 362, 352, 520, 432, 660,
                };
                static const uint32_t topology_phase[] = {
                    80u << 22, 160u << 22, 240u << 22, 320u << 22,
                };
                static const uint32_t attack[] = {
                    0x00255578u, 0x80000000u, 0x04a788e5u, 0x80000000u,
                };
                static const uint32_t decay[] = {
                    0x3ff14531u, 0x3ffe6bd1u, 0x3ff14531u, 0x3ffcd7acu,
                };
                static const uint32_t sustain[] = {
                    0x3ffc50f7u, 0x3fff35e7u, 0x3ffe2875u, 0x3fff35e7u,
                };
                static const uint32_t phase_step[] = {
                    0x2be30000u, 0x06450000u, 0x4b3c0000u, 0x06450000u,
                };
                static const uint32_t gain[] = {
                    4092u, 32511u, 1464u, 21279u,
                };
                static const int32_t expected[] = {
                    0, 8989, 15365, 22035, 32961, 37436, 39155, 48537,
                    51994, 50748, 53302, 50320, 52030, 50160, 38918, 34850,
                    42339, 28362, 3903, 17095, 13857, -17229, -14127, -650,
                    -34547, -44201, -25880, -37674, -44615, -50765, -41658,
                    -47285,
                };

                for (operation = 0u; operation < 4u; operation++) {
                    for (index = 0u; index < MSM5XXX_MA2_FM_WAVE_SAMPLES;
                         index++) {
                        wave[operation][index] = (int16_t)index;
                    }
                }
                for (algorithm = 0u; algorithm < 8u; algorithm++) {
                    memset(&voice, 0, sizeof(voice));
                    voice.algorithm = (uint8_t)algorithm;
                    voice.operator_count = algorithm <= 1u ? 2u : 4u;
                    for (operation = 0u; operation < voice.operator_count;
                         operation++) {
                        init_operator(&voice.operation[operation],
                                      wave[operation], 0u, 0u, 0u, 0u,
                                      0x8000u);
                        voice.operation[operation].envelope = 0x80000000u;
                        voice.operation[operation].envelope_state = 3u;
                        voice.operation[operation].phase =
                            topology_phase[operation];
                    }
                    assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                    assert(sample == topology[algorithm]);
                }

                memset(&voice, 0, sizeof(voice));
                voice.algorithm = 1u;
                voice.operator_count = 2u;
                for (operation = 0u; operation < 2u; operation++) {
                    init_operator(&voice.operation[operation], wave[operation],
                                  0u, 0u, 0u, 0u, 0x8000u);
                    voice.operation[operation].envelope_state = 0u;
                }
                voice.operation[0].envelope = 0x40000000u;
                voice.operation[0].sustain_factor = 0x40000000u;
                voice.operation[0].state1_uses_sustain = true;
                voice.operation[0].envelope_state = 1u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].envelope == 0x40000000u);
                assert(voice.operation[0].envelope_state == 1u);
                voice.operation[0].release_factor = 0u;
                voice.operation[0].state1_uses_sustain = false;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].envelope == 0u);
                assert(voice.operation[0].envelope_state == 0u);
                voice.operation[0].envelope = 0x40000000u;
                voice.operation[0].release_factor = 0x20000000u;
                voice.operation[0].envelope_state = 1u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].envelope == 0x20000000u);
                assert(voice.operation[0].envelope_state == 1u);
                voice.operation[0].envelope = 0xffffffffu;
                voice.operation[0].decay_factor = 0xffffffffu;
                voice.operation[0].threshold = 0u;
                voice.operation[0].envelope_state = 4u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].envelope == 0xfffffff8u);
                assert(voice.operation[0].envelope_state == 4u);
                voice.operation[0].envelope = 0x80000000u;
                voice.operation[0].decay_factor = 0x40000000u;
                voice.operation[0].threshold = 0x80000000u;
                voice.operation[0].envelope_state = 4u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].envelope == 0x80000000u);
                assert(voice.operation[0].envelope_state == 5u);
                voice.operation[0].envelope = 0x40000000u;
                voice.operation[0].decay_factor = 0u;
                voice.operation[0].envelope_state = 4u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].envelope == 0u);
                assert(voice.operation[0].envelope_state == 0u);
                voice.operation[0].envelope = 0x40000000u;
                voice.operation[0].sustain_factor = 0x20000000u;
                voice.operation[0].envelope_state = 5u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].envelope == 0x20000000u);
                assert(voice.operation[0].envelope_state == 5u);
                voice.operation[0].envelope = 1u;
                voice.operation[0].sustain_factor = 0u;
                voice.operation[0].envelope_state = 5u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].envelope == 0u);
                assert(voice.operation[0].envelope_state == 0u);
                voice.operation[0].phase = 123u;
                voice.operation[0].envelope = 0x7fffffffu;
                voice.operation[0].attack_step = 2u;
                voice.operation[0].envelope_state = 6u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].phase == 0u);
                assert(voice.operation[0].envelope == 0x80000000u);
                assert(voice.operation[0].envelope_state == 1u);
                voice.operation[0].phase = 123u;
                voice.operation[0].envelope = 0x10000000u;
                voice.operation[0].attack_step = 1u;
                voice.operation[0].envelope_state = 6u;
                assert(msm5xxx_ma2_fm_render(&voice, &sample, 1u));
                assert(voice.operation[0].phase == 0u);
                assert(voice.operation[0].envelope == 0x10000001u);
                assert(voice.operation[0].envelope_state == 1u);

                for (index = 0u; index < MSM5XXX_MA2_FM_WAVE_SAMPLES;
                     index++) {
                    double angle = 2.0 * acos(-1.0) * (double)index /
                                   MSM5XXX_MA2_FM_WAVE_SAMPLES;
                    int value = (int)(32768.0 * sin(angle) + 0.5);

                    sine[index] = (int16_t)(value > 32767 ? 32767 : value);
                }
                memset(&voice, 0, sizeof(voice));
                voice.algorithm = 5u;
                voice.operator_count = 4u;
                for (operation = 0u; operation < 4u; operation++) {
                    init_operator(&voice.operation[operation], sine,
                                  attack[operation], decay[operation],
                                  sustain[operation], phase_step[operation],
                                  gain[operation]);
                }
                assert(msm5xxx_ma2_fm_render(&voice, samples, 32u));
                assert(memcmp(samples, expected, sizeof(expected)) == 0);
                voice.extended_mode = true;
                assert(!msm5xxx_ma2_fm_render(&voice, samples, 1u));
                voice.extended_mode = false;
                voice.feedback0_enabled = true;
                assert(!msm5xxx_ma2_fm_render(&voice, samples, 1u));
                voice.feedback0_enabled = false;
                voice.feedback2_enabled = true;
                assert(!msm5xxx_ma2_fm_render(&voice, samples, 1u));
                voice.algorithm = 4u;
                assert(msm5xxx_ma2_fm_render(&voice, NULL, 0u));
                voice.operator_count = 2u;
                assert(!msm5xxx_ma2_fm_render(&voice, samples, 1u));
                voice.operator_count = 4u;
                voice.algorithm = 8u;
                assert(!msm5xxx_ma2_fm_render(&voice, samples, 1u));
                voice.algorithm = 4u;
                voice.operation[0].wave = NULL;
                assert(!msm5xxx_ma2_fm_render(&voice, samples, 1u));
                voice.operation[0].output_gain = 0u;
                assert(msm5xxx_ma2_fm_render(&voice, samples, 1u));
                voice.operation[0].output_gain = gain[0];
                voice.operation[0].envelope_state = 0u;
                assert(msm5xxx_ma2_fm_render(&voice, samples, 1u));
                voice.operation[0].wave = sine;
                voice.operation[0].envelope_state = 7u;
                assert(!msm5xxx_ma2_fm_render(&voice, samples, 1u));
                assert(!msm5xxx_ma2_fm_render(NULL, samples, 1u));
                return 0;
            }
            """
        )

        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            harness_path = temporary / "ma2_fm_harness.c"
            binary_path = temporary / "ma2_fm_harness"
            harness_path.write_text(harness, encoding="utf-8")
            compile_command = [
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                f"-I{include_dir}",
                str(core),
                str(harness_path),
                "-lm",
                "-o",
                str(binary_path),
            ]
            subprocess.run(compile_command, check=True, capture_output=True,
                           text=True)
            subprocess.run([str(binary_path)], check=True,
                           capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
