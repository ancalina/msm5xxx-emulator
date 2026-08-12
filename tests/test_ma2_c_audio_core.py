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
        self.assertIn("MSM5XXX_MA2_FM_CHANNEL_ASSIGN", read)
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
        self.assertIn("MSM5XXX_POC_AUDIO_STATUS_REJECTED", tick)
        self.assertNotIn("qemu_set_irq", tick)
        setter = source[source.index("static void msm5xxx_poc_set_audio_aperture"):]
        setter = setter[:setter.index("\nstatic ", 1)]
        self.assertIn("data_offset != 2", setter)
        self.assertIn('object_class_property_add_str(oc, "audio-sites"',
                      source)

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
                    0x80u, 0x00u, 0x01u, 0x81u, 0x00u,
                };
                static const uint8_t invalid_wide[] = {0x80u, 0x80u};
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
                    0x43u, 0x03u, 0x01u, 0x01u, 0x0au, 0x45u, 0x01u,
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
                    0x00u, 0x1cu, 0x02u,
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

                /* Handy two-byte values are not MIDI VLQ. */
                msm5xxx_ma2_compact_parser_reset(&parser);
                for (i = 0u; i < sizeof(wide_values); ++i) {
                    result = msm5xxx_ma2_compact_parser_feed(
                        &parser, wide_values[i], &event);
                }
                assert(result == MSM5XXX_MA2_COMPACT_EVENT);
                assert(event.kind == MSM5XXX_MA2_COMPACT_NOTE);
                assert(event.delta_ticks == 128u);
                assert(event.gate_ticks == 256u);

                /* Undefined high-bit second bytes fail closed. */
                msm5xxx_ma2_compact_parser_reset(&parser);
                result = msm5xxx_ma2_compact_parser_feed(
                    &parser, invalid_wide[0], &event);
                assert(result == MSM5XXX_MA2_COMPACT_NEED_MORE);
                result = msm5xxx_ma2_compact_parser_feed(
                    &parser, invalid_wide[1], &event);
                assert(result == MSM5XXX_MA2_COMPACT_ERROR);
                assert(parser.rejected);

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
                assert(audio.fm_voice[1].valid);
                assert(audio.fm_voice[1].bank == 1u);
                assert(audio.fm_voice[1].program == 0x0au);
                assert(audio.fm_voice[1].info == 0x45u);
                assert(audio.fm_voice[1].basic_octave == 1u);
                assert(audio.fm_voice[1].operator_count == 4u);
                assert(audio.fm_voice[1].operation[0].data[0] == 0x71u);
                assert(audio.fm_voice[1].operation[0].data[4] == 0xa0u);
                assert(memcmp(audio.fm_voice[1].decoded, decoded_voice,
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
                assert(audio.fm_channel[0].key_on);
                assert(audio.fm_channel[0].note_octave == 1u);
                assert(audio.fm_channel[0].note_id == 12u);
                assert(audio.fm_channel[0].active_voice_slot == 1u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_END);
                assert(msm5xxx_ma2_scheduler_step(&audio, 2000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_GATE_OFF);
                assert(!audio.fm_channel[0].key_on);
                assert(audio.fm_state_unhandled == 0u);

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

                /* A later-stream parse error rolls back earlier FM staging. */
                {
                    MSM5xxxMA2SequenceState before_fm0;
                    MSM5xxxMA2SequenceState before_fm1;
                    size_t before_fm0_count;
                    size_t before_fm1_count;
                    uint64_t before_now;
                    bool before_clock_initialized;

                    msm5xxx_ma2_reset(&audio);
                    enable_voice(&audio, 0u, 0u);
                    write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                                 max_deadline_fm, sizeof(max_deadline_fm));
                    write_stream(&audio, MSM5XXX_MA2_FM_DATA1,
                                 invalid_wide, sizeof(invalid_wide));
                    write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                                   MSM5XXX_MA2_CONTROL,
                                   MSM5XXX_MA2_FM_START);
                    before_fm0 = audio.sequence[0];
                    before_fm1 = audio.sequence[1];
                    before_fm0_count = msm5xxx_ma2_fifo_occupancy(
                        &audio, MSM5XXX_MA2_FIFO_FM0);
                    before_fm1_count = msm5xxx_ma2_fifo_occupancy(
                        &audio, MSM5XXX_MA2_FIFO_FM1);
                    before_now = audio.scheduler_now_ns;
                    before_clock_initialized = audio.scheduler_clock_initialized;
                    assert(!msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                    assert(msm5xxx_ma2_rejected(&audio));
                    assert(msm5xxx_ma2_reject_reason(&audio) ==
                           MSM5XXX_MA2_REJECT_INVALID_ENCODING);
                    assert(msm5xxx_ma2_fifo_occupancy(
                        &audio, MSM5XXX_MA2_FIFO_FM0) == before_fm0_count);
                    assert(msm5xxx_ma2_fifo_occupancy(
                        &audio, MSM5XXX_MA2_FIFO_FM1) == before_fm1_count);
                    assert(memcmp(&audio.sequence[0], &before_fm0,
                                  sizeof(before_fm0)) == 0);
                    assert(memcmp(&audio.sequence[1], &before_fm1,
                                  sizeof(before_fm1)) == 0);
                    assert(audio.scheduler_now_ns == before_now);
                    assert(audio.scheduler_clock_initialized ==
                           before_clock_initialized);
                    assert(output.kind == MSM5XXX_MA2_OUTPUT_NONE);
                }

                /* Undefined assignments never key on or arm phantom gates. */
                msm5xxx_ma2_reset(&audio);
                write_stream(&audio, MSM5XXX_MA2_FM_DATA0,
                             unresolved_fm, sizeof(unresolved_fm));
                write_register(&audio, MSM5XXX_MA2_PAGE_REG1,
                               MSM5XXX_MA2_CONTROL, MSM5XXX_MA2_FM_START);
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(msm5xxx_ma2_scheduler_step(&audio, 0u, &output));
                assert(output.event.kind == MSM5XXX_MA2_COMPACT_NOTE);
                assert(!audio.fm_channel[0].key_on);
                assert(!audio.fm_gate[0].active);
                assert(audio.fm_state_unhandled == 1u);

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
                assert(msm5xxx_ma2_scheduler_step(&audio, 3000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_EVENT);
                assert(output.timestamp_ns == 3000000u);
                assert(output.event.note_id == 2u);
                assert(msm5xxx_ma2_scheduler_step(&audio, 3000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_END);
                assert(output.stream == MSM5XXX_MA2_FIFO_FM0);
                assert(msm5xxx_ma2_scheduler_step(&audio, 4000000u, &output));
                assert(output.kind == MSM5XXX_MA2_OUTPUT_GATE_OFF);
                assert(output.channel == 0u);

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


if __name__ == "__main__":
    unittest.main()
