import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


class TestAudioSynthC(unittest.TestCase):
    def test_integer_synth_and_bounded_ring(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "experiments" / "qemu-tcg" / "msm5xxx-audio-synth.c"
        harness = textwrap.dedent(
            r"""
            #include <assert.h>
            #include <stdint.h>
            #include <string.h>

            #include "msm5xxx-audio-synth.h"

            static uint64_t hash_pcm(uint64_t hash, int16_t pcm[][2],
                                     size_t frames)
            {
                const uint8_t *bytes = (const uint8_t *)pcm;
                size_t index;

                for (index = 0; index < frames * 4; index++) {
                    hash ^= bytes[index];
                    hash *= UINT64_C(1099511628211);
                }
                return hash;
            }

            static uint64_t render_sequence(unsigned voices, bool timbre)
            {
                MSM5xxxAudioSynth synth;
                MSM5xxxAudioEvent event = {
                    .kind = MSM5XXX_AUDIO_EVENT_NOTE_ON,
                    .channel = 0, .note = 69, .velocity = 100,
                    .volume = 110, .pan = 32, .expression = 120,
                    .pitch_bend = 64,
                };
                int16_t pcm[MSM5XXX_AUDIO_CHUNK_FRAMES][2];
                uint64_t epoch, sequence, start;
                uint64_t hash = UINT64_C(1469598103934665603);

                if (timbre) {
                    static const uint8_t multiplier[] = {7, 1, 12, 1};
                    static const uint8_t level[] = {24, 0, 36, 5};
                    static const uint32_t attack[] = {
                        0x001b1720, 0x80000000, 0x03609b10, 0x80000000,
                    };
                    static const uint32_t sustain[] = {
                        0x3ffd53b1, 0x3fff6d5a, 0x3ffea9d5, 0x3fff6d5a,
                    };
                    static const uint32_t decay[] = {
                        0x3ff14531, 0x3ffe6bd1, 0x3ff14531, 0x3ffcd7ac,
                    };

                    event.timbre_valid = true;
                    event.timbre_algorithm = 5;
                    event.timbre_operator_count = 4;
                    memcpy(event.timbre_multiplier, multiplier,
                           sizeof(multiplier));
                    memcpy(event.timbre_level, level, sizeof(level));
                    memcpy(event.timbre_attack_step, attack, sizeof(attack));
                    memcpy(event.timbre_decay_factor, decay, sizeof(decay));
                    memcpy(event.timbre_sustain_factor, sustain,
                           sizeof(sustain));
                    memcpy(event.timbre_release_factor, sustain,
                           sizeof(sustain));
                }
                msm5xxx_audio_synth_init(&synth);
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                if (voices == 2) {
                    event.channel = 1;
                    event.note = 76;
                    event.pan = 96;
                    assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                }
                assert(msm5xxx_audio_synth_advance(&synth, 10000000));
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    &epoch, &sequence, &start) ==
                    MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(epoch == 1 && sequence == 1 && start == 0);
                hash = hash_pcm(hash, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES);

                event.kind = MSM5XXX_AUDIO_EVENT_CONTROL;
                event.channel = 0;
                event.note = 69;
                event.volume = 70;
                event.pan = 64;
                event.expression = 80;
                event.pitch_bend = 80;
                assert(msm5xxx_audio_synth_event(
                    &synth, 10000000, &event));
                assert(synth.voice[0].phase_step > synth.voice[0].base_step);
                assert(msm5xxx_audio_synth_advance(&synth, 20000000));
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    NULL, NULL, NULL) == MSM5XXX_AUDIO_CHUNK_FRAMES);
                hash = hash_pcm(hash, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES);

                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_OFF;
                assert(msm5xxx_audio_synth_event(
                    &synth, 20000000, &event));
                assert(synth.voice[0].releasing);
                assert(msm5xxx_audio_synth_advance(&synth, 20000000000));
                assert(!synth.voice[0].active);
                return hash;
            }

            int main(void)
            {
                MSM5xxxAudioSynth synth;
                MSM5xxxAudioSynth stepped;
                MSM5xxxAudioEvent event = {
                    .kind = MSM5XXX_AUDIO_EVENT_NOTE_ON,
                    .channel = 0, .note = 60, .velocity = 100,
                    .volume = 127, .pan = 64, .expression = 127,
                    .pitch_bend = 64,
                };
                int16_t pcm[MSM5XXX_AUDIO_CHUNK_FRAMES][2];
                uint64_t epoch;
                uint64_t sequence;
                uint64_t start;
                uint64_t hash1 = render_sequence(2, false);
                uint64_t hash2 = render_sequence(2, false);
                uint64_t timbre_hash = render_sequence(2, true);

                assert(hash1 == hash2);
                assert(hash1 != render_sequence(1, false));
                assert(timbre_hash == render_sequence(2, true));
                assert(timbre_hash != hash1);

                /* ALG5 keeps one bit of carrier headroom before voice mix. */
                msm5xxx_audio_synth_init(&synth);
                synth.clock_initialized = true;
                synth.voice[0].active = true;
                synth.voice[0].timbre_valid = true;
                synth.voice[0].velocity = 127;
                synth.voice[0].volume = 127;
                synth.voice[0].expression = 127;
                synth.voice[0].pan = 0;
                synth.voice[0].timbre_envelope_state[1] = 5;
                synth.voice[0].timbre_envelope_state[3] = 5;
                synth.voice[0].timbre_envelope[1] = 0x40000000u;
                synth.voice[0].timbre_envelope[3] = 0x40000000u;
                synth.voice[0].timbre_sustain_factor[1] = 0x40000000u;
                synth.voice[0].timbre_sustain_factor[3] = 0x40000000u;
                synth.voice[0].timbre_phase[1] = 0x40000000u;
                synth.voice[0].timbre_phase[3] = 0x40000000u;
                assert(msm5xxx_audio_synth_advance(&synth, 22676));
                assert(synth.ring_count == 1);
                assert(synth.ring[0][0] == 16382 && synth.ring[0][1] == 0);

                /* Independent voices sum before the final S16 clamp. */
                msm5xxx_audio_synth_init(&synth);
                synth.clock_initialized = true;
                synth.voice[0].active = true;
                synth.voice[0].envelope = 32767;
                synth.voice[0].velocity = 127;
                synth.voice[0].volume = 32;
                synth.voice[0].expression = 127;
                synth.voice[0].pan = 0;
                synth.voice[1] = synth.voice[0];
                assert(msm5xxx_audio_synth_advance(&synth, 22676));
                assert(synth.ring_count == 1);
                assert(synth.ring[0][0] == -16512 && synth.ring[0][1] == 0);

                msm5xxx_audio_synth_init(&synth);
                assert(msm5xxx_audio_synth_advance(&synth, 0));
                assert(msm5xxx_audio_synth_advance(&synth, 1000000000));
                assert(synth.ring_count == 0 && synth.overflow_frames == 0);
                assert(synth.generated_frame == 44100 &&
                       synth.ring_start_frame == 44100 &&
                       synth.output_frame == 44100);
                assert(msm5xxx_audio_synth_event(&synth, 1000000000,
                                                 &event));
                assert(msm5xxx_audio_synth_advance(&synth, 1010000000));
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    NULL, NULL, &epoch) == MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(epoch == 44100);
                assert(memcmp(pcm,
                              (int16_t[MSM5XXX_AUDIO_CHUNK_FRAMES][2]){{0}},
                              sizeof(pcm)) != 0);

                msm5xxx_audio_synth_init(&synth);
                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                assert(msm5xxx_audio_synth_advance(&synth, 10000000));
                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_OFF;
                assert(msm5xxx_audio_synth_event(&synth, 10000000, &event));
                assert(msm5xxx_audio_synth_advance(&synth, 30000000));
                assert(!msm5xxx_audio_synth_active(&synth));
                assert(synth.sequence == 0 && synth.ring_count == 1323);
                assert(msm5xxx_audio_synth_advance(&synth, 40000000));
                assert(synth.ring_count == 1764);

                msm5xxx_audio_synth_init(&synth);
                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                assert(msm5xxx_audio_synth_advance(&synth, 10000000));
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    &epoch, &sequence, &start) ==
                    MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(epoch == 1 && sequence == 1 && start == 0);
                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_OFF;
                assert(msm5xxx_audio_synth_event(&synth, 10000000, &event));
                assert(msm5xxx_audio_synth_advance(&synth, 20000000));
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    &epoch, &sequence, &start) ==
                    MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(epoch == 1 && sequence == 2 && start == 441);
                assert(msm5xxx_audio_synth_advance(&synth, 30000000));
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    &epoch, &sequence, &start) ==
                    MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(epoch == 1 && sequence == 3 && start == 882);
                assert(!msm5xxx_audio_synth_active(&synth));
                assert(msm5xxx_audio_synth_advance(&synth, 40000000));
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    &epoch, &sequence, &start) ==
                    MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(epoch == 1 && sequence == 4 && start == 1323);
                assert(memcmp(pcm,
                              (int16_t[MSM5XXX_AUDIO_CHUNK_FRAMES][2]){{0}},
                              sizeof(pcm)) == 0);

                memset(&event, 0, sizeof(event));
                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
                event.note = 69;
                event.velocity = event.volume = event.expression = 127;
                event.pan = event.pitch_bend = 64;
                event.timbre_valid = true;
                event.timbre_algorithm = 5;
                event.timbre_operator_count = 4;
                for (unsigned operation = 0; operation < 4; operation++) {
                    event.timbre_multiplier[operation] = 1;
                    event.timbre_attack_step[operation] = 0x80000000u;
                    event.timbre_decay_factor[operation] = 0x20000000u;
                    event.timbre_sustain_factor[operation] = 0x40000000u;
                    event.timbre_release_factor[operation] = 0x20000000u;
                }
                msm5xxx_audio_synth_init(&synth);
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                assert(msm5xxx_audio_synth_advance(&synth, 22676));
                assert(synth.voice[0].timbre_envelope_state[0] == 3 &&
                       synth.voice[0].timbre_envelope[0] == 0);
                assert(msm5xxx_audio_synth_advance(&synth, 45352));
                assert(synth.voice[0].timbre_envelope_state[0] == 4 &&
                       synth.voice[0].timbre_envelope[0] == 0x80000000u);
                assert(msm5xxx_audio_synth_advance(&synth, 68028));
                assert(synth.voice[0].timbre_envelope_state[0] == 5 &&
                       synth.voice[0].timbre_envelope[0] == 0x40000000u);
                stepped = synth;
                assert(msm5xxx_audio_synth_advance(&synth, 1000068028));
                for (unsigned chunk = 1; chunk <= 100; chunk++) {
                    assert(msm5xxx_audio_synth_advance(
                        &stepped, 68028 + (uint64_t)chunk * 10000000));
                }
                assert(memcmp(&synth.voice[0], &stepped.voice[0],
                              sizeof(synth.voice[0])) == 0);

                for (unsigned operation = 0; operation < 4; operation++) {
                    event.timbre_attack_step[operation] = 0;
                }
                msm5xxx_audio_synth_init(&synth);
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                assert(msm5xxx_audio_synth_advance(&synth, 22676));
                assert(!msm5xxx_audio_synth_active(&synth));
                assert(synth.ring_count == 1);
                assert(synth.ring[synth.ring_read][0] == 0 &&
                       synth.ring[synth.ring_read][1] == 0);

                msm5xxx_audio_synth_init(&synth);
                memset(&event, 0, sizeof(event));
                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
                event.channel = 0;
                event.note = 60;
                event.velocity = 100;
                event.volume = 127;
                event.pan = 64;
                event.expression = 127;
                event.pitch_bend = 64;
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                event.note = 64;
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                assert(synth.voice[0].active && synth.voice[0].note == 60);
                assert(synth.voice[1].active && synth.voice[1].note == 64);
                event.kind = MSM5XXX_AUDIO_EVENT_CONTROL;
                event.volume = 63;
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                assert(synth.voice[0].volume == 63);
                assert(synth.voice[1].volume == 63);
                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_OFF;
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                assert(!synth.voice[0].releasing);
                assert(synth.voice[1].releasing);

                msm5xxx_audio_synth_init(&synth);
                event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
                event.note = 60;
                event.volume = 127;
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    NULL, NULL, NULL) == MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(synth.underflow_frames == MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(memcmp(pcm, (int16_t[MSM5XXX_AUDIO_CHUNK_FRAMES][2]){{0}},
                              sizeof(pcm)) == 0);
                assert(synth.ring_start_frame == synth.output_frame);
                assert(msm5xxx_audio_synth_event(&synth, 10000000, &event));
                assert(msm5xxx_audio_synth_clamp_event_timestamp(
                    &synth, 8000000) == 10000000);
                assert(synth.late_events == 1 &&
                       synth.collapsed_events == 0 &&
                       synth.max_lateness_ns == 2000000);
                assert(msm5xxx_audio_synth_clamp_event_timestamp(
                    &synth, 9000000) == 10000000);
                assert(synth.late_events == 2 &&
                       synth.collapsed_events == 1);
                assert(msm5xxx_audio_synth_clamp_event_timestamp(
                    &synth, 9000000) == 10000000);
                assert(synth.collapsed_events == 1);
                assert(msm5xxx_audio_synth_advance(&synth, 20000000));
                assert(msm5xxx_audio_synth_read(
                    &synth, pcm, MSM5XXX_AUDIO_CHUNK_FRAMES,
                    NULL, NULL, NULL) == MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(memcmp(pcm,
                              (int16_t[MSM5XXX_AUDIO_CHUNK_FRAMES][2]){{0}},
                              sizeof(pcm)) != 0);

                msm5xxx_audio_synth_reset(&synth);
                assert(synth.epoch == 2 && synth.sequence == 0);
                assert(synth.underflow_frames == 0 && synth.ring_count == 0);
                assert(synth.late_events == 0 && synth.collapsed_events == 0 &&
                       synth.max_lateness_ns == 0);
                assert(msm5xxx_audio_synth_event(&synth, 0, &event));
                assert(msm5xxx_audio_synth_advance(&synth, 1000000000));
                assert(synth.ring_count == MSM5XXX_AUDIO_TARGET_FRAMES);
                assert(synth.overflow_frames == 40572);
                epoch = synth.epoch;
                for (unsigned chunk = 1; chunk <= 17; chunk++) {
                    assert(msm5xxx_audio_synth_advance(
                        &synth, 1000000000 +
                                (uint64_t)chunk * 10000000));
                    assert(synth.epoch == epoch);
                }
                assert(synth.ring_count == MSM5XXX_AUDIO_MAX_FRAMES);
                assert(msm5xxx_audio_synth_advance(&synth, 1180000000));
                assert(synth.ring_count == MSM5XXX_AUDIO_TARGET_FRAMES);
                assert(synth.epoch == epoch + 1);
                assert(synth.overflow_frames == 48510);
                epoch = synth.epoch;
                assert(msm5xxx_audio_synth_advance(&synth, 1190000000));
                assert(synth.ring_count == MSM5XXX_AUDIO_TARGET_FRAMES +
                                           MSM5XXX_AUDIO_CHUNK_FRAMES);
                assert(synth.epoch == epoch);
                return 0;
            }
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test.c"
            binary = Path(directory) / "test"
            source.write_text(harness, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-I", str(core.parent), str(source), str(core),
                 "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
