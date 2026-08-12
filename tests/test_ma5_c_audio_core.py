import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


class TestMA5CAudioCore(unittest.TestCase):
    def test_qemu_keeps_unowned_ma5_native(self):
        repo = Path(__file__).resolve().parents[1]
        machine = (repo / "experiments" / "qemu-tcg" /
                   "msm5xxx-poc.c").read_text(encoding="utf-8")
        setter = machine[
            machine.index("static void msm5xxx_poc_set_audio_aperture"):
        ]
        setter = setter[:setter.index("\nstatic ", 1)]
        launcher = (repo / "experiments" / "qemu-tcg" /
                    "qemu_transport.py").read_text(encoding="utf-8")
        self.assertNotIn("msm5xxx_ma5_data_write", machine)
        self.assertNotIn("ma5", setter)
        self.assertNotIn('audio_family == "ma5"', launcher)
        self.assertIn('family != "ma2"', launcher)

    def test_transport_contract(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "experiments" / "qemu-tcg" / "msm5xxx-ma5-audio.c"
        include_dir = core.parent
        harness = textwrap.dedent(
            r"""
            #include <assert.h>
            #include <stdint.h>

            #include "msm5xxx-ma5-audio.h"

            static MSM5xxxMA5Event feed(MSM5xxxMA5Audio *audio,
                                        uint8_t value)
            {
                MSM5xxxMA5Event event;
                assert(msm5xxx_ma5_data_write(audio, value, true, &event));
                return event;
            }

            int main(void)
            {
                MSM5xxxMA5Audio audio;
                MSM5xxxMA5Event event;
                uint8_t value;

                msm5xxx_ma5_reset(&audio);
                assert(msm5xxx_ma5_index_write(&audio, 1u));
                assert(feed(&audio, 0x80u).kind == MSM5XXX_MA5_EVENT_NONE);
                event = feed(&audio, 0x83u);
                assert(event.kind == MSM5XXX_MA5_EVENT_REGISTER_PACKET);
                assert(event.delay == 0u && event.address == 3u);
                event = feed(&audio, 0xc0u);
                assert(event.kind == MSM5XXX_MA5_EVENT_REGISTER_WRITE);
                assert(event.address == 3u && event.value == 0x40u);
                assert(event.terminal);
                assert(msm5xxx_ma5_shadow_read(&audio, 3u, &value));
                assert(value == 0x40u);
                assert(audio.fifo_state == MSM5XXX_MA5_DELAY_0);

                msm5xxx_ma5_reset(&audio);
                assert(msm5xxx_ma5_index_write(&audio, 1u));
                feed(&audio, 0x80u);
                event = feed(&audio, 0x83u);
                assert(event.kind == MSM5XXX_MA5_EVENT_REGISTER_PACKET);
                assert(audio.fifo_state == MSM5XXX_MA5_REGISTER_DATA);
                assert(msm5xxx_ma5_shadow_read(&audio, 3u, &value));
                assert(value == 0u);
                event = feed(&audio, 0xc0u);
                assert(event.kind == MSM5XXX_MA5_EVENT_REGISTER_WRITE);

                msm5xxx_ma5_reset(&audio);
                assert(msm5xxx_ma5_index_write(&audio, 1u));
                feed(&audio, 0x00u);
                feed(&audio, 0x81u);
                feed(&audio, 0x03u);
                event = feed(&audio, 0x80u);
                assert(event.kind == MSM5XXX_MA5_EVENT_REGISTER_PACKET);
                assert(event.delay == 128u && event.address == 3u);
                event = feed(&audio, 0xc0u);
                assert(event.kind == MSM5XXX_MA5_EVENT_REGISTER_WRITE);

                msm5xxx_ma5_reset(&audio);
                assert(msm5xxx_ma5_index_write(&audio, 1u));
                feed(&audio, 0x80u);
                feed(&audio, 0x23u);
                feed(&audio, 0x02u);
                feed(&audio, 0x00u);
                event = feed(&audio, 0x82u);
                assert(event.kind == MSM5XXX_MA5_EVENT_VOICE_PACKET);
                assert(event.address == 0x123u && event.count == 2u);
                event = feed(&audio, 0xaau);
                assert(event.kind == MSM5XXX_MA5_EVENT_VOICE_WRITE);
                assert(event.address == 0x123u && event.value == 0xaau);
                event = feed(&audio, 0xbbu);
                assert(event.kind == MSM5XXX_MA5_EVENT_VOICE_WRITE);
                assert(event.address == 0x124u && event.value == 0xbbu);
                assert(audio.fifo_state == MSM5XXX_MA5_DELAY_0);

                msm5xxx_ma5_reset(&audio);
                assert(msm5xxx_ma5_index_write(&audio, 1u));
                feed(&audio, 0x80u);
                feed(&audio, 0x33u);
                feed(&audio, 0x84u);
                event = feed(&audio, 0x80u);
                assert(event.kind == MSM5XXX_MA5_EVENT_REGISTER_WRITE);
                assert(event.address == 0x233u);
                assert(msm5xxx_ma5_shadow_read(&audio, 0x233u, &value));
                assert(value == 0u);

                msm5xxx_ma5_reset(&audio);
                assert(msm5xxx_ma5_index_write(&audio, 1u));
                feed(&audio, 0x80u);
                feed(&audio, 0x34u);
                feed(&audio, 0x84u);
                event = feed(&audio, 0x80u);
                assert(event.kind == MSM5XXX_MA5_EVENT_REGISTER_WRITE);
                assert(event.address == 0x234u);
                assert(!msm5xxx_ma5_shadow_read(&audio, 0x234u, &value));

                msm5xxx_ma5_reset(&audio);
                assert(msm5xxx_ma5_index_write(&audio, 1u));
                assert(msm5xxx_ma5_data_write(
                    &audio, 0x80u, false, &event));
                assert(event.kind == MSM5XXX_MA5_EVENT_IMMEDIATE_WRITE);
                assert(audio.fifo_state == MSM5XXX_MA5_DELAY_0);
                assert(msm5xxx_ma5_index_write(&audio, 2u));
                assert(msm5xxx_ma5_data_write(
                    &audio, 0x80u, true, &event));
                assert(event.kind == MSM5XXX_MA5_EVENT_IMMEDIATE_WRITE);
                assert(audio.fifo_state == MSM5XXX_MA5_DELAY_0);
                return 0;
            }
            """
        )

        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            harness_path = temporary / "ma5_harness.c"
            binary_path = temporary / "ma5_harness"
            harness_path.write_text(harness, encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-pedantic", f"-I{include_dir}", str(core),
                str(harness_path), "-o", str(binary_path),
            ], check=True, capture_output=True, text=True)
            subprocess.run([str(binary_path)], check=True,
                           capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
