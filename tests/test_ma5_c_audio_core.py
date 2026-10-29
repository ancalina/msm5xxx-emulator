import subprocess
import os
import tempfile
import textwrap
import unittest
from pathlib import Path


class TestMA5CAudioCore(unittest.TestCase):
    def test_qemu_maps_only_site_owned_ma5_boot_writes(self):
        repo = Path(__file__).resolve().parents[1]
        machine = (repo / "native" / "qemu" /
                   "msm5xxx-poc.c").read_text(encoding="utf-8")
        launcher = (repo / "src/msm5xxx_emulator/qemu/transport.py").read_text(encoding="utf-8")
        self.assertNotIn("msm5xxx_ma5_data_write", machine)
        self.assertIn("msm5xxx_poc_audio_opaque_write", machine)
        self.assertIn("msm5xxx_poc_audio_site_owned", machine)
        self.assertIn(".read_with_attrs = msm5xxx_poc_audio_opaque_read",
                      machine)
        self.assertIn("return MEMTX_ERROR;", machine)
        self.assertIn('audio_family == "ma5"', launcher)
        self.assertIn('(\"ma5\", \"indexed-rw-v1\")', launcher)
        self.assertIn('"aperture_write_sites"', launcher)
        self.assertIn('"qemu-audio-adapter-unsupported"', launcher)
        self.assertIn('source=%s', machine)
        self.assertIn('read_control_guest_written', machine)
        self.assertIn('"unwritten-backing"', machine)
        self.assertIn("s->audio_base != 0x02840000", machine)
        self.assertIn("experimental-ma5-byte-ns requires MA5 byte", machine)
        self.assertIn("msm5xxx_ma5_device_read", machine)
        self.assertIn("data_offset == 2", machine)

    def test_readback_backing_contract(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native/qemu/msm5xxx-ma5-audio.c"
        harness = r"""
        #include <assert.h>
        #include <stdint.h>
        #include "msm5xxx-ma5-audio.h"
        static void address(MSM5xxxMA5Readback *a, unsigned port,
                            unsigned value, unsigned width) {
            for (unsigned i = 0; i < width; i++) {
                unsigned byte = (value >> (7 * i)) & 127;
                assert(msm5xxx_ma5_readback_consume(
                    a, port, byte | (i + 1 == width ? 128 : 0)));
            }
        }
        static uint8_t read_c(MSM5xxxMA5Readback *a, unsigned reg) {
            uint8_t value;
            address(a, 3, reg, 2);
            assert(msm5xxx_ma5_readback_consume(a, 3, 128));
            assert(msm5xxx_ma5_readback_index(a, 129));
            assert(msm5xxx_ma5_readback_data(a, &value));
            return value;
        }
        int main(void) {
            MSM5xxxMA5Readback a;
            uint8_t value;
            msm5xxx_ma5_readback_init(&a);
            assert(read_c(&a, 192) == 0x60);
            assert(a.read_address == 192 && !a.read_from_sram);
            assert(!a.read_control_guest_written);
            assert(read_c(&a, 223) == 0x3c);
            assert(a.read_address == 223 && !a.read_control_guest_written);
            assert(a.irq_enabled && msm5xxx_ma5_readback_status(&a) == 64);
            assert(msm5xxx_ma5_readback_index(&a, 0x41));
            assert(!a.irq_enabled && !msm5xxx_ma5_readback_status(&a));
            assert(msm5xxx_ma5_readback_data(&a, &value) && value == 0x3c);
            address(&a, 2, 192, 2);
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0xd5));
            assert(a.control_write_valid && a.control_write_raw == 0xd5);
            assert(read_c(&a, 192) == 0x55);
            assert(a.read_control_guest_written);
            /* Independent cursors survive index switches and read requests. */
            address(&a, 2, 0x4000, 3);
            assert(read_c(&a, 192) == 0x55);
            assert(!msm5xxx_ma5_readback_consume(&a, 1, 0xff));
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0x84));
            const uint8_t raw[] = {0, 127, 128, 255};
            for (unsigned i = 0; i < 4; i++) {
                assert(msm5xxx_ma5_readback_consume(&a, 2, raw[i]));
                address(&a, 3, 0x4000 + i, 3);
                assert(msm5xxx_ma5_readback_consume(&a, 3, 0x80));
                assert(msm5xxx_ma5_readback_data(&a, &value));
                assert(value == raw[i]);
                assert(a.read_from_sram && a.read_address == 0x4000 + i);
                assert(!a.read_control_guest_written);
            }
            assert(msm5xxx_ma5_readback_index(&a, 0x41));
            address(&a, 3, 0, 3); /* ROM address zero is not C0. */
            assert(!msm5xxx_ma5_readback_consume(&a, 3, 0x80));
            assert(!msm5xxx_ma5_readback_status(&a));
            assert(msm5xxx_ma5_readback_data(&a, &value) && value == 255);
            address(&a, 2, 0, 3);
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0x81));
            assert(msm5xxx_ma5_readback_consume(&a, 2, 255));
            assert(a.control[0] == 0 && a.sram[0] == 0);
            assert(a.control_writes == 1 && a.sram_writes == 4);
            address(&a, 2, 563, 2);
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0xfe));
            assert(read_c(&a, 563) == 126);
            address(&a, 2, 564, 2);
            assert(!msm5xxx_ma5_readback_consume(&a, 2, 0xff));
            address(&a, 2, 0x5fff, 3);
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0x81));
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0xab));
            address(&a, 2, 0x5fff, 3);
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0x82));
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0xff));
            assert(!msm5xxx_ma5_readback_consume(&a, 2, 0xff));
            assert(a.sram[8191] == 0xff);
            for (unsigned i = 0; i < 2; i++)
                assert(msm5xxx_ma5_readback_consume(&a, 2, 0));
            assert(!msm5xxx_ma5_readback_consume(&a, 2, 0));
            address(&a, 2, 0x4000, 3);
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0));
            assert(!msm5xxx_ma5_readback_consume(&a, 2, 0));
            address(&a, 2, 0x4000, 3);
            assert(!msm5xxx_ma5_readback_consume(&a, 2, 0x80));
            address(&a, 2, 192, 2);
            assert(msm5xxx_ma5_readback_consume(&a, 2, 0x81));
            assert(read_c(&a, 192) == 1);
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "readback.c"
            binary = Path(temporary) / "readback"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core.parent}", str(core), str(source), "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_experimental_timed_device_contract(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native/qemu/msm5xxx-ma5-audio.c"
        harness = r"""
        #include <assert.h>
        #include <stdint.h>
        #include "msm5xxx-ma5-audio.h"
        static void reg(MSM5xxxMA5Device *d, uint8_t b, uint8_t value) {
            assert(msm5xxx_ma5_device_write(d, true, b, 0));
            assert(msm5xxx_ma5_device_write(d, false, value, 0));
        }
        int main(void) {
            MSM5xxxMA5Device d;
            uint8_t value;
            assert(msm5xxx_ma5_device_init(&d, 10));
            reg(&d, 30, 0x95); reg(&d, 31, 0x51);
            reg(&d, 5, 8); reg(&d, 6, 0x3e);
            reg(&d, 4, 0x80);
            assert(msm5xxx_ma5_device_read(&d, true, &value, 0) && value == 0x83);
            reg(&d, 4, 0);
            assert(d.resets == 1 && d.b[30] == 0x95 && d.b[31] == 0x51);
            assert(d.b[5] == 8 && d.b[6] == 0x3e);
            assert(msm5xxx_ma5_device_write(&d, true, 2, 0));
            assert(msm5xxx_ma5_device_write(&d, false, 0x40, 0));
            assert(msm5xxx_ma5_device_write(&d, false, 0x81, 0));
            assert(msm5xxx_ma5_device_write(&d, false, 0xd5, 0));
            assert(msm5xxx_ma5_device_write(&d, true, 3, 0));
            assert(msm5xxx_ma5_device_write(&d, false, 0x40, 0));
            assert(msm5xxx_ma5_device_write(&d, false, 0x81, 0));
            assert(msm5xxx_ma5_device_write(&d, false, 0x80, 0));
            assert(msm5xxx_ma5_device_read(&d, true, &value, 0) && value == 2);
            assert(msm5xxx_ma5_device_read(&d, true, &value, 59) && value == 2);
            assert(!d.backing.read_valid && d.count == 1);
            assert(msm5xxx_ma5_device_read(&d, true, &value, 60) && value == 0x43);
            assert(d.reads == 1 && d.consumed == 6 && d.max_count == 6);
            assert(msm5xxx_ma5_device_write(&d, true, 0x41, 60));
            assert(msm5xxx_ma5_device_read(&d, false, &value, 60) && value == 0x55);
            assert(!d.backing.read_valid);
            reg(&d, 38, 2);
            for (unsigned b = 32; b <= 34; b++) {
                assert(msm5xxx_ma5_device_write(&d, true, b, 60));
                assert(msm5xxx_ma5_device_read(&d, false, &value, 60) && value == 0);
            }
            assert(d.backing.control[192] == 0x55 && d.control_dirty);
            assert(msm5xxx_ma5_device_write(&d, true, 4, 60));
            assert(!msm5xxx_ma5_device_write(&d, false, 0x80, 60));
            assert(d.reject == MSM5XXX_MA5_REJECT_RESET_RETENTION);

            assert(msm5xxx_ma5_device_init(&d, 10));
            assert(msm5xxx_ma5_device_write(&d, true, 2, 0));
            for (unsigned i = 0; i < 64; i++)
                assert(msm5xxx_ma5_device_write(&d, false, 0, 0));
            assert(msm5xxx_ma5_device_read(&d, true, &value, 0) && value == 6);
            assert(!msm5xxx_ma5_device_write(&d, false, 0, 0));
            assert(d.count == 64 && d.reject == MSM5XXX_MA5_REJECT_FIFO_OVERFLOW);

            assert(msm5xxx_ma5_device_init(&d, 10));
            reg(&d, 55, 0); reg(&d, 17, 0x80);
            assert(!msm5xxx_ma5_device_irq(&d));
            assert(msm5xxx_ma5_device_write(&d, true, 0x80, 0));
            assert(msm5xxx_ma5_device_irq(&d));
            assert(msm5xxx_ma5_device_write(&d, false, 0x80, 0));
            assert(msm5xxx_ma5_device_irq(&d)); /* Level cause survives ACK. */
            reg(&d, 55, 2);
            assert(msm5xxx_ma5_device_write(&d, true, 0x80, 0));
            assert(msm5xxx_ma5_device_write(&d, false, 0x80, 0));
            assert(!msm5xxx_ma5_device_irq(&d));
            reg(&d, 17, 0);
            assert(msm5xxx_ma5_device_read(&d, false, &value, 0) && value == 0);
            assert(msm5xxx_ma5_device_write(&d, true, 1, 0));
            assert(!msm5xxx_ma5_device_write(&d, false, 0, 0));
            assert(d.reject == MSM5XXX_MA5_REJECT_DELAYED);

            assert(msm5xxx_ma5_device_init(&d, 10));
            for (unsigned i = 0; i < 300; i++) {
                uint64_t now = i * 20;
                assert(msm5xxx_ma5_device_write(&d, true, 2, now));
                assert(msm5xxx_ma5_device_write(&d, false, 0x80, now));
                assert(msm5xxx_ma5_device_write(&d, false, 0x81, now));
                msm5xxx_ma5_device_advance(&d, now + 20);
                assert(d.count == 0 && d.backing.control[0] == 1);
            }
            assert(msm5xxx_ma5_device_init(&d, 10));
            assert(msm5xxx_ma5_device_write(&d, true, 2, UINT64_MAX));
            assert(!msm5xxx_ma5_device_write(&d, false, 0x80, UINT64_MAX));
            assert(d.reject == MSM5XXX_MA5_REJECT_CLOCK);
            for (unsigned bit = 8; bit <= 64; bit <<= 1) {
                assert(msm5xxx_ma5_device_init(&d, 10));
                assert(msm5xxx_ma5_device_write(&d, true, 4, 0));
                assert(!msm5xxx_ma5_device_write(&d, false, bit, 0));
                assert(d.reject == MSM5XXX_MA5_REJECT_RESET_RETENTION);
            }
            /* A partial packet cannot survive an unmodeled reset silently. */
            assert(msm5xxx_ma5_device_init(&d, 10));
            assert(msm5xxx_ma5_device_write(&d, true, 2, 0));
            assert(msm5xxx_ma5_device_write(&d, false, 0x40, 0));
            msm5xxx_ma5_device_advance(&d, 10);
            assert(msm5xxx_ma5_device_write(&d, true, 4, 10));
            assert(!msm5xxx_ma5_device_write(&d, false, 0x80, 10));
            assert(d.reject == MSM5XXX_MA5_REJECT_RESET_RETENTION);
            assert(msm5xxx_ma5_device_init(&d, 10));
            assert(msm5xxx_ma5_device_write(&d, true, 38, 0));
            assert(!msm5xxx_ma5_device_write(&d, false, 3, 0));
            assert(d.reject == MSM5XXX_MA5_REJECT_START && !d.counter_reset);
            assert(msm5xxx_ma5_device_init(&d, 10));
            reg(&d, 38, 2);
            reg(&d, 4, 0x80); reg(&d, 4, 0);
            assert(msm5xxx_ma5_device_write(&d, true, 32, 0));
            assert(!msm5xxx_ma5_device_read(&d, false, &value, 0));
            assert(d.reject == MSM5XXX_MA5_REJECT_DYNAMIC_READ);
            assert(!msm5xxx_ma5_device_init(&d, 0));
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "device.c"
            binary = Path(temporary) / "device"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core.parent}", str(core), str(source), "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_explicit_clock_counter_and_snapshot(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native" / "qemu" / "msm5xxx-ma5-audio.c"
        harness = r"""
        #include <assert.h>
        #include <stdint.h>
        #include "msm5xxx-ma5-audio.h"
        static bool wr(MSM5xxxMA5Device *d, unsigned b, unsigned v, uint64_t t) {
            return msm5xxx_ma5_device_write(d, true, b, t) &&
                   msm5xxx_ma5_device_write(d, false, v, t);
        }
        static uint8_t rd(MSM5xxxMA5Device *d, unsigned b, uint64_t t) {
            uint8_t v;
            assert(msm5xxx_ma5_device_write(d, true, b, t));
            assert(msm5xxx_ma5_device_read(d, false, &v, t));
            return v;
        }
        static void prepared(MSM5xxxMA5Device *d, uint64_t hz, unsigned ms) {
            assert(msm5xxx_ma5_device_init(d, 10));
            assert(msm5xxx_ma5_device_set_clock(d, hz));
            assert(wr(d, 30, 0x14, 0) && wr(d, 31, 0x4b, 0));
            assert(wr(d, 35, ms >> 6, 0) && wr(d, 36, (ms & 63) << 2, 0));
            assert(wr(d, 38, 2, 0));
        }
        static uint64_t due(unsigned ticks) {
            /* CLKI19660800, known PLL20/75, MS_S1. */
            return ((uint64_t)ticks * UINT64_C(1600000000000) +
                    UINT64_C(1474560000) - 1) / UINT64_C(1474560000);
        }
        int main(void) {
            MSM5xxxMA5Device a, b;
            uint64_t phase;
            prepared(&a, 19660800, 922);
            assert(wr(&a, 35, 1, 0) && a.ms_s == 922);
            assert(wr(&a, 36, 0, 0) && a.ms_s == 64);
            prepared(&a, 19660800, 922);
            assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 1000000);
            assert(a.counter == 0);
            msm5xxx_ma5_device_advance(&a, 1000435);
            assert(a.counter == 1 && !a.count); /* Explicit empty-FIFO policy. */
            phase = a.counter_phase;
            assert(rd(&a, 32, 1000435) == 0 && rd(&a, 33, 1000435) == 0 &&
                   rd(&a, 34, 1000435) == 1);
            assert(a.counter_phase == phase && a.counter == 1);
            prepared(&a, 19660800, 922); prepared(&b, 19660800, 922);
            assert(wr(&a, 38, 1, 0) && wr(&b, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 9999999);
            for (uint64_t t = 1; t < 9999999; t += 997)
                msm5xxx_ma5_device_advance(&b, t);
            msm5xxx_ma5_device_advance(&b, 9999999);
            assert(a.counter == b.counter && a.counter_phase == b.counter_phase);
            prepared(&a, 19660800, 1); assert(wr(&a, 38, 1, 0));
            assert(rd(&a, 32, due(255)) == 0);
            assert(rd(&a, 33, due(257)) == 0 && rd(&a, 34, due(258)) == 255);
            assert(rd(&a, 32, due(258)) == 0 && rd(&a, 33, due(258)) == 1 &&
                   rd(&a, 34, due(258)) == 2);
            msm5xxx_ma5_device_advance(&a, due(0x200000));
            assert(a.counter == 0);
            prepared(&a, 1000000000, 1); prepared(&b, 1000000000, 1);
            assert(wr(&a, 38, 1, 0) && wr(&b, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, UINT64_MAX);
            msm5xxx_ma5_device_advance(&b, UINT64_MAX / 2);
            msm5xxx_ma5_device_advance(&b, UINT64_MAX);
            assert(a.counter == 0x1fffff && a.counter == b.counter &&
                   a.counter_phase == b.counter_phase);
            prepared(&a, 19660800, 0); assert(wr(&a, 38, 1, 0));
            assert(a.counter_den == UINT64_C(1600000000000) * 16384);
            prepared(&a, 19200000, 922);
            assert(wr(&a, 30, 0x95, 0) && wr(&a, 31, 0x51, 0));
            assert(wr(&a, 38, 1, 0));
            assert(a.counter_num == UINT64_C(19200000) * 81 &&
                   a.counter_den == UINT64_C(80000000000) * 21 * 922);
            for (unsigned reg = 0; reg < 5; reg++) {
                const unsigned regs[] = {30, 31, 35, 36, 4};
                prepared(&a, 19660800, 1); assert(wr(&a, 38, 1, 0));
                assert(!wr(&a, regs[reg], regs[reg] == 4 ? 0x80 : 0, 1));
                assert(a.reject == MSM5XXX_MA5_REJECT_CLOCK);
            }
            for (unsigned v = 1; v < 4; v++) {
                prepared(&a, 19660800, 1); assert(wr(&a, 38, 1, 0));
                assert(!wr(&a, 38, v, 1)); /* Running restart/reset phase not modeled. */
            }
            prepared(&a, 19660800, 1);
            assert(!wr(&a, 30, 0, 0));
            assert(msm5xxx_ma5_device_init(&a, 10));
            assert(msm5xxx_ma5_device_set_clock(&a, 19660800));
            assert(!wr(&a, 36, 0, 0)); /* Unknown high shadow cannot commit. */
            prepared(&a, 19660800, 1);
            assert(wr(&a, 4, 0x80, 0) && wr(&a, 4, 0, 0));
            assert(!a.ms_s_committed && !a.b_written[35] && !a.b_written[36]);
            assert(!wr(&a, 36, 0, 0));
            prepared(&a, 19660800, 1);
            assert(wr(&a, 4, 0x80, 0) && wr(&a, 4, 0, 0));
            assert(wr(&a, 35, 0, 0) && wr(&a, 36, 4, 0));
            assert(wr(&a, 38, 2, 0) && wr(&a, 38, 1, 0));
            prepared(&a, 19660800, 1);
            assert(wr(&a, 4, 0x80, 0));
            assert(wr(&a, 35, 0, 0) && wr(&a, 36, 4, 0));
            assert(wr(&a, 38, 2, 0));
            assert(!wr(&a, 38, 1, 0) && !a.counter_running);
            assert(a.reject == MSM5XXX_MA5_REJECT_RESET_RETENTION);
            prepared(&a, 19660800, 1); assert(!wr(&a, 36, 1, 0));
            prepared(&a, 19660800, 1); assert(wr(&a, 31, 0x51, 0));
            assert(!wr(&a, 38, 1, 0)); /* Mismatched proven-pair halves. */
            assert(msm5xxx_ma5_device_init(&a, 10));
            assert(msm5xxx_ma5_device_set_clock(&a, 1));
            assert(!wr(&a, 38, 1, 0)); /* Missing PLL/MS_S/CNTRST. */
            prepared(&a, 19660800, 1);
            assert(!wr(&a, 38, 3, 0)); /* Combined START/reset remains atomic. */
            assert(!a.counter_running && a.counter == 0);
            assert(msm5xxx_ma5_device_init(&a, 10));
            assert(msm5xxx_ma5_device_set_clock(&a, 1));
            assert(!msm5xxx_ma5_device_set_clock(&a, 2));
            for (unsigned i = 0; i < 2; i++) {
                assert(msm5xxx_ma5_device_init(&a, 10));
                assert(!msm5xxx_ma5_device_set_clock(&a, i ? 1000000001 : 0));
            }
            assert(msm5xxx_ma5_device_init(&a, 10));
            assert(msm5xxx_ma5_device_write(&a, true, 0, 0));
            assert(!msm5xxx_ma5_device_set_clock(&a, 19660800));
            prepared(&a, 19660800, 1); assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 100);
            msm5xxx_ma5_device_advance(&a, 99);
            assert(a.reject == MSM5XXX_MA5_REJECT_CLOCK);
            prepared(&a, 19660800, 1);
            assert(wr(&a, 1, 0x80, 0)); /* Queued until explicit START. */
            assert(a.delayed_count == 1 && a.delayed_consumed == 0);
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "clock.c"
            binary = Path(temporary) / "clock"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core.parent}", str(core), str(source), "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_target_rate_infers_only_closed_runtime_pll_pairs(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native/qemu/msm5xxx-ma5-audio.c"
        harness = r"""
        #include <assert.h>
        #include <stdint.h>
        #include "msm5xxx-ma5-audio.h"
        static bool wr(MSM5xxxMA5Device *d, unsigned b, unsigned v) {
            return msm5xxx_ma5_device_write(d, true, b, 0) &&
                   msm5xxx_ma5_device_write(d, false, v, 0);
        }
        static void run(unsigned b30, unsigned b31, uint64_t expected) {
            MSM5xxxMA5Device d;
            assert(msm5xxx_ma5_device_init(&d, 1000));
            assert(msm5xxx_ma5_device_set_target_rate(&d, 48000));
            assert(wr(&d, 30, b30));
            assert(d.clki_hz == 0);
            assert(wr(&d, 31, b31));
            assert(d.clki_hz == expected && d.clki_inferred);
            assert(wr(&d, 35, 14) && wr(&d, 36, 104)); /* MS_S=922 */
            assert(wr(&d, 38, 2) && wr(&d, 38, 1));
            assert(d.counter_running);
            assert(d.counter_num == expected * (b31 & 0x7f));
            assert(d.counter_den == UINT64_C(80000000000) *
                                      (b30 & 0x1f) * 922u);
        }
        int main(void) {
            MSM5xxxMA5Device d;
            run(0x14, 0x4b, UINT64_C(19660800));
            run(0x95, 0x51, UINT64_C(19114667));
            assert(msm5xxx_ma5_device_init(&d, 1000));
            assert(msm5xxx_ma5_device_set_target_rate(&d, 48000));
            assert(wr(&d, 30, 0x14));
            assert(!wr(&d, 31, 0x51)); /* Do not combine PLL halves. */
            assert(d.reject == MSM5XXX_MA5_REJECT_CLOCK && !d.clki_hz);
            assert(msm5xxx_ma5_device_init(&d, 1000));
            assert(!msm5xxx_ma5_device_set_target_rate(&d, 7999));
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "device.c"
            binary = Path(temporary) / "device"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core.parent}", str(core), str(source), "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_predecoded_adpcm_loop_wraps_to_loop_point_and_one_shot_holds(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native/qemu"
        harness = r"""
        #include <assert.h>
        #include <stdint.h>
        #include <string.h>
        #include "msm5xxx-ma2-audio.c"
        #include "msm5xxx-ma5-wt-engine.h"
        static uint64_t emitted;
        static bool emit(void *opaque, uint64_t first, const int16_t *pcm,
                         size_t frames) {
            (void)opaque; (void)pcm;
            assert(first == emitted);
            emitted += frames;
            return true;
        }
        static void commit(MA5WTEngine *engine, MSM5xxxMA5CommitKind kind,
                           uint32_t address, uint8_t value) {
            MSM5xxxMA5Commit c = {kind, address, value, value, 0};
            ma5_wt_engine_commit(engine, &c);
        }
        static void render(unsigned loop, bool held, uint32_t phase) {
            MA5WTEngine *engine = ma5_wt_engine_new(0, emit, 0);
            uint8_t desc[13] = {0x78,0,0,0xf0,0xf0,0,0,0x41,0,
                                (uint8_t)(loop >> 8),(uint8_t)loop,0,8};
            const uint8_t sample[4] = {0x17,0x29,0x3b,0x4d};
            assert(engine);
            emitted = 0;
            commit(engine, MSM5XXX_MA5_COMMIT_B,39,0xf8);
            commit(engine, MSM5XXX_MA5_COMMIT_B,40,0xf8);
            commit(engine, MSM5XXX_MA5_COMMIT_B,42,0);
            commit(engine, MSM5XXX_MA5_COMMIT_B,55,0);
            commit(engine, MSM5XXX_MA5_COMMIT_B,56,0);
            commit(engine, MSM5XXX_MA5_COMMIT_CONTROL,192,0x60);
            commit(engine, MSM5XXX_MA5_COMMIT_CONTROL,208,0x3c);
            commit(engine, MSM5XXX_MA5_COMMIT_CONTROL,224,0);
            commit(engine, MSM5XXX_MA5_COMMIT_CONTROL,240,8);
            commit(engine, MSM5XXX_MA5_COMMIT_CONTROL,241,0);
            for (unsigned i=0;i<13;i++)
                commit(engine,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,desc[i]);
            for (unsigned i=0;i<sizeof(sample);i++)
                commit(engine,MSM5XXX_MA5_COMMIT_SRAM,0x4100+i,sample[i]);
            commit(engine,MSM5XXX_MA5_COMMIT_CONTROL,102,0x40);
            commit(engine,MSM5XXX_MA5_COMMIT_CONTROL,103,0);
            commit(engine,MSM5XXX_MA5_COMMIT_CONTROL,104,0x40);
            commit(engine,MSM5XXX_MA5_COMMIT_CONTROL,105,0);
            commit(engine,MSM5XXX_MA5_COMMIT_CONTROL,106,0);
            commit(engine,MSM5XXX_MA5_COMMIT_CONTROL,107,0);
            commit(engine,MSM5XXX_MA5_COMMIT_CONTROL,107,0x40);
            MA5WTStatus status=ma5_wt_engine_status(engine);
            MA5WTVoiceInfo voice=ma5_wt_engine_voice(engine,1);
            assert(status.admitted==1 && status.skipped==0 && voice.active);
            ma5_wt_engine_advance(engine,21333333); /* exactly 1024 frames */
            status=ma5_wt_engine_status(engine);
            voice=ma5_wt_engine_voice(engine,1);
            assert(status.frame==1024 && emitted==1024);
            assert(voice.held==held);
            if (!held) assert(voice.phase==phase);
            ma5_wt_engine_free(engine);
        }
        int main(void) {
            render(4,false,4u<<16); /* loop starts at LP, not sample zero */
            render(8,true,0);       /* LP=EP remains one-shot */
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "wt-loop.c"
            binary = Path(temporary) / "wt-loop"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            compile_result = subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core}", str(source), str(core / "msm5xxx-ma5-wt-engine.c"),
                str(core / "msm5xxx-ma5-gain.c"),
                str(core / "msm5xxx-ma5-fm-voice.c"),
                str(core / "msm5xxx-ma5-operator.c"),
                str(core / "msm5xxx-ma5-waveform.c"), "-lm", "-o", str(binary),
            ], capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_wt_ar15_key_reset_attack_decay_and_endpoint_pipeline(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native/qemu"
        harness = r"""
        #include <assert.h>
        #include <stdint.h>
        #include "msm5xxx-ma5-wt-engine.c"
        static uint64_t emitted;
        static int16_t first_left;
        static bool emit(void *opaque, uint64_t first, const int16_t *pcm,
                         size_t frames) {
            (void)opaque;
            assert(first == emitted);
            if (!first) first_left=pcm[0];
            emitted+=frames;
            return true;
        }
        static void commit(MA5WTEngine *e, MSM5xxxMA5CommitKind kind,
                           unsigned address, unsigned value) {
            MSM5xxxMA5Commit c={kind,address,value,value,0};
            ma5_wt_engine_commit(e,&c);
        }
        static Voice *setup(MA5WTEngine *e, unsigned endpoint, unsigned loop) {
            const uint8_t desc[13]={0x78,0,0,0x73,0xf1,0,0,0x41,0,
                0,(uint8_t)loop,0,(uint8_t)endpoint};
            const unsigned globals[][2]={{39,0xf8},{40,0xf8},{42,0},{55,0},{56,0}};
            const unsigned channel[][2]={{192,0x60},{208,0x3c},{224,0},{240,8},{241,0}};
            const uint8_t slot[6]={0x40,0,0x40,0x28,0,0};
            for (unsigned i=0;i<5;i++) {
                commit(e,MSM5XXX_MA5_COMMIT_B,globals[i][0],globals[i][1]);
                commit(e,MSM5XXX_MA5_COMMIT_CONTROL,channel[i][0],channel[i][1]);
            }
            for (unsigned i=0;i<13;i++)
                commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,desc[i]);
            commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4100,0x77);
            for (unsigned i=0;i<6;i++)
                commit(e,MSM5XXX_MA5_COMMIT_CONTROL,102+i,slot[i]);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,107,0x40);
            assert(e->stats.admitted==1 && !e->stats.skipped);
            Voice *v=&e->voice[1];
            assert(v->info.envelope==2 && !v->level && v->info.step==65536);
            return v;
        }
        static void attack(Voice *v) {
            assert(sample(v,0)==0);
            assert(v->info.envelope==3 && !v->level);
            assert(v->info.phase==65536 && !v->info.saved);
            int32_t second=sample(v,1);
            assert(v->info.envelope==4 && v->level==UINT32_C(0x80000000));
            assert(second==floor_div((int64_t)v->decoded[1]*32767,32768));
            assert(second>0);
        }
        int main(void) {
            MA5WTEngine *e=ma5_wt_engine_new(0,emit,0);
            assert(e);
            Voice *v=setup(e,2,0);
            attack(v);
            assert(!v->info.held && !v->info.phase); /* Loop wraps on full attack. */
            (void)sample(v,2);
            assert(v->level==(uint32_t)((UINT64_C(0x80000000)*v->dr)>>30));
            assert(v->info.envelope==4 && v->info.phase==65536);
            /* RST+KEY re-enters reset independently of the current decay. */
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,107,0x50);
            assert(v->info.envelope==2 && !v->level && !v->info.saved);
            attack(v);
            /* Engine reset emits nothing and clears the admitted voice. */
            ma5_wt_engine_reset(e,0);
            assert(!emitted && !e->voice[1].info.active);
            v=setup(e,2,2);
            attack(v);
            assert(v->info.held && v->info.crossed_frame==1);
            int32_t saved=v->info.saved;
            uint32_t phase=v->info.phase;
            uint32_t decay=(uint32_t)((UINT64_C(0x80000000)*v->dr)>>30);
            uint32_t amp=((decay>>16)*32767u)>>15;
            assert(sample(v,2)==floor_div((int64_t)saved*amp,32768));
            assert(v->level==decay && v->info.saved==saved && v->info.phase==phase);
            /* EP1 crosses during the silent reset frame: preserve scaled-zero hold. */
            ma5_wt_engine_reset(e,0);
            v=setup(e,1,1);
            assert(sample(v,0)==0 && v->info.envelope==3);
            assert(v->info.held && v->info.crossed_frame==0 && !v->info.saved);
            assert(sample(v,1)==0 && v->info.envelope==4);
            assert(v->level==UINT32_C(0x80000000));
            assert(sample(v,2)==0 && v->info.saved==0);
            /* The public render path retains the reset frame in its emitted stream. */
            ma5_wt_engine_reset(e,0);
            (void)setup(e,2,0);
            ma5_wt_engine_advance(e,1);
            assert(emitted==1 && first_left==0 && e->voice[1].info.envelope==3);
            ma5_wt_engine_free(e);
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "wt-key.c"
            binary = Path(temporary) / "wt-key"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            result = subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                *([] if os.name == "nt" else
                  ["-fsanitize=undefined", "-fno-sanitize-recover=all"]), "-O1",
                f"-I{core}", str(source), str(core / "msm5xxx-ma2-audio.c"),
                str(core / "msm5xxx-ma5-gain.c"),
                str(core / "msm5xxx-ma5-fm-voice.c"),
                str(core / "msm5xxx-ma5-operator.c"),
                str(core / "msm5xxx-ma5-waveform.c"), "-lm", "-o", str(binary),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_manual_closed_wt_envelope_and_tl_class(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native/qemu"
        harness = r"""
        #include <assert.h>
        #include <math.h>
        #include <stdint.h>
        #include <string.h>
        #include "msm5xxx-ma5-wt-engine.c"
        static bool emit(void *opaque, uint64_t first, const int16_t *pcm,
                         size_t frames) {
            (void)opaque; (void)first; (void)pcm; (void)frames;
            return true;
        }
        static void commit(MA5WTEngine *e, MSM5xxxMA5CommitKind kind,
                           unsigned address, unsigned value, uint64_t ns) {
            MSM5xxxMA5Commit c={kind,address,value,value,ns};
            ma5_wt_engine_commit(e,&c);
        }
        int main(void) {
            MA5WTEngine *e=ma5_wt_engine_new(0,emit,0);
            const unsigned base=102, ch=0, rate_offset=4;
            const unsigned char descriptor[13]={0x78,0,0x02,0x73,0xf1,0x20,0x44,
                                                  0x41,0,0,4,0,8};
            const unsigned char sample_data[4]={0x77,0x77,0x77,0x77};
            const unsigned base2=108, ch2=3, rate_offset2=6;
            const unsigned char lfo_descriptor[13]={0x78,0x80,0x32,0x8a,0xf2,0x10,0x01,
                                                     0x41,0x20,0x03,0x0c,0x03,0x5c};
            assert(e);
            commit(e,MSM5XXX_MA5_COMMIT_B,39,0xf8,0);
            commit(e,MSM5XXX_MA5_COMMIT_B,40,0xf8,0);
            commit(e,MSM5XXX_MA5_COMMIT_B,42,0xf8,0);
            commit(e,MSM5XXX_MA5_COMMIT_B,55,0,0);
            commit(e,MSM5XXX_MA5_COMMIT_B,56,0,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192+ch,0x60,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208+ch,0x3c,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224+ch,0,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240+2*ch,8,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241+2*ch,0,0);
            for (unsigned i=0;i<13;i++)
                commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4000+i,descriptor[i],0);
            for (unsigned i=0;i<sizeof(sample_data);i++)
                commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4100+i,sample_data[i],0);
            for (unsigned i=0;i<13;i++)
                commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4020+i,lfo_descriptor[i],0);
            for (unsigned i=0;i<430;i++)
                commit(e,MSM5XXX_MA5_COMMIT_SRAM,0x4120+i,0x77,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base,0x40,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+1,0,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+2,0x40,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+3,0x10,0); /* BLOCK=2 */
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+4,105,0);  /* FNUM=105 */
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+5,0,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+5,0x40,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,192+ch2,0x60,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,208+ch2,0x3c,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224+ch2,0,0); /* XVB=0 gates EVB. */
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,240+2*ch2,7,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,241+2*ch2,0x7a,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base2,0x40,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base2+1,0x10,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base2+2,0x40,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base2+3,0x18,0); /* BLOCK=3 */
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base2+4,105,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base2+5,0x03,0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base2+5,0x43,0); /* LFO2/EVB1 with XVB=0. */
            MA5WTVoiceInfo voice=ma5_wt_engine_voice(e,1);
            MA5WTVoiceInfo lfo_voice=ma5_wt_engine_voice(e,2);
            assert(ma5_wt_engine_status(e).admitted==2 && voice.active && lfo_voice.active);
            assert(e->voice[1].dr==eg_rate_q30(3,rate_offset));
            assert(e->voice[1].rr==eg_rate_q30(7,rate_offset));
            assert(e->voice[1].sustain==e->gain.sl[1]);
            assert(e->gain.tl[8]>=16421 && e->gain.tl[8]<=16423);
            assert(e->voice[1].side[0] < e->gain.g32[31]);
            assert(e->voice[2].dr==eg_rate_q30(10,rate_offset2));
            assert(e->voice[2].sr==eg_rate_q30(3,rate_offset2));
            assert(e->voice[2].rr==eg_rate_q30(8,rate_offset2));
            assert(lfo_voice.step==17958); /* Manual BEND factor from the committed 07:7a pair. */
            assert(e->voice[2].side[0] < e->gain.g32[31]);
            ma5_wt_engine_advance(e,150000000);
            double level=(double)e->voice[1].level/2147483648.0;
            double expected=pow(10.0,-96.0*(7198.0/48000.0)/(20.0*5.376));
            assert(fabs(level-expected)<0.003);
            ma5_wt_engine_advance(e,200000000);
            voice=ma5_wt_engine_voice(e,1);
            assert(voice.envelope==5 && e->voice[1].level<=e->voice[1].sustain);
            uint32_t at_keyoff=e->voice[1].level;
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,base+5,0,200000000);
            assert(ma5_wt_engine_voice(e,1).envelope==1);
            ma5_wt_engine_advance(e,300000000);
            level=(double)e->voice[1].level/at_keyoff;
            expected=pow(10.0,-96.0*(4800.0/48000.0)/(20.0*0.336));
            assert(fabs(level-expected)<0.003);
            ma5_wt_engine_advance(e,540000000);
            assert(ma5_wt_engine_voice(e,1).envelope==0);
            commit(e,MSM5XXX_MA5_COMMIT_CONTROL,224+ch2,1,540000000);
            assert(!ma5_wt_engine_voice(e,2).active);
            assert(ma5_wt_engine_voice(e,2).skip==MA5_WT_SKIP_MUTATION);
            ma5_wt_engine_free(e);
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "wt-eg.c"
            binary = Path(temporary) / "wt-eg"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            result = subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core}", str(source), str(core / "msm5xxx-ma2-audio.c"),
                str(core / "msm5xxx-ma5-gain.c"),
                str(core / "msm5xxx-ma5-fm-voice.c"),
                str(core / "msm5xxx-ma5-operator.c"),
                str(core / "msm5xxx-ma5-waveform.c"), "-lm", "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            run_result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_mode_shadow_readback_keeps_dirty_reset_closed(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native" / "qemu" / "msm5xxx-ma5-audio.c"
        harness = r"""
        #include <assert.h>
        #include <string.h>
        #include "msm5xxx-ma5-audio.h"
        static bool wr(MSM5xxxMA5Device *d, unsigned b, unsigned value) {
            return msm5xxx_ma5_device_write(d, true, b, 0) &&
                   msm5xxx_ma5_device_write(d, false, value, 0);
        }
        static uint8_t rd(MSM5xxxMA5Device *d, unsigned b) {
            uint8_t value;
            assert(msm5xxx_ma5_device_write(d, true, b, 0));
            assert(msm5xxx_ma5_device_read(d, false, &value, 0));
            return value;
        }
        int main(void) {
            MSM5xxxMA5Device d;
            MSM5xxxMA5Readback before;
            uint8_t value;
            assert(msm5xxx_ma5_device_init(&d, 10));
            assert(wr(&d, 4, 0x80) && wr(&d, 4, 0));
            assert(rd(&d, 56) == 0 && !d.b_written[56]);
            d.backing.control[3] = 0x5a;
            d.backing.sram[7] = 0xa5;
            d.backing.read_latch = 0x78;
            d.backing.read_valid = true;
            before = d.backing;
            assert(wr(&d, 56, 1) && rd(&d, 56) == 1);
            assert(wr(&d, 56, rd(&d, 56) | 2) && rd(&d, 56) == 3);
            assert(wr(&d, 56, rd(&d, 56) & ~1u) && rd(&d, 56) == 2);
            assert(wr(&d, 2, 0x80)); /* Preserve an immediate packet fragment. */
            assert(d.count == 1);
            d.pending = 0x40;
            assert(wr(&d, 4, 0x28) && wr(&d, 4, 0));
            assert(d.count == 1 && d.pending == 0x40 && rd(&d, 56) == 2);
            assert(!memcmp(before.control, d.backing.control, sizeof(before.control)));
            assert(!memcmp(before.sram, d.backing.sram, sizeof(before.sram)));
            assert(d.backing.read_latch == before.read_latch && d.backing.read_valid);
            d.backing.read_valid = false;
            assert(!wr(&d, 4, 0x80)); /* Mode retention remains unknown. */
            assert(d.reject == MSM5XXX_MA5_REJECT_RESET_RETENTION && d.b[56] == 2);
            for (unsigned i = 0; i < 4; i++) {
                const unsigned unsupported[] = {0x08, 0x20, 0x40, 0xa8};
                assert(msm5xxx_ma5_device_init(&d, 10));
                assert(!wr(&d, 4, unsupported[i]));
            }
            assert(msm5xxx_ma5_device_init(&d, 10));
            assert(wr(&d, 4, 0x80) && !wr(&d, 4, 0x28));
            assert(msm5xxx_ma5_device_init(&d, 10));
            assert(wr(&d, 56, 0)); /* Explicit zero is still a dirty mode write. */
            assert(!wr(&d, 4, 0x80));
            assert(msm5xxx_ma5_device_init(&d, 10));
            assert(msm5xxx_ma5_device_write(&d, true, 57, 0));
            assert(!msm5xxx_ma5_device_read(&d, false, &value, 0));
            assert(d.reject == MSM5XXX_MA5_REJECT_DYNAMIC_READ);
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "mode.c"
            binary = Path(temporary) / "mode"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core.parent}", str(core), str(source), "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_clocked_delayed_fifo_deadlines_and_isolation(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native" / "qemu" / "msm5xxx-ma5-audio.c"
        harness = r"""
        #include <assert.h>
        #include <string.h>
        #include "msm5xxx-ma5-audio.h"
        static bool wr(MSM5xxxMA5Device *d, unsigned b, unsigned v, uint64_t t) {
            return msm5xxx_ma5_device_write(d, true, b, t) &&
                   msm5xxx_ma5_device_write(d, false, v, t);
        }
        static void setup(MSM5xxxMA5Device *d) {
            assert(msm5xxx_ma5_device_init(d, 10));
            assert(msm5xxx_ma5_device_set_clock(d, 19660800));
            assert(wr(d, 30, 0x14, 0) && wr(d, 31, 0x4b, 0));
            assert(wr(d, 35, 14, 0) && wr(d, 36, 0x68, 0));
            assert(wr(d, 38, 2, 0));
        }
        static void bytes(MSM5xxxMA5Device *d, unsigned port,
                          const unsigned char *p, unsigned n, uint64_t t) {
            assert(msm5xxx_ma5_device_write(d, true, port, t));
            for (unsigned i = 0; i < n; i++)
                assert(msm5xxx_ma5_device_write(d, false, p[i], t));
        }
        static uint64_t due(unsigned n) {
            return ((uint64_t)n * UINT64_C(1475200000000000) + 1474559999) /
                   UINT64_C(1474560000);
        }
        int main(void) {
            MSM5xxxMA5Device a, b;
            uint64_t next;
            uint8_t status;
            const unsigned char zero[] = {0x80, 0x80, 0x81};
            const unsigned char positive[] = {0x82, 0x80, 0x81, 0x81, 0x80, 0x82};
            setup(&a);
            bytes(&a, 1, zero, 1, 0);
            assert(!msm5xxx_ma5_device_next_deadline(&a, &next));
            assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 10);
            assert(a.delayed_delta_ready && !a.backing.control_write_valid);
            bytes(&a, 1, zero + 1, 1, 10);
            msm5xxx_ma5_device_advance(&a, 20);
            bytes(&a, 1, zero + 2, 1, 20);
            msm5xxx_ma5_device_advance(&a, 30);
            assert(a.backing.control[0] == 1 && !a.delayed_count && !a.reject);
            setup(&a); bytes(&a, 1, positive, sizeof(positive), 0);
            assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 20);
            assert(a.delayed_count == 4 && a.delayed_previous_due == 0);
            assert(msm5xxx_ma5_device_next_deadline(&a, &next) && next == due(2));
            msm5xxx_ma5_device_advance(&a, next - 1);
            assert(a.backing.control[0] == 0);
            msm5xxx_ma5_device_advance(&a, next);
            assert(a.backing.control[0] == 1 && a.delayed_previous_due == 2);
            msm5xxx_ma5_device_advance(&a, due(2) + 20);
            assert(msm5xxx_ma5_device_next_deadline(&a, &next) && next == due(3));
            msm5xxx_ma5_device_advance(&a, next);
            assert(a.backing.control[0] == 2 && a.delayed_previous_due == 3);
            bytes(&a, 1, zero, sizeof(zero), due(10)); /* Late zero delta catches up. */
            msm5xxx_ma5_device_advance(&a, due(10) + 30);
            assert(a.backing.control[0] == 1 && a.delayed_previous_due == 3);
            setup(&a); setup(&b);
            const unsigned char immediate[] = {0x80, 0x82, 0x80, 0x83};
            const unsigned char read[] = {0x80, 0x80};
            bytes(&a, 1, zero, 3, 0); bytes(&b, 1, zero, 3, 0);
            bytes(&a, 2, immediate, 4, 0); bytes(&b, 2, immediate, 4, 0);
            bytes(&a, 3, read, 2, 0); bytes(&b, 3, read, 2, 0);
            assert(wr(&a, 38, 1, 0) && wr(&b, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 60);
            for (unsigned t = 10; t <= 60; t += 10) msm5xxx_ma5_device_advance(&b, t);
            assert(a.backing.control[0] == 3 && a.backing.read_latch == 3);
            assert(!memcmp(a.backing.control, b.backing.control, sizeof(a.backing.control)));
            assert(a.delayed_consumed == b.delayed_consumed && a.counter_phase == b.counter_phase);
            setup(&a);
            const unsigned char terminal[] = {0x80, 0x40, 0x81, 0xff, 0x80, 0x80, 0x80};
            bytes(&a, 1, terminal, sizeof(terminal), 0); assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 40);
            assert(a.backing.control[192] == 127 && a.backing.control_write_raw == 0xff);
            msm5xxx_ma5_device_advance(&a, 70);
            assert(a.backing.control[0] == 0 && a.backing.control_write_raw == 0x80);
            setup(&a);
            const unsigned char memory[] = {0x80, 0, 0, 0x81, 0x84, 0, 0x7f, 0x80, 0xff};
            const unsigned char rom[] = {0x80, 0, 0, 0x80, 0x81, 0xff};
            bytes(&a, 1, memory, sizeof(memory), 0); bytes(&a, 1, rom, sizeof(rom), 0);
            assert(wr(&a, 38, 1, 0)); msm5xxx_ma5_device_advance(&a, 150);
            assert(a.backing.sram[0] == 0 && a.backing.sram[1] == 0x7f &&
                   a.backing.sram[2] == 0x80 && a.backing.sram[3] == 0xff);
            assert(a.backing.control[0] == 0 && a.backing.sram_writes == 4 && !a.reject);
            setup(&a);
            for (unsigned i = 0; i < 512; i++) assert(wr(&a, 1, 0x80, 0));
            assert(msm5xxx_ma5_device_read(&a, true, &status, 0) && status == 9);
            assert(!wr(&a, 1, 0x80, 0) && a.delayed_count == 512);
            assert(a.reject == MSM5XXX_MA5_REJECT_FIFO_OVERFLOW);
            for (unsigned edge = 0; edge < 2; edge++) {
                setup(&a); assert(wr(&a, 37, 1, 0) && wr(&a, 55, edge * 2, 0));
                for (unsigned i = 0; i < 70; i++) assert(wr(&a, 1, 0x80, 0));
                assert(!(a.pending & 0x80));
                assert(wr(&a, 38, 1, 0)); msm5xxx_ma5_device_advance(&a, 50);
                assert(a.delayed_count == 65 && !(a.pending & 0x80));
                msm5xxx_ma5_device_advance(&a, 60);
                assert(a.delayed_count == 64 && (a.pending & 0x80));
                assert(wr(&a, 0, 0x80, 60));
                assert(!!(a.pending & 0x80) == !edge);
                msm5xxx_ma5_device_advance(&a, 70);
                assert(!!(a.pending & 0x80) == !edge);
                a.pending |= 0x402;
                assert(wr(&a, 1, 0x80, 70) && wr(&a, 1, 0x80, 70));
                assert(a.delayed_count == 65 && !(a.pending & 0x80));
                msm5xxx_ma5_device_advance(&a, 80);
                assert(a.pending == 0x482);
                assert(wr(&a, 4, 0x28, 80) && a.pending == 0x482);
            }
            setup(&a);
            const unsigned char delta128[] = {0, 0x81, 0x80, 0x81};
            bytes(&a, 1, delta128, sizeof(delta128), 0); assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 30);
            assert(msm5xxx_ma5_device_next_deadline(&a, &next) && next == due(128));
            msm5xxx_ma5_device_advance(&a, next);
            assert(a.delayed_previous_due == 128 && a.backing.control[0] == 1);
            setup(&a); bytes(&a, 1, positive, 2, 0);
            const unsigned char prefix[] = {0x40};
            bytes(&a, 2, prefix, 1, 0); bytes(&a, 3, prefix, 1, 0);
            assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 20);
            assert(a.backing.immediate.address_bytes == 1 && a.backing.read.address_bytes == 1);
            const unsigned char finish_control[] = {0x81, 0x83};
            const unsigned char finish_read[] = {0x81, 0x80};
            bytes(&a, 2, finish_control, 2, 20); bytes(&a, 3, finish_read, 2, 20);
            a.pending = 0x402; a.backing.read_latch = 0xa5; a.backing.read_valid = true;
            a.backing.sram[0] = 0x5a; a.backing.control[3] = 0x6a;
            assert(wr(&a, 56, 2, 20));
            assert(wr(&a, 4, 0x28, 20) && wr(&a, 4, 0, 20));
            assert(!a.delayed_count && !a.delayed_delta_ready && a.delayed_previous_due == 0);
            assert(a.pending == 0x402 && a.b[56] == 2 && a.backing.read_latch == 0xa5 &&
                   a.backing.read_valid && a.backing.sram[0] == 0x5a && a.backing.control[3] == 0x6a);
            assert(a.count == 4 && a.backing.immediate.address_bytes == 1 &&
                   a.backing.read.address_bytes == 1 && a.counter_last_ns == 20);
            msm5xxx_ma5_device_advance(&a, 60);
            assert(a.backing.control[192] == 3 && a.backing.read_latch == 3);
            setup(&a); bytes(&a, 1, positive, 2, 0); assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, due(2)); /* Header due, payload not supplied. */
            assert(a.delayed_previous_due == 2);
            assert(wr(&a, 4, 0x28, due(2)) && a.delayed_previous_due == 2);
            bytes(&a, 1, zero, 3, due(2));
            msm5xxx_ma5_device_advance(&a, due(2) + 30);
            assert(a.delayed_previous_due == 2 && a.backing.control[0] == 1);
            setup(&a); assert(!wr(&a, 55, 1, 0));
            assert(a.reject == MSM5XXX_MA5_REJECT_DELAYED);
            const unsigned char bad[][6] = {{0,0,0}, {0x80,0,0,0}, {0x80,0,0,0x80,0,0},
                                          {0x80,0,0,0x81,0x80}};
            const unsigned lengths[] = {3,4,6,5};
            for (unsigned n = 0; n < 4; n++) {
                setup(&a); bytes(&a, 1, bad[n], lengths[n], 0);
                assert(wr(&a, 38, 1, 0)); msm5xxx_ma5_device_advance(&a, 100);
                assert(a.reject == MSM5XXX_MA5_REJECT_PACKET);
            }
            setup(&a); assert(wr(&a, 1, 0x80, 0));
            assert(!wr(&a, 4, 0x80, 0));
            assert(a.reject == MSM5XXX_MA5_REJECT_RESET_RETENTION);
            assert(msm5xxx_ma5_device_init(&a, 10));
            assert(!wr(&a, 1, 0x80, 0)); /* No implicit default clock. */
            assert(a.reject == MSM5XXX_MA5_REJECT_DELAYED);
            assert(msm5xxx_ma5_device_init(&a, 10));
            assert(msm5xxx_ma5_device_set_clock(&a, 1));
            assert(wr(&a, 30, 0x14, 0) && wr(&a, 31, 0x4b, 0));
            assert(wr(&a, 35, 0, 0) && wr(&a, 36, 0, 0) && wr(&a, 38, 2, 0));
            const unsigned char far[] = {0x7f, 0x7f, 0xff, 0x80, 0x81};
            bytes(&a, 1, far, sizeof(far), 0); assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 40);
            assert(a.reject == MSM5XXX_MA5_REJECT_CLOCK); /* Unrepresentable due ns. */
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "delayed.c"
            binary = Path(temporary) / "delayed"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core.parent}", str(core), str(source), "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_stop_resume_retains_phase_and_clock_changes_require_reset(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native" / "qemu" / "msm5xxx-ma5-audio.c"
        harness = r"""
        #include <assert.h>
        #include <string.h>
        #include "msm5xxx-ma5-audio.h"
        static bool wr(MSM5xxxMA5Device *d, unsigned b, unsigned v, uint64_t t) {
            return msm5xxx_ma5_device_write(d, true, b, t) &&
                   msm5xxx_ma5_device_write(d, false, v, t);
        }
        static uint8_t rd(MSM5xxxMA5Device *d, unsigned b, uint64_t t) {
            uint8_t value;
            assert(msm5xxx_ma5_device_write(d, true, b, t));
            assert(msm5xxx_ma5_device_read(d, false, &value, t));
            return value;
        }
        static void setup(MSM5xxxMA5Device *d) {
            assert(msm5xxx_ma5_device_init(d, 10));
            assert(msm5xxx_ma5_device_set_clock(d, 1000000000));
            assert(wr(d, 30, 0x14, 0) && wr(d, 31, 0x4b, 0));
            assert(wr(d, 35, 0, 0) && wr(d, 36, 4, 0) && wr(d, 38, 2, 0));
        }
        static void bytes(MSM5xxxMA5Device *d, unsigned b,
                          const unsigned char *p, unsigned n) {
            for (unsigned i = 0; i < n; i++) assert(wr(d, b, p[i], 0));
        }
        int main(void) {
            MSM5xxxMA5Device a;
            uint64_t phase, total, next;
            uint32_t latch;
            setup(&a);
            assert(wr(&a, 38, 0, 0) && !a.counter_needs_reset);
            assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 100);
            assert(a.counter_total == 4 && rd(&a, 34, 100) == 0); /* Old reset snapshot. */
            assert(rd(&a, 32, 100) == 0 && rd(&a, 33, 100) == 0 && rd(&a, 34, 100) == 4);
            phase = a.counter_phase; total = a.counter_total; latch = a.counter_latch;
            a.pending = 0x402; a.backing.control[7] = 0x5a; a.backing.sram[3] = 0xa5;
            a.backing.read_latch = 0x78; a.backing.read_valid = true;
            assert(wr(&a, 4, 0, 100) && wr(&a, 4, 0, 100));
            assert(a.counter_running && !a.reject && a.counter_total == total &&
                   a.counter_phase == phase && a.counter_latch == latch);
            assert(a.pending == 0x402 && a.backing.control[7] == 0x5a &&
                   a.backing.sram[3] == 0xa5 && a.backing.read_valid &&
                   a.backing.read_latch == 0x78);
            assert(wr(&a, 38, 0, 100));
            assert(!a.counter_running && a.counter_needs_reset && !(a.b[38] & 1));
            msm5xxx_ma5_device_advance(&a, 1000);
            assert(a.counter_total == total && a.counter_phase == phase && a.counter_latch == latch);
            assert(rd(&a, 32, 1000) == 0 && rd(&a, 33, 1000) == 0 && rd(&a, 34, 1000) == 4);
            assert(a.pending == 0x402 && a.backing.control[7] == 0x5a &&
                   a.backing.sram[3] == 0xa5 && a.backing.read_latch == 0x78 && a.backing.read_valid);
            assert(wr(&a, 38, 0, 1000));
            assert(wr(&a, 38, 1, 1000) && !a.counter_needs_reset);
            assert(a.counter_total == total && a.counter_phase == phase && a.counter_latch == latch);
            msm5xxx_ma5_device_advance(&a, 1100);
            assert(a.counter_total == 9 && a.counter_phase == UINT64_C(600000000000));
            assert(a.backing.control[7] == 0x5a && a.backing.sram[3] == 0xa5);
            setup(&a); assert(wr(&a, 38, 1, 0) && wr(&a, 38, 0, 100));
            total = a.counter_total; phase = a.counter_phase;
            assert(wr(&a, 36, 8, 100));
            assert(!wr(&a, 38, 1, 1000) && a.reject == MSM5XXX_MA5_REJECT_CLOCK);
            assert(a.counter_total == total && a.counter_phase == phase);
            setup(&a);
            const unsigned char future[] = {0x8a, 0x80, 0x81};
            bytes(&a, 1, future, sizeof(future));
            assert(wr(&a, 38, 1, 0) && wr(&a, 38, 0, 50));
            assert(!msm5xxx_ma5_device_next_deadline(&a, &next));
            assert(wr(&a, 38, 1, 1000));
            assert(msm5xxx_ma5_device_next_deadline(&a, &next) && next == 1164);
            msm5xxx_ma5_device_advance(&a, 1163); assert(!a.backing.control[0]);
            msm5xxx_ma5_device_advance(&a, 1164); assert(a.backing.control[0] == 1);
            setup(&a); assert(wr(&a, 38, 1, 0) && wr(&a, 38, 0, 100));
            assert(wr(&a, 4, 0x80, 100));
            assert(!a.counter_reset && !a.counter_needs_reset);
            assert(msm5xxx_ma5_device_write(&a, true, 32, 100));
            uint8_t unknown;
            assert(!msm5xxx_ma5_device_read(&a, false, &unknown, 100));
            assert(a.reject == MSM5XXX_MA5_REJECT_DYNAMIC_READ);
            setup(&a);
            const unsigned char incomplete[] = {0};
            bytes(&a, 1, incomplete, 1); assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 10);
            assert(wr(&a, 38, 0, 10));
            assert(!wr(&a, 38, 2, 10) && a.reject == MSM5XXX_MA5_REJECT_RESET_RETENTION);
            assert(a.delayed_delta_bytes == 1 && a.counter_needs_reset);
            setup(&a); bytes(&a, 1, incomplete, 1); assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 10); assert(wr(&a, 38, 0, 10));
            assert(wr(&a, 4, 0x28, 10) && wr(&a, 4, 0, 10) && wr(&a, 38, 2, 10));
            assert(!a.counter_needs_reset && !a.counter_total && !a.counter_phase &&
                   !a.delayed_due && !a.delayed_previous_due);
            assert(wr(&a, 38, 1, 10));
            for (unsigned port = 1; port <= 2; port++) {
                setup(&a);
                const unsigned char stop[] = {0x80, 0x60, 0x83, 0x81};
                const unsigned char immediate[] = {0x80, 0x82};
                const unsigned char hold[] = {0x80, 0x80, 0x83};
                bytes(&a, port, stop + (port == 2), sizeof(stop) - (port == 2));
                if (port == 2) bytes(&a, 1, hold, sizeof(hold));
                bytes(&a, 2, immediate, sizeof(immediate));
                a.pending = 0x402; a.backing.sram[3] = 0xa5;
                assert(wr(&a, 38, 1, 0));
                msm5xxx_ma5_device_advance(&a, 1000);
                assert(!a.reject && !a.counter_running && a.counter_needs_reset);
                assert(a.counter_last_ns == (port == 1 ? 40 : 30));
                assert(a.counter_total == 1 && a.backing.control[480] == 1 &&
                       a.backing.control[0] == 2 && a.pending == 0x402 && a.backing.sram[3] == 0xa5);
                phase = a.counter_phase; total = a.counter_total;
                assert(a.delayed_count == (port == 2 ? 1u : 0u));
                assert(!msm5xxx_ma5_device_next_deadline(&a, &next));
                msm5xxx_ma5_device_advance(&a, 100000);
                assert(a.counter_total == total && a.counter_phase == phase);
                assert(rd(&a, 32, 100000) == 0 && rd(&a, 33, 100000) == 0 &&
                       rd(&a, 34, 100000) == 1);
            }
            /* C480 bit0 clear is an ordinary write, not an implicit STOP. */
            setup(&a);
            const unsigned char clear[] = {0x60, 0x83, 0x80};
            bytes(&a, 2, clear, sizeof(clear)); assert(wr(&a, 38, 1, 0));
            msm5xxx_ma5_device_advance(&a, 100);
            assert(a.counter_running && !a.counter_needs_reset && a.counter_total == 4);
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "stop.c"
            binary = Path(temporary) / "stop"
            source.write_text(textwrap.dedent(harness), encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                f"-I{core.parent}", str(core), str(source), "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_transport_contract(self):
        repo = Path(__file__).resolve().parents[1]
        core = repo / "native" / "qemu" / "msm5xxx-ma5-audio.c"
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
