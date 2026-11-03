import subprocess
import tempfile
import unittest
from pathlib import Path


class TestMA3CAudioCore(unittest.TestCase):
    def test_register_packet_readback_fifo_and_guest_timing(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "check.c"
            binary = root / "check"
            source.write_text(r'''#include "msm5xxx-ma3-audio.h"
#include <assert.h>
static void write_reg(MSM5xxxMA3Audio *a, uint16_t address, uint8_t value,
                      uint64_t now) {
    assert(msm5xxx_ma3_status_write(a, 2, now));
    assert(msm5xxx_ma3_data_write(a, address & 0x7f, now));
    assert(msm5xxx_ma3_data_write(a, ((address >> 7) & 0x7f) | 0x80, now));
    assert(msm5xxx_ma3_data_write(a, value | 0x80, now));
}
int main(void) {
    MSM5xxxMA3Audio a;
    MSM5xxxMA3Operation op;
    uint8_t value = 0;
    uint64_t deadline = 0;
    msm5xxx_ma3_reset(&a);
    assert(a.reg[0x90] == 0x60 && a.reg[0xa0] == 0x3c);
    assert(a.reg[0x14a] == 0x40 && a.reg[0x151] == 0x40);
    a.interrupt_flags = 0x80;
    assert(!(msm5xxx_ma3_status_read(&a) & 0x80));
    assert(msm5xxx_ma3_status_write(&a, 0, 0));
    assert(msm5xxx_ma3_data_read(&a, &value, 0) && value == 0x80);
    assert(msm5xxx_ma3_data_write(&a, 0x80, 0));
    assert(a.interrupt_flags == 0);
    assert(msm5xxx_ma3_status_write(&a, 4, 1));
    assert(msm5xxx_ma3_data_write(&a, 0x80, 1));
    assert(a.mode == 4 && a.host_reg[0][4] == 0x80 && a.reg[4] == 0);
    assert(msm5xxx_ma3_data_write(&a, 0x00, 2));
    assert(a.host_reg[0][4] == 0 && a.reg[4] == 0);
    assert(msm5xxx_ma3_status_write(&a, 3, 10));
    assert(msm5xxx_ma3_data_write(&a, 0x10, 10));
    assert(msm5xxx_ma3_data_write(&a, 0x81, 10));
    assert(msm5xxx_ma3_data_write(&a, 0x80, 10));
    assert(msm5xxx_ma3_status_read(&a) & 0x10);
    assert(msm5xxx_ma3_status_write(&a, 0x11, 11));
    assert(msm5xxx_ma3_data_read(&a, &value, 11) && value == 0x60);
    assert(msm5xxx_ma3_status_write(&a, 3, 11));
    assert(msm5xxx_ma3_data_write(&a, 0x10, 11));
    assert(msm5xxx_ma3_data_write(&a, 0x81, 11));
    assert(!msm5xxx_ma3_data_write(&a, 0x83, 11));
    assert(msm5xxx_ma3_status_write(&a, 4, 11));
    assert(msm5xxx_ma3_data_write(&a, 0x01, 11));
    assert(msm5xxx_ma3_status_write(&a, 5, 11));
    assert(msm5xxx_ma3_data_write(&a, 0x55, 11));
    assert(a.host_reg[1][5] == 0x55 && a.reg[0x90] == 0x60);
    assert(msm5xxx_ma3_status_write(&a, 4, 12));
    assert(msm5xxx_ma3_data_write(&a, 0x00, 12));
    assert(msm5xxx_ma3_status_write(&a, 2, 12));
    assert(msm5xxx_ma3_data_write(&a, 0x84, 12));
    assert(msm5xxx_ma3_data_write(&a, 0xff, 12));
    assert(a.reg[4] == 0x7f && a.host_reg[0][4] == 0);
    assert(msm5xxx_ma3_pop_operation(&a, &op) && op.address == 4);
    assert(msm5xxx_ma3_status_write(&a, 3, 12));
    assert(msm5xxx_ma3_data_write(&a, 0x10, 12));
    assert(msm5xxx_ma3_data_write(&a, 0x81, 12));
    assert(msm5xxx_ma3_data_write(&a, 0x80, 12));
    assert(msm5xxx_ma3_status_read(&a) & 0x10);
    assert(msm5xxx_ma3_status_write(&a, 0x11, 12));
    assert(msm5xxx_ma3_data_read(&a, &value, 12) && value == 0x60);
    assert(msm5xxx_ma3_status_write(&a, 2, 12));
    assert(msm5xxx_ma3_data_write(&a, 0x10, 12));
    assert(msm5xxx_ma3_data_write(&a, 0x81, 12));
    assert(msm5xxx_ma3_data_write(&a, 0xff, 12));
    assert(a.reg[0x90] == 0x7f);
    assert(msm5xxx_ma3_pop_operation(&a, &op));
    assert(op.address == 0x90 && op.value == 0x7f && op.timestamp_ns == 12);
    assert(msm5xxx_ma3_status_write(&a, 2, 13));
    assert(msm5xxx_ma3_data_write(&a, 0x00, 13));
    assert(msm5xxx_ma3_data_write(&a, 0x00, 13));
    assert(msm5xxx_ma3_data_write(&a, 0x81, 13));
    assert(msm5xxx_ma3_data_write(&a, 0x81, 13));
    assert(msm5xxx_ma3_data_write(&a, 0xff, 13));
    assert(a.memory[0x4000] == 0xff);
    assert(msm5xxx_ma3_status_write(&a, 1, 20));
    assert(msm5xxx_ma3_data_write(&a, 0x80, 20));
    assert(msm5xxx_ma3_data_write(&a, 0x10, 20));
    assert(msm5xxx_ma3_data_write(&a, 0x81, 20));
    assert(msm5xxx_ma3_data_write(&a, 0xff, 20));
    assert(msm5xxx_ma3_fifo_occupancy(&a) == 4);
    assert(msm5xxx_ma3_status_read(&a) & 0x01);
    assert(!(msm5xxx_ma3_status_read(&a) & 0x02));
    assert(!(msm5xxx_ma3_status_read(&a) & 0x04));
    a.reg[350] = 0x06;
    a.reg[351] = 0x60;
    a.fifo[0] = 0x81;
    a.fifo[1] = 0x10;
    a.fifo[2] = 0x81;
    a.fifo[3] = 0xff;
    a.fifo_count = 4;
    a.running = true;
    assert(msm5xxx_ma3_next_deadline(&a, &deadline) && deadline == 20);
    assert(msm5xxx_ma3_advance(&a, 20, &op));
    assert(msm5xxx_ma3_next_deadline(&a, &deadline) && deadline == 1000020);
    assert(msm5xxx_ma3_advance(&a, 10000020, &op));
    assert(msm5xxx_ma3_advance(&a, 10000020, &op));
    assert(msm5xxx_ma3_advance(&a, 10000020, &op));
    assert(op.kind == MSM5XXX_MA3_OP_REGISTER_WRITE);
    assert(op.address == 0x90 && op.value == 0x7f);
    assert(op.timestamp_ns == 1000020);
    assert(msm5xxx_ma3_pop_operation(&a, &op));
    assert(op.kind == MSM5XXX_MA3_OP_REGISTER_WRITE);
    assert(op.address == 0x90 && op.value == 0x7f);
    assert(op.timestamp_ns == 1000020);
    assert(a.reg[0x90] == 0x7f);

    msm5xxx_ma3_reset(&a);
    a.reg[350] = 0x06;
    a.reg[351] = 0x60;
    a.running = true;
    assert(msm5xxx_ma3_status_write(&a, 1, 20));
    assert(msm5xxx_ma3_data_write(&a, 0x82, 20));
    assert(msm5xxx_ma3_advance(&a, 20, &op));
    assert(a.stream_phase == 1 && a.fifo_count == 0);
    assert(a.stream_ready_ns == 2000020);
    assert(msm5xxx_ma3_data_write(&a, 0x90, 1000020));
    assert(msm5xxx_ma3_data_write(&a, 0xff, 1000020));
    assert(a.stream_ready_ns == 2000020);
    assert(msm5xxx_ma3_advance(&a, 1000020, &op));
    assert(op.kind == MSM5XXX_MA3_OP_NONE);
    assert(msm5xxx_ma3_advance(&a, 2000020, &op));
    assert(msm5xxx_ma3_advance(&a, 2000020, &op));
    assert(op.kind == MSM5XXX_MA3_OP_REGISTER_WRITE);
    assert(op.address == 0x10 && op.value == 0x7f);
    assert(op.timestamp_ns == 2000020);

    msm5xxx_ma3_reset(&a);
    a.reg[350] = 0x06;
    a.reg[351] = 0x60;
    a.running = true;
    assert(msm5xxx_ma3_status_write(&a, 1, 20));
    assert(msm5xxx_ma3_data_write(&a, 0x82, 20));
    assert(msm5xxx_ma3_data_write(&a, 0x61, 20));
    assert(msm5xxx_ma3_data_write(&a, 0x82, 20));
    assert(msm5xxx_ma3_data_write(&a, 0x81, 20));
    assert(msm5xxx_ma3_advance(&a, 20, &op));
    assert(msm5xxx_ma3_advance(&a, 5000020, &op));
    assert(msm5xxx_ma3_advance(&a, 5000020, &op));
    assert(msm5xxx_ma3_advance(&a, 5000020, &op));
    assert(op.kind == MSM5XXX_MA3_OP_REGISTER_WRITE);
    assert(op.address == 353 && op.value == 1);
    assert(op.timestamp_ns == 2000020);
    assert(a.stream_cursor_ns == 2000020 && a.stream_ready_ns == 2000020);

    msm5xxx_ma3_reset(&a);
    assert(msm5xxx_ma3_status_write(&a, 2, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x00, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x00, 0));
    assert(!msm5xxx_ma3_data_write(&a, 0x84, 0));
    assert(a.rejected && a.reg[0] == 0 && a.operation_count == 0);

    msm5xxx_ma3_reset(&a);
    a.running = true;
    assert(msm5xxx_ma3_status_write(&a, 1, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x80, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x00, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x00, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x84, 0));
    assert(msm5xxx_ma3_data_write(&a, 0xff, 0));
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(a.rejected && a.reg[0] == 0 && a.operation_count == 0);

    msm5xxx_ma3_reset(&a);
    a.running = true;
    assert(msm5xxx_ma3_status_write(&a, 1, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x80, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x01, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x02, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x03, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x80, 0));
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(a.rejected && a.stream_phase == 0);
    assert(a.stream_address_length == 0 && a.stream_delta == 0);

    /* Software interrupts latch bits 0..3; the line is masked by register
     * 354 and flags clear by write-one-to-clear through mode zero. */
    msm5xxx_ma3_reset(&a);
    write_reg(&a, 354, 0x02, 0);
    write_reg(&a, 345, 0x02, 10);
    assert(a.interrupt_flags == 0x02);
    assert(!msm5xxx_ma3_irq_line_level(&a));
    assert(msm5xxx_ma3_status_write(&a, 0x80, 10));
    assert(msm5xxx_ma3_irq_line_level(&a));
    assert(msm5xxx_ma3_status_write(&a, 0, 10));
    assert(!msm5xxx_ma3_irq_line_level(&a));
    assert(msm5xxx_ma3_status_write(&a, 0, 10));
    assert(msm5xxx_ma3_data_write(&a, 0x02, 10));
    assert(a.interrupt_flags == 0 && !msm5xxx_ma3_irq_line_level(&a));

    /* Firmware's timer 0 setup uses base=27/count=20, giving 19.98 ms.
     * It raises flag bit 5 on guest time, repeats, and clears by W1C. */
    write_reg(&a, 338, 27, 20);
    write_reg(&a, 340, 20, 20);
    write_reg(&a, 354, 0x20, 20);
    write_reg(&a, 341, 1, 20);
    assert(msm5xxx_ma3_status_write(&a, 0x80, 20));
    assert(msm5xxx_ma3_next_timer_deadline(&a, &deadline));
    assert(deadline == 20 + (uint64_t)27 * 20 * 1000000000u / 27027u);
    assert(msm5xxx_ma3_advance_time(&a, deadline - 1));
    assert(!(a.interrupt_flags & 0x20));
    assert(msm5xxx_ma3_advance_time(&a, deadline));
    assert((a.interrupt_flags & 0x20) && msm5xxx_ma3_irq_line_level(&a));
    assert(msm5xxx_ma3_next_timer_deadline(&a, &deadline));
    assert(deadline > a.now_ns);
    assert(msm5xxx_ma3_status_write(&a, 0, a.now_ns));
    assert(msm5xxx_ma3_data_write(&a, 0x20, a.now_ns));
    assert(!(a.interrupt_flags & 0x20));

    /* Firmware writes the sequencer base time high byte at 350, then low
     * byte at 351. 8640 ticks * 10 counts is 100 ms; one-shot stops it. */
    msm5xxx_ma3_reset(&a);
    write_reg(&a, 350, 0x43, 0);
    write_reg(&a, 351, 0x40, 0); /* 8640 ticks */
    write_reg(&a, 343, 10, 0);
    write_reg(&a, 344, 7, 0);
    assert(msm5xxx_ma3_next_timer_deadline(&a, &deadline));
    assert(deadline == 100000000u);
    assert(msm5xxx_ma3_advance_time(&a, deadline));
    assert(a.interrupt_flags & 0x40);
    assert(!msm5xxx_ma3_next_timer_deadline(&a, &deadline));

    /* A one-tick sequencer base is 864 ticks / 864 kHz = 1 ms. */
    msm5xxx_ma3_reset(&a);
    write_reg(&a, 350, 6, 0);
    write_reg(&a, 351, 96, 0);
    write_reg(&a, 343, 10, 0);
    write_reg(&a, 344, 5, 0);
    assert(msm5xxx_ma3_next_timer_deadline(&a, &deadline));
    assert(deadline == 10000000u);

    /* Firmware starts the delayed sequencer with register 354 = 0x7f while
     * registering the FIFO handler. FIFO source 7 is not masked by that
     * seven-bit setting; the host status bit still gates the IRQ output. */
    msm5xxx_ma3_reset(&a);
    write_reg(&a, 354, 0x7f, 0);
    assert(a.reg[354] == 0x7f);
    assert(msm5xxx_ma3_status_write(&a, 0x80, 0));
    a.running = true;
    a.mode = 1;
    a.fifo[0] = 0x80;
    a.fifo_count = 1;
    assert(msm5xxx_ma3_advance(&a, 0, &op));
    assert(a.interrupt_flags & 0x80);
    assert(msm5xxx_ma3_irq_line_level(&a));
    assert(msm5xxx_ma3_status_write(&a, 0, 0));
    assert(!msm5xxx_ma3_irq_line_level(&a));
    assert(msm5xxx_ma3_status_write(&a, 0, 0));
    assert(msm5xxx_ma3_data_write(&a, 0x80, 0));
    assert(a.interrupt_flags == 0);

    /* The delayed stream accepts a full 1024-byte burst and reports full
     * only at its actual boundary. */
    msm5xxx_ma3_reset(&a);
    assert(msm5xxx_ma3_status_write(&a, 1, 0));
    for (unsigned i = 0; i < 1024; ++i) {
        assert(msm5xxx_ma3_data_write(&a, 0x80, 0));
        assert(msm5xxx_ma3_fifo_occupancy(&a) == i + 1);
        assert(!!(msm5xxx_ma3_status_read(&a) & 8) == (i == 1023));
    }
    assert(!msm5xxx_ma3_data_write(&a, 0x80, 0));
    assert(msm5xxx_ma3_fifo_occupancy(&a) == 1024);
    return 0;
}
''', encoding="utf-8")
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(repo / "native" / "qemu"), str(source),
                str(repo / "native" / "qemu" / "msm5xxx-ma3-audio.c"),
                "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
