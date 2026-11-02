/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma3-audio.h"

#include <string.h>

#define MA3_MODE_DELAYED 1u
#define MA3_MODE_IMMEDIATE 2u
#define MA3_MODE_READ 3u
#define MA3_MODE_IRQ 0u
#define MA3_IRQ_FIFO 0x80u
#define MA3_IRQ_TIMER0 0x20u
#define MA3_IRQ_TIMER1 0x40u
#define MA3_TIMER0_COUNT 339u
#define MA3_TIMER0_TIME 340u
#define MA3_TIMER0_CTRL 341u
#define MA3_TIMER1_COUNT 342u
#define MA3_TIMER1_TIME 343u
#define MA3_TIMER1_CTRL 344u
#define MA3_SOFTINT_CTRL 345u

static uint32_t ma3_decode_address(const uint8_t *bytes, unsigned count)
{
    uint32_t address = 0;
    unsigned i;

    for (i = 0; i < count; i++) {
        address |= (uint32_t)(bytes[i] & 0x7fu) << (i * 7u);
    }
    return address;
}

static void ma3_queue_operation(MSM5xxxMA3Audio *audio, uint16_t address,
                                uint8_t value, uint64_t timestamp_ns)
{
    MSM5xxxMA3Operation *op;
    if (audio->operation_count == MSM5XXX_MA3_OPERATION_CAPACITY) {
        audio->rejected = true;
        return;
    }
    op = &audio->operation_queue[audio->operation_write];
    op->kind = MSM5XXX_MA3_OP_REGISTER_WRITE;
    op->timestamp_ns = timestamp_ns;
    op->address = address;
    op->value = value;
    op->bank = 0;
    audio->operation_write = (audio->operation_write + 1u) %
                             MSM5XXX_MA3_OPERATION_CAPACITY;
    audio->operation_count++;
}

static void ma3_abort_stream_event(MSM5xxxMA3Audio *audio)
{
    audio->rejected = true;
    audio->stream_phase = 0;
    audio->stream_address_length = 0;
    audio->stream_address = 0;
    audio->stream_delta = 0;
}

static uint64_t ma3_timer_period(const MSM5xxxMA3Audio *audio,
                                unsigned timer)
{
    unsigned count;
    uint64_t base;

    if (timer == 0u) {
        if (audio->reg[MA3_TIMER0_CTRL] & 0x04u) {
            return 0;
        }
        /* Firmware uses base=0x1b,count=20 for an approximately 19.98 ms
         * service interval. The timer base is 1/27027 second. */
        count = audio->reg[MA3_TIMER0_TIME] & 0x7fu;
        return (uint64_t)(audio->reg[338] & 0x7fu) * count *
               UINT64_C(1000000000) / UINT64_C(27027);
    }

    /* Timer 1 counts sequencer base-time ticks. */
    if (!(audio->reg[MA3_TIMER1_CTRL] & 0x04u)) {
        return 0;
    }
    count = audio->reg[MA3_TIMER1_TIME] & 0x7fu;
    base = ((uint64_t)(audio->reg[350] & 0x7fu) << 7u) |
           (uint64_t)(audio->reg[351] & 0x7fu);
    if (!base || !count) {
        return 0;
    }
    return base * count * UINT64_C(1000000000) / UINT64_C(864000);
}

static void ma3_timer_start(MSM5xxxMA3Audio *audio, unsigned timer,
                            uint64_t now_ns)
{
    unsigned ctrl = audio->reg[timer == 0u ? MA3_TIMER0_CTRL :
                                                MA3_TIMER1_CTRL];
    audio->timer_active[timer] = (ctrl & 1u) != 0u;
    audio->timer_period_ns[timer] = ma3_timer_period(audio, timer);
    if (audio->timer_active[timer] && audio->timer_period_ns[timer]) {
        audio->timer_deadline_ns[timer] = now_ns +
                                          audio->timer_period_ns[timer];
    } else {
        audio->timer_deadline_ns[timer] = 0;
    }
}

static uint8_t ma3_timer_count(const MSM5xxxMA3Audio *audio,
                               unsigned timer)
{
    unsigned time_address = timer == 0u ? MA3_TIMER0_TIME : MA3_TIMER1_TIME;
    uint64_t period = audio->timer_period_ns[timer];
    uint64_t remaining;
    uint64_t count;

    if (!audio->timer_active[timer] || !period ||
        !audio->timer_deadline_ns[timer]) {
        return audio->reg[time_address] & 0x7fu;
    }
    remaining = audio->timer_deadline_ns[timer] > audio->now_ns ?
                audio->timer_deadline_ns[timer] - audio->now_ns : 0;
    count = (remaining * (audio->reg[time_address] & 0x7fu) + period - 1u) /
            period;
    return (uint8_t)(count > 127u ? 127u : count);
}

static uint8_t ma3_read_register(const MSM5xxxMA3Audio *audio,
                                 unsigned address)
{
    if (address == MA3_TIMER0_COUNT) {
        return ma3_timer_count(audio, 0u);
    }
    if (address == MA3_TIMER1_COUNT) {
        return ma3_timer_count(audio, 1u);
    }
    return audio->reg[address];
}

bool msm5xxx_ma3_advance_time(MSM5xxxMA3Audio *audio, uint64_t now_ns)
{
    static const uint8_t flags[2] = { MA3_IRQ_TIMER0, MA3_IRQ_TIMER1 };
    unsigned timer;

    if (!audio || now_ns < audio->now_ns) {
        if (audio) {
            audio->rejected = true;
        }
        return false;
    }
    audio->now_ns = now_ns;
    for (timer = 0; timer < 2u; timer++) {
        uint64_t period = audio->timer_period_ns[timer];
        unsigned ctrl_address = timer == 0u ? MA3_TIMER0_CTRL :
                                             MA3_TIMER1_CTRL;
        if (!audio->timer_active[timer] || !period ||
            !audio->timer_deadline_ns[timer] ||
            audio->timer_deadline_ns[timer] > now_ns) {
            continue;
        }
        audio->interrupt_flags |= flags[timer];
        if (audio->reg[ctrl_address] & 0x02u) {
            audio->timer_active[timer] = false;
            audio->timer_deadline_ns[timer] = 0;
        } else {
            uint64_t elapsed = now_ns - audio->timer_deadline_ns[timer];
            uint64_t periods = elapsed / period + 1u;
            if (periods > (UINT64_MAX - audio->timer_deadline_ns[timer]) /
                          period) {
                audio->timer_deadline_ns[timer] = UINT64_MAX;
            } else {
                audio->timer_deadline_ns[timer] += periods * period;
            }
        }
    }
    return true;
}

bool msm5xxx_ma3_next_timer_deadline(const MSM5xxxMA3Audio *audio,
                                    uint64_t *deadline_ns)
{
    uint64_t deadline = UINT64_MAX;
    unsigned timer;

    if (!audio || !deadline_ns) {
        return false;
    }
    for (timer = 0; timer < 2u; timer++) {
        if (audio->timer_active[timer] && audio->timer_deadline_ns[timer] &&
            audio->timer_deadline_ns[timer] < deadline) {
            deadline = audio->timer_deadline_ns[timer];
        }
    }
    if (deadline == UINT64_MAX) {
        return false;
    }
    *deadline_ns = deadline;
    return true;
}

bool msm5xxx_ma3_irq_line_level(const MSM5xxxMA3Audio *audio)
{
    if (!audio || !audio->host_irq_enabled) {
        return false;
    }
    return ((audio->interrupt_flags & 0x7fu) & (audio->reg[354] & 0x7fu)) ||
           (audio->interrupt_flags & MA3_IRQ_FIFO);
}

void msm5xxx_ma3_reset(MSM5xxxMA3Audio *audio)
{
    unsigned i;

    if (!audio) {
        return;
    }
    memset(audio, 0, sizeof(*audio));
    for (i = 0x90; i <= 0x9f; i++) {
        audio->reg[i] = 0x60;
    }
    for (i = 0xa0; i <= 0xaf; i++) {
        audio->reg[i] = 0x3c;
    }
    for (i = 0x14a; i <= 0x151; i++) {
        audio->reg[i] = 0x40;
    }
    audio->fifo_empty_time_ns = 1;
}

bool msm5xxx_ma3_status_write(MSM5xxxMA3Audio *audio, uint8_t value,
                              uint64_t now_ns)
{
    if (!audio || now_ns < audio->now_ns) {
        if (audio) {
            audio->rejected = true;
        }
        return false;
    }
    if (!msm5xxx_ma3_advance_time(audio, now_ns)) {
        return false;
    }
    audio->host_irq_enabled = (value & 0x80u) != 0u;
    if (value == 0x80) {
        return true;
    }
    if (value & 0x70u) {
        unsigned buffer;
        for (buffer = 0; buffer < 3; buffer++) {
            if (value & (0x10u << buffer)) {
                audio->selector = (uint8_t)buffer;
                return true;
            }
        }
    }
    audio->mode = value;
    audio->address_length = 0;
    audio->address_complete = false;
    audio->selector_pending = false;
    return true;
}

static bool ma3_write_register(MSM5xxxMA3Audio *audio, uint16_t address,
                               uint8_t value, uint64_t now_ns)
{
    if (address >= MSM5XXX_MA3_ADDRESS_SPACE) {
        audio->rejected = true;
        return false;
    }
    if (address >= MSM5XXX_MA3_REGISTER_COUNT) {
        audio->memory[address] = value;
        return true;
    }
    audio->memory[address] = value;
    audio->reg[address] = value;
    if (address == MA3_TIMER0_TIME || address == 338u ||
        address == MA3_TIMER0_CTRL) {
        ma3_timer_start(audio, 0u, now_ns);
    } else if (address == MA3_TIMER1_TIME || address == MA3_TIMER1_CTRL ||
               address == 350u || address == 351u) {
        ma3_timer_start(audio, 1u, now_ns);
    } else if (address == MA3_SOFTINT_CTRL) {
        audio->interrupt_flags |= value & 0x0fu;
    }
    if (address == 353) {
        audio->running = (value & 1u) != 0;
        if (audio->running) {
            audio->next_fifo_ns = now_ns;
            audio->stream_cursor_ns = now_ns;
            audio->stream_ready_ns = now_ns;
        }
    }
    return true;
}

bool msm5xxx_ma3_data_write(MSM5xxxMA3Audio *audio, uint8_t value,
                            uint64_t now_ns)
{
    if (!audio || now_ns < audio->now_ns) {
        if (audio) {
            audio->rejected = true;
        }
        return false;
    }
    if (!msm5xxx_ma3_advance_time(audio, now_ns)) {
        return false;
    }
    if (audio->mode == MA3_MODE_IRQ) {
        audio->interrupt_flags &= (uint8_t)~value;
        return true;
    }
    if (audio->mode >= 4u && audio->mode <= 14u) {
        if (audio->mode == 4u && (value & 0x80u)) {
            uint8_t mode = audio->mode;
            msm5xxx_ma3_reset(audio);
            audio->mode = mode;
            audio->now_ns = now_ns;
            audio->host_reg[0][4] = value;
            audio->host_bank = 0;
        } else if (audio->mode == 4u && value == 0x28u) {
            audio->host_reg[0][4] = value;
            audio->host_bank = value & 1u;
            audio->fifo_read = audio->fifo_write = audio->fifo_count = 0;
            audio->stream_phase = 0;
            audio->stream_delta = 0;
            audio->stream_address = 0;
            audio->stream_ready_ns = now_ns;
            audio->stream_cursor_ns = now_ns;
        } else if (audio->mode == 4u) {
            audio->host_reg[0][4] = value;
            audio->host_bank = value & 1u;
        } else {
            audio->host_reg[audio->host_bank][audio->mode] = value;
        }
        return true;
    }
    if (audio->mode == MA3_MODE_DELAYED) {
        if (audio->fifo_count == MSM5XXX_MA3_FIFO_CAPACITY) {
            audio->rejected = true;
            return false;
        }
        if (!audio->fifo_count && audio->stream_phase == 0 &&
            audio->stream_address_length == 0 && audio->stream_delta == 0) {
            audio->stream_cursor_ns = now_ns;
            audio->stream_ready_ns = now_ns;
        }
        audio->fifo[audio->fifo_write] = value;
        audio->fifo_write = (audio->fifo_write + 1u) % MSM5XXX_MA3_FIFO_CAPACITY;
        audio->fifo_count++;
        return true;
    }
    if (audio->mode == MA3_MODE_IMMEDIATE && audio->ram_upload_data) {
        if (audio->address >= MSM5XXX_MA3_ADDRESS_SPACE) {
            audio->rejected = true;
            return false;
        }
        audio->memory[audio->address++] = value;
        if (--audio->ram_upload_count == 0) {
            audio->ram_upload_data = false;
            audio->address_complete = false;
            audio->address_length = 0;
        }
        return true;
    }
    if (audio->mode != MA3_MODE_IMMEDIATE && audio->mode != MA3_MODE_DELAYED &&
        audio->mode != MA3_MODE_READ) {
        return true;
    }
    if (!audio->address_complete) {
        if (audio->address_length >= 3) {
            audio->rejected = true;
            return false;
        }
        audio->address_bytes[audio->address_length++] = value;
        if (value & 0x80u) {
            uint32_t address = ma3_decode_address(audio->address_bytes,
                                                  audio->address_length);
            if (address >= MSM5XXX_MA3_ADDRESS_SPACE) {
                audio->address_length = 0;
                audio->address_complete = false;
                audio->rejected = true;
                return false;
            }
            audio->address = (uint16_t)address;
            audio->address_complete = true;
            audio->address_length = 0;
            if (audio->mode == MA3_MODE_READ) {
                audio->selector_pending = true;
            } else if (audio->mode == MA3_MODE_IMMEDIATE &&
                       audio->address >= 0x4000u &&
                       audio->address < MSM5XXX_MA3_ADDRESS_SPACE) {
                audio->ram_upload_length = true;
                audio->ram_upload_count = 0;
            }
        }
        return true;
    }
    if (audio->selector_pending) {
        audio->selector = value;
        audio->selector_pending = false;
        if ((value & 3u) >= 3u) {
            audio->rejected = true;
            return false;
        }
        audio->read_buffer[value & 3u] =
            audio->address < MSM5XXX_MA3_REGISTER_COUNT ?
            ma3_read_register(audio, audio->address) :
            audio->address < MSM5XXX_MA3_ADDRESS_SPACE ?
            audio->memory[audio->address] : 0xff;
        audio->read_valid |= (uint8_t)(0x10u << (value & 3u));
        return true;
    }
    if (audio->ram_upload_length) {
        if (audio->address_length >= 2u) {
            audio->rejected = true;
            return false;
        }
        audio->ram_upload_count = (uint16_t)(audio->ram_upload_count |
                                      ((uint16_t)(value & 0x7fu) <<
                                       (audio->address_length * 7u)));
        audio->address_length++;
        if (value & 0x80u) {
            if (audio->ram_upload_count >
                MSM5XXX_MA3_ADDRESS_SPACE - audio->address) {
                audio->rejected = true;
                return false;
            }
            audio->ram_upload_length = false;
            audio->address_length = 0;
            audio->ram_upload_data = audio->ram_upload_count != 0;
            if (!audio->ram_upload_data) {
                audio->address_complete = false;
            }
        }
        return true;
    }
    if (audio->mode == MA3_MODE_IMMEDIATE) {
        if (!ma3_write_register(audio, audio->address, value & 0x7fu, now_ns)) {
            return false;
        }
        ma3_queue_operation(audio, audio->address, value & 0x7fu, now_ns);
        audio->address++;
    }
    if (value & 0x80u) {
        audio->address_complete = false;
        audio->address_length = 0;
    }
    return true;
}

uint8_t msm5xxx_ma3_status_read(const MSM5xxxMA3Audio *audio)
{
    uint8_t result;

    if (!audio) {
        return 0xff;
    }
    /* The index port returns transport/FIFO status. IRQ flags are read from
     * the data port after selecting host register zero. */
    result = 0;
    result |= 0x01;
    if (audio->fifo_count == 0) {
        result |= 0x02;
    }
    if (audio->fifo_count == MSM5XXX_MA3_FIFO_CAPACITY) {
        result |= 0x08;
    }
    result |= audio->read_valid;
    return result;
}

bool msm5xxx_ma3_data_read(MSM5xxxMA3Audio *audio, uint8_t *value,
                           uint64_t now_ns)
{
    unsigned buffer;
    if (!audio || !value || now_ns < audio->now_ns) {
        if (audio) {
            audio->rejected = true;
        }
        return false;
    }
    if (!msm5xxx_ma3_advance_time(audio, now_ns)) {
        return false;
    }
    if (audio->mode == MA3_MODE_IRQ) {
        *value = audio->interrupt_flags;
        return true;
    }
    if (audio->mode >= 4u && audio->mode <= 14u) {
        *value = audio->mode == 4u ? audio->host_reg[0][4] :
                 audio->host_reg[audio->host_bank][audio->mode];
        return true;
    }
    buffer = audio->selector & 3u;
    if (buffer > 2 || !(audio->read_valid & (0x10u << buffer))) {
        return false;
    }
    *value = audio->read_buffer[buffer];
    audio->read_valid &= (uint8_t)~(0x10u << buffer);
    return true;
}

bool msm5xxx_ma3_advance(MSM5xxxMA3Audio *audio, uint64_t now_ns,
                         MSM5xxxMA3Operation *operation)
{
    uint8_t byte;
    uint64_t base_ns;
    if (!audio || !operation || now_ns < audio->now_ns) {
        if (audio) {
            audio->rejected = true;
        }
        return false;
    }
    memset(operation, 0, sizeof(*operation));
    if (!msm5xxx_ma3_advance_time(audio, now_ns)) {
        return false;
    }
    if (!audio->running || !audio->fifo_count || now_ns < audio->stream_ready_ns) {
        return true;
    }
    byte = audio->fifo[audio->fifo_read];
    audio->fifo_read = (audio->fifo_read + 1u) % MSM5XXX_MA3_FIFO_CAPACITY;
    audio->fifo_count--;
    if (audio->stream_phase == 0) {
        if (audio->stream_address_length >= 3) {
            ma3_abort_stream_event(audio);
            return true;
        }
        audio->stream_delta |= (uint32_t)(byte & 0x7fu) <<
                               (7u * audio->stream_address_length);
        if (!(byte & 0x80u)) {
            audio->stream_address_length++;
            if (audio->stream_address_length >= 3) {
                ma3_abort_stream_event(audio);
            }
        } else {
            uint16_t ticks = (uint16_t)(audio->reg[350] & 0x7fu) << 7u |
                             (uint16_t)(audio->reg[351] & 0x7fu);
            base_ns = ticks ? (uint64_t)ticks * 1000000000u / 864000u :
                      1000000u;
            if (!audio->stream_cursor_ns) {
                audio->stream_cursor_ns = now_ns;
            }
            audio->stream_ready_ns = audio->stream_cursor_ns +
                                     audio->stream_delta * base_ns;
            audio->stream_delta = 0;
            audio->stream_address_length = 0;
            audio->stream_phase = 1;
        }
    } else if (audio->stream_phase == 1) {
        if (audio->stream_address_length >= 3) {
            ma3_abort_stream_event(audio);
            return true;
        }
        audio->stream_address |= (uint32_t)(byte & 0x7fu) <<
                                 (7u * audio->stream_address_length);
        audio->stream_address_length++;
        if (byte & 0x80u) {
            if (audio->stream_address >= MSM5XXX_MA3_ADDRESS_SPACE) {
                ma3_abort_stream_event(audio);
                return true;
            }
            audio->stream_address_length = 0;
            audio->stream_phase = 2;
        } else if (audio->stream_address_length >= 3) {
            ma3_abort_stream_event(audio);
        }
    } else {
        operation->kind = MSM5XXX_MA3_OP_REGISTER_WRITE;
        operation->timestamp_ns = audio->stream_ready_ns;
        operation->address = audio->stream_address++;
        operation->value = byte & 0x7fu;
        if (!ma3_write_register(audio, operation->address, operation->value,
                                operation->timestamp_ns)) {
            operation->kind = MSM5XXX_MA3_OP_NONE;
            ma3_abort_stream_event(audio);
            return true;
        }
        ma3_queue_operation(audio, operation->address, operation->value,
                            operation->timestamp_ns);
        audio->operations++;
        audio->stream_cursor_ns = audio->stream_ready_ns;
        if (byte & 0x80u) {
            audio->stream_phase = 0;
            audio->stream_address = 0;
        }
    }
    audio->next_fifo_ns = audio->stream_ready_ns;
    if (audio->fifo_count == 0) {
        audio->interrupt_flags |= MA3_IRQ_FIFO;
    }
    return true;
}

bool msm5xxx_ma3_next_deadline(const MSM5xxxMA3Audio *audio,
                               uint64_t *deadline_ns)
{
    if (!audio || !deadline_ns || !audio->running || !audio->fifo_count) {
        return false;
    }
    *deadline_ns = audio->stream_ready_ns > audio->now_ns ?
                   audio->stream_ready_ns : audio->now_ns;
    return true;
}

bool msm5xxx_ma3_pop_operation(MSM5xxxMA3Audio *audio,
                               MSM5xxxMA3Operation *operation)
{
    if (!audio || !operation || !audio->operation_count) {
        return false;
    }
    *operation = audio->operation_queue[audio->operation_read];
    audio->operation_read = (audio->operation_read + 1u) %
                            MSM5XXX_MA3_OPERATION_CAPACITY;
    audio->operation_count--;
    return true;
}

size_t msm5xxx_ma3_fifo_occupancy(const MSM5xxxMA3Audio *audio)
{
    return audio ? audio->fifo_count : 0;
}
