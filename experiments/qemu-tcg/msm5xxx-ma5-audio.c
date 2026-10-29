/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma5-audio.h"

#include <string.h>

void
msm5xxx_ma5_reset(MSM5xxxMA5Audio *audio)
{
    if (audio == 0) {
        return;
    }
    memset(audio, 0, sizeof(*audio));
}

bool
msm5xxx_ma5_index_write(MSM5xxxMA5Audio *audio, uint8_t index)
{
    if (audio == 0) {
        return false;
    }
    audio->index = index;
    return true;
}

static void
ma5_begin_payload(MSM5xxxMA5Audio *audio, MSM5xxxMA5Event *event)
{
    if (audio->fifo_state == MSM5XXX_MA5_REGISTER_BEGIN) {
        event->kind = MSM5XXX_MA5_EVENT_REGISTER_PACKET;
        event->delay = audio->delay;
        event->address = audio->address;
        audio->fifo_state = MSM5XXX_MA5_REGISTER_DATA;
    } else if (audio->fifo_state == MSM5XXX_MA5_VOICE_BEGIN) {
        event->kind = MSM5XXX_MA5_EVENT_VOICE_PACKET;
        event->delay = audio->delay;
        event->address = audio->address;
        event->count = audio->remaining;
        audio->fifo_state = MSM5XXX_MA5_VOICE_DATA;
    }
}

bool
msm5xxx_ma5_data_write(MSM5xxxMA5Audio *audio, uint8_t value,
                        bool block_site, MSM5xxxMA5Event *event)
{
    uint8_t payload;

    if (audio == 0 || event == 0) {
        return false;
    }
    memset(event, 0, sizeof(*event));
    event->index = audio->index;
    event->value = value;
    if (!block_site || audio->index != 1u) {
        event->kind = MSM5XXX_MA5_EVENT_IMMEDIATE_WRITE;
        return true;
    }

    ma5_begin_payload(audio, event);
    payload = (uint8_t)(value & 0x7fu);
    switch (audio->fifo_state) {
    case MSM5XXX_MA5_DELAY_0:
        audio->delay = payload;
        audio->fifo_state = (value & 0x80u) != 0u ?
            MSM5XXX_MA5_ADDRESS_0 : MSM5XXX_MA5_DELAY_1;
        break;
    case MSM5XXX_MA5_DELAY_1:
        audio->delay |= (uint32_t)payload << 7;
        audio->fifo_state = (value & 0x80u) != 0u ?
            MSM5XXX_MA5_ADDRESS_0 : MSM5XXX_MA5_DELAY_2;
        break;
    case MSM5XXX_MA5_DELAY_2:
        audio->delay |= (uint32_t)payload << 14;
        audio->fifo_state = MSM5XXX_MA5_ADDRESS_0;
        break;
    case MSM5XXX_MA5_ADDRESS_0:
        audio->address = payload;
        audio->fifo_state = (value & 0x80u) != 0u ?
            MSM5XXX_MA5_REGISTER_BEGIN : MSM5XXX_MA5_ADDRESS_1;
        break;
    case MSM5XXX_MA5_ADDRESS_1:
        audio->address |= (uint32_t)payload << 7;
        audio->fifo_state = (value & 0x80u) != 0u ?
            MSM5XXX_MA5_REGISTER_BEGIN : MSM5XXX_MA5_ADDRESS_2;
        break;
    case MSM5XXX_MA5_ADDRESS_2:
        audio->address |= (uint32_t)payload << 14;
        audio->fifo_state = MSM5XXX_MA5_COUNT_0;
        break;
    case MSM5XXX_MA5_COUNT_0:
        audio->remaining = payload;
        audio->fifo_state = (value & 0x80u) != 0u ?
            (audio->remaining != 0u ? MSM5XXX_MA5_VOICE_BEGIN :
             MSM5XXX_MA5_DELAY_0) : MSM5XXX_MA5_COUNT_1;
        break;
    case MSM5XXX_MA5_COUNT_1:
        audio->remaining |= (uint16_t)payload << 7;
        audio->fifo_state = audio->remaining != 0u ?
            MSM5XXX_MA5_VOICE_BEGIN : MSM5XXX_MA5_DELAY_0;
        break;
    case MSM5XXX_MA5_REGISTER_DATA:
        event->kind = MSM5XXX_MA5_EVENT_REGISTER_WRITE;
        event->address = audio->address;
        event->value = payload;
        event->terminal = (value & 0x80u) != 0u;
        if (audio->address < MSM5XXX_MA5_REGISTER_COUNT) {
            audio->register_shadow[audio->address] = payload;
        }
        audio->address++;
        if (event->terminal) {
            audio->fifo_state = MSM5XXX_MA5_DELAY_0;
        }
        break;
    case MSM5XXX_MA5_VOICE_DATA:
        event->kind = MSM5XXX_MA5_EVENT_VOICE_WRITE;
        event->address = audio->address;
        if (--audio->remaining != 0u) {
            audio->address++;
        } else {
            audio->fifo_state = MSM5XXX_MA5_DELAY_0;
        }
        break;
    case MSM5XXX_MA5_REGISTER_BEGIN:
    case MSM5XXX_MA5_VOICE_BEGIN:
        break;
    }
    if (event->kind == MSM5XXX_MA5_EVENT_NONE) {
        ma5_begin_payload(audio, event);
    }
    return true;
}

bool
msm5xxx_ma5_shadow_read(const MSM5xxxMA5Audio *audio,
                         uint32_t address, uint8_t *value)
{
    if (audio == 0 || value == 0 ||
        address >= MSM5XXX_MA5_REGISTER_COUNT) {
        return false;
    }
    *value = audio->register_shadow[address];
    return true;
}


enum {
    MA5_CURSOR_ADDRESS,
    MA5_CURSOR_CONTROL,
    MA5_CURSOR_LENGTH,
    MA5_CURSOR_MEMORY,
    MA5_CURSOR_READ_BUFFER,
};

void
msm5xxx_ma5_readback_init(MSM5xxxMA5Readback *audio)
{
    if (audio == NULL) {
        return;
    }
    memset(audio, 0, sizeof(*audio));
    memset(audio->control + 192u, 0x60, 16u);
    memset(audio->control + 208u, 0x3c, 16u);
}

bool
msm5xxx_ma5_readback_index(MSM5xxxMA5Readback *audio, uint8_t value)
{
    if (audio == NULL) {
        return false;
    }
    audio->index = value & 0x3fu;
    audio->irq_enabled = (value & 0x80u) != 0u;
    if (value & MSM5XXX_MA5_VALID_R) {
        audio->read_valid = false;
    }
    return true;
}

static bool
ma5_readback_reject(MSM5xxxMA5Readback *audio,
                    MSM5xxxMA5ByteCursor *cursor)
{
    audio->rejected++;
    memset(cursor, 0, sizeof(*cursor));
    return false;
}

static bool
ma5_readback_complete(MSM5xxxMA5Readback *audio,
                      MSM5xxxMA5ByteCursor *cursor, uint8_t buffer)
{
    uint32_t address = cursor->address;
    uint8_t value;

    if (buffer != 0x80u) {
        return ma5_readback_reject(audio, cursor);
    }
    if (cursor->address_bytes < 3u) {
        if (address >= MSM5XXX_MA5_REGISTER_COUNT) {
            return ma5_readback_reject(audio, cursor);
        }
        value = audio->control[address];
        audio->read_from_sram = false;
        audio->read_control_guest_written =
            (audio->control_guest_written[address / 8u] &
             (uint8_t)(1u << (address % 8u))) != 0u;
    } else {
        /* No ROM contents are invented for unsupported device revisions. */
        if (address < MSM5XXX_MA5_SRAM_BASE ||
            address >= MSM5XXX_MA5_SRAM_BASE + MSM5XXX_MA5_SRAM_SIZE) {
            return ma5_readback_reject(audio, cursor);
        }
        value = audio->sram[address - MSM5XXX_MA5_SRAM_BASE];
        audio->read_from_sram = true;
        audio->read_control_guest_written = false;
    }
    audio->read_address = address;
    audio->read_latch = value;
    audio->read_valid = true;
    memset(cursor, 0, sizeof(*cursor));
    return true;
}

static bool
ma5_readback_byte(MSM5xxxMA5Readback *audio, MSM5xxxMA5ByteCursor *cursor,
                  bool reading, uint8_t value)
{
    uint8_t payload = value & 0x7fu;
    bool accepted = true;

    if (audio == NULL) {
        return false;
    }
    audio->control_write_valid = false;
    switch (cursor->phase) {
    case MA5_CURSOR_ADDRESS:
        cursor->address |= (uint32_t)payload << (7u * cursor->address_bytes);
        cursor->address_bytes++;
        if (value & 0x80u) {
            cursor->phase = reading ? MA5_CURSOR_READ_BUFFER :
                (cursor->address_bytes == 3u ? MA5_CURSOR_LENGTH :
                 MA5_CURSOR_CONTROL);
        } else if (cursor->address_bytes == 3u) {
            return ma5_readback_reject(audio, cursor);
        }
        return true;
    case MA5_CURSOR_READ_BUFFER:
        return ma5_readback_complete(audio, cursor, value);
    case MA5_CURSOR_CONTROL:
        if (cursor->address < MSM5XXX_MA5_REGISTER_COUNT) {
            audio->control[cursor->address] = payload;
            audio->control_guest_written[cursor->address / 8u] |=
                (uint8_t)(1u << (cursor->address % 8u));
            audio->control_writes++;
            audio->control_write_address = cursor->address;
            audio->control_write_raw = value;
            audio->control_write_valid = true;
        } else {
            if (!cursor->discard) {
                audio->rejected++;
            }
            cursor->discard = true;
            accepted = false;
        }
        cursor->address++;
        if (value & 0x80u) {
            memset(cursor, 0, sizeof(*cursor));
        }
        return accepted;
    case MA5_CURSOR_LENGTH:
        cursor->length |= (uint16_t)((uint16_t)payload <<
                                    (7u * cursor->length_bytes));
        cursor->length_bytes++;
        if (!(value & 0x80u)) {
            return cursor->length_bytes == 2u ?
                ma5_readback_reject(audio, cursor) : true;
        }
        if (cursor->length == 0u) {
            return ma5_readback_reject(audio, cursor);
        }
        cursor->remaining = cursor->length;
        cursor->phase = MA5_CURSOR_MEMORY;
        return true;
    case MA5_CURSOR_MEMORY:
        if (cursor->address >= MSM5XXX_MA5_SRAM_BASE + MSM5XXX_MA5_SRAM_SIZE) {
            if (!cursor->discard) {
                audio->rejected++;
            }
            cursor->discard = true;
        }
        if (!cursor->discard && cursor->address >= MSM5XXX_MA5_SRAM_BASE) {
            audio->sram[cursor->address - MSM5XXX_MA5_SRAM_BASE] = value;
            audio->sram_writes++;
        }
        /* ROM writes are consumed without making the ROM writable. */
        accepted = !cursor->discard;
        cursor->address++;
        if (--cursor->remaining == 0u) {
            memset(cursor, 0, sizeof(*cursor));
        }
        return accepted;
    default:
        return ma5_readback_reject(audio, cursor);
    }
}

bool
msm5xxx_ma5_readback_consume(MSM5xxxMA5Readback *audio,
                             uint8_t port, uint8_t value)
{
    if (audio == NULL) {
        return false;
    }
    if (port != 2u && port != 3u) {
        audio->control_write_valid = false;
        audio->rejected++;
        return false;
    }
    return ma5_readback_byte(audio, port == 2u ? &audio->immediate : &audio->read,
                             port == 3u, value);
}

bool
msm5xxx_ma5_readback_data(const MSM5xxxMA5Readback *audio, uint8_t *value)
{
    if (audio == NULL || value == NULL || audio->index != 1u) {
        return false;
    }
    *value = audio->read_latch;
    return true;
}

uint8_t
msm5xxx_ma5_readback_status(const MSM5xxxMA5Readback *audio)
{
    return audio != NULL && audio->read_valid ? MSM5XXX_MA5_VALID_R : 0u;
}

static void ma5_device_irq_update(MSM5xxxMA5Device *device)
{
    bool condition = device->delayed_count <= (device->b[37] & 7u) * 64u;
    bool edge = (device->b[55] & 2u) != 0u;

    if (device->fifo_mode_known) {
        if (condition && (!edge || !device->fifo_condition)) {
            device->pending |= 0x80u;
        } else if (!edge && !condition) {
            device->pending &= ~0x80u;
        }
    }
    device->fifo_condition = condition;
}

bool msm5xxx_ma5_device_init(MSM5xxxMA5Device *device, uint64_t period_ns)
{
    if (device == NULL) {
        return false;
    }
    memset(device, 0, sizeof(*device));
    msm5xxx_ma5_readback_init(&device->backing);
    /* shortcut: B56 cold shadow only; physical retention/execution unverified. */
    device->b[56] = 0;
    device->period_ns = period_ns;
    if (!period_ns) {
        device->reject = MSM5XXX_MA5_REJECT_CLOCK;
        return false;
    }
    return true;
}

bool msm5xxx_ma5_device_set_clock(MSM5xxxMA5Device *device, uint64_t clki_hz)
{
    if (device == NULL) {
        return false;
    }
    if (device->reject || device->accessed || device->clki_hz ||
        device->target_rate_hz || !clki_hz || clki_hz > UINT64_C(1000000000)) {
        device->reject = MSM5XXX_MA5_REJECT_CLOCK;
        return false;
    }
    device->clki_hz = clki_hz;
    return true;
}

bool msm5xxx_ma5_device_set_target_rate(MSM5xxxMA5Device *device,
                                       uint64_t target_rate_hz)
{
    if (device == NULL) {
        return false;
    }
    if (device->reject || device->accessed || device->clki_hz ||
        device->target_rate_hz || target_rate_hz < 8000u ||
        target_rate_hz > 96000u) {
        device->reject = MSM5XXX_MA5_REJECT_CLOCK;
        return false;
    }
    device->target_rate_hz = target_rate_hz;
    return true;
}

static bool ma5_infer_clki(MSM5xxxMA5Device *device)
{
    uint64_t adjust1, adjust2, numerator;

    if (!device->target_rate_hz || !device->b_written[30] ||
        !device->b_written[31]) {
        return true;
    }
    if (!((device->b[30] == 0x14u && device->b[31] == 0x4bu) ||
          (device->b[30] == 0x95u && device->b[31] == 0x51u))) {
        device->reject = MSM5XXX_MA5_REJECT_CLOCK;
        return false;
    }
    adjust1 = device->b[30] & 0x1fu;
    adjust2 = device->b[31] & 0x7fu;
    numerator = device->target_rate_hz * UINT64_C(1536) * adjust1;
    device->clki_hz = (numerator + adjust2 / 2u) / adjust2;
    if (!device->clki_hz || device->clki_hz > UINT64_C(1000000000)) {
        device->clki_hz = 0;
        device->reject = MSM5XXX_MA5_REJECT_CLOCK;
        return false;
    }
    device->clki_inferred = true;
    return true;
}

static void ma5_counter_advance(MSM5xxxMA5Device *device, uint64_t now_ns)
{
    const uint32_t mask = 0x1fffffu;
    uint64_t elapsed, remainder = 0, fraction, ticks;

    if (!device->counter_running) {
        return;
    }
    if (now_ns < device->counter_last_ns) {
        device->reject = MSM5XXX_MA5_REJECT_CLOCK;
        return;
    }
    elapsed = now_ns - device->counter_last_ns;
    if (!elapsed) {
        return;
    }
    /* Admitted clock/pairs imply numerator < denominator (<1 tick/ns). */
    fraction = device->counter_num;
    /* Long division keeps elapsed*fraction exact without a 128-bit product. */
    uint64_t fractional_ticks = 0;
    for (unsigned bit = 64; bit-- > 0;) {
        remainder = remainder * 2u + ((elapsed >> bit & 1u) ? fraction : 0u);
        fractional_ticks = fractional_ticks * 2u +
                           remainder / device->counter_den;
        remainder %= device->counter_den;
    }
    remainder += device->counter_phase;
    ticks = fractional_ticks + remainder / device->counter_den;
    device->counter_phase = remainder % device->counter_den;
    if (device->counter_total > UINT64_MAX - ticks) {
        device->reject = MSM5XXX_MA5_REJECT_CLOCK;
        return;
    }
    device->counter_total += ticks;
    device->counter = device->counter_total & mask;
    device->counter_last_ns = now_ns;
}

static bool ma5_delayed_deadline(MSM5xxxMA5Device *device, uint64_t *deadline)
{
    uint64_t when = device->delayed_next_ns;

    if (!device->delayed_count || !device->counter_running) {
        return false;
    }
    if (when < device->counter_last_ns) {
        when = device->counter_last_ns;
    }
    if ((device->delayed.phase == MA5_CURSOR_CONTROL ||
         device->delayed.phase == MA5_CURSOR_MEMORY) &&
        device->delayed_due > device->counter_total) {
        uint64_t needed = device->delayed_due - device->counter_total;
        uint64_t whole = device->counter_den / device->counter_num;
        uint64_t remainder = device->counter_den % device->counter_num;
        uint64_t wait, tail;

        if (needed > 0x1fffffu || (needed - 1u) > UINT64_MAX / whole) {
            device->reject = MSM5XXX_MA5_REJECT_CLOCK;
            return false;
        }
        wait = (needed - 1u) * whole;
        /* At most 21-bit delta times <81e9 remainder, so tail fits uint64. */
        tail = (needed - 1u) * remainder + device->counter_den - device->counter_phase;
        tail = tail / device->counter_num + (tail % device->counter_num != 0u);
        if (wait > UINT64_MAX - tail ||
            device->counter_last_ns > UINT64_MAX - (wait + tail)) {
            device->reject = MSM5XXX_MA5_REJECT_CLOCK;
            return false;
        }
        when = when > device->counter_last_ns + wait + tail ? when :
               device->counter_last_ns + wait + tail;
    }
    *deadline = when;
    return true;
}

bool msm5xxx_ma5_device_next_deadline(MSM5xxxMA5Device *device,
                                     uint64_t *deadline_ns)
{
    uint64_t delayed;
    bool have_delayed;

    if (device == NULL || deadline_ns == NULL || device->reject) {
        return false;
    }
    have_delayed = ma5_delayed_deadline(device, &delayed);
    if (device->reject) {
        return false;
    }
    if (!device->count && !have_delayed) {
        return false;
    }
    *deadline_ns = device->count && (!have_delayed || device->next_ns <= delayed) ?
                   device->next_ns : delayed;
    return true;
}

static bool ma5_delayed_byte(MSM5xxxMA5Device *device, uint8_t value)
{
    device->backing.control_write_valid = false;
    if (!device->delayed_delta_ready) {
        device->delayed_delta |= (uint32_t)(value & 0x7fu) <<
                                 (7u * device->delayed_delta_bytes++);
        if (value & 0x80u) {
            if (device->delayed_previous_due > UINT64_MAX - device->delayed_delta) {
                device->reject = MSM5XXX_MA5_REJECT_CLOCK;
                return false;
            }
            /* shortcut: cumulative deadlines from START origin, including
             * starvation catch-up; physical DADJT recovery remains unverified. */
            device->delayed_due = device->delayed_previous_due + device->delayed_delta;
            device->delayed_delta_ready = true;
        } else if (device->delayed_delta_bytes == 3u) {
            return false;
        }
        return true;
    }
    if (device->delayed.phase == MA5_CURSOR_CONTROL ||
        device->delayed.phase == MA5_CURSOR_MEMORY) {
        device->delayed_previous_due = device->delayed_due;
    }
    if (!ma5_readback_byte(&device->backing, &device->delayed, false, value)) {
        return false;
    }
    if (device->delayed.phase == MA5_CURSOR_ADDRESS &&
        !device->delayed.address_bytes) {
        device->delayed_delta_ready = false;
        device->delayed_delta = device->delayed_delta_bytes = 0;
    }
    return true;
}

static void ma5_emit_commit(MSM5xxxMA5Device *device,
                            MSM5xxxMA5CommitKind kind, uint32_t address,
                            uint8_t value, uint8_t raw, uint64_t time_ns)
{
    if (device->commit_sink) {
        const MSM5xxxMA5Commit commit = {kind, address, value, raw, time_ns};
        device->commit_sink(device->commit_opaque, &commit);
    }
}

static void ma5_counter_stop(MSM5xxxMA5Device *device)
{
    if (device->counter_running) {
        /* shortcut: STOP freezes phase; changed-clock resume still needs CNTRST. */
        device->counter_needs_reset = true;
        device->counter_running = false;
    }
    device->b[38] &= ~1u;
}

void msm5xxx_ma5_device_advance(MSM5xxxMA5Device *device, uint64_t now_ns)
{
    uint64_t event_ns;

    if (device == NULL || device->reject) {
        return;
    }
    /* shortcut: experimental START-driven counter runs even with empty FIFO;
     * replace only after physical starvation/DADJT phase rules are proven. */
    if (device->counter_running && now_ns < device->counter_last_ns) {
        device->reject = MSM5XXX_MA5_REJECT_CLOCK;
        return;
    }
    while (msm5xxx_ma5_device_next_deadline(device, &event_ns) && event_ns <= now_ns) {
        bool immediate = device->count && device->next_ns <= event_ns;
        unsigned slot = immediate ? device->head : device->delayed_head;
        unsigned port = immediate ? device->queue_port[slot] : 1u;
        unsigned value = immediate ? device->queue_value[slot] : device->delayed_value[slot];
        bool completed_read = port == 3u && device->backing.read.phase ==
                              MA5_CURSOR_READ_BUFFER;
        uint64_t sram_before = device->backing.sram_writes;
        uint32_t sram_address = immediate ? device->backing.immediate.address :
                                           device->delayed.address;

        ma5_counter_advance(device, event_ns);
        if (device->reject) {
            return;
        }
        if (!(immediate ? msm5xxx_ma5_readback_consume(&device->backing, port, value) :
              ma5_delayed_byte(device, value))) {
            if (!device->reject) {
                device->reject = MSM5XXX_MA5_REJECT_PACKET;
            }
            return;
        }
        device->memory_dirty |= device->backing.sram_writes != sram_before;
        device->control_dirty |= device->backing.control_write_valid;
        if (device->backing.control_write_valid &&
            device->backing.control_write_address == 480u &&
            (device->backing.control_write_raw & 1u)) {
            ma5_counter_stop(device);
        }
        device->reads += completed_read;
        if (immediate) {
            device->consumed++;
            device->head = (slot + 1u) % MSM5XXX_MA5_IMMEDIATE_CAPACITY;
            device->count--;
        } else {
            device->delayed_consumed++;
            device->delayed_head = (slot + 1u) % MSM5XXX_MA5_DELAYED_CAPACITY;
            device->delayed_count--;
        }
        if (device->backing.control_write_valid) {
            ma5_emit_commit(device, MSM5XXX_MA5_COMMIT_CONTROL,
                            device->backing.control_write_address,
                            device->backing.control_write_raw & 0x7fu,
                            device->backing.control_write_raw, event_ns);
        } else if (device->backing.sram_writes != sram_before) {
            ma5_emit_commit(device, MSM5XXX_MA5_COMMIT_SRAM, sram_address,
                            value, value, event_ns);
        }
        if (immediate ? device->count : device->delayed_count) {
            if (event_ns > UINT64_MAX - device->period_ns) {
                device->reject = MSM5XXX_MA5_REJECT_CLOCK;
                return;
            }
            if (immediate) {
                device->next_ns = event_ns + device->period_ns;
            } else {
                device->delayed_next_ns = event_ns + device->period_ns;
            }
        }
        ma5_device_irq_update(device);
    }
    if (device->reject) {
        return;
    }
    ma5_counter_advance(device, now_ns);
    if (device->delayed_delta_ready && device->counter_total >= device->delayed_due &&
        (device->delayed.phase == MA5_CURSOR_CONTROL ||
         device->delayed.phase == MA5_CURSOR_MEMORY)) {
        device->delayed_previous_due = device->delayed_due;
    }
    ma5_device_irq_update(device);
}

bool msm5xxx_ma5_device_irq(const MSM5xxxMA5Device *device)
{
    uint16_t enabled;

    if (device == NULL || device->reject || !device->backing.irq_enabled) {
        return false;
    }
    enabled = device->b[17] | (uint16_t)device->b[18] << 8;
    return (device->pending & enabled) != 0u;
}

bool msm5xxx_ma5_device_write(MSM5xxxMA5Device *device, bool index,
                              uint8_t value, uint64_t now_ns)
{
    unsigned selected;
    uint8_t raw = value;

    if (device == NULL) {
        return false;
    }
    msm5xxx_ma5_device_advance(device, now_ns);
    if (device->reject) {
        return false;
    }
    device->accessed = true;
    if (index) {
        msm5xxx_ma5_readback_index(&device->backing, value);
        ma5_device_irq_update(device);
        return true;
    }
    selected = device->backing.index;
    if (selected == 1u) {
        unsigned slot;

        if (!device->clki_hz || (device->b[55] & 1u)) {
            device->reject = MSM5XXX_MA5_REJECT_DELAYED;
            return false;
        }
        if (device->b[4] & 0x80u) {
            device->reject = MSM5XXX_MA5_REJECT_RESET_RETENTION;
            return false;
        }
        if (device->delayed_count == MSM5XXX_MA5_DELAYED_CAPACITY) {
            device->reject = MSM5XXX_MA5_REJECT_FIFO_OVERFLOW;
            return false;
        }
        if (!device->delayed_count) {
            if (now_ns > UINT64_MAX - device->period_ns) {
                device->reject = MSM5XXX_MA5_REJECT_CLOCK;
                return false;
            }
            device->delayed_next_ns = now_ns + device->period_ns;
        }
        slot = (device->delayed_head + device->delayed_count) % MSM5XXX_MA5_DELAYED_CAPACITY;
        device->delayed_value[slot] = value;
        device->delayed_count++;
        device->delayed_dirty = true;
        if (device->delayed_count > device->delayed_max_count) {
            device->delayed_max_count = device->delayed_count;
        }
        ma5_device_irq_update(device);
        return true;
    }
    if (selected == 2u || selected == 3u) {
        unsigned slot;

        if (device->b[4] & 0x80u) {
            device->reject = MSM5XXX_MA5_REJECT_RESET_RETENTION;
            return false;
        }

        if (device->count == MSM5XXX_MA5_IMMEDIATE_CAPACITY) {
            device->reject = MSM5XXX_MA5_REJECT_FIFO_OVERFLOW;
            return false;
        }
        if (!device->count) {
            if (now_ns > UINT64_MAX - device->period_ns) {
                device->reject = MSM5XXX_MA5_REJECT_CLOCK;
                return false;
            }
            device->next_ns = now_ns + device->period_ns;
        }
        slot = (device->head + device->count) %
               MSM5XXX_MA5_IMMEDIATE_CAPACITY;
        device->queue_port[slot] = selected;
        device->queue_value[slot] = value;
        device->count++;
        if (device->count > device->max_count) {
            device->max_count = device->count;
        }
        return true;
    }
    if (device->clki_hz &&
        (selected == 30u || selected == 31u || selected == 35u ||
         selected == 36u || selected == 38u || selected == 4u)) {
        bool delayed_clear = selected == 4u &&
            (value == 0x28u || (!value && device->b[4] == 0x28u));
        bool stop = selected == 38u && value == 0u;
        bool reset_noop = selected == 4u && !value && !device->b[4];
        if (device->counter_running && !delayed_clear && !stop && !reset_noop) {
            device->reject = MSM5XXX_MA5_REJECT_CLOCK;
            return false;
        }
        if ((selected == 30u && value != 0x14u && value != 0x95u) ||
            (selected == 31u && value != 0x4bu && value != 0x51u) ||
            (selected == 36u && ((value & 3u) || !device->b_written[35]))) {
            device->reject = MSM5XXX_MA5_REJECT_CLOCK;
            return false;
        }
        if (selected == 36u) {
            device->ms_s = ((uint16_t)device->b[35] << 6) | (value >> 2);
            device->ms_s_committed = true;
        }
    }
    if ((selected == 38u && (value & 1u) && !device->clki_hz) ||
        ((selected == 48u || selected == 50u) && (value & 1u)) ||
        ((selected == 53u || selected == 54u || selected == 58u) && value)) {
        device->reject = MSM5XXX_MA5_REJECT_START;
        return false;
    }
    if (selected == 38u) {
        if (value & ~3u) {
            device->reject = MSM5XXX_MA5_REJECT_PACKET;
            return false;
        }
        if (value & 2u) {
            if (device->clki_hz && (value & 1u)) {
                device->reject = MSM5XXX_MA5_REJECT_START;
                return false;
            }
            if (device->clki_hz &&
                (device->delayed_delta_bytes || device->delayed_delta_ready ||
                 device->delayed.address_bytes || device->delayed.length_bytes ||
                 device->delayed.phase != MA5_CURSOR_ADDRESS)) {
                device->reject = MSM5XXX_MA5_REJECT_RESET_RETENTION;
                return false;
            }
            device->counter_reset = true;
            device->counter_needs_reset = false;
            device->counter = device->counter_latch = 0;
            device->counter_total = 0;
            device->counter_phase = 0;
            device->delayed_due = device->delayed_previous_due = 0;
        }
        if (device->clki_hz && (value & 1u) && (device->b[4] & 0x80u)) {
            device->reject = MSM5XXX_MA5_REJECT_RESET_RETENTION;
            return false;
        }
        if (device->clki_hz && (value & 1u)) {
            bool pll = (device->b[30] == 0x14u && device->b[31] == 0x4bu) ||
                       (device->b[30] == 0x95u && device->b[31] == 0x51u);
            uint64_t num = device->clki_hz * (device->b[31] & 0x7fu);
            uint64_t den = UINT64_C(80000000000) *
                (device->b[30] & 0x1fu) * (device->ms_s ? device->ms_s : 16384u);
            if (!pll || !device->b_written[30] || !device->b_written[31] ||
                !device->ms_s_committed || !device->counter_reset) {
                device->reject = MSM5XXX_MA5_REJECT_START;
                return false;
            }
            if (device->counter_needs_reset &&
                (num != device->counter_num || den != device->counter_den)) {
                device->reject = MSM5XXX_MA5_REJECT_CLOCK;
                return false;
            }
            device->counter_num = num;
            device->counter_den = den;
            device->counter_needs_reset = false;
            device->counter_last_ns = now_ns;
            if (device->delayed_count) {
                if (now_ns > UINT64_MAX - device->period_ns) {
                    device->reject = MSM5XXX_MA5_REJECT_CLOCK;
                    return false;
                }
                device->delayed_next_ns = now_ns + device->period_ns;
            }
            device->counter_running = true;
        }
        if (!value) {
            ma5_counter_stop(device);
        }
        value &= ~2u;
    }
    if (selected == 4u) {
        if (value & 7u) {
            device->reject = MSM5XXX_MA5_REJECT_BANK;
            return false;
        }
        if ((value & 0x78u) &&
            (value != 0x28u || (device->b[4] & 0x80u))) {
            device->reject = MSM5XXX_MA5_REJECT_RESET_RETENTION;
            return false;
        }
        /* shortcut: only an unmodified cold pulse is modeled; extend after
         * independent SRAM/C/latch/parser retention vectors exist. */
        if ((value & 0x80u) &&
            (device->count || device->control_dirty || device->memory_dirty ||
             device->delayed_dirty ||
             device->b_written[56] ||
             device->backing.read_valid ||
             device->backing.immediate.address_bytes ||
             device->backing.immediate.phase != MA5_CURSOR_ADDRESS ||
             device->backing.read.address_bytes ||
             device->backing.read.phase != MA5_CURSOR_ADDRESS)) {
            device->reject = MSM5XXX_MA5_REJECT_RESET_RETENTION;
            return false;
        }
        if (!(value & 0x80u) && (device->b[4] & 0x80u)) {
            device->counter_reset = false;
            memset(device->backing.control + 192u, 0x60, 16u);
            memset(device->backing.control + 208u, 0x3c, 16u);
            device->resets++;
        }
        if (device->clki_hz && ((value | device->b[4]) & 0x80u)) {
            device->ms_s_committed = false;
            device->counter_reset = false;
            device->counter_needs_reset = false;
            device->b_written[35] = device->b_written[36] = false;
        }
        if (value == 0x28u) {
            device->delayed_head = device->delayed_count = 0;
            memset(&device->delayed, 0, sizeof(device->delayed));
            device->delayed_delta = device->delayed_delta_bytes = 0;
            device->delayed_delta_ready = false;
            device->delayed_due = device->delayed_previous_due;
            device->delayed_next_ns = 0;
        }
    }
    if (selected == 55u && device->clki_hz && (value & 1u)) {
        device->reject = MSM5XXX_MA5_REJECT_DELAYED;
        return false;
    }
    if (selected == 0u || selected == 16u) {
        device->pending &= ~((uint16_t)value << (selected == 16u ? 8u : 0u));
    } else {
        device->b[selected] = value;
        device->b_written[selected] = true;
        if ((selected == 30u || selected == 31u) &&
            !ma5_infer_clki(device)) {
            return false;
        }
        if (selected == 55u) {
            device->fifo_mode_known = true;
        }
    }
    ma5_device_irq_update(device);
    ma5_emit_commit(device, MSM5XXX_MA5_COMMIT_B, selected, value, raw, now_ns);
    return true;
}

bool msm5xxx_ma5_device_read(MSM5xxxMA5Device *device, bool index,
                             uint8_t *value, uint64_t now_ns)
{
    unsigned selected;
    uint16_t enabled;

    if (device == NULL || value == NULL) {
        return false;
    }
    msm5xxx_ma5_device_advance(device, now_ns);
    if (device->reject) {
        return false;
    }
    device->accessed = true;
    if (index) {
        *value = msm5xxx_ma5_readback_status(&device->backing) |
                 (device->b[4] & 0x80u) |
                 (device->delayed_count == 0u ? 2u : 0u) |
                 (device->delayed_count == MSM5XXX_MA5_DELAYED_CAPACITY ? 8u : 0u) |
                 (device->count == 0u ? 1u : 0u) |
                 (device->count == MSM5XXX_MA5_IMMEDIATE_CAPACITY ? 4u : 0u);
        return true;
    }
    selected = device->backing.index;
    if (selected == 1u) {
        return msm5xxx_ma5_readback_data(&device->backing, value);
    }
    if (selected == 0u || selected == 16u) {
        enabled = device->b[17] | (uint16_t)device->b[18] << 8;
        *value = (device->pending & enabled) >> (selected == 16u ? 8u : 0u);
        return true;
    }
    if (device->clki_hz && (device->counter_running || device->counter_needs_reset ||
                           device->counter_reset) &&
        selected >= 32u && selected <= 34u) {
        if (selected == 32u) {
            device->counter_latch = device->counter;
        }
        *value = device->counter_latch >> (8u * (34u - selected));
        return true;
    }
    if (selected >= 32u && selected <= 34u && device->counter_reset) {
        *value = 0;
        return true;
    }
    if (selected == 2u || selected == 3u ||
        (selected >= 19u && selected <= 29u) ||
        (selected >= 32u && selected <= 36u) ||
        (!device->b_written[selected] && selected != 56u)) {
        device->reject = MSM5XXX_MA5_REJECT_DYNAMIC_READ;
        return false;
    }
    *value = device->b[selected];
    return true;
}
