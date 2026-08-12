/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-ma2-audio.h"

#include <string.h>

static void
ma2_reject(MSM5xxxMA2Audio *audio, MSM5xxxMA2RejectReason reason)
{
    if (audio != 0) {
        audio->rejected = true;
        audio->reject_reason = reason;
    }
}

static bool
ma2_valid_fifo(MSM5xxxMA2Fifo fifo)
{
    return fifo >= MSM5XXX_MA2_FIFO_FM0 &&
           fifo <= MSM5XXX_MA2_FIFO_ADPCM_WAVE;
}

size_t
msm5xxx_ma2_fifo_capacity(MSM5xxxMA2Fifo fifo)
{
    if (fifo >= MSM5XXX_MA2_FIFO_FM0 &&
        fifo <= MSM5XXX_MA2_FIFO_FM3) {
        return MSM5XXX_MA2_FM_FIFO_CAPACITY;
    }
    if (fifo == MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE) {
        return MSM5XXX_MA2_ADPCM_SEQUENCE_CAPACITY;
    }
    if (fifo == MSM5XXX_MA2_FIFO_ADPCM_WAVE) {
        return MSM5XXX_MA2_ADPCM_WAVE_CAPACITY;
    }
    return 0u;
}

static void
ma2_clear_fifo(MSM5xxxMA2Audio *audio, MSM5xxxMA2Fifo fifo)
{
    audio->fifo_read[fifo] = 0u;
    audio->fifo_write[fifo] = 0u;
    audio->fifo_count[fifo] = 0u;
}

static bool
ma2_fifo_push(MSM5xxxMA2Audio *audio, MSM5xxxMA2Fifo fifo, uint8_t value)
{
    uint16_t write;
    size_t capacity;

    capacity = msm5xxx_ma2_fifo_capacity(fifo);
    if (capacity == 0u) {
        ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_FIFO);
        return false;
    }
    if ((size_t)audio->fifo_count[fifo] >= capacity) {
        ma2_reject(audio, MSM5XXX_MA2_REJECT_FIFO_FULL);
        return false;
    }

    write = audio->fifo_write[fifo];
    if (fifo <= MSM5XXX_MA2_FIFO_FM3) {
        audio->fm_fifo[fifo][write] = value;
    } else if (fifo == MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE) {
        audio->adpcm_sequence_fifo[write] = value;
    } else {
        audio->adpcm_wave_fifo[write] = value;
    }
    write++;
    if ((size_t)write == capacity) {
        write = 0u;
    }
    audio->fifo_write[fifo] = write;
    audio->fifo_count[fifo]++;
    return true;
}

void
msm5xxx_ma2_reset(MSM5xxxMA2Audio *audio)
{
    size_t fifo;
    size_t channel;
    size_t slot;
    size_t page;

    if (audio == 0) {
        return;
    }

    audio->index = 0u;
    audio->page = MSM5XXX_MA2_PAGE_REG0;
    audio->power = 0u;
    audio->control = 0u;
    audio->fm_timebase = 0u;
    audio->adpcm_timebase = 0u;
    audio->clock_adjust1 = 0u;
    audio->clock_adjust2 = 0u;
    audio->fm_irq_ctrl = 0u;
    audio->adpcm_irq_ctrl = 0u;
    audio->fifo_control = 0u;
    audio->soft_reset_mask = 0u;
    audio->repeat_flags = 0u;
    audio->gend_status = 0u;
    audio->fm_start_pending = false;
    audio->adpcm_start_pending = false;
    audio->fm_state_unhandled = 0u;
    audio->scheduler_now_ns = 0u;
    audio->scheduler_clock_initialized = false;
    audio->rejected = false;
    audio->reject_reason = MSM5XXX_MA2_REJECT_NONE;

    memset(audio->sequence, 0, sizeof(audio->sequence));
    memset(audio->fm_gate, 0, sizeof(audio->fm_gate));
    memset(&audio->adpcm_gate, 0, sizeof(audio->adpcm_gate));
    memset(audio->fm_voice, 0, sizeof(audio->fm_voice));
    memset(audio->fm_assignment, 0, sizeof(audio->fm_assignment));
    for (channel = 0u; channel < MSM5XXX_MA2_FM_CHANNEL_COUNT; channel++) {
        MSM5xxxMA2FMChannel *state = &audio->fm_channel[channel];

        memset(state, 0, sizeof(*state));
        state->modulation = 1u;
        state->pitch_bend = 0x40u;
        state->volume = 0x63u;
        state->pan = 0x40u;
        state->expression = 0x7fu;
    }

    for (page = 0u; page < 2u; page++) {
        for (slot = 0u; slot < 256u; slot++) {
            audio->register_shadow[page][slot] = 0u;
        }
    }
    for (fifo = 0u; fifo < MSM5XXX_MA2_FIFO_COUNT; fifo++) {
        audio->fifo_read[fifo] = 0u;
        audio->fifo_write[fifo] = 0u;
        audio->fifo_count[fifo] = 0u;
    }
    for (fifo = 0u; fifo < MSM5XXX_MA2_FM_FIFO_COUNT; fifo++) {
        for (slot = 0u; slot < MSM5XXX_MA2_FM_FIFO_CAPACITY; slot++) {
            audio->fm_fifo[fifo][slot] = 0u;
        }
    }
    for (slot = 0u; slot < MSM5XXX_MA2_ADPCM_SEQUENCE_CAPACITY; slot++) {
        audio->adpcm_sequence_fifo[slot] = 0u;
    }
    for (slot = 0u; slot < MSM5XXX_MA2_ADPCM_WAVE_CAPACITY; slot++) {
        audio->adpcm_wave_fifo[slot] = 0u;
    }
}

bool
msm5xxx_ma2_index_write(MSM5xxxMA2Audio *audio, uint8_t index)
{
    if (audio == 0) {
        return false;
    }
    audio->index = index;
    return true;
}

bool
msm5xxx_ma2_index_read(const MSM5xxxMA2Audio *audio, uint8_t *index)
{
    if (audio == 0 || index == 0) {
        return false;
    }
    *index = audio->index;
    return true;
}

static bool
ma2_valid_timebase(uint8_t value)
{
    return (value & 0x88u) == 0u;
}

bool
msm5xxx_ma2_timebase_ns(uint8_t value, bool gate, uint64_t *nanoseconds)
{
    static const uint8_t milliseconds[8] = {1u, 2u, 4u, 5u,
                                             10u, 20u, 40u, 50u};
    uint8_t code;

    if (nanoseconds == 0 || !ma2_valid_timebase(value)) {
        return false;
    }
    code = gate ? value & 7u : value >> 4;
    *nanoseconds = (uint64_t)milliseconds[code] * 1000000u;
    return true;
}

static bool
ma2_valid_control(uint8_t value)
{
    return (value & 0x20u) == 0u;
}

static bool
ma2_valid_fm_irq(uint8_t value)
{
    uint8_t point = (uint8_t)(value & 0x07u);
    return point == 0u || point == 3u;
}

static bool
ma2_valid_adpcm_irq(uint8_t value)
{
    uint8_t sequence_point = (uint8_t)(value & 0x18u);
    uint8_t wave_point = (uint8_t)(value & 0x07u);

    return (sequence_point == 0u || sequence_point == 0x10u) &&
           (wave_point == 0u || wave_point == 4u);
}

static bool
ma2_write_page0(MSM5xxxMA2Audio *audio, uint8_t index, uint8_t value)
{
    if (index <= MSM5XXX_MA2_ADPCM_WAVE_DATA) {
        if (!ma2_fifo_push(audio, (MSM5xxxMA2Fifo)index, value)) {
            return false;
        }
        audio->register_shadow[0][index] = value;
        return true;
    }

    switch (index) {
    case MSM5XXX_MA2_FM_IRQ_CTRL:
        if (!ma2_valid_fm_irq(value)) {
            ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
            return false;
        }
        audio->fm_irq_ctrl = value;
        audio->register_shadow[0][index] = value;
        return true;
    case MSM5XXX_MA2_ADPCM_IRQ_CTRL:
        if (!ma2_valid_adpcm_irq(value)) {
            ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
            return false;
        }
        audio->adpcm_irq_ctrl = value;
        audio->register_shadow[0][index] = value;
        return true;
    case MSM5XXX_MA2_STATUS2:
        if ((value & (uint8_t)~0x20u) != 0u) {
            ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
            return false;
        }
        if ((value & 0x20u) != 0u) {
            audio->gend_status &= (uint8_t)~0x20u;
        }
        audio->register_shadow[0][index] = audio->gend_status;
        return true;
    case MSM5XXX_MA2_STATUS1:
    case MSM5XXX_MA2_WAVE_STATUS:
    case MSM5XXX_MA2_FULL_STATUS:
    case MSM5XXX_MA2_EMPTY_STATUS:
        ma2_reject(audio, MSM5XXX_MA2_REJECT_UNSUPPORTED_REGISTER);
        return false;
    default:
        audio->register_shadow[0][index] = value;
        return true;
    }
}

static bool
ma2_set_fm_assignment(MSM5xxxMA2Audio *audio, size_t slot, uint8_t value)
{
    size_t channel;

    if (slot >= MSM5XXX_MA2_FM_ASSIGNMENT_COUNT) {
        return false;
    }
    channel = slot * 2u;
    audio->fm_assignment[slot] = value;
    audio->fm_channel[channel].voice_slot = (uint8_t)(value & 0x0fu);
    audio->fm_channel[channel].voice_slot_valid = true;
    audio->fm_channel[channel + 1u].voice_slot = (uint8_t)(value >> 4);
    audio->fm_channel[channel + 1u].voice_slot_valid = true;
    return true;
}

static bool
ma2_write_page1(MSM5xxxMA2Audio *audio, uint8_t index, uint8_t value)
{
    if (index >= MSM5XXX_MA2_FM_CHANNEL_ASSIGN &&
        index < MSM5XXX_MA2_FM_CHANNEL_ASSIGN +
                    MSM5XXX_MA2_FM_ASSIGNMENT_COUNT) {
        size_t slot = (size_t)(index - MSM5XXX_MA2_FM_CHANNEL_ASSIGN);

        (void)ma2_set_fm_assignment(audio, slot, value);
        audio->register_shadow[1][index] = value;
        return true;
    }
    switch (index) {
    case MSM5XXX_MA2_POWER:
        audio->power = value;
        audio->register_shadow[1][index] = value;
        return true;
    case MSM5XXX_MA2_CONTROL:
    {
        uint8_t prior;

        if (!ma2_valid_control(value)) {
            ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
            return false;
        }
        prior = audio->control;
        if ((prior & MSM5XXX_MA2_FM_START) == 0u &&
            (value & MSM5XXX_MA2_FM_START) != 0u) {
            audio->fm_start_pending = true;
        }
        if ((prior & MSM5XXX_MA2_ADPCM_START) == 0u &&
            (value & MSM5XXX_MA2_ADPCM_START) != 0u) {
            audio->adpcm_start_pending = true;
        }
        audio->control = value;
        audio->register_shadow[1][index] = value;
        return true;
    }
    case MSM5XXX_MA2_FM_TIMEBASE:
        if (!ma2_valid_timebase(value)) {
            ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
            return false;
        }
        audio->fm_timebase = value;
        audio->register_shadow[1][index] = value;
        return true;
    case MSM5XXX_MA2_ADPCM_TIMEBASE:
        if (!ma2_valid_timebase(value)) {
            ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
            return false;
        }
        audio->adpcm_timebase = value;
        audio->register_shadow[1][index] = value;
        return true;
    case MSM5XXX_MA2_FIFO_CONTROL:
        audio->fifo_control = value;
        audio->soft_reset_mask = (uint8_t)(value & 0xe0u);
        audio->repeat_flags = (uint8_t)(value & 0x18u);
        audio->register_shadow[1][index] = value;
        if ((value & MSM5XXX_MA2_WAVE_FIFO_CLEAR) != 0u) {
            ma2_clear_fifo(audio, MSM5XXX_MA2_FIFO_ADPCM_WAVE);
        }
        if ((value & MSM5XXX_MA2_SEQUENCE_FIFO_CLEAR) != 0u) {
            ma2_clear_fifo(audio, MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE);
        }
        if ((value & MSM5XXX_MA2_FM_FIFO_CLEAR) != 0u) {
            ma2_clear_fifo(audio, MSM5XXX_MA2_FIFO_FM0);
            ma2_clear_fifo(audio, MSM5XXX_MA2_FIFO_FM1);
            ma2_clear_fifo(audio, MSM5XXX_MA2_FIFO_FM2);
            ma2_clear_fifo(audio, MSM5XXX_MA2_FIFO_FM3);
        }
        return true;
    case MSM5XXX_MA2_CLOCK_ADJUST1:
        audio->clock_adjust1 = value;
        audio->register_shadow[1][index] = value;
        return true;
    case MSM5XXX_MA2_CLOCK_ADJUST2:
        audio->clock_adjust2 = value;
        audio->register_shadow[1][index] = value;
        return true;
    default:
        audio->register_shadow[1][index] = value;
        return true;
    }
}

bool
msm5xxx_ma2_data_write(MSM5xxxMA2Audio *audio, uint8_t value)
{
    if (audio == 0) {
        return false;
    }
    if (audio->index == MSM5XXX_MA2_PAGE_SELECT) {
        if (value != MSM5XXX_MA2_PAGE_REG0 && value != MSM5XXX_MA2_PAGE_REG1) {
            ma2_reject(audio, MSM5XXX_MA2_REJECT_UNSUPPORTED_PAGE);
            return false;
        }
        audio->page = value;
        audio->register_shadow[0][MSM5XXX_MA2_PAGE_SELECT] = value;
        return true;
    }
    if (audio->page == MSM5XXX_MA2_PAGE_REG0) {
        return ma2_write_page0(audio, audio->index, value);
    }
    if (audio->page == MSM5XXX_MA2_PAGE_REG1) {
        return ma2_write_page1(audio, audio->index, value);
    }
    ma2_reject(audio, MSM5XXX_MA2_REJECT_UNSUPPORTED_PAGE);
    return false;
}

static uint8_t
ma2_full_status(const MSM5xxxMA2Audio *audio)
{
    uint8_t status = 0u;
    size_t fifo;

    for (fifo = 0u; fifo < MSM5XXX_MA2_FM_FIFO_COUNT; fifo++) {
        if (audio->fifo_count[fifo] == MSM5XXX_MA2_FM_FIFO_CAPACITY) {
            status |= (uint8_t)(1u << fifo);
        }
    }
    if (audio->fifo_count[MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE] ==
        MSM5XXX_MA2_ADPCM_SEQUENCE_CAPACITY) {
        status |= MSM5XXX_MA2_ADPCM_FULL;
    }
    return status;
}

static uint8_t
ma2_empty_status(const MSM5xxxMA2Audio *audio)
{
    uint8_t status = 0u;
    size_t fifo;

    for (fifo = 0u; fifo < MSM5XXX_MA2_FM_FIFO_COUNT; fifo++) {
        if (audio->fifo_count[fifo] == 0u) {
            status |= (uint8_t)(1u << fifo);
        }
    }
    if (audio->fifo_count[MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE] == 0u) {
        status |= MSM5XXX_MA2_ADPCM_EMPTY;
    }
    return status;
}

static uint8_t
ma2_read_page0(const MSM5xxxMA2Audio *audio, uint8_t index, bool *ok)
{
    *ok = true;
    switch (index) {
    case MSM5XXX_MA2_FM_IRQ_CTRL:
        return audio->fm_irq_ctrl;
    case MSM5XXX_MA2_ADPCM_IRQ_CTRL:
        return audio->adpcm_irq_ctrl;
    case MSM5XXX_MA2_STATUS2:
        return (uint8_t)(audio->gend_status & 0x20u);
    case MSM5XXX_MA2_FULL_STATUS:
        return ma2_full_status(audio);
    case MSM5XXX_MA2_EMPTY_STATUS:
        return ma2_empty_status(audio);
    case MSM5XXX_MA2_PAGE_SELECT:
        return audio->page;
    case MSM5XXX_MA2_FM_DATA0:
    case MSM5XXX_MA2_FM_DATA1:
    case MSM5XXX_MA2_FM_DATA2:
    case MSM5XXX_MA2_FM_DATA3:
    case MSM5XXX_MA2_ADPCM_SEQ_DATA:
    case MSM5XXX_MA2_ADPCM_WAVE_DATA:
    case MSM5XXX_MA2_STATUS1:
    case MSM5XXX_MA2_WAVE_STATUS:
        *ok = false;
        return 0u;
    default:
        return audio->register_shadow[0][index];
    }
}

static uint8_t
ma2_read_page1(const MSM5xxxMA2Audio *audio, uint8_t index, bool *ok)
{
    *ok = true;
    switch (index) {
    case MSM5XXX_MA2_POWER:
        return audio->power;
    case MSM5XXX_MA2_CONTROL:
        return audio->control;
    case MSM5XXX_MA2_FM_TIMEBASE:
        return audio->fm_timebase;
    case MSM5XXX_MA2_ADPCM_TIMEBASE:
        return audio->adpcm_timebase;
    case MSM5XXX_MA2_CLOCK_ADJUST1:
        return audio->clock_adjust1;
    case MSM5XXX_MA2_CLOCK_ADJUST2:
        return audio->clock_adjust2;
    default:
        return audio->register_shadow[1][index];
    }
}

bool
msm5xxx_ma2_data_read(MSM5xxxMA2Audio *audio, uint8_t *value)
{
    bool ok;

    if (audio == 0 || value == 0) {
        return false;
    }
    if (audio->index == MSM5XXX_MA2_PAGE_SELECT) {
        *value = audio->page;
        return true;
    }
    if (audio->page == MSM5XXX_MA2_PAGE_REG0) {
        *value = ma2_read_page0(audio, audio->index, &ok);
    } else if (audio->page == MSM5XXX_MA2_PAGE_REG1) {
        *value = ma2_read_page1(audio, audio->index, &ok);
    } else {
        *value = 0u;
        ok = false;
    }
    if (!ok) {
        ma2_reject(audio, MSM5XXX_MA2_REJECT_UNSUPPORTED_READ);
    }
    return ok;
}

bool
msm5xxx_ma2_chip_fifo_pop(MSM5xxxMA2Audio *audio,
                          MSM5xxxMA2Fifo fifo,
                          uint8_t *value)
{
    uint16_t read;
    size_t capacity;

    if (audio == 0 || value == 0) {
        return false;
    }
    if (!ma2_valid_fifo(fifo)) {
        ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_FIFO);
        *value = 0u;
        return false;
    }
    if (audio->fifo_count[fifo] == 0u) {
        *value = 0u;
        return false;
    }

    read = audio->fifo_read[fifo];
    if (fifo <= MSM5XXX_MA2_FIFO_FM3) {
        *value = audio->fm_fifo[fifo][read];
    } else if (fifo == MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE) {
        *value = audio->adpcm_sequence_fifo[read];
    } else {
        *value = audio->adpcm_wave_fifo[read];
    }
    capacity = msm5xxx_ma2_fifo_capacity(fifo);
    read++;
    if ((size_t)read == capacity) {
        read = 0u;
    }
    audio->fifo_read[fifo] = read;
    audio->fifo_count[fifo]--;
    return true;
}

size_t
msm5xxx_ma2_fifo_occupancy(const MSM5xxxMA2Audio *audio,
                           MSM5xxxMA2Fifo fifo)
{
    if (audio == 0 || !ma2_valid_fifo(fifo)) {
        return 0u;
    }
    return audio->fifo_count[fifo];
}

bool
msm5xxx_ma2_take_fm_start(MSM5xxxMA2Audio *audio)
{
    bool pending;

    if (audio == 0) {
        return false;
    }
    pending = audio->fm_start_pending;
    audio->fm_start_pending = false;
    return pending;
}

bool
msm5xxx_ma2_take_adpcm_start(MSM5xxxMA2Audio *audio)
{
    bool pending;

    if (audio == 0) {
        return false;
    }
    pending = audio->adpcm_start_pending;
    audio->adpcm_start_pending = false;
    return pending;
}

bool
msm5xxx_ma2_rejected(const MSM5xxxMA2Audio *audio)
{
    return audio != 0 && audio->rejected;
}

MSM5xxxMA2RejectReason
msm5xxx_ma2_reject_reason(const MSM5xxxMA2Audio *audio)
{
    if (audio == 0) {
        return MSM5XXX_MA2_REJECT_NULL_ARGUMENT;
    }
    return audio->reject_reason;
}

void
msm5xxx_ma2_clear_rejection(MSM5xxxMA2Audio *audio)
{
    if (audio == 0) {
        return;
    }
    audio->rejected = false;
    audio->reject_reason = MSM5XXX_MA2_REJECT_NONE;
}

void
msm5xxx_ma2_compact_parser_reset(MSM5xxxMA2CompactParser *parser)
{
    if (parser == 0) {
        return;
    }
    parser->length = 0u;
    parser->rejected = false;
}

typedef enum MA2CompactVarResult {
    MA2_COMPACT_VAR_NEED_MORE = 0,
    MA2_COMPACT_VAR_VALUE,
    MA2_COMPACT_VAR_INVALID,
} MA2CompactVarResult;

static MA2CompactVarResult
ma2_compact_var(const uint8_t *bytes, size_t length, size_t *position,
                uint16_t *value)
{
    uint8_t first;

    if (*position >= length) {
        return MA2_COMPACT_VAR_NEED_MORE;
    }
    first = bytes[(*position)++];
    if ((first & 0x80u) == 0u) {
        *value = first;
        return MA2_COMPACT_VAR_VALUE;
    }
    if (*position >= length) {
        return MA2_COMPACT_VAR_NEED_MORE;
    }
    if ((bytes[*position] & 0x80u) != 0u) {
        return MA2_COMPACT_VAR_INVALID;
    }
    *value = (uint16_t)(128u + ((uint16_t)(first & 0x7fu) << 7) +
                        bytes[(*position)++]);
    return MA2_COMPACT_VAR_VALUE;
}

static MSM5xxxMA2CompactResult
ma2_compact_commit(MSM5xxxMA2CompactParser *parser, size_t consumed,
                   MSM5xxxMA2CompactEvent *event,
                   MSM5xxxMA2CompactResult result)
{
    size_t remaining = (size_t)parser->length - consumed;

    if (remaining != 0u) {
        memmove(parser->bytes, parser->bytes + consumed, remaining);
    }
    parser->length = (uint16_t)remaining;
    if (result == MSM5XXX_MA2_COMPACT_END) {
        event->kind = MSM5XXX_MA2_COMPACT_NOP;
    }
    return result;
}

static MSM5xxxMA2CompactResult
ma2_compact_parser_feed(MSM5xxxMA2CompactParser *parser,
                        uint8_t value,
                        MSM5xxxMA2CompactEvent *event,
                        bool adpcm)
{
    const uint8_t *bytes;
    size_t length;
    size_t position = 0u;
    uint16_t delta;
    uint16_t gate;
    uint8_t raw_event;
    uint8_t control;
    uint8_t code;
    uint8_t size;
    MA2CompactVarResult var_result;

    if (event != 0) {
        memset(event, 0, sizeof(*event));
    }
    if (parser == 0 || event == 0 || parser->rejected ||
        parser->length >= MSM5XXX_MA2_COMPACT_EVENT_CAPACITY) {
        if (parser != 0) {
            parser->rejected = true;
        }
        return MSM5XXX_MA2_COMPACT_ERROR;
    }
    parser->bytes[parser->length++] = value;
    bytes = parser->bytes;
    length = parser->length;

    if (length < 4u && bytes[0] == 0u &&
        (length < 2u || bytes[1] == 0u) &&
        (length < 3u || bytes[2] == 0u)) {
        return MSM5XXX_MA2_COMPACT_NEED_MORE;
    }
    if (length >= 4u && bytes[0] == 0u && bytes[1] == 0u &&
        bytes[2] == 0u && bytes[3] == 0u) {
        return ma2_compact_commit(parser, 4u, event,
                                  MSM5XXX_MA2_COMPACT_END);
    }
    var_result = ma2_compact_var(bytes, length, &position, &delta);
    if (var_result == MA2_COMPACT_VAR_NEED_MORE) {
        return MSM5XXX_MA2_COMPACT_NEED_MORE;
    }
    if (var_result == MA2_COMPACT_VAR_INVALID) {
        parser->rejected = true;
        return MSM5XXX_MA2_COMPACT_ERROR;
    }
    if (position >= length) {
        return MSM5XXX_MA2_COMPACT_NEED_MORE;
    }
    raw_event = bytes[position++];
    event->delta_ticks = delta;

    if (raw_event == 0u) {
        if (position >= length) {
            return MSM5XXX_MA2_COMPACT_NEED_MORE;
        }
        control = bytes[position++];
        event->kind = MSM5XXX_MA2_COMPACT_CONTROL;
        event->local_channel = (uint8_t)((control >> 6) & 3u);
        event->control_family = (uint8_t)((control >> 4) & 3u);
        event->control_code = (uint8_t)(control & 0x0fu);
        if (event->control_family == 3u) {
            if (position >= length) {
                return MSM5XXX_MA2_COMPACT_NEED_MORE;
            }
            event->control_value = bytes[position++];
        }
        return ma2_compact_commit(parser, position, event,
                                  MSM5XXX_MA2_COMPACT_EVENT);
    }

    if (raw_event == 0xffu) {
        if (position >= length) {
            return MSM5XXX_MA2_COMPACT_NEED_MORE;
        }
        code = bytes[position++];
        if (code == 0u) {
            event->kind = MSM5XXX_MA2_COMPACT_NOP;
        } else if (code == 0xf0u) {
            if (position >= length) {
                return MSM5XXX_MA2_COMPACT_NEED_MORE;
            }
            size = bytes[position++];
            if (length - position < size) {
                return MSM5XXX_MA2_COMPACT_NEED_MORE;
            }
            event->kind = MSM5XXX_MA2_COMPACT_SYSEX;
            event->sysex_length = size;
            memcpy(event->sysex, bytes + position, size);
            position += size;
        } else {
            event->kind = MSM5XXX_MA2_COMPACT_UNSUPPORTED;
            event->control_code = code;
        }
        return ma2_compact_commit(parser, position, event,
                                  MSM5XXX_MA2_COMPACT_EVENT);
    }

    var_result = ma2_compact_var(bytes, length, &position, &gate);
    if (var_result == MA2_COMPACT_VAR_NEED_MORE) {
        return MSM5XXX_MA2_COMPACT_NEED_MORE;
    }
    if (var_result == MA2_COMPACT_VAR_INVALID) {
        parser->rejected = true;
        return MSM5XXX_MA2_COMPACT_ERROR;
    }
    event->gate_ticks = gate;
    if (adpcm) {
        event->wave_id = (uint8_t)(raw_event & 0x3fu);
        if ((raw_event & 0xc0u) != 0u || event->wave_id == 0u ||
            event->wave_id == 0x3fu) {
            parser->rejected = true;
            return MSM5XXX_MA2_COMPACT_ERROR;
        }
        event->kind = MSM5XXX_MA2_COMPACT_WAVE;
        return ma2_compact_commit(parser, position, event,
                                  MSM5XXX_MA2_COMPACT_EVENT);
    }
    event->local_channel = (uint8_t)((raw_event >> 6) & 3u);
    event->octave = (uint8_t)((raw_event >> 4) & 3u);
    event->note_id = (uint8_t)(raw_event & 0x0fu);
    event->kind = event->note_id >= 1u && event->note_id <= 12u ?
        MSM5XXX_MA2_COMPACT_NOTE : MSM5XXX_MA2_COMPACT_UNSUPPORTED;
    return ma2_compact_commit(parser, position, event,
                              MSM5XXX_MA2_COMPACT_EVENT);
}

MSM5xxxMA2CompactResult
msm5xxx_ma2_compact_parser_feed(MSM5xxxMA2CompactParser *parser,
                                uint8_t value,
                                MSM5xxxMA2CompactEvent *event)
{
    return ma2_compact_parser_feed(parser, value, event, false);
}

MSM5xxxMA2CompactResult
msm5xxx_ma2_adpcm_parser_feed(MSM5xxxMA2CompactParser *parser,
                              uint8_t value,
                              MSM5xxxMA2CompactEvent *event)
{
    return ma2_compact_parser_feed(parser, value, event, true);
}

static bool
ma2_add_ticks(MSM5xxxMA2Audio *audio, uint64_t base, uint64_t unit,
              uint16_t ticks, uint64_t *result)
{
    if (ticks != 0u && unit > (UINT64_MAX - base) / ticks) {
        ma2_reject(audio, MSM5XXX_MA2_REJECT_TIME_OVERFLOW);
        return false;
    }
    *result = base + unit * ticks;
    return true;
}

static bool
ma2_sequence_desired(const MSM5xxxMA2Audio *audio, size_t stream)
{
    uint8_t bit = stream < MSM5XXX_MA2_FM_FIFO_COUNT ?
        MSM5XXX_MA2_FM_START : MSM5XXX_MA2_ADPCM_START;

    return (audio->control & bit) != 0u;
}

static bool
ma2_can_shift(uint64_t value, uint64_t delta)
{
    return value <= UINT64_MAX - delta;
}

static bool
ma2_shift_sequence(MSM5xxxMA2Audio *audio, size_t stream, uint64_t delta)
{
    MSM5xxxMA2SequenceState *sequence = &audio->sequence[stream];
    size_t first_channel;
    size_t channel;

    if (!ma2_can_shift(sequence->cursor_ns, delta) ||
        ((sequence->pending || sequence->end_pending) &&
         !ma2_can_shift(sequence->deadline_ns, delta))) {
        ma2_reject(audio, MSM5XXX_MA2_REJECT_TIME_OVERFLOW);
        return false;
    }
    if (stream < MSM5XXX_MA2_FM_FIFO_COUNT) {
        first_channel = stream * 4u;
        for (channel = first_channel; channel < first_channel + 4u;
             channel++) {
            if (audio->fm_gate[channel].active &&
                !ma2_can_shift(audio->fm_gate[channel].deadline_ns, delta)) {
                ma2_reject(audio, MSM5XXX_MA2_REJECT_TIME_OVERFLOW);
                return false;
            }
        }
    } else if (audio->adpcm_gate.active &&
               !ma2_can_shift(audio->adpcm_gate.deadline_ns, delta)) {
        ma2_reject(audio, MSM5XXX_MA2_REJECT_TIME_OVERFLOW);
        return false;
    }

    sequence->cursor_ns += delta;
    if (sequence->pending || sequence->end_pending) {
        sequence->deadline_ns += delta;
    }
    if (stream < MSM5XXX_MA2_FM_FIFO_COUNT) {
        first_channel = stream * 4u;
        for (channel = first_channel; channel < first_channel + 4u;
             channel++) {
            if (audio->fm_gate[channel].active) {
                audio->fm_gate[channel].deadline_ns += delta;
            }
        }
    } else if (audio->adpcm_gate.active) {
        audio->adpcm_gate.deadline_ns += delta;
    }
    return true;
}

static bool
ma2_sync_sequence(MSM5xxxMA2Audio *audio, size_t stream, uint64_t now_ns)
{
    MSM5xxxMA2SequenceState *sequence = &audio->sequence[stream];
    bool desired = ma2_sequence_desired(audio, stream);
    uint64_t paused_ns;

    if (desired == sequence->running) {
        return true;
    }
    if (!desired) {
        sequence->running = false;
        sequence->pause_started_ns = now_ns;
        return true;
    }
    if (!sequence->started) {
        sequence->started = true;
        sequence->running = true;
        sequence->cursor_ns = now_ns;
        return true;
    }
    paused_ns = now_ns - sequence->pause_started_ns;
    if (!ma2_shift_sequence(audio, stream, paused_ns)) {
        return false;
    }
    sequence->running = true;
    return true;
}

static bool
ma2_stage_sequence(MSM5xxxMA2Audio *audio, size_t stream)
{
    MSM5xxxMA2SequenceState *sequence = &audio->sequence[stream];
    MSM5xxxMA2CompactResult result;
    uint64_t duration_unit;
    uint8_t value;

    if (!sequence->running || sequence->pending || sequence->end_pending ||
        sequence->ended) {
        return true;
    }

    /* Physical FIFO fetch and IRQ timing remain outside this scheduler. */
    while (msm5xxx_ma2_chip_fifo_pop(
               audio, (MSM5xxxMA2Fifo)stream, &value)) {
        if (stream < MSM5XXX_MA2_FM_FIFO_COUNT) {
            result = msm5xxx_ma2_compact_parser_feed(
                &sequence->parser, value, &sequence->pending_event);
            if (!msm5xxx_ma2_timebase_ns(audio->fm_timebase, false,
                                         &duration_unit) ||
                !msm5xxx_ma2_timebase_ns(audio->fm_timebase, true,
                                         &sequence->gate_unit_ns)) {
                ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
                return false;
            }
        } else {
            result = msm5xxx_ma2_adpcm_parser_feed(
                &sequence->parser, value, &sequence->pending_event);
            if (!msm5xxx_ma2_timebase_ns(audio->adpcm_timebase, false,
                                         &duration_unit) ||
                !msm5xxx_ma2_timebase_ns(audio->adpcm_timebase, true,
                                         &sequence->gate_unit_ns)) {
                ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
                return false;
            }
        }
        if (result == MSM5XXX_MA2_COMPACT_ERROR) {
            ma2_reject(audio, MSM5XXX_MA2_REJECT_INVALID_ENCODING);
            return false;
        }
        if (result == MSM5XXX_MA2_COMPACT_END) {
            sequence->deadline_ns = sequence->cursor_ns;
            sequence->end_pending = true;
            return true;
        }
        if (result == MSM5XXX_MA2_COMPACT_EVENT) {
            if (!ma2_add_ticks(audio, sequence->cursor_ns, duration_unit,
                               sequence->pending_event.delta_ticks,
                               &sequence->deadline_ns)) {
                return false;
            }
            sequence->pending = true;
            return true;
        }
    }
    return true;
}

static bool
ma2_gate_running(const MSM5xxxMA2Audio *audio, size_t channel)
{
    return audio->sequence[channel / 4u].running;
}

static void
ma2_decode_operator(const uint8_t packed[7], uint8_t decoded[18])
{
    decoded[0] = (uint8_t)(packed[0] >> 4);
    decoded[1] = (uint8_t)((packed[0] & 0x08u) != 0u);
    decoded[2] = (uint8_t)((packed[0] & 0x02u) != 0u);
    decoded[3] = (uint8_t)(packed[0] & 0x01u);
    decoded[4] = (uint8_t)(packed[1] >> 4);
    decoded[5] = (uint8_t)(packed[1] & 0x0fu);
    decoded[6] = (uint8_t)(packed[2] >> 4);
    decoded[7] = (uint8_t)(packed[2] & 0x0fu);
    decoded[8] = (uint8_t)(packed[3] >> 2);
    decoded[9] = (uint8_t)(packed[3] & 0x03u);
    decoded[10] = (uint8_t)((packed[4] >> 5) & 0x03u);
    decoded[11] = (uint8_t)((packed[4] & 0x10u) != 0u);
    decoded[12] = (uint8_t)((packed[4] >> 1) & 0x03u);
    decoded[13] = (uint8_t)(packed[4] & 0x01u);
    decoded[14] = (uint8_t)(packed[5] >> 4);
    decoded[15] = (uint8_t)(packed[5] & 0x07u);
    decoded[16] = (uint8_t)(packed[6] >> 3);
    decoded[17] = (uint8_t)(packed[6] & 0x07u);
}

static void
ma2_decode_voice(const uint8_t *source, size_t operators,
                 uint8_t decoded[MSM5XXX_MA2_FM_DECODED_VOICE_SIZE])
{
    uint8_t packed[30];
    size_t operation;

    memset(packed, 0, sizeof(packed));
    memset(decoded, 0, MSM5XXX_MA2_FM_DECODED_VOICE_SIZE);
    packed[0] = (uint8_t)((source[4] & 0x03u) | 0x80u);
    packed[1] = (uint8_t)((source[3] & 0xc7u));
    for (operation = 0u; operation < operators; operation++) {
        const uint8_t *raw = source + 5u + operation * 5u;
        uint8_t *target = packed + 2u + operation * 7u;
        uint8_t high = (uint8_t)(raw[1] >> 4);

        target[0] = (uint8_t)((raw[0] & 0x01u) | 0x04u |
                              ((raw[0] & 0x04u) == 0u ?
                               (unsigned int)high << 4 : 0u));
        target[1] = (uint8_t)((raw[1] & 0x0fu) |
                              ((raw[0] & 0x02u) != 0u ? 0x40u :
                               (unsigned int)high << 4));
        target[2] = raw[2];
        target[3] = raw[3];
        target[4] = (uint8_t)(((raw[0] >> 3) & 0x01u) |
                              ((raw[4] >> 5) & 0x06u) |
                              ((raw[4] & 0x08u) << 1) |
                              ((raw[4] & 0x30u) << 1));
        target[5] = (uint8_t)(raw[0] & 0xf0u);
        target[6] = (uint8_t)((operation == 0u ?
                              ((source[3] >> 3) & 0x07u) : 0u) |
                              ((raw[4] & 0x07u) << 3));
    }

    decoded[0] = (uint8_t)(packed[0] >> 3);
    decoded[1] = (uint8_t)((packed[1] & 0x20u) != 0u);
    decoded[2] = (uint8_t)((packed[1] & 0x10u) != 0u);
    decoded[3] = (uint8_t)(packed[0] & 0x03u);
    decoded[4] = (uint8_t)(packed[1] >> 6);
    decoded[5] = (uint8_t)(packed[1] & 0x07u);
    for (operation = 0u; operation < operators; operation++) {
        ma2_decode_operator(packed + 2u + operation * 7u,
                            decoded + 6u + operation * 18u);
    }
    decoded[41] = 0u;
    decoded[77] = 0u;
}

static bool
ma2_apply_fm_sysex(MSM5xxxMA2Audio *audio,
                   const MSM5xxxMA2CompactEvent *event)
{
    const uint8_t *bytes = event->sysex;
    MSM5xxxMA2FMVoice voice;
    size_t operators;
    size_t slot;
    size_t operation;

    if (event->sysex_length == 6u && bytes[0] == 0x43u &&
        bytes[1] == 0x03u && bytes[2] == 0x91u && bytes[3] >= 0x18u &&
        bytes[3] <= 0x1fu && bytes[5] == 0xf7u) {
        slot = (size_t)(bytes[3] - 0x18u);
        return ma2_set_fm_assignment(audio, slot, bytes[4]);
    }
    if ((event->sysex_length != 18u && event->sysex_length != 28u) ||
        bytes[0] != 0x43u || bytes[1] != 0x03u ||
        bytes[event->sysex_length - 1u] != 0xf7u ||
        bytes[2] >= MSM5XXX_MA2_FM_VOICE_COUNT) {
        return false;
    }
    operators = (bytes[5] & 7u) <= 1u ? 2u : 4u;
    if ((operators == 2u && event->sysex_length != 18u) ||
        (operators == 4u && (event->sysex_length != 28u || bytes[2] > 11u))) {
        return false;
    }

    memset(&voice, 0, sizeof(voice));
    voice.valid = true;
    voice.bank = bytes[3];
    voice.program = bytes[4];
    voice.info = bytes[5];
    voice.basic_octave = bytes[6];
    voice.operator_count = (uint8_t)operators;
    for (operation = 0u; operation < operators; operation++) {
        memcpy(voice.operation[operation].data,
               bytes + 7u + operation * 5u,
               sizeof(voice.operation[operation].data));
    }
    ma2_decode_voice(bytes + 2u, operators, voice.decoded);
    audio->fm_voice[bytes[2]] = voice;
    return true;
}

static bool
ma2_short_modulation(uint8_t value, uint8_t *result)
{
    static const uint8_t upper_bound[] = {
        0x00u, 0x08u, 0x10u, 0x18u, 0x20u, 0x28u, 0x30u,
        0x38u, 0x40u, 0x48u, 0x50u, 0x60u, 0x70u, 0x7fu,
    };
    size_t index;

    for (index = 0u; index < sizeof(upper_bound); index++) {
        if (value <= upper_bound[index]) {
            *result = (uint8_t)(index + 1u);
            return true;
        }
    }
    return false;
}

static bool
ma2_apply_fm_control(MSM5xxxMA2FMChannel *channel,
                     const MSM5xxxMA2CompactEvent *event)
{
    static const uint8_t expression[15] = {
        0x00u, 0x00u, 0x10u, 0x20u, 0x30u, 0x38u, 0x40u, 0x48u,
        0x50u, 0x58u, 0x60u, 0x68u, 0x70u, 0x78u, 0x7fu,
    };
    static const uint8_t pitch_bend[15] = {
        0x00u, 0x08u, 0x10u, 0x18u, 0x20u, 0x28u, 0x30u, 0x38u,
        0x40u, 0x48u, 0x50u, 0x58u, 0x60u, 0x68u, 0x70u,
    };

    switch (event->control_family) {
    case 0u:
        if (event->control_code >= sizeof(expression)) {
            return false;
        }
        channel->expression = expression[event->control_code];
        return true;
    case 1u:
        if (event->control_code >= sizeof(pitch_bend)) {
            return false;
        }
        channel->pitch_bend = pitch_bend[event->control_code];
        return true;
    case 2u:
        channel->modulation = event->control_code;
        return true;
    case 3u:
        break;
    default:
        return false;
    }

    switch (event->control_code) {
    case 0x0u:
        channel->program = event->control_value;
        return true;
    case 0x1u:
        channel->bank = event->control_value;
        return true;
    case 0x2u:
        channel->octave_shift = event->control_value;
        return true;
    case 0x3u:
        return ma2_short_modulation(event->control_value,
                                    &channel->modulation);
    case 0x4u:
        channel->pitch_bend = event->control_value;
        return true;
    case 0x7u:
        channel->volume = event->control_value;
        return true;
    case 0xau:
        channel->pan = event->control_value;
        return true;
    case 0xbu:
        channel->expression = event->control_value;
        return true;
    default:
        return false;
    }
}

static bool
ma2_apply_fm_event(MSM5xxxMA2Audio *audio,
                   const MSM5xxxMA2Output *output)
{
    MSM5xxxMA2FMChannel *channel = &audio->fm_channel[output->channel];
    bool handled = true;

    switch (output->event.kind) {
    case MSM5XXX_MA2_COMPACT_NOP:
        break;
    case MSM5XXX_MA2_COMPACT_NOTE:
        if (!channel->voice_slot_valid ||
            channel->voice_slot >= MSM5XXX_MA2_FM_VOICE_COUNT ||
            !audio->fm_voice[channel->voice_slot].valid) {
            handled = false;
            break;
        }
        channel->note_octave = output->event.octave;
        channel->note_id = output->event.note_id;
        channel->active_voice_slot = channel->voice_slot;
        channel->key_on = true;
        break;
    case MSM5XXX_MA2_COMPACT_CONTROL:
        handled = ma2_apply_fm_control(channel, &output->event);
        break;
    case MSM5XXX_MA2_COMPACT_SYSEX:
        handled = ma2_apply_fm_sysex(audio, &output->event);
        break;
    case MSM5XXX_MA2_COMPACT_WAVE:
    case MSM5XXX_MA2_COMPACT_UNSUPPORTED:
        handled = false;
        break;
    }
    if (!handled) {
        audio->fm_state_unhandled++;
    }
    return handled;
}

bool
msm5xxx_ma2_scheduler_step(MSM5xxxMA2Audio *audio,
                           uint64_t now_ns,
                           MSM5xxxMA2Output *output)
{
    MSM5xxxMA2Audio snapshot;
    uint64_t gate_deadline = UINT64_MAX;
    uint64_t sequence_deadline = UINT64_MAX;
    uint64_t note_gate_deadline;
    size_t gate_channel = SIZE_MAX;
    size_t due_stream = SIZE_MAX;
    size_t stream;
    size_t channel;
    MSM5xxxMA2SequenceState *sequence;
    MSM5xxxMA2GateState *gate;
    MSM5xxxMA2RejectReason reject_reason;
    bool gate_found = false;
    bool sequence_found = false;
    bool handled;

    if (audio == 0 || output == 0 || audio->rejected) {
        return false;
    }
    /* ponytail: one small state copy; split only if profiling finds it hot. */
    snapshot = *audio;
    memset(output, 0, sizeof(*output));
    if (audio->scheduler_clock_initialized &&
        now_ns < audio->scheduler_now_ns) {
        ma2_reject(audio, MSM5XXX_MA2_REJECT_CLOCK_ROLLBACK);
        goto rollback;
    }
    audio->scheduler_clock_initialized = true;
    audio->scheduler_now_ns = now_ns;

    for (stream = 0u; stream < MSM5XXX_MA2_SEQUENCE_COUNT; stream++) {
        if (!ma2_sync_sequence(audio, stream, now_ns) ||
            !ma2_stage_sequence(audio, stream)) {
            goto rollback;
        }
    }

    for (channel = 0u; channel < MSM5XXX_MA2_FM_CHANNEL_COUNT; channel++) {
        gate = &audio->fm_gate[channel];
        if (gate->active && ma2_gate_running(audio, channel) &&
            gate->deadline_ns <= now_ns &&
            (!gate_found || gate->deadline_ns < gate_deadline)) {
            gate_deadline = gate->deadline_ns;
            gate_channel = channel;
            gate_found = true;
        }
    }
    if (audio->adpcm_gate.active &&
        audio->sequence[MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE].running &&
        audio->adpcm_gate.deadline_ns <= now_ns &&
        (!gate_found || audio->adpcm_gate.deadline_ns < gate_deadline)) {
        gate_deadline = audio->adpcm_gate.deadline_ns;
        gate_channel = MSM5XXX_MA2_FM_CHANNEL_COUNT;
        gate_found = true;
    }
    for (stream = 0u; stream < MSM5XXX_MA2_SEQUENCE_COUNT; stream++) {
        sequence = &audio->sequence[stream];
        if (sequence->running && (sequence->pending || sequence->end_pending) &&
            sequence->deadline_ns <= now_ns &&
            (!sequence_found || sequence->deadline_ns < sequence_deadline)) {
            sequence_deadline = sequence->deadline_ns;
            due_stream = stream;
            sequence_found = true;
        }
    }

    if (gate_found && (!sequence_found || gate_deadline <= sequence_deadline)) {
        output->kind = MSM5XXX_MA2_OUTPUT_GATE_OFF;
        output->timestamp_ns = gate_deadline;
        if (gate_channel < MSM5XXX_MA2_FM_CHANNEL_COUNT) {
            output->stream = (MSM5xxxMA2Fifo)(gate_channel / 4u);
            output->channel = (uint8_t)gate_channel;
            audio->fm_gate[gate_channel].active = false;
            audio->fm_channel[gate_channel].key_on = false;
        } else {
            output->stream = MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE;
            audio->adpcm_gate.active = false;
        }
        return true;
    }
    if (!sequence_found) {
        return true;
    }

    sequence = &audio->sequence[due_stream];
    output->timestamp_ns = sequence->deadline_ns;
    output->stream = (MSM5xxxMA2Fifo)due_stream;
    if (sequence->end_pending) {
        sequence->end_pending = false;
        sequence->ended = true;
        output->kind = MSM5XXX_MA2_OUTPUT_END;
        return true;
    }

    output->kind = MSM5XXX_MA2_OUTPUT_EVENT;
    output->event = sequence->pending_event;
    if (due_stream < MSM5XXX_MA2_FM_FIFO_COUNT) {
        output->channel = (uint8_t)(due_stream * 4u +
                                    output->event.local_channel);
        handled = ma2_apply_fm_event(audio, output);
        if (handled && output->event.kind == MSM5XXX_MA2_COMPACT_NOTE) {
            if (!ma2_add_ticks(audio, sequence->deadline_ns,
                               sequence->gate_unit_ns,
                               output->event.gate_ticks,
                               &note_gate_deadline)) {
                goto rollback;
            }
            gate = &audio->fm_gate[output->channel];
            gate->deadline_ns = note_gate_deadline;
            gate->active = true;
        }
    } else if (output->event.kind == MSM5XXX_MA2_COMPACT_WAVE) {
        if (!ma2_add_ticks(audio, sequence->deadline_ns,
                           sequence->gate_unit_ns,
                           output->event.gate_ticks,
                           &audio->adpcm_gate.deadline_ns)) {
            goto rollback;
        }
        audio->adpcm_gate.active = true;
    }
    sequence->cursor_ns = sequence->deadline_ns;
    sequence->pending = false;
    return true;

rollback:
    reject_reason = audio->reject_reason;
    *audio = snapshot;
    ma2_reject(audio, reject_reason);
    memset(output, 0, sizeof(*output));
    return false;
}

bool
msm5xxx_ma2_scheduler_next_deadline(const MSM5xxxMA2Audio *audio,
                                    uint64_t *deadline_ns)
{
    uint64_t deadline = UINT64_MAX;
    size_t stream;
    size_t channel;
    bool found = false;

    if (audio == 0 || deadline_ns == 0 || audio->rejected) {
        return false;
    }
    for (stream = 0u; stream < MSM5XXX_MA2_SEQUENCE_COUNT; stream++) {
        const MSM5xxxMA2SequenceState *sequence = &audio->sequence[stream];

        if (sequence->running && (sequence->pending || sequence->end_pending) &&
            (!found || sequence->deadline_ns < deadline)) {
            deadline = sequence->deadline_ns;
            found = true;
        }
    }
    for (channel = 0u; channel < MSM5XXX_MA2_FM_CHANNEL_COUNT; channel++) {
        if (audio->fm_gate[channel].active &&
            ma2_gate_running(audio, channel) &&
            (!found || audio->fm_gate[channel].deadline_ns < deadline)) {
            deadline = audio->fm_gate[channel].deadline_ns;
            found = true;
        }
    }
    if (audio->adpcm_gate.active &&
        audio->sequence[MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE].running &&
        (!found || audio->adpcm_gate.deadline_ns < deadline)) {
        deadline = audio->adpcm_gate.deadline_ns;
        found = true;
    }
    if (!found) {
        return false;
    }
    *deadline_ns = deadline;
    return true;
}

void
msm5xxx_ma2_adpcm_decoder_reset(MSM5xxxMA2AdpcmDecoder *decoder)
{
    if (decoder == 0) {
        return;
    }
    decoder->accumulator = 0;
    decoder->step = 127u;
}

static int16_t
ma2_adpcm_decode_nibble(MSM5xxxMA2AdpcmDecoder *decoder, uint8_t nibble)
{
    static const uint16_t coefficients[8] = {
        0x3980u, 0x3980u, 0x3980u, 0x3980u,
        0x4cc0u, 0x6640u, 0x8000u, 0x9980u,
    };
    uint32_t step = decoder->step;
    int32_t delta = (int32_t)(step >> 3);
    int32_t accumulator;

    nibble &= 0x0fu;
    if ((nibble & 1u) != 0u) {
        delta += (int32_t)(step >> 2);
    }
    if ((nibble & 2u) != 0u) {
        delta += (int32_t)(step >> 1);
    }
    if ((nibble & 4u) != 0u) {
        delta += (int32_t)step;
    }
    accumulator = decoder->accumulator +
        ((nibble & 8u) != 0u ? -delta : delta);
    if (accumulator > INT16_MAX) {
        accumulator = INT16_MAX;
    } else if (accumulator < INT16_MIN) {
        accumulator = INT16_MIN;
    }
    decoder->accumulator = accumulator;
    step = (step * coefficients[nibble & 7u]) >> 14;
    if (step < 127u) {
        step = 127u;
    } else if (step > 0x6000u) {
        step = 0x6000u;
    }
    decoder->step = step;
    return (int16_t)accumulator;
}

bool
msm5xxx_ma2_adpcm_decode_byte(MSM5xxxMA2AdpcmDecoder *decoder,
                              uint8_t value,
                              int16_t samples[2])
{
    if (decoder == 0 || samples == 0) {
        return false;
    }
    samples[0] = ma2_adpcm_decode_nibble(decoder, value);
    samples[1] = ma2_adpcm_decode_nibble(decoder, value >> 4);
    return true;
}
