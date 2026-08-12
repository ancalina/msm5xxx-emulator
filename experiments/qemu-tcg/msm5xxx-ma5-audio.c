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
