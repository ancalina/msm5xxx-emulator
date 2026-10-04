/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-audio-request.h"

#include <string.h>

void msm5xxx_audio_request_begin(MSM5xxxAudioRequest *request)
{
    if (request != NULL) {
        memset(request, 0, sizeof(*request));
    }
}

MSM5xxxAudioRequestResult msm5xxx_audio_request_feed(
    MSM5xxxAudioRequest *request, uint8_t value)
{
    if (request == NULL) {
        return MSM5XXX_AUDIO_REQUEST_INVALID;
    }
    if (request->invalid || request->finished) {
        request->invalid = true;
        return MSM5XXX_AUDIO_REQUEST_INVALID;
    }
    if (!request->address_complete) {
        if (request->address_bytes >= 3 ||
            (request->address_bytes == 2 && !(value & 0x80)) ||
            (request->address_bytes != 0 && value == 0x80)) {
            /* Only the minimal one-to-three-byte producer form is admitted. */
            request->invalid = true;
            return MSM5XXX_AUDIO_REQUEST_INVALID;
        }
        request->address |= (uint32_t)(value & 0x7f) <<
                            (7 * request->address_bytes++);
        request->address_complete = (value & 0x80) != 0;
        return MSM5XXX_AUDIO_REQUEST_PARTIAL;
    }
    if (!(value & 0x80)) {
        request->invalid = true;
        return MSM5XXX_AUDIO_REQUEST_INVALID;
    }
    request->type = value & 0x7f;
    request->finished = true;
    return MSM5XXX_AUDIO_REQUEST_COMPLETE;
}

enum {
    PACKET_ADDRESS_FIRST, PACKET_ADDRESS_SECOND, PACKET_ADDRESS_THIRD,
    PACKET_LENGTH_FIRST, PACKET_LENGTH_SECOND,
    PACKET_REGISTER_DATA, PACKET_MEMORY_DATA, PACKET_INVALID,
};

void msm5xxx_audio_packet_reset(MSM5xxxAudioPacket *packet)
{
    if (packet != NULL) {
        memset(packet, 0, sizeof(*packet));
    }
}

MSM5xxxAudioPacketResult msm5xxx_audio_packet_feed(
    MSM5xxxAudioPacket *p, uint8_t value, MSM5xxxAudioPacketWrite *write)
{
    MSM5xxxAudioPacketResult kind;
    bool last;

    if (p == NULL || write == NULL) {
        return MSM5XXX_AUDIO_PACKET_INVALID;
    }
    switch (p->phase) {
    case PACKET_ADDRESS_FIRST:
        p->address = value & 0x7f;
        p->phase = value & 0x80 ? PACKET_REGISTER_DATA : PACKET_ADDRESS_SECOND;
        return MSM5XXX_AUDIO_PACKET_PARTIAL;
    case PACKET_ADDRESS_SECOND:
        p->address |= (uint32_t)(value & 0x7f) << 7;
        p->phase = value & 0x80 ? PACKET_REGISTER_DATA : PACKET_ADDRESS_THIRD;
        return MSM5XXX_AUDIO_PACKET_PARTIAL;
    case PACKET_ADDRESS_THIRD:
        p->address |= (uint32_t)(value & 0x7f) << 14;
        p->phase = PACKET_LENGTH_FIRST;
        return MSM5XXX_AUDIO_PACKET_PARTIAL;
    case PACKET_LENGTH_FIRST:
        p->remaining = value & 0x7f;
        p->phase = value & 0x80 ?
            (p->remaining ? PACKET_MEMORY_DATA : PACKET_ADDRESS_FIRST) :
            PACKET_LENGTH_SECOND;
        return MSM5XXX_AUDIO_PACKET_PARTIAL;
    case PACKET_LENGTH_SECOND:
        p->remaining |= (uint16_t)(value & 0x7f) << 7;
        p->phase = p->remaining ? PACKET_MEMORY_DATA : PACKET_ADDRESS_FIRST;
        return MSM5XXX_AUDIO_PACKET_PARTIAL;
    case PACKET_REGISTER_DATA:
        kind = MSM5XXX_AUDIO_PACKET_REGISTER;
        last = (value & 0x80) != 0;
        break;
    case PACKET_MEMORY_DATA:
        if (!p->remaining) {
            p->phase = PACKET_INVALID;
            return MSM5XXX_AUDIO_PACKET_INVALID;
        }
        kind = MSM5XXX_AUDIO_PACKET_MEMORY;
        last = p->remaining == 1;
        break;
    default:
        p->phase = PACKET_INVALID;
        return MSM5XXX_AUDIO_PACKET_INVALID;
    }
    if (!last && p->address == UINT32_MAX) {
        p->phase = PACKET_INVALID;
        return MSM5XXX_AUDIO_PACKET_INVALID;
    }
    *write = (MSM5xxxAudioPacketWrite) {
        .address = p->address, .value = value, .last = last,
    };
    if (kind == MSM5XXX_AUDIO_PACKET_MEMORY) {
        p->remaining--;
    }
    if (last) {
        p->phase = PACKET_ADDRESS_FIRST;
    } else {
        p->address++;
    }
    return kind;
}

void msm5xxx_audio_timed_packet_reset(MSM5xxxAudioTimedPacket *packet)
{
    if (packet != NULL) {
        memset(packet, 0, sizeof(*packet));
    }
}

MSM5xxxAudioPacketResult msm5xxx_audio_timed_packet_feed(
    MSM5xxxAudioTimedPacket *p, uint8_t value, MSM5xxxAudioTimedPacketWrite *write)
{
    MSM5xxxAudioPacketWrite packet_write;
    MSM5xxxAudioPacketResult kind;

    if (p == NULL || write == NULL || p->delta_bytes > 3) {
        return MSM5XXX_AUDIO_PACKET_INVALID;
    }
    if (p->delta_bytes < 3) {
        if (!p->delta_bytes) {
            p->pending_delta = value & 0x7f;
        } else {
            p->pending_delta |= (uint32_t)(value & 0x7f) <<
                                (7 * p->delta_bytes);
        }
        p->delta_bytes++;
        if (value & 0x80) {
            p->delta_bytes = 3;
        }
        return MSM5XXX_AUDIO_PACKET_PARTIAL;
    }
    kind = msm5xxx_audio_packet_feed(&p->packet, value, &packet_write);
    if (kind == MSM5XXX_AUDIO_PACKET_REGISTER ||
        kind == MSM5XXX_AUDIO_PACKET_MEMORY) {
        *write = (MSM5xxxAudioTimedPacketWrite) {
            .write = packet_write, .delta = p->pending_delta,
        };
        p->pending_delta = 0;
    }
    if (p->packet.phase == PACKET_ADDRESS_FIRST) {
        p->delta_bytes = 0;
        p->pending_delta = 0;
    }
    return kind;
}

void msm5xxx_audio_packet_sink_reset(MSM5xxxAudioPacketSink *s)
{
    if (s != NULL) {
        memset(s, 0, sizeof(*s));
        msm5xxx_audio_packet_reset(&s->packet);
    }
}

bool msm5xxx_audio_packet_sink_feed(MSM5xxxAudioPacketSink *s, uint8_t value)
{
    MSM5xxxAudioPacketWrite write;
    MSM5xxxAudioPacketResult kind;
    MSM5xxxAudioPacketReject reject = MSM5XXX_AUDIO_PACKET_REJECT_NONE;
    unsigned slot = 0, offset = 0;

    if (s == NULL || s->reject != MSM5XXX_AUDIO_PACKET_REJECT_NONE) {
        return false;
    }
    kind = msm5xxx_audio_packet_feed(&s->packet, value, &write);
    if (kind == MSM5XXX_AUDIO_PACKET_PARTIAL) {
        return true;
    }
    if (kind == MSM5XXX_AUDIO_PACKET_REGISTER) {
        if (write.address == 0x163) {
            if (value & 0x40) {
                reject = MSM5XXX_AUDIO_PACKET_REJECT_REGISTER;
            }
        } else if (write.address < 0x60) {
            slot = write.address / 6;
            offset = write.address % 6;
        } else if (write.address >= 0xe0 && write.address < 0x140) {
            slot = 16 + (write.address - 0xe0) / 6;
            offset = (write.address - 0xe0) % 6;
        } else {
            reject = MSM5XXX_AUDIO_PACKET_REJECT_REGISTER;
        }
        if (reject == MSM5XXX_AUDIO_PACKET_REJECT_NONE &&
            write.address != 0x163) {
            if (offset == 1 && !s->channel[slot].high_valid) {
                reject = MSM5XXX_AUDIO_PACKET_REJECT_POINTER;
            } else if (offset == 4 && !s->channel[slot].pitch_high_valid) {
                reject = MSM5XXX_AUDIO_PACKET_REJECT_DEPENDENCY;
            }
        }
    } else if (kind == MSM5XXX_AUDIO_PACKET_MEMORY) {
        if (write.address < 0x4000 || write.address >= 0x6000) {
            reject = MSM5XXX_AUDIO_PACKET_REJECT_MEMORY;
        }
    } else {
        reject = MSM5XXX_AUDIO_PACKET_REJECT_SYNTAX;
    }
    if (reject != MSM5XXX_AUDIO_PACKET_REJECT_NONE) {
        s->reject = reject;
        s->rejected_address = kind == MSM5XXX_AUDIO_PACKET_INVALID ?
            s->packet.address : write.address;
        s->rejected_value = value;
        return false;
    }
    if (kind == MSM5XXX_AUDIO_PACKET_REGISTER) {
        MSM5xxxAudioPacketChannel *channel = &s->channel[slot];
        if (write.address == 0x163) {
            s->smoothing_config = value & 0x3f;
            s->smoothing_config_valid = true;
        } else if (offset == 0) {
            channel->high = value & 0x7f;
            channel->high_valid = true;
        } else if (offset == 1) {
            channel->pointer = 2 * (((uint16_t)channel->high << 7) |
                                    (value & 0x7f));
            channel->pointer_valid = true;
        } else if (offset == 2) {
            channel->level = (value >> 2) & 31;
            channel->level_valid = true;
        } else if (offset == 3) {
            channel->pitch_high = value & 0x7f;
            channel->pitch_high_valid = true;
        } else if (offset == 4) {
            channel->pitch = ((uint16_t)channel->pitch_high << 7) |
                             (value & 0x7f);
            channel->pitch_valid = true;
        } else {
            channel->control = value & 0x7f;
            channel->control_valid = true;
        }
        if (s->register_writes != UINT32_MAX) {
            s->register_writes++;
        }
    } else {
        s->memory[write.address - 0x4000] = value;
        if (s->memory_writes != UINT32_MAX) {
            s->memory_writes++;
        }
    }
    return true;
}

void msm5xxx_audio_readback_index(MSM5xxxAudioReadback *s, uint8_t value)
{
    s->index = value;
    if (value == 3) {
        msm5xxx_audio_request_begin(&s->request);
        s->result_valid = false;
    }
}

bool msm5xxx_audio_readback_write(MSM5xxxAudioReadback *s, uint8_t value)
{
    if (s->index == 4 && value == 0x80) {
        s->reset_asserted = true;
        s->reset_known = false;
        s->result_valid = false;
        msm5xxx_audio_request_begin(&s->request);
    } else if (s->index == 4 && value == 0 && s->reset_asserted) {
        s->reset_known = true;
        s->reset_asserted = false;
    } else if (s->index == 3) {
        MSM5xxxAudioRequestResult result =
            msm5xxx_audio_request_feed(&s->request, value);
        if (result == MSM5XXX_AUDIO_REQUEST_INVALID) {
            s->result_valid = false;
            return false;
        }
        if (result == MSM5XXX_AUDIO_REQUEST_COMPLETE) {
            uint32_t address = s->request.address;
            s->result_valid = false;
            if (s->reset_known && !s->reset_asserted && s->request.type == 2) {
                /* Provisional shared consumer expectations, not silicon values.
                 * Unmodeled writes discard this entire reset-only profile. */
                if (address >= 0x90 && address <= 0x9f) {
                    s->result = 0x60;
                    s->result_valid = true;
                } else if (address >= 0xa0 && address <= 0xaf) {
                    s->result = 0x3c;
                    s->result_valid = true;
                } else if (address >= 0x14a && address <= 0x151) {
                    s->result = 0x40;
                    s->result_valid = true;
                }
            }
        }
    } else {
        s->reset_known = false;
        s->reset_asserted = false;
        s->result_valid = false;
    }
    return true;
}

uint8_t msm5xxx_audio_readback_status(const MSM5xxxAudioReadback *s)
{
    /* ponytail: synchronous parser capacity; replace with measured FIFO timing
     * before enabling by default. Capacity never promises a query result. */
    bool capacity = !s->request.invalid && !s->reset_asserted;
    return (capacity ? 1 : 0) | (s->result_valid ? 0x40 : 0);
}

bool msm5xxx_audio_readback_read(MSM5xxxAudioReadback *s, uint8_t *value)
{
    if (s->index != 0x43 || !s->result_valid) {
        return false;
    }
    *value = s->result;
    s->result_valid = false;
    return true;
}
