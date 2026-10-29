/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Modified 2026-10-17: add bounded encoder FIFO packet metadata. */
#include "msm5xxx-search2.h"

#include <string.h>

static unsigned search2_next(unsigned index)
{
    return (index + 1) % MSM5XXX_SEARCH2_DEPTH;
}

void msm5xxx_search2_init(MSM5xxxSearch2 *s)
{
    memset(s, 0, sizeof(*s));
    s->epoch = 1;
}

void msm5xxx_search2_reset(MSM5xxxSearch2 *s)
{
    uint64_t epoch = s->epoch + 1;

    memset(s, 0, sizeof(*s));
    s->epoch = epoch;
}

bool msm5xxx_search2_read(MSM5xxxSearch2 *s, unsigned offset,
                         unsigned width, uint16_t *value)
{
    if (!value) {
        return false;
    }
    if (offset == 8 && width == 1) {
        *value = s->status;
        s->status = 0;
    } else if (offset == 12 && width == 2) {
        if (!s->result_records) {
            return false;
        }
        *value = s->results[s->result_read][s->result_sub];
        if (++s->result_sub == MSM5XXX_SEARCH2_RESULTS) {
            s->result_sub = 0;
            s->result_read = search2_next(s->result_read);
            s->result_records--;
        }
    } else if (offset == 16 && width == 2) {
        *value = (s->queue_write << 12) | (s->queue_sub << 8) |
                 (s->queue_read << 4);
    } else if (offset == 20 && width == 2) {
        *value = (s->result_write << 12) | (s->result_read << 4) |
                 s->result_sub;
    } else {
        return false;
    }
    return true;
}

bool msm5xxx_search2_write(MSM5xxxSearch2 *s, unsigned offset,
                          unsigned width, uint16_t value)
{
    if (offset == 4 && width == 2) {
        if (s->queued_records == MSM5XXX_SEARCH2_DEPTH) {
            return false;
        }
        s->parameters[s->queue_write][s->queue_sub] = value;
        if (++s->queue_sub == MSM5XXX_SEARCH2_PARAMETERS) {
            s->queue_sub = 0;
            s->queue_write = search2_next(s->queue_write);
            s->queued_records++;
        }
    } else if (offset == 20 && width == 1 && value <= 3) {
        s->dump_enable = value;
    } else if (offset == 0 && width == 1 && !(value & ~12u)) {
        /* Active-search abort/reset ordering needs a device-level contract. */
        if (s->active && value) {
            return false;
        }
        if (value & 8) {
            s->queue_write = s->queue_read = s->queue_sub = 0;
            s->queued_records = 0;
        }
        if (value & 4) {
            s->result_write = s->result_read = s->result_sub = 0;
            s->result_records = 0;
        }
    } else {
        return false;
    }
    return true;
}

bool msm5xxx_search2_begin(MSM5xxxSearch2 *s, MSM5xxxSearch2Job *job)
{
    if (!job || s->active || !s->queued_records) {
        return false;
    }
    s->job.epoch = s->epoch;
    s->job.sequence = ++s->sequence;
    memcpy(s->job.parameters, s->parameters[s->queue_read],
           sizeof(s->job.parameters));
    s->queue_read = search2_next(s->queue_read);
    s->queued_records--;
    s->active = true;
    *job = s->job;
    return true;
}

bool msm5xxx_search2_complete(MSM5xxxSearch2 *s,
                             const MSM5xxxSearch2Job *job,
                             const uint16_t words[MSM5XXX_SEARCH2_RESULTS])
{
    if (!job || !words || !s->active || job->epoch != s->job.epoch ||
        job->sequence != s->job.sequence ||
        s->result_records == MSM5XXX_SEARCH2_DEPTH) {
        return false;
    }
    memcpy(s->results[s->result_write], words, sizeof(s->results[0]));
    s->result_write = search2_next(s->result_write);
    s->result_records++;
    s->active = false;
    if (s->job.parameters[0] & 0x8000) {
        s->status |= 2;
    }
    return true;
}

bool msm5xxx_search2_dump_requested(const MSM5xxxSearch2 *s)
{
    return (s->status & s->dump_enable & 2) != 0;
}

bool msm5xxx_search2_decode(const MSM5xxxSearch2Job *job,
                           MSM5xxxSearch2Parameters *parameters)
{
    const uint16_t *p;

    if (!job || !parameters) {
        return false;
    }
    p = job->parameters;
    if ((p[0] & 63) != 62 || !p[1] || p[1] > 0x7fff ||
        !p[2] || p[2] > 0x7fff || p[4] > 63) {
        return false;
    }
    /* This packet class leaves the window's physical units unresolved. */
    *parameters = (MSM5xxxSearch2Parameters) {
        .phase_index = (((p[0] & 0x7fff) + 2) >> 6) & 511,
        .mask_i = p[1], .mask_q = p[2], .window_word = p[3],
        .phase_fraction = (p[4] << 3) | (p[5] >> 13),
        .integration = (p[5] >> 10) & 7,
        .gain = (p[5] >> 8) & 3, .chips = p[5] & 255,
        .dump = (p[0] & 0x8000) != 0,
    };
    return true;
}

bool msm5xxx_search1_decode(const uint8_t p[MSM5XXX_SEARCH1_PARAMETERS],
                           MSM5xxxSearch2Parameters *parameters)
{
    MSM5xxxSearch2Job job = {0};
    uint32_t slew;

    if (!p || !parameters) {
        return false;
    }
    slew = p[14] | ((uint32_t)p[15] << 8) | ((uint32_t)p[16] << 16);
    if (slew > 511 || (slew & 7) || p[3] > 7 ||
        (p[4] & ~0x33u) || (p[0] | (p[1] << 8)) > 8192) {
        return false;
    }
    /* PN zero wraps to 0xfffe; the offset field discards bit 15. */
    job.parameters[0] = p[8] | (p[9] << 8) | 0x8000;
    job.parameters[1] = p[10] | (p[11] << 8);
    job.parameters[2] = p[12] | (p[13] << 8);
    job.parameters[3] = p[0] | (p[1] << 8);
    job.parameters[4] = slew >> 3;
    job.parameters[5] = (p[3] << 10) | ((p[4] & 3) << 8) | p[2];
    /* shortcut: explicit post-correlator energy does not model early integration
     * termination; replace with calibrated sampling before claiming RF fidelity. */
    return msm5xxx_search2_decode(&job, parameters);
}

bool msm5xxx_search2_virtual_result(const MSM5xxxSearch2Parameters *p,
                                   uint32_t position_before, uint32_t pilot_phase,
                                   uint16_t peak_energy, uint16_t words[8],
                                   uint32_t *position_after)
{
    const uint32_t mask = 0x3ffff;
    uint16_t result[8] = {0};
    uint32_t start, delta, end, candidates[4];
    unsigned i;

    if (!p || !words || !position_after || position_before > mask ||
        pilot_phase > mask || p->phase_index > 511 || p->phase_fraction > 511 ||
        p->window_word > 8192) {
        return false;
    }
    end = (position_before + p->phase_fraction + p->window_word * 4) & mask;
    start = (position_before + p->phase_fraction + p->phase_index * 512) & mask;
    delta = (pilot_phase - start) & mask;
    candidates[0] = 0;
    candidates[1] = p->window_word ? p->window_word - 1 : 0;
    candidates[2] = delta / 4;
    candidates[3] = delta / 4 + 1;
    /* Provisional ideal single path: zero noise, triangular-chip correlation.
     * Energy is supplied in post-correlator units, not calibrated RF power. */
    for (i = 0; i < 4; i++) {
        uint32_t index = candidates[i];
        uint32_t distance, energy;

        if (index >= p->window_word) {
            continue;
        }
        distance = (start + index * 4 - pilot_phase) & mask;
        if (distance > (mask + 1) / 2) {
            distance = mask + 1 - distance;
        }
        if (distance >= 8) {
            continue;
        }
        energy = (uint32_t)peak_energy * (8 - distance) * (8 - distance) / 64;
        if (energy > result[0] || (energy == result[0] && index < result[1])) {
            result[0] = energy;
            result[1] = index;
        }
    }
    memcpy(words, result, sizeof(result));
    *position_after = end;
    return true;
}

void msm5xxx_fingers_reset(MSM5xxxFingers *s)
{
    unsigned i;

    memset(s, 0, sizeof(*s));
    for (i = 0; i < MSM5XXX_FINGER_COUNT; i++) {
        s->bank[i].supported = true;
    }
}

bool msm5xxx_fingers_write(MSM5xxxFingers *s, unsigned offset,
                          unsigned width, uint16_t value)
{
    static const unsigned offsets[] = {
        0x70, 0x74, 0x94, 0x98, 0x9c, 0xa0,
        0xa4, 0xa8, 0xb0, 0xb4, 0xb8, 0x90,
    };
    unsigned i, reg;
    bool supported = true;

    if (width != 1 || value > 255) {
        return false;
    }
    if (offset == 0x78) {
        s->selected = value;
        return !(value & ~15u);
    }
    if (offset == 0x8c) {
        s->filter_gain = value;
        return value <= 31;
    }
    if (!s->selected || (s->selected & ~15u)) {
        return false;
    }
    for (reg = 0; reg < sizeof(offsets) / sizeof(offsets[0]); reg++) {
        if (offsets[reg] == offset) {
            break;
        }
    }
    if (reg == sizeof(offsets) / sizeof(offsets[0])) {
        return false;
    }
    for (i = 0; i < MSM5XXX_FINGER_COUNT; i++) {
        MSM5xxxFinger *f = &s->bank[i];

        if (!(s->selected & (1u << i))) {
            continue;
        }
        f->registers[reg] = value;
        f->seen |= 1u << reg;
        if ((reg == 0 && (value & ~0x27u)) || (reg == 1 && (value & ~1u))) {
            f->supported = false;
            f->unsupported_offset = offset;
            f->unsupported_value = value;
            f->latched = false;
            supported = false;
        }
        if (reg == 10 && (f->seen & 0x700) == 0x700) {
            uint32_t slew = f->registers[8] | (f->registers[9] << 8) |
                            ((uint32_t)f->registers[10] << 16);
            f->position = (f->position + slew) & 0x3ffff;
        }
    }
    return supported;
}

void msm5xxx_fingers_latch(MSM5xxxFingers *s, uint32_t pilot_phase,
                          uint16_t peak_energy, const uint16_t masks_i[512],
                          const uint16_t masks_q[512])
{
    unsigned i;

    for (i = 0; i < MSM5XXX_FINGER_COUNT; i++) {
        MSM5xxxFinger *f = &s->bank[i];
        const uint8_t *p = f->registers;
        uint16_t pn = p[2] | ((p[3] & 0x7f) << 8);
        uint16_t seed_i = p[4] | ((p[5] & 0x7f) << 8);
        uint16_t seed_q = p[6] | ((p[7] & 0x7f) << 8);
        uint16_t words[8];
        uint32_t end;
        MSM5xxxSearch2Parameters parameters = {
            .phase_index = ((pn + 2) >> 6) & 511, .window_word = 1,
        };

        f->latched = f->supported && s->filter_gain <= 31;
        f->latched_position = f->position;
        f->rssi = 0;
        if (!f->latched || !(p[0] & 1) || (p[0] & 0x20)) {
            continue;
        }
        if ((f->seen & 0x7fc) != 0x7fc || (pn & 63) != 62 ||
            !masks_i || !masks_q || pilot_phase > 0x3ffff) {
            f->latched = false;
            continue;
        }
        if (!seed_i || !seed_q || seed_i != masks_i[parameters.phase_index] ||
            seed_q != masks_q[parameters.phase_index]) {
            continue;
        }
        /* shortcut: noiseless RSSI settles on each status dump; filter/init
         * transients and common PN clock need hardware timing calibration. */
        if (msm5xxx_search2_virtual_result(&parameters, f->position, pilot_phase,
                                          peak_energy, words, &end)) {
            f->rssi = words[0];
        }
    }
}

bool msm5xxx_fingers_read(const MSM5xxxFingers *s, unsigned offset,
                         unsigned width, uint16_t *value)
{
    unsigned i;
    const MSM5xxxFinger *f;

    if (!value || !s->selected || (s->selected & ~15u) ||
        (s->selected & (s->selected - 1))) {
        return false;
    }
    for (i = 0; !(s->selected & (1u << i)); i++) {
        /* The validated one-hot selector has four possible banks. */
    }
    f = &s->bank[i];
    if (!f->supported || !f->latched) {
        return false;
    }
    if (offset == 0x8c && width == 2) {
        *value = f->rssi;
    } else if (offset == 0xb0 && width == 2) {
        *value = f->latched_position & 0xffff;
    } else if (offset == 0xb8 && width == 1) {
        *value = f->latched_position >> 16;
    } else {
        return false;
    }
    return true;
}

uint64_t msm5xxx_combiner_deadline(uint64_t roll)
{
    uint64_t cycles = roll / 3, remainder = (roll % 3) * 80000000;

    if (cycles > (UINT64_MAX - 80000000) / 80000000) {
        return UINT64_MAX;
    }
    return cycles * 80000000 + (remainder + 2) / 3;
}

uint16_t msm5xxx_combiner_position(uint64_t elapsed_ns)
{
    uint64_t scaled = (elapsed_ns % 80000000) * 3;

    return ((scaled / 80000000) << 14) |
           ((scaled % 80000000) * 0x4000 / 80000000);
}

bool msm5xxx_sync_frame(const uint8_t *message, unsigned length,
                        uint64_t frame, uint16_t words[8])
{
    uint32_t crc = 0x3fffffff;
    unsigned bits, padded, start, i;
    uint8_t data[12] = {0};

    if (!message || !words || length < 5 || length > MSM5XXX_SYNC_MAX_BYTES || message[0] != length) {
        return false;
    }
    bits = length * 8;
    for (i = 0; i < bits; i++) {
        unsigned bit = (message[i / 8] >> (7 - i % 8)) & 1;
        unsigned feedback = ((crc >> 29) ^ bit) & 1;
        crc = (crc << 1) ^ (feedback ? 0x6030b9c7 : 0);
    }
    if (((~crc) & 0x3fffffff) != 0x0b105aa5) {
        return false;
    }
    padded = (bits + 92) / 93;
    start = (frame % padded) * 93;
    for (i = 0; i < 96; i++) {
        unsigned bit;
        if (!(i % 32)) {
            bit = !start && !i;
        } else {
            unsigned payload = start + (i / 32) * 31 + i % 32 - 1;
            bit = payload < bits ? (message[payload / 8] >> (7 - payload % 8)) & 1 : 0;
        }
        data[i / 8] |= bit << (7 - i % 8);
    }
    for (i = 0; i < 6; i++) {
        words[i] = data[2 * i] | (data[2 * i + 1] << 8);
    }
    /* shortcut: ideal zero-error metrics, replace when decoder status semantics are measured. */
    words[6] = words[7] = 0;
    return true;
}

bool msm5xxx_sync_decoder_frame(const uint8_t *message, unsigned length,
                                uint64_t frame, uint16_t words[8])
{
    uint16_t previous[8] = {0}, following[8];
    unsigned i;

    if (!words || !msm5xxx_sync_frame(message, length, frame, following) ||
        (frame && !msm5xxx_sync_frame(message, length, frame - 1, previous))) {
        return false;
    }
    memset(words, 0, 8 * sizeof(*words));
    /* RX carries the previous hardware tail24 before consuming the new head72. */
    for (i = 0; i < 12; i++) {
        const uint16_t *source = i < 9 ? previous : following;
        unsigned at = i < 9 ? i + 3 : i - 9;
        uint8_t value = (source[at / 2] >> (8 * (at % 2))) & 255;
        words[i / 2] |= (uint16_t)value << (8 * (i % 2));
    }
    return true;
}

uint64_t msm5xxx_radio_deadline(uint64_t tick)
{
    uint64_t cycles = tick / 12;
    uint64_t fraction = ((tick % 12) * 80000000 + 11) / 12;

    if (cycles > (UINT64_MAX - fraction) / 80000000) {
        return UINT64_MAX;
    }
    return cycles * 80000000 + fraction;
}

static uint32_t paging_crc30(const uint8_t *message, unsigned bits)
{
    uint32_t crc = 0x3fffffff;
    unsigned i;

    for (i = 0; i < bits; i++) {
        unsigned bit = (message[i / 8] >> (7 - i % 8)) & 1;
        unsigned feedback = ((crc >> 29) ^ bit) & 1;
        crc = (crc << 1) ^ (feedback ? 0x6030b9c7 : 0);
    }
    return (~crc) & 0x3fffffff;
}

static bool paging_message_valid(const uint8_t *message, unsigned length)
{
    return message && length >= 5 && length <= MSM5XXX_PAGING_MAX_BYTES &&
        message[0] == length && paging_crc30(message, length * 8) == 0x0b105aa5;
}

static void paging_packet_frame(const uint8_t *message, unsigned length,
                                 unsigned frame_bits, unsigned at,
                                 uint8_t data[24])
{
    unsigned i, payload_bits = frame_bits - 2, subframe_bits = frame_bits / 2;

    memset(data, 0, 24);
    for (i = 0; i < frame_bits; i++) {
        unsigned bit;
        if (!(i % subframe_bits)) {
            bit = !at && !i;
        } else {
            unsigned payload = at * payload_bits +
                (i / subframe_bits) * (subframe_bits - 1) +
                i % subframe_bits - 1;
            bit = payload < length * 8 ?
                (message[payload / 8] >> (7 - payload % 8)) & 1 : 0;
        }
        data[i / 8] |= bit << (7 - i % 8);
    }
}

static void paging_logical_frame(
    const uint8_t messages[MSM5XXX_PAGING_MESSAGES][MSM5XXX_PAGING_MAX_BYTES],
    const uint8_t lengths[MSM5XXX_PAGING_MESSAGES], unsigned frame_bits,
    unsigned cycle_frames, uint64_t frame, uint8_t data[24])
{
    unsigned at = frame % cycle_frames, packet;

    for (packet = 0; packet < MSM5XXX_PAGING_MESSAGES; packet++) {
        unsigned count = (lengths[packet] * 8 + frame_bits - 3) / (frame_bits - 2);
        if (at < count) {
            break;
        }
        at -= count;
    }
    paging_packet_frame(messages[packet], lengths[packet], frame_bits, at, data);
}

bool msm5xxx_paging_decoder_frame(
    const uint8_t messages[MSM5XXX_PAGING_MESSAGES][MSM5XXX_PAGING_MAX_BYTES],
    const uint8_t lengths[MSM5XXX_PAGING_MESSAGES], unsigned rate,
    uint64_t frame, uint16_t words[14])
{
    uint8_t previous[24] = {0}, following[24];
    unsigned frame_bits, cycle_frames = 0, packet, i;

    if (!messages || !lengths || !words || rate > 1) {
        return false;
    }
    frame_bits = rate ? 96 : 192;
    for (packet = 0; packet < MSM5XXX_PAGING_MESSAGES; packet++) {
        unsigned bits = lengths[packet] * 8;
        if (!paging_message_valid(messages[packet], lengths[packet])) {
            return false;
        }
        cycle_frames += (bits + frame_bits - 3) / (frame_bits - 2);
    }
    paging_logical_frame(messages, lengths, frame_bits, cycle_frames, frame, following);
    if (frame) {
        paging_logical_frame(messages, lengths, frame_bits, cycle_frames, frame - 1, previous);
    }
    memset(words, 0, 14 * sizeof(*words));
    /* RX carries the previous hardware tail before consuming the new head72. */
    for (i = 0; i < frame_bits / 8; i++) {
        unsigned carry_bytes = (frame_bits - 72) / 8;
        uint8_t value = i < 9 ? previous[carry_bytes + i] : following[i - 9];
        words[i / 2] |= (uint16_t)value << (8 * (i % 2));
    }
    /* shortcut: ideal zero-error metrics, replace when decoder status semantics are measured. */
    words[frame_bits / 16] = words[frame_bits / 16 + 1] = 0;
    return true;
}

static uint32_t access_bits(const uint8_t *data, unsigned start, unsigned width)
{
    uint32_t value = 0;
    unsigned bit;

    for (bit = start; bit < start + width; bit++) {
        value = (value << 1) | ((data[bit / 8] >> (7 - bit % 8)) & 1);
    }
    return value;
}

void msm5xxx_access_init(MSM5xxxAccess *s)
{
    memset(s, 0, sizeof(*s));
}

void msm5xxx_access_gap(MSM5xxxAccess *s)
{
    memset(s->window, 0, sizeof(s->window));
    s->window_length = 0;
    s->examined = 0;
    s->last_end = 0;
    s->gaps++;
}

bool msm5xxx_access_push(MSM5xxxAccess *s, const uint8_t *piece,
                         unsigned length)
{
    bool accepted = false;
    unsigned start;

    s->last_end = 0;
    if (!piece || length != MSM5XXX_ACCESS_PIECE_BYTES) {
        msm5xxx_access_gap(s);
        return false;
    }
    if (s->window_length == sizeof(s->window)) {
        memmove(s->window, s->window + MSM5XXX_ACCESS_PIECE_BYTES,
                sizeof(s->window) - MSM5XXX_ACCESS_PIECE_BYTES);
        s->window_length -= MSM5XXX_ACCESS_PIECE_BYTES;
        s->examined >>= 1;
    }
    memcpy(s->window + s->window_length, piece, length);
    s->window_length += length;
    s->pieces++;
    for (start = 0; start < s->window_length / MSM5XXX_ACCESS_PIECE_BYTES;
         start++) {
        const uint8_t *packet = s->window + start * MSM5XXX_ACCESS_PIECE_BYTES;
        unsigned available = s->window_length - start * MSM5XXX_ACCESS_PIECE_BYTES;
        unsigned count = packet[0], format = packet[1] >> 6;
        unsigned type = packet[1] & 0x3f;
        unsigned sequence_bit = format ? 24 : 19;
        unsigned protected_bits, bit;
        uint32_t crc = 0x3fffffff, mask = (uint32_t)1 << start;
        MSM5xxxAccessPacket metadata = {0};

        if (s->examined & mask) {
            continue;
        }
        if (count >= 5 && count > available) {
            continue;
        }
        s->examined |= mask;
        if (count < 5 || count * 8 - 30 < sequence_bit + 3 ||
            format > 1 || type != 4) {
            s->header_rejections++;
            continue;
        }
        protected_bits = count * 8 - 30;
        for (bit = 0; bit < count * 8; bit++) {
            unsigned value = (packet[bit / 8] >> (7 - bit % 8)) & 1;
            unsigned feedback = ((crc >> 29) ^ value) & 1;
            crc = (crc << 1) ^ (feedback ? 0x6030b9c7 : 0);
        }
        if (((~crc) & 0x3fffffff) != 0x0b105aa5) {
            s->crc_rejections++;
            continue;
        }
        metadata.length = count;
        metadata.type = type;
        metadata.format = format;
        metadata.sequence = access_bits(packet, sequence_bit, 3);
        metadata.address_mode = 0xff;
        if (!format && protected_bits >= 34) {
            metadata.address_mode = access_bits(packet, 27, 3);
            metadata.address_length = access_bits(packet, 30, 4);
            if (!metadata.address_mode && metadata.address_length == 9 &&
                protected_bits >= 106) {
                metadata.address_valid = true;
                metadata.network24 = access_bits(packet, 34, 24);
                metadata.network10 = access_bits(packet, 58, 10);
            }
        }
        s->last_end = start * MSM5XXX_ACCESS_PIECE_BYTES + count;
        s->last = metadata;
        s->packets++;
        accepted = true;
    }
    return accepted;
}

static void access_put_bits(uint8_t *data, unsigned start, unsigned width,
                            uint32_t value)
{
    unsigned i;

    for (i = 0; i < width; i++) {
        unsigned at = start + i;
        uint8_t mask = 1U << (7 - at % 8);
        data[at / 8] = (data[at / 8] & ~mask) |
            (((value >> (width - i - 1)) & 1) ? mask : 0);
    }
}

static bool access_response_header(const MSM5xxxAccessPacket *packet,
                                   unsigned station_sequence, uint8_t *message)
{
    if (!packet || packet->type != 4 || packet->format != 0 ||
        !packet->address_valid || packet->address_mode != 0 ||
        packet->address_length != 9 || packet->sequence >= 8 ||
        station_sequence >= 8 || packet->network24 > 0xffffff ||
        packet->network10 > 0x3ff) {
        return false;
    }
    access_put_bits(message, 16, 3, packet->sequence);
    access_put_bits(message, 19, 3, station_sequence);
    access_put_bits(message, 23, 1, 1);
    access_put_bits(message, 27, 4, 5);
    access_put_bits(message, 31, 24, packet->network24);
    access_put_bits(message, 55, 10, packet->network10);
    return true;
}

static void access_response_crc(uint8_t *message, unsigned length)
{
    unsigned protected_bits = length * 8 - 30;

    access_put_bits(message, protected_bits, 30,
                    paging_crc30(message, protected_bits));
}

bool msm5xxx_access_ack(const MSM5xxxAccessPacket *packet,
                        unsigned station_sequence,
                        uint8_t out[MSM5XXX_ACCESS_ACK_BYTES])
{
    uint8_t message[MSM5XXX_ACCESS_ACK_BYTES] = {MSM5XXX_ACCESS_ACK_BYTES, 7};

    if (!out || !access_response_header(packet, station_sequence, message)) {
        return false;
    }
    access_put_bits(message, 71, 6, 0x10);
    /* Zero reserved/spare bits are this virtual transmitter's explicit choice. */
    access_response_crc(message, sizeof(message));
    memcpy(out, message, sizeof(message));
    return true;
}

bool msm5xxx_access_assignment(const MSM5xxxAccessPacket *packet,
                               unsigned station_sequence, uint8_t code,
                               uint8_t out[MSM5XXX_ACCESS_ASSIGNMENT_BYTES])
{
    uint8_t message[MSM5XXX_ACCESS_ASSIGNMENT_BYTES] = {
        MSM5XXX_ACCESS_ASSIGNMENT_BYTES, 8
    };

    if (!out || code < 1 || code > 128 ||
        !access_response_header(packet, station_sequence, message)) {
        return false;
    }
    /* Explicit virtual fixture: kind0, length2, include0 uses serving channel.
     * Remaining body, reserved and padding bits are zero by fixture policy.
     * The eight-bit code has no physical codec/channel-name claim here. */
    access_put_bits(message, 74, 3, 2);
    access_put_bits(message, 78, 8, code);
    access_response_crc(message, sizeof(message));
    memcpy(out, message, sizeof(message));
    return true;
}

void msm5xxx_paging_stream_init(MSM5xxxPagingStream *s)
{
    memset(s, 0, sizeof(*s));
}

bool msm5xxx_paging_stream_queue_message(
    MSM5xxxPagingStream *s, const uint8_t *reply, size_t length)
{
    if (!s || !reply || s->reply_pending || s->reply_active ||
        !((length == MSM5XXX_ACCESS_ACK_BYTES && reply[1] == 7) ||
          (length == MSM5XXX_ACCESS_ASSIGNMENT_BYTES && reply[1] == 8)) ||
        !paging_message_valid(reply, length)) {
        return false;
    }
    memmove(s->reply, reply, length);
    memset(s->reply + length, 0, sizeof(s->reply) - length);
    s->reply_length = length;
    s->reply_pending = true;
    return true;
}

bool msm5xxx_paging_stream_queue(
    MSM5xxxPagingStream *s, const uint8_t reply[MSM5XXX_ACCESS_ACK_BYTES])
{
    return msm5xxx_paging_stream_queue_message(s, reply, MSM5XXX_ACCESS_ACK_BYTES);
}

bool msm5xxx_paging_stream_frame(
    MSM5xxxPagingStream *s,
    const uint8_t messages[MSM5XXX_PAGING_MESSAGES][MSM5XXX_PAGING_MAX_BYTES],
    const uint8_t lengths[MSM5XXX_PAGING_MESSAGES], unsigned rate,
    uint16_t words[14])
{
    MSM5xxxPagingStream next;
    uint8_t logical[24];
    uint16_t output[14] = {0};
    unsigned frame_bits, length, count, packet, i;

    if (!s || !messages || !lengths || !words || rate > 1 ||
        (s->initialized && s->rate != rate) ||
        s->packet_index >= MSM5XXX_PAGING_MESSAGES ||
        ((s->reply_pending || s->reply_active) &&
         s->reply_length != MSM5XXX_ACCESS_ACK_BYTES &&
         s->reply_length != MSM5XXX_ACCESS_ASSIGNMENT_BYTES)) {
        return false;
    }
    frame_bits = rate ? 96 : 192;
    for (packet = 0; packet < MSM5XXX_PAGING_MESSAGES; packet++) {
        if (!paging_message_valid(messages[packet], lengths[packet])) {
            return false;
        }
    }
    length = s->reply_active ? s->reply_length : lengths[s->packet_index];
    count = (length * 8 + frame_bits - 3) / (frame_bits - 2);
    if (s->packet_frame >= count) {
        return false;
    }
    next = *s;
    next.initialized = true;
    next.rate = rate;
    if (!next.packet_frame && next.reply_pending && !next.reply_active) {
        next.reply_pending = false;
        next.reply_active = true;
    }
    length = next.reply_active ? next.reply_length : lengths[next.packet_index];
    count = (length * 8 + frame_bits - 3) / (frame_bits - 2);
    paging_packet_frame(next.reply_active ? next.reply : messages[next.packet_index],
                        length, frame_bits, next.packet_frame, logical);
    for (i = 0; i < frame_bits / 8; i++) {
        uint8_t value = i < 9 ? next.previous_tail[i] : logical[i - 9];
        output[i / 2] |= (uint16_t)value << (8 * (i % 2));
    }
    memcpy(next.previous_tail, logical + frame_bits / 8 - 9,
           sizeof(next.previous_tail));
    if (++next.packet_frame == count) {
        next.packet_frame = 0;
        if (next.reply_active) {
            next.reply_active = false;
            next.replies_encoded++;
        } else {
            next.packet_index = (next.packet_index + 1) % MSM5XXX_PAGING_MESSAGES;
        }
    }
    *s = next;
    memcpy(words, output, sizeof(output));
    return true;
}

/* Descriptor starts/counts are bytes; each payload has a four-byte metric tail. */
bool msm5xxx_traffic_erasure_frame(const uint8_t descriptor[8],
                                  uint16_t words[MSM5XXX_TRAFFIC_MAX_WORDS],
                                  unsigned *word_count)
{
    static const unsigned capacities[4] = {36, 18, 10, 6};
    unsigned end = 0, rate;

    if (!descriptor || !words || !word_count) {
        return false;
    }
    for (rate = 0; rate < 4; rate++) {
        unsigned start = descriptor[rate], count = descriptor[rate + 4];

        if (start != end || (start & 1) || (count & 1) || !count ||
            count > capacities[rate]) {
            return false;
        }
        end = start + count + 4;
        if (end > 2 * MSM5XXX_TRAFFIC_MAX_WORDS) {
            return false;
        }
    }
    memset(words, 0, end);
    *word_count = end / 2;
    return true;
}

bool msm5xxx_traffic_decoded_frame(const uint8_t descriptor[8],
                                  const uint8_t *frame, size_t frame_bytes,
                                  uint16_t words[MSM5XXX_TRAFFIC_MAX_WORDS],
                                  unsigned *word_count)
{
    uint16_t next[MSM5XXX_TRAFFIC_MAX_WORDS], crc = 0xfff;
    unsigned count, i;

    if (!descriptor || !frame || !words || !word_count || frame_bytes != 24 ||
        frame[23] != 0 || descriptor[4] != 24 ||
        !msm5xxx_traffic_erasure_frame(descriptor, next, &count)) {
        return false;
    }
    for (i = 0; i < 184; i++) {
        unsigned bit = (frame[i / 8] >> (7 - i % 8)) & 1;
        unsigned feedback = (crc >> 11) ^ bit;

        crc = (crc << 1) & 0xfff;
        if (feedback) {
            crc ^= 0xf13;
        }
    }
    for (i = 0; i < 12; i++) {
        next[i] = frame[2 * i] | ((uint16_t)frame[2 * i + 1] << 8);
    }
    /* Ideal decoded input has zero SER; ACS and unavailable views stay zero. */
    next[12] = crc == 0 ? 0x0100 : 0;
    memcpy(words, next, count * sizeof(*words));
    *word_count = count;
    return true;
}

static unsigned traffic_field(const uint8_t *bytes, unsigned start, unsigned count)
{
    unsigned value = 0, i;
    for (i = 0; i < count; i++) {
        value = (value << 1) | ((bytes[(start + i) / 8] >>
                                (7 - (start + i) % 8)) & 1);
    }
    return value;
}

static unsigned traffic_crc(const uint8_t *bytes, unsigned start, unsigned count,
                             unsigned width, unsigned poly, unsigned crc)
{
    unsigned i, mask = (1u << width) - 1;
    for (i = 0; i < count; i++) {
        unsigned feedback = (crc >> (width - 1)) ^ traffic_field(bytes, start + i, 1);
        crc = (crc << 1) & mask;
        if (feedback) {
            crc ^= poly;
        }
    }
    return crc;
}

bool msm5xxx_traffic_response_init(MSM5xxxTrafficResponse *s,
                                  const uint8_t *frame, size_t length)
{
    MSM5xxxTrafficResponse next;
    if (!s || !frame || length != 24 || frame[23] ||
        traffic_field(frame, 0, 5) != 0x17 ||
        traffic_field(frame, 5, 8) != 11 ||
        traffic_field(frame, 13, 8) != 1 ||
        traffic_field(frame, 27, 1) != 1 ||
        traffic_field(frame, 28, 9) != 0 ||
        traffic_field(frame, 37, 6) != 20 ||
        traffic_field(frame, 43, 3) != 3 ||
        traffic_field(frame, 46, 8) != 0 ||
        traffic_crc(frame, 0, 184, 12, 0xf13, 0xfff) ||
        traffic_crc(frame, 5, 88, 16, 0x1021, 0xffff) != 0x1d0f) {
        return false;
    }
    next.sequence = traffic_field(frame, 24, 3);
    next.pending = true;
    next.delivered = false;
    *s = next;
    return true;
}

bool msm5xxx_traffic_response_ack(MSM5xxxTrafficResponse *s,
                                 const uint8_t *frame, size_t length)
{
    static const unsigned starts[] = {84, 44, 20, 4};
    uint8_t packet[7] = {0};
    unsigned index, start, i;
    if (!s || !s->pending || !s->delivered || !frame || length != 24 ||
        !(frame[0] & 0x80) || (index = (frame[0] >> 4) & 7) >= 4) {
        return false;
    }
    start = starts[index];
    if (!traffic_field(frame, start, 1)) {
        return false;
    }
    for (i = 0; i < 56; i++) {
        packet[i / 8] |= traffic_field(frame, start + 1 + i, 1) << (7 - i % 8);
    }
    if (packet[0] != 7 || packet[1] != 1 || (packet[2] & 3) ||
        packet[3] != 0x20 || (packet[4] & 0xc0) ||
        traffic_crc(packet, 0, 56, 16, 0x1021, 0xffff) != 0x1d0f ||
        (packet[2] >> 5) != s->sequence) {
        return false;
    }
    s->pending = false;
    return true;
}

bool msm5xxx_traffic_no_message_frame(const uint8_t descriptor[8],
                                     uint16_t words[MSM5XXX_TRAFFIC_MAX_WORDS],
                                     unsigned *word_count)
{
    uint8_t frame[24] = {0xb0};
    unsigned crc = traffic_crc(frame, 0, 172, 12, 0xf13, 0xfff), i;

    for (i = 0; i < 12; i++) {
        frame[(172 + i) / 8] |= ((crc >> (11 - i)) & 1) << (7 - (172 + i) % 8);
    }
    return msm5xxx_traffic_decoded_frame(descriptor, frame, sizeof(frame), words, word_count);
}

bool msm5xxx_access_service_request(const uint8_t *packet, size_t length,
                                    unsigned revision, MSM5xxxServiceRequest *out)
{
    MSM5xxxServiceRequest next = {0};
    unsigned protected, count, body_end, i;
    if (!packet || !out || (revision != 2 && revision != 3) ||
        length < 5 || length > 255 || packet[0] != length ||
        (protected = length * 8 - 30) < 159 ||
        paging_crc30(packet, length * 8) != 0x0b105aa5 ||
        access_bits(packet, 8, 2) || access_bits(packet, 10, 6) != 4 ||
        access_bits(packet, 27, 3) || access_bits(packet, 30, 4) != 9 ||
        access_bits(packet, 106, 2) || !access_bits(packet, 131, 1) ||
        access_bits(packet, 149, 1) || access_bits(packet, 150, 1)) {
        return false;
    }
    count = access_bits(packet, 151, 8);
    body_end = 160 + 4 * count;
    if (!count || count > 32 || protected < body_end ||
        length != (body_end + 30 + 7) / 8) {
        return false;
    }
    for (i = 0; i < count; i++) {
        unsigned symbol = access_bits(packet, 159 + 4 * i, 4);
        if (!symbol || symbol > 12) {
            return false;
        }
    }
    next.service_option = access_bits(packet, 132, 16);
    next.digit_count = count;
    *out = next;
    return true;
}

bool msm5xxx_traffic_service_response(uint16_t service, unsigned ack_sequence,
                                      unsigned message_sequence, uint8_t out[24])
{
    uint8_t frame[24] = {0};
    if (!out || ack_sequence > 7 || message_sequence > 7) {
        return false;
    }
    access_put_bits(frame, 0, 4, 0xb);
    access_put_bits(frame, 4, 1, 1);
    access_put_bits(frame, 5, 8, 11);
    access_put_bits(frame, 13, 8, 1);
    access_put_bits(frame, 21, 3, ack_sequence);
    access_put_bits(frame, 24, 3, message_sequence);
    access_put_bits(frame, 27, 1, 1);
    access_put_bits(frame, 37, 6, 20);
    access_put_bits(frame, 43, 3, 3);
    access_put_bits(frame, 54, 16, service);
    access_put_bits(frame, 77, 16, traffic_crc(frame, 5, 72, 16, 0x1021, 0xffff) ^ 0xffff);
    access_put_bits(frame, 172, 12, traffic_crc(frame, 0, 172, 12, 0xf13, 0xfff));
    memcpy(out, frame, sizeof(frame));
    return true;
}

bool msm5xxx_access_last_service_request(const MSM5xxxAccess *s, unsigned revision,
                                         MSM5xxxServiceRequest *out)
{
    if (!s || !s->last_end || !s->last.length || s->last_end > s->window_length ||
        s->last.length > s->last_end) {
        return false;
    }
    return msm5xxx_access_service_request(s->window + s->last_end - s->last.length,
                                           s->last.length, revision, out);
}
