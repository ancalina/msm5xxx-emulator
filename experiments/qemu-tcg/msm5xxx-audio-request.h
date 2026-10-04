/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_AUDIO_REQUEST_H
#define MSM5XXX_AUDIO_REQUEST_H

#include <stdbool.h>
#include <stdint.h>

typedef enum MSM5xxxAudioRequestResult {
    MSM5XXX_AUDIO_REQUEST_INVALID = -1,
    MSM5XXX_AUDIO_REQUEST_PARTIAL = 0,
    MSM5XXX_AUDIO_REQUEST_COMPLETE = 1,
} MSM5xxxAudioRequestResult;

typedef struct MSM5xxxAudioRequest {
    uint32_t address;
    uint8_t address_bytes;
    uint8_t type;
    bool address_complete;
    bool finished;
    bool invalid;
} MSM5xxxAudioRequest;

/* Begin an explicitly selected request. Partial/invalid packets need a restart. */
void msm5xxx_audio_request_begin(MSM5xxxAudioRequest *request);
/* COMPLETE describes syntax only; it does not assert device result-ready. */
MSM5xxxAudioRequestResult msm5xxx_audio_request_feed(
    MSM5xxxAudioRequest *request, uint8_t value);

typedef enum MSM5xxxAudioPacketResult {
    MSM5XXX_AUDIO_PACKET_INVALID = -1,
    MSM5XXX_AUDIO_PACKET_PARTIAL = 0,
    MSM5XXX_AUDIO_PACKET_REGISTER = 1,
    MSM5XXX_AUDIO_PACKET_MEMORY = 2,
} MSM5xxxAudioPacketResult;

typedef struct MSM5xxxAudioPacket {
    uint32_t address;
    uint16_t remaining;
    uint8_t phase;
} MSM5xxxAudioPacket;

typedef struct MSM5xxxAudioPacketWrite {
    uint32_t address;
    uint8_t value;
    bool last;
} MSM5xxxAudioPacketWrite;

/* Command-2 stream framing only. Selector changes do not reset partial packets.
 * Register data retains its terminal bit; counted memory data is an opaque byte.
 * Output writes still require a device consumer: parsing asserts neither ready
 * nor register/memory acceptance. PARTIAL/INVALID leave the output untouched. */
void msm5xxx_audio_packet_reset(MSM5xxxAudioPacket *packet);
MSM5xxxAudioPacketResult msm5xxx_audio_packet_feed(
    MSM5xxxAudioPacket *packet, uint8_t value, MSM5xxxAudioPacketWrite *write);

typedef struct MSM5xxxAudioTimedPacket {
    MSM5xxxAudioPacket packet;
    uint32_t pending_delta;
    /* 0..2: delta groups received; 3: complete header, receiving packet body. */
    uint8_t delta_bytes;
} MSM5xxxAudioTimedPacket;

typedef struct MSM5xxxAudioTimedPacketWrite {
    MSM5xxxAudioPacketWrite write;
    uint32_t delta;
} MSM5xxxAudioTimedPacketWrite;

/* Command-1 syntax only: LE7 delta (1..3 groups, third forced), then the
 * command-2 body. Delta is emitted with its first write only, not milliseconds
 * or a scheduled deadline. Zero-count memory bodies discard their delta.
 * PARTIAL/INVALID leave output untouched; no FIFO/device acceptance implied. */
void msm5xxx_audio_timed_packet_reset(MSM5xxxAudioTimedPacket *packet);
MSM5xxxAudioPacketResult msm5xxx_audio_timed_packet_feed(
    MSM5xxxAudioTimedPacket *packet, uint8_t value,
    MSM5xxxAudioTimedPacketWrite *write);

typedef enum MSM5xxxAudioPacketReject {
    MSM5XXX_AUDIO_PACKET_REJECT_NONE = 0,
    MSM5XXX_AUDIO_PACKET_REJECT_SYNTAX,
    MSM5XXX_AUDIO_PACKET_REJECT_REGISTER,
    MSM5XXX_AUDIO_PACKET_REJECT_POINTER,
    MSM5XXX_AUDIO_PACKET_REJECT_MEMORY,
    MSM5XXX_AUDIO_PACKET_REJECT_DEPENDENCY,
} MSM5xxxAudioPacketReject;

typedef struct MSM5xxxAudioPacketChannel {
    uint8_t high, level;
    uint16_t pointer;
    bool high_valid, pointer_valid, level_valid;
    uint8_t pitch_high, control;
    uint16_t pitch;
    bool pitch_high_valid, pitch_valid, control_valid;
} MSM5xxxAudioPacketChannel;

typedef struct MSM5xxxAudioPacketSink {
    MSM5xxxAudioPacket packet;
    MSM5xxxAudioPacketChannel channel[32];
    uint8_t memory[0x2000];
    /* 0x163 raw smoothing config: mute[5:4], channel volume[3:2], panpot[1:0]. */
    uint8_t smoothing_config;
    bool smoothing_config_valid;
    MSM5xxxAudioPacketReject reject;
    uint32_t rejected_address;
    uint8_t rejected_value;
    uint32_t register_writes, memory_writes;
} MSM5xxxAudioPacketSink;

/* Voice registers use six-byte slots at 0..0x5f and 0xe0..0x13f.
 * 0x163 retains smoothing configuration only; no rates or reset default implied.
 * Other register classes remain unsupported; pitch is a raw 14-bit pair, not Hz.
 * Partial interface state only: no renderer, ROM/PCM, status or readback.
 * Rejection is sticky until full reset; earlier consumed writes are retained.
 * A rejected byte may advance framing but cannot mutate consumer state. */
void msm5xxx_audio_packet_sink_reset(MSM5xxxAudioPacketSink *sink);
bool msm5xxx_audio_packet_sink_feed(MSM5xxxAudioPacketSink *sink, uint8_t value);

/* Explicit experimental profile: firmware-inferred reset readback only.
 * No chip identity, IRQ, FIFO timing or synthesis accuracy is implied. */
typedef struct MSM5xxxAudioReadback {
    MSM5xxxAudioRequest request;
    uint8_t index, result;
    bool reset_asserted, reset_known, result_valid;
} MSM5xxxAudioReadback;

void msm5xxx_audio_readback_index(MSM5xxxAudioReadback *state, uint8_t value);
bool msm5xxx_audio_readback_write(MSM5xxxAudioReadback *state, uint8_t value);
uint8_t msm5xxx_audio_readback_status(const MSM5xxxAudioReadback *state);
bool msm5xxx_audio_readback_read(MSM5xxxAudioReadback *state, uint8_t *value);

#endif
