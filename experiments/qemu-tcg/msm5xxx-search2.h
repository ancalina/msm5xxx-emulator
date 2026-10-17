/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Modified 2026-10-17: add bounded encoder FIFO packet metadata. */
#ifndef MSM5XXX_SEARCH2_H
#define MSM5XXX_SEARCH2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSM5XXX_SEARCH2_DEPTH 8
#define MSM5XXX_SEARCH2_PARAMETERS 6
#define MSM5XXX_SEARCH2_RESULTS 8
#define MSM5XXX_SEARCH1_PARAMETERS 17
#define MSM5XXX_FINGER_COUNT 4

typedef struct MSM5xxxFinger {
    uint8_t registers[12];
    uint8_t unsupported_offset, unsupported_value;
    uint16_t seen, rssi;
    uint32_t position, latched_position;
    bool supported, latched;
} MSM5xxxFinger;

typedef struct MSM5xxxFingers {
    MSM5xxxFinger bank[MSM5XXX_FINGER_COUNT];
    uint8_t selected, filter_gain;
} MSM5xxxFingers;

void msm5xxx_fingers_reset(MSM5xxxFingers *s);
bool msm5xxx_fingers_write(MSM5xxxFingers *s, unsigned offset,
                          unsigned width, uint16_t value);
bool msm5xxx_fingers_read(const MSM5xxxFingers *s, unsigned offset,
                         unsigned width, uint16_t *value);
void msm5xxx_fingers_latch(MSM5xxxFingers *s, uint32_t pilot_phase,
                          uint16_t peak_energy, const uint16_t masks_i[512],
                          const uint16_t masks_q[512]);

/* Transport accounting only. The serialized caller owns RF data and timing.
 * Unsupported accesses return false without inventing a register value. */

typedef struct MSM5xxxSearch2Job {
    uint64_t epoch;
    uint64_t sequence;
    uint16_t parameters[MSM5XXX_SEARCH2_PARAMETERS];
} MSM5xxxSearch2Job;

typedef struct MSM5xxxSearch2Parameters {
    uint16_t phase_index, mask_i, mask_q, window_word, phase_fraction;
    uint8_t integration, gain, chips;
    bool dump;
} MSM5xxxSearch2Parameters;

typedef struct MSM5xxxSearch2 {
    uint16_t parameters[MSM5XXX_SEARCH2_DEPTH][MSM5XXX_SEARCH2_PARAMETERS];
    uint16_t results[MSM5XXX_SEARCH2_DEPTH][MSM5XXX_SEARCH2_RESULTS];
    uint8_t queue_write, queue_sub, queue_read;
    uint8_t result_write, result_read, result_sub;
    uint8_t queued_records, result_records;
    uint8_t status, dump_enable;
    bool active;
    uint64_t epoch, sequence;
    MSM5xxxSearch2Job job;
} MSM5xxxSearch2;

void msm5xxx_search2_init(MSM5xxxSearch2 *s);
void msm5xxx_search2_reset(MSM5xxxSearch2 *s);
bool msm5xxx_search2_read(MSM5xxxSearch2 *s, unsigned offset,
                         unsigned width, uint16_t *value);
bool msm5xxx_search2_write(MSM5xxxSearch2 *s, unsigned offset,
                          unsigned width, uint16_t value);
bool msm5xxx_search2_begin(MSM5xxxSearch2 *s, MSM5xxxSearch2Job *job);
bool msm5xxx_search2_complete(MSM5xxxSearch2 *s,
                             const MSM5xxxSearch2Job *job,
                             const uint16_t words[MSM5XXX_SEARCH2_RESULTS]);
bool msm5xxx_search2_dump_requested(const MSM5xxxSearch2 *s);
bool msm5xxx_search2_decode(const MSM5xxxSearch2Job *job,
                           MSM5xxxSearch2Parameters *parameters);
bool msm5xxx_search1_decode(const uint8_t words[MSM5XXX_SEARCH1_PARAMETERS],
                           MSM5xxxSearch2Parameters *parameters);
bool msm5xxx_search2_virtual_result(const MSM5xxxSearch2Parameters *parameters,
                                   uint32_t position_before, uint32_t pilot_phase,
                                   uint16_t peak_energy, uint16_t words[8],
                                   uint32_t *position_after);

/* Explicit decoded sync source; packet includes its length byte and CRC30. */
#define MSM5XXX_SYNC_MAX_BYTES 147
bool msm5xxx_sync_frame(const uint8_t *message, unsigned length,
                        uint64_t frame, uint16_t words[8]);
bool msm5xxx_sync_decoder_frame(const uint8_t *message, unsigned length,
                                uint64_t frame, uint16_t words[8]);
uint16_t msm5xxx_combiner_position(uint64_t elapsed_ns);
uint64_t msm5xxx_combiner_deadline(uint64_t roll);

#define MSM5XXX_PAGING_MESSAGES 4
#define MSM5XXX_PAGING_MAX_BYTES 255
bool msm5xxx_paging_decoder_frame(
    const uint8_t messages[MSM5XXX_PAGING_MESSAGES][MSM5XXX_PAGING_MAX_BYTES],
    const uint8_t lengths[MSM5XXX_PAGING_MESSAGES], unsigned rate,
    uint64_t frame, uint16_t words[14]);
uint64_t msm5xxx_radio_deadline(uint64_t tick);

#define MSM5XXX_ACCESS_PIECE_BYTES 11
#define MSM5XXX_ACCESS_WINDOW_BYTES 264
#define MSM5XXX_ACCESS_ACK_BYTES 14
#define MSM5XXX_ACCESS_ASSIGNMENT_BYTES 16

typedef struct MSM5xxxAccessPacket {
    uint8_t length, type, format, sequence, address_mode, address_length;
    bool address_valid;
    uint32_t network24;
    uint16_t network10;
} MSM5xxxAccessPacket;

typedef struct MSM5xxxAccess {
    uint8_t window[MSM5XXX_ACCESS_WINDOW_BYTES];
    unsigned window_length;
    unsigned last_end; /* Current packet end; zero after the next push/gap. */
    uint32_t examined;
    MSM5xxxAccessPacket last;
    uint64_t pieces, packets, crc_rejections, header_rejections, gaps;
} MSM5xxxAccess;

void msm5xxx_access_init(MSM5xxxAccess *s);
void msm5xxx_access_gap(MSM5xxxAccess *s);
bool msm5xxx_access_push(MSM5xxxAccess *s, const uint8_t *piece,
                         unsigned length);
bool msm5xxx_access_ack(const MSM5xxxAccessPacket *packet,
                        unsigned station_sequence,
                        uint8_t out[MSM5XXX_ACCESS_ACK_BYTES]);

bool msm5xxx_access_assignment(const MSM5xxxAccessPacket *packet,
                               unsigned station_sequence, uint8_t code,
                               uint8_t out[MSM5XXX_ACCESS_ASSIGNMENT_BYTES]);

typedef struct MSM5xxxPagingStream {
    uint8_t previous_tail[9], reply[MSM5XXX_ACCESS_ASSIGNMENT_BYTES];
    unsigned rate, packet_index, packet_frame, reply_length;
    bool initialized, reply_pending, reply_active;
    uint64_t replies_encoded;
} MSM5xxxPagingStream;

void msm5xxx_paging_stream_init(MSM5xxxPagingStream *s);
bool msm5xxx_paging_stream_queue(
    MSM5xxxPagingStream *s, const uint8_t reply[MSM5XXX_ACCESS_ACK_BYTES]);
bool msm5xxx_paging_stream_queue_message(
    MSM5xxxPagingStream *s, const uint8_t *reply, size_t length);
bool msm5xxx_paging_stream_frame(
    MSM5xxxPagingStream *s,
    const uint8_t messages[MSM5XXX_PAGING_MESSAGES][MSM5XXX_PAGING_MAX_BYTES],
    const uint8_t lengths[MSM5XXX_PAGING_MESSAGES], unsigned rate,
    uint16_t words[14]);

/* Traffic output; no cadence, IRQ or qualified-frame production. */
#define MSM5XXX_TRAFFIC_MAX_WORDS 43
/* words has MAX_WORDS capacity; word_count is a separate, nonoverlapping output. */
bool msm5xxx_traffic_erasure_frame(const uint8_t descriptor[8],
                                  uint16_t words[MSM5XXX_TRAFFIC_MAX_WORDS],
                                  unsigned *word_count);
/* Ideal decoded input: zero SER; CRC status is derived from the codeword. */
bool msm5xxx_traffic_decoded_frame(const uint8_t descriptor[8],
                                  const uint8_t *frame, size_t frame_bytes,
                                  uint16_t words[MSM5XXX_TRAFFIC_MAX_WORDS],
                                  unsigned *word_count);

/* One explicitly supplied service response; unknown traffic remains unclassified. */
typedef struct MSM5xxxTrafficResponse {
    uint8_t sequence;
    bool pending, delivered;
} MSM5xxxTrafficResponse;

bool msm5xxx_traffic_response_init(MSM5xxxTrafficResponse *s,
                                  const uint8_t *frame, size_t length);
bool msm5xxx_traffic_response_ack(MSM5xxxTrafficResponse *s,
                                 const uint8_t *frame, size_t length);

/* Full signalling container without a message start; no voice payload. */
bool msm5xxx_traffic_no_message_frame(const uint8_t descriptor[8],
                                     uint16_t words[MSM5XXX_TRAFFIC_MAX_WORDS],
                                     unsigned *word_count);

/* Complete observed legacy body; no dial symbols or packet bytes are retained. */
typedef struct MSM5xxxServiceRequest {
    uint16_t service_option;
    uint8_t digit_count;
} MSM5xxxServiceRequest;
bool msm5xxx_access_service_request(const uint8_t *packet, size_t length,
                                    unsigned revision, MSM5xxxServiceRequest *out);
bool msm5xxx_access_last_service_request(const MSM5xxxAccess *s, unsigned revision,
                                         MSM5xxxServiceRequest *out);
bool msm5xxx_traffic_service_response(uint16_t service, unsigned ack_sequence,
                                      unsigned message_sequence, uint8_t out[24]);

#endif
