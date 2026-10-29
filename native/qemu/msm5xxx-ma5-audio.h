/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_AUDIO_H
#define MSM5XXX_MA5_AUDIO_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MSM5XXX_MA5_REGISTER_COUNT 0x234u

typedef enum MSM5xxxMA5FifoState {
    MSM5XXX_MA5_DELAY_0 = 0,
    MSM5XXX_MA5_DELAY_1 = 1,
    MSM5XXX_MA5_DELAY_2 = 2,
    MSM5XXX_MA5_ADDRESS_0 = 3,
    MSM5XXX_MA5_ADDRESS_1 = 4,
    MSM5XXX_MA5_ADDRESS_2 = 5,
    MSM5XXX_MA5_COUNT_0 = 6,
    MSM5XXX_MA5_COUNT_1 = 7,
    MSM5XXX_MA5_REGISTER_BEGIN = 8,
    MSM5XXX_MA5_REGISTER_DATA = 9,
    MSM5XXX_MA5_VOICE_BEGIN = 10,
    MSM5XXX_MA5_VOICE_DATA = 11,
} MSM5xxxMA5FifoState;

typedef enum MSM5xxxMA5EventKind {
    MSM5XXX_MA5_EVENT_NONE = 0,
    MSM5XXX_MA5_EVENT_IMMEDIATE_WRITE,
    MSM5XXX_MA5_EVENT_REGISTER_PACKET,
    MSM5XXX_MA5_EVENT_REGISTER_WRITE,
    MSM5XXX_MA5_EVENT_VOICE_PACKET,
    MSM5XXX_MA5_EVENT_VOICE_WRITE,
} MSM5xxxMA5EventKind;

typedef struct MSM5xxxMA5Event {
    MSM5xxxMA5EventKind kind;
    uint32_t delay;
    uint32_t address;
    uint16_t count;
    uint8_t index;
    uint8_t value;
    bool terminal;
} MSM5xxxMA5Event;

typedef struct MSM5xxxMA5Audio {
    uint8_t index;
    MSM5xxxMA5FifoState fifo_state;
    uint32_t delay;
    uint32_t address;
    uint16_t remaining;
    uint8_t register_shadow[MSM5XXX_MA5_REGISTER_COUNT];
} MSM5xxxMA5Audio;

void msm5xxx_ma5_reset(MSM5xxxMA5Audio *audio);
bool msm5xxx_ma5_index_write(MSM5xxxMA5Audio *audio, uint8_t index);
bool msm5xxx_ma5_data_write(MSM5xxxMA5Audio *audio, uint8_t value,
                            bool block_site, MSM5xxxMA5Event *event);
bool msm5xxx_ma5_shadow_read(const MSM5xxxMA5Audio *audio,
                             uint32_t address, uint8_t *value);

#define MSM5XXX_MA5_SRAM_BASE 0x4000u
#define MSM5XXX_MA5_SRAM_SIZE 0x2000u
#define MSM5XXX_MA5_VALID_R 0x40u

typedef struct MSM5xxxMA5ByteCursor {
    uint32_t address;
    uint16_t remaining;
    uint16_t length;
    uint8_t address_bytes;
    uint8_t length_bytes;
    uint8_t phase;
    bool discard;
} MSM5xxxMA5ByteCursor;

/* Backing state after FIFO consumption, not a timed chip or bus-ready model. */
typedef struct MSM5xxxMA5Readback {
    uint8_t control[MSM5XXX_MA5_REGISTER_COUNT];
    uint8_t control_guest_written[(MSM5XXX_MA5_REGISTER_COUNT + 7u) / 8u];
    uint8_t sram[MSM5XXX_MA5_SRAM_SIZE];
    MSM5xxxMA5ByteCursor immediate;
    MSM5xxxMA5ByteCursor read;
    uint8_t index;
    uint8_t read_latch;
    uint32_t read_address;
    bool read_valid;
    bool read_from_sram;
    bool read_control_guest_written;
    bool irq_enabled;
    bool control_write_valid;
    uint32_t control_write_address;
    uint8_t control_write_raw;
    uint64_t rejected;
    uint64_t control_writes, sram_writes;
} MSM5xxxMA5Readback;

/* Constructor only: does not define B4 software/FIFO-reset retention. */
void msm5xxx_ma5_readback_init(MSM5xxxMA5Readback *audio);
bool msm5xxx_ma5_readback_index(MSM5xxxMA5Readback *audio, uint8_t value);
/* Called only after the scheduler consumes a B2/B3 byte. B1 delayed is not
 * implemented here. Preserve raw control terminal bits for later consumers. */
bool msm5xxx_ma5_readback_consume(MSM5xxxMA5Readback *audio,
                                 uint8_t port, uint8_t value);
bool msm5xxx_ma5_readback_data(const MSM5xxxMA5Readback *audio, uint8_t *value);
/* Only VALID_R contribution; caller owns FIFO-empty/full, BUSY and IRQ bits. */
uint8_t msm5xxx_ma5_readback_status(const MSM5xxxMA5Readback *audio);

/* Experimental cold-init transport; service period is supplied, not calibrated.
 * B2/B3 are serialized through one bounded queue to preserve write/read order.
 * Clocked delayed sequencing is experimental; ambiguous retention rejects. */
#define MSM5XXX_MA5_IMMEDIATE_CAPACITY 64u
#define MSM5XXX_MA5_DELAYED_CAPACITY 512u

typedef enum MSM5xxxMA5Reject {
    MSM5XXX_MA5_REJECT_NONE,
    MSM5XXX_MA5_REJECT_FIFO_OVERFLOW,
    MSM5XXX_MA5_REJECT_PACKET,
    MSM5XXX_MA5_REJECT_BANK,
    MSM5XXX_MA5_REJECT_DELAYED,
    MSM5XXX_MA5_REJECT_DYNAMIC_READ,
    MSM5XXX_MA5_REJECT_RESET_RETENTION,
    MSM5XXX_MA5_REJECT_CLOCK,
    MSM5XXX_MA5_REJECT_START,
} MSM5xxxMA5Reject;

typedef enum MSM5xxxMA5CommitKind {
    MSM5XXX_MA5_COMMIT_CONTROL,
    MSM5XXX_MA5_COMMIT_SRAM,
    MSM5XXX_MA5_COMMIT_B,
} MSM5xxxMA5CommitKind;

typedef struct MSM5xxxMA5Commit {
    MSM5xxxMA5CommitKind kind;
    uint32_t address;
    uint8_t value, raw;
    uint64_t time_ns;
} MSM5xxxMA5Commit;

/* Synchronous readonly sink; no reentry, failure return or IRQ snapshot promise.
 * Byte commits are reported after queue pop, even if later scheduling rejects. */
typedef void (*MSM5xxxMA5CommitSink)(void *opaque,
                                    const MSM5xxxMA5Commit *commit);

typedef struct MSM5xxxMA5Device {
    MSM5xxxMA5Readback backing;
    uint8_t b[64];
    bool b_written[64];
    uint8_t queue_value[MSM5XXX_MA5_IMMEDIATE_CAPACITY];
    uint8_t queue_port[MSM5XXX_MA5_IMMEDIATE_CAPACITY];
    unsigned head, count, max_count;
    uint8_t delayed_value[MSM5XXX_MA5_DELAYED_CAPACITY];
    unsigned delayed_head, delayed_count, delayed_max_count;
    MSM5xxxMA5ByteCursor delayed;
    uint32_t delayed_delta;
    uint8_t delayed_delta_bytes;
    bool delayed_delta_ready, delayed_dirty;
    uint64_t delayed_next_ns, delayed_due, delayed_previous_due, delayed_consumed;
    uint64_t period_ns, next_ns, consumed, reads, resets;
    uint16_t pending;
    bool fifo_condition, fifo_mode_known, control_dirty, memory_dirty;
    bool counter_reset;
    bool accessed, counter_running, counter_needs_reset, ms_s_committed;
    uint16_t ms_s;
    uint32_t counter, counter_latch;
    uint64_t clki_hz, target_rate_hz, counter_last_ns, counter_phase;
    uint64_t counter_num, counter_den;
    uint64_t counter_total;
    bool clki_inferred;
    MSM5xxxMA5Reject reject;
    /* Caller configures after init; constructor clears both fields. */
    MSM5xxxMA5CommitSink commit_sink;
    void *commit_opaque;
} MSM5xxxMA5Device;

bool msm5xxx_ma5_device_init(MSM5xxxMA5Device *device, uint64_t period_ns);
/* Explicit experimental clock, configured immediately after init. */
bool msm5xxx_ma5_device_set_clock(MSM5xxxMA5Device *device, uint64_t clki_hz);
/* Temporary PC-rate policy; guest PLL registers determine inferred CLKI. */
bool msm5xxx_ma5_device_set_target_rate(MSM5xxxMA5Device *device,
                                        uint64_t target_rate_hz);
void msm5xxx_ma5_device_advance(MSM5xxxMA5Device *device, uint64_t now_ns);
bool msm5xxx_ma5_device_next_deadline(MSM5xxxMA5Device *device,
                                     uint64_t *deadline_ns);
bool msm5xxx_ma5_device_write(MSM5xxxMA5Device *device, bool index,
                              uint8_t value, uint64_t now_ns);
bool msm5xxx_ma5_device_read(MSM5xxxMA5Device *device, bool index,
                             uint8_t *value, uint64_t now_ns);
bool msm5xxx_ma5_device_irq(const MSM5xxxMA5Device *device);

#endif
