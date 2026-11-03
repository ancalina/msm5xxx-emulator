/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA3_AUDIO_H
#define MSM5XXX_MA3_AUDIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSM5XXX_MA3_REGISTER_COUNT 360u
#define MSM5XXX_MA3_FIFO_CAPACITY 1024u
#define MSM5XXX_MA3_OPERATION_CAPACITY 512u
#define MSM5XXX_MA3_ADDRESS_SPACE 0x6000u

typedef enum MSM5xxxMA3OperationKind {
    MSM5XXX_MA3_OP_NONE = 0,
    MSM5XXX_MA3_OP_REGISTER_WRITE,
    MSM5XXX_MA3_OP_FIFO_EMPTY,
} MSM5xxxMA3OperationKind;

typedef struct MSM5xxxMA3Operation {
    MSM5xxxMA3OperationKind kind;
    uint64_t timestamp_ns;
    uint16_t address;
    uint8_t value;
    uint8_t bank;
} MSM5xxxMA3Operation;

typedef struct MSM5xxxMA3Audio {
    uint8_t reg[MSM5XXX_MA3_REGISTER_COUNT];
    uint8_t host_reg[2][16];
    uint8_t host_bank;
    uint8_t memory[MSM5XXX_MA3_ADDRESS_SPACE];
    uint8_t mode;
    uint8_t read_buffer[3];
    uint8_t read_valid;
    uint8_t interrupt_flags;
    uint8_t address_bytes[3];
    uint8_t address_length;
    uint16_t address;
    bool address_complete;
    bool ram_upload_length;
    bool ram_upload_data;
    uint16_t ram_upload_count;
    uint8_t selector;
    bool selector_pending;
    uint8_t fifo[MSM5XXX_MA3_FIFO_CAPACITY];
    uint16_t fifo_read;
    uint16_t fifo_write;
    uint16_t fifo_count;
    uint8_t stream_phase;
    uint8_t stream_address_length;
    uint32_t stream_address;
    uint32_t stream_delta;
    uint64_t stream_ready_ns;
    uint64_t stream_cursor_ns;
    uint64_t now_ns;
    uint64_t next_fifo_ns;
    uint64_t fifo_empty_time_ns;
    uint64_t timer_deadline_ns[2];
    uint64_t timer_period_ns[2];
    uint64_t operations;
    MSM5xxxMA3Operation operation_queue[MSM5XXX_MA3_OPERATION_CAPACITY];
    uint16_t operation_read;
    uint16_t operation_write;
    uint16_t operation_count;
    bool timer_active[2];
    bool host_irq_enabled;
    bool running;
    bool rejected;
} MSM5xxxMA3Audio;

void msm5xxx_ma3_reset(MSM5xxxMA3Audio *audio);
bool msm5xxx_ma3_status_write(MSM5xxxMA3Audio *audio, uint8_t value,
                              uint64_t now_ns);
bool msm5xxx_ma3_data_write(MSM5xxxMA3Audio *audio, uint8_t value,
                            uint64_t now_ns);
uint8_t msm5xxx_ma3_status_read(const MSM5xxxMA3Audio *audio);
bool msm5xxx_ma3_data_read(MSM5xxxMA3Audio *audio, uint8_t *value,
                           uint64_t now_ns);
/* Advance one delayed stream byte; emitted register operations are also queued
 * for immediate and delayed writes and should be consumed with pop_operation. */
bool msm5xxx_ma3_advance(MSM5xxxMA3Audio *audio, uint64_t now_ns,
                         MSM5xxxMA3Operation *operation);
bool msm5xxx_ma3_next_deadline(const MSM5xxxMA3Audio *audio,
                               uint64_t *deadline_ns);
/* Advance chip timers against guest virtual time. Timer flags remain latched
 * until acknowledged through the interrupt-flag data port. */
bool msm5xxx_ma3_advance_time(MSM5xxxMA3Audio *audio, uint64_t now_ns);
bool msm5xxx_ma3_next_timer_deadline(const MSM5xxxMA3Audio *audio,
                                     uint64_t *deadline_ns);
bool msm5xxx_ma3_irq_line_level(const MSM5xxxMA3Audio *audio);
bool msm5xxx_ma3_pop_operation(MSM5xxxMA3Audio *audio,
                               MSM5xxxMA3Operation *operation);
size_t msm5xxx_ma3_fifo_occupancy(const MSM5xxxMA3Audio *audio);

#endif
