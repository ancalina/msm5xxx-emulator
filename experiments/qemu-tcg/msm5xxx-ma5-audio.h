/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA5_AUDIO_H
#define MSM5XXX_MA5_AUDIO_H

#include <stdbool.h>
#include <stdint.h>

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

#endif
