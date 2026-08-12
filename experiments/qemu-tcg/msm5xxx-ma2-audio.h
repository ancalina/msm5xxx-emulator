/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_MA2_AUDIO_H
#define MSM5XXX_MA2_AUDIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Indirect register pages. */
#define MSM5XXX_MA2_PAGE_REG0 0u
#define MSM5XXX_MA2_PAGE_REG1 1u

/* Page-0 register indices. */
#define MSM5XXX_MA2_FM_DATA0 0x00u
#define MSM5XXX_MA2_FM_DATA1 0x01u
#define MSM5XXX_MA2_FM_DATA2 0x02u
#define MSM5XXX_MA2_FM_DATA3 0x03u
#define MSM5XXX_MA2_ADPCM_SEQ_DATA 0x04u
#define MSM5XXX_MA2_ADPCM_WAVE_DATA 0x05u
#define MSM5XXX_MA2_FM_IRQ_CTRL 0x06u
#define MSM5XXX_MA2_ADPCM_IRQ_CTRL 0x07u
#define MSM5XXX_MA2_STATUS1 0x08u
#define MSM5XXX_MA2_STATUS2 0x09u
#define MSM5XXX_MA2_WAVE_STATUS 0x0au
#define MSM5XXX_MA2_FULL_STATUS 0x0bu
#define MSM5XXX_MA2_EMPTY_STATUS 0x0cu
#define MSM5XXX_MA2_VERSION 0x0eu
#define MSM5XXX_MA2_PAGE_SELECT 0x0fu

/* Page-1 register indices. */
#define MSM5XXX_MA2_POWER 0x00u
#define MSM5XXX_MA2_CONTROL 0x01u
#define MSM5XXX_MA2_FM_TIMEBASE 0x02u
#define MSM5XXX_MA2_ADPCM_TIMEBASE 0x03u
#define MSM5XXX_MA2_FIFO_CONTROL 0x04u
#define MSM5XXX_MA2_CLOCK_ADJUST1 0x05u
#define MSM5XXX_MA2_CLOCK_ADJUST2 0x06u
#define MSM5XXX_MA2_FM_CHANNEL_ASSIGN 0x18u

/* CONTROL register bits. */
#define MSM5XXX_MA2_FM_START 0x01u
#define MSM5XXX_MA2_ADPCM_START 0x02u
#define MSM5XXX_MA2_DIRECT_START 0x04u
#define MSM5XXX_MA2_SAMPLE_RATE_8KHZ 0x08u
#define MSM5XXX_MA2_TIMER_START 0x10u
#define MSM5XXX_MA2_PLL_DOWN 0x40u
#define MSM5XXX_MA2_MA1_ATTENUATE 0x80u

/* FIFO control bits. */
#define MSM5XXX_MA2_ADPCM_SOFT_RESET 0x80u
#define MSM5XXX_MA2_SEQUENCE_SOFT_RESET 0x40u
#define MSM5XXX_MA2_FM_SOFT_RESET 0x20u
#define MSM5XXX_MA2_FIFO_REPEAT_ENABLE 0x10u
#define MSM5XXX_MA2_FIFO_REPEAT 0x08u
#define MSM5XXX_MA2_WAVE_FIFO_CLEAR 0x04u
#define MSM5XXX_MA2_SEQUENCE_FIFO_CLEAR 0x02u
#define MSM5XXX_MA2_FM_FIFO_CLEAR 0x01u

/* Occupancy bits with closed read semantics. */
#define MSM5XXX_MA2_ADPCM_FULL 0x10u
#define MSM5XXX_MA2_ADPCM_EMPTY 0x10u

#define MSM5XXX_MA2_FM_FIFO_COUNT 4u
#define MSM5XXX_MA2_FIFO_COUNT 6u
#define MSM5XXX_MA2_FM_FIFO_CAPACITY 96u
#define MSM5XXX_MA2_ADPCM_SEQUENCE_CAPACITY 32u
#define MSM5XXX_MA2_ADPCM_WAVE_CAPACITY 384u
#define MSM5XXX_MA2_COMPACT_EVENT_CAPACITY 260u
#define MSM5XXX_MA2_SEQUENCE_COUNT 5u
#define MSM5XXX_MA2_FM_CHANNEL_COUNT 16u
#define MSM5XXX_MA2_FM_VOICE_COUNT 16u
#define MSM5XXX_MA2_FM_ASSIGNMENT_COUNT 8u
#define MSM5XXX_MA2_FM_OPERATOR_COUNT 4u
#define MSM5XXX_MA2_FM_DECODED_VOICE_SIZE 78u

typedef enum MSM5xxxMA2Fifo {
    MSM5XXX_MA2_FIFO_FM0 = 0,
    MSM5XXX_MA2_FIFO_FM1 = 1,
    MSM5XXX_MA2_FIFO_FM2 = 2,
    MSM5XXX_MA2_FIFO_FM3 = 3,
    MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE = 4,
    MSM5XXX_MA2_FIFO_ADPCM_WAVE = 5,
} MSM5xxxMA2Fifo;

typedef enum MSM5xxxMA2RejectReason {
    MSM5XXX_MA2_REJECT_NONE = 0,
    MSM5XXX_MA2_REJECT_NULL_ARGUMENT,
    MSM5XXX_MA2_REJECT_UNSUPPORTED_PAGE,
    MSM5XXX_MA2_REJECT_UNSUPPORTED_REGISTER,
    MSM5XXX_MA2_REJECT_UNSUPPORTED_READ,
    MSM5XXX_MA2_REJECT_INVALID_ENCODING,
    MSM5XXX_MA2_REJECT_FIFO_FULL,
    MSM5XXX_MA2_REJECT_INVALID_FIFO,
    MSM5XXX_MA2_REJECT_CLOCK_ROLLBACK,
    MSM5XXX_MA2_REJECT_TIME_OVERFLOW,
} MSM5xxxMA2RejectReason;

typedef enum MSM5xxxMA2CompactResult {
    MSM5XXX_MA2_COMPACT_NEED_MORE = 0,
    MSM5XXX_MA2_COMPACT_EVENT,
    MSM5XXX_MA2_COMPACT_END,
    MSM5XXX_MA2_COMPACT_ERROR,
} MSM5xxxMA2CompactResult;

typedef enum MSM5xxxMA2CompactEventKind {
    MSM5XXX_MA2_COMPACT_NOP = 0,
    MSM5XXX_MA2_COMPACT_NOTE,
    MSM5XXX_MA2_COMPACT_WAVE,
    MSM5XXX_MA2_COMPACT_CONTROL,
    MSM5XXX_MA2_COMPACT_SYSEX,
    MSM5XXX_MA2_COMPACT_UNSUPPORTED,
} MSM5xxxMA2CompactEventKind;

typedef struct MSM5xxxMA2CompactEvent {
    MSM5xxxMA2CompactEventKind kind;
    uint16_t delta_ticks;
    uint16_t gate_ticks;
    uint8_t local_channel;
    uint8_t octave;
    uint8_t note_id;
    uint8_t wave_id;
    uint8_t control_family;
    uint8_t control_code;
    uint8_t control_value;
    uint8_t sysex_length;
    uint8_t sysex[255];
} MSM5xxxMA2CompactEvent;

typedef struct MSM5xxxMA2FMOperator {
    uint8_t data[5];
} MSM5xxxMA2FMOperator;

typedef struct MSM5xxxMA2FMVoice {
    bool valid;
    uint8_t bank;
    uint8_t program;
    uint8_t info;
    uint8_t basic_octave;
    uint8_t operator_count;
    MSM5xxxMA2FMOperator operation[MSM5XXX_MA2_FM_OPERATOR_COUNT];
    uint8_t decoded[MSM5XXX_MA2_FM_DECODED_VOICE_SIZE];
} MSM5xxxMA2FMVoice;

typedef struct MSM5xxxMA2FMChannel {
    uint8_t program;
    uint8_t bank;
    uint8_t octave_shift;
    uint8_t modulation;
    uint8_t pitch_bend;
    uint8_t volume;
    uint8_t pan;
    uint8_t expression;
    uint8_t voice_slot;
    uint8_t active_voice_slot;
    uint8_t note_octave;
    uint8_t note_id;
    bool voice_slot_valid;
    bool key_on;
} MSM5xxxMA2FMChannel;

typedef struct MSM5xxxMA2CompactParser {
    uint8_t bytes[MSM5XXX_MA2_COMPACT_EVENT_CAPACITY];
    uint16_t length;
    bool rejected;
} MSM5xxxMA2CompactParser;

typedef struct MSM5xxxMA2AdpcmDecoder {
    int32_t accumulator;
    uint32_t step;
} MSM5xxxMA2AdpcmDecoder;

typedef struct MSM5xxxMA2SequenceState {
    MSM5xxxMA2CompactParser parser;
    MSM5xxxMA2CompactEvent pending_event;
    uint64_t cursor_ns;
    uint64_t deadline_ns;
    uint64_t gate_unit_ns;
    uint64_t pause_started_ns;
    bool started;
    bool running;
    bool pending;
    bool end_pending;
    bool ended;
} MSM5xxxMA2SequenceState;

typedef struct MSM5xxxMA2GateState {
    uint64_t deadline_ns;
    bool active;
} MSM5xxxMA2GateState;

typedef enum MSM5xxxMA2OutputKind {
    MSM5XXX_MA2_OUTPUT_NONE = 0,
    MSM5XXX_MA2_OUTPUT_EVENT,
    MSM5XXX_MA2_OUTPUT_GATE_OFF,
    MSM5XXX_MA2_OUTPUT_END,
} MSM5xxxMA2OutputKind;

typedef struct MSM5xxxMA2Output {
    MSM5xxxMA2OutputKind kind;
    uint64_t timestamp_ns;
    MSM5xxxMA2Fifo stream;
    uint8_t channel;
    MSM5xxxMA2CompactEvent event;
} MSM5xxxMA2Output;

/*
 * State for the firmware-visible MA2 indirect bus and its six byte FIFOs.
 * No wall clock, renderer, synthesizer, or interrupt-line polarity lives
 * here; the owner supplies chip time and physical interrupt routing.
 */
typedef struct MSM5xxxMA2Audio {
    uint8_t index;
    uint8_t page;

    uint8_t power;
    uint8_t control;
    uint8_t fm_timebase;
    uint8_t adpcm_timebase;
    uint8_t clock_adjust1;
    uint8_t clock_adjust2;
    uint8_t fm_irq_ctrl;
    uint8_t adpcm_irq_ctrl;
    uint8_t fifo_control;
    uint8_t soft_reset_mask;
    uint8_t repeat_flags;
    uint8_t gend_status;
    bool fm_start_pending;
    bool adpcm_start_pending;
    uint8_t register_shadow[2][256];

    uint8_t fm_fifo[MSM5XXX_MA2_FM_FIFO_COUNT]
                   [MSM5XXX_MA2_FM_FIFO_CAPACITY];
    uint8_t adpcm_sequence_fifo[MSM5XXX_MA2_ADPCM_SEQUENCE_CAPACITY];
    uint8_t adpcm_wave_fifo[MSM5XXX_MA2_ADPCM_WAVE_CAPACITY];
    uint16_t fifo_read[MSM5XXX_MA2_FIFO_COUNT];
    uint16_t fifo_write[MSM5XXX_MA2_FIFO_COUNT];
    uint16_t fifo_count[MSM5XXX_MA2_FIFO_COUNT];

    MSM5xxxMA2SequenceState sequence[MSM5XXX_MA2_SEQUENCE_COUNT];
    MSM5xxxMA2GateState fm_gate[MSM5XXX_MA2_FM_CHANNEL_COUNT];
    MSM5xxxMA2GateState adpcm_gate;
    MSM5xxxMA2FMVoice fm_voice[MSM5XXX_MA2_FM_VOICE_COUNT];
    MSM5xxxMA2FMChannel fm_channel[MSM5XXX_MA2_FM_CHANNEL_COUNT];
    uint8_t fm_assignment[MSM5XXX_MA2_FM_ASSIGNMENT_COUNT];
    uint64_t fm_state_unhandled;
    uint64_t scheduler_now_ns;
    bool scheduler_clock_initialized;

    bool rejected;
    MSM5xxxMA2RejectReason reject_reason;
} MSM5xxxMA2Audio;

void msm5xxx_ma2_reset(MSM5xxxMA2Audio *audio);

bool msm5xxx_ma2_index_write(MSM5xxxMA2Audio *audio, uint8_t index);
bool msm5xxx_ma2_index_read(const MSM5xxxMA2Audio *audio, uint8_t *index);
bool msm5xxx_ma2_data_write(MSM5xxxMA2Audio *audio, uint8_t value);
bool msm5xxx_ma2_data_read(MSM5xxxMA2Audio *audio, uint8_t *value);

bool msm5xxx_ma2_chip_fifo_pop(MSM5xxxMA2Audio *audio,
                               MSM5xxxMA2Fifo fifo,
                               uint8_t *value);
size_t msm5xxx_ma2_fifo_occupancy(const MSM5xxxMA2Audio *audio,
                                  MSM5xxxMA2Fifo fifo);
size_t msm5xxx_ma2_fifo_capacity(MSM5xxxMA2Fifo fifo);
bool msm5xxx_ma2_take_fm_start(MSM5xxxMA2Audio *audio);
bool msm5xxx_ma2_take_adpcm_start(MSM5xxxMA2Audio *audio);
bool msm5xxx_ma2_scheduler_step(MSM5xxxMA2Audio *audio,
                                uint64_t now_ns,
                                MSM5xxxMA2Output *output);
bool msm5xxx_ma2_scheduler_next_deadline(const MSM5xxxMA2Audio *audio,
                                         uint64_t *deadline_ns);

bool msm5xxx_ma2_rejected(const MSM5xxxMA2Audio *audio);
MSM5xxxMA2RejectReason msm5xxx_ma2_reject_reason(
    const MSM5xxxMA2Audio *audio);
void msm5xxx_ma2_clear_rejection(MSM5xxxMA2Audio *audio);
bool msm5xxx_ma2_timebase_ns(uint8_t value, bool gate,
                             uint64_t *nanoseconds);

void msm5xxx_ma2_compact_parser_reset(MSM5xxxMA2CompactParser *parser);
MSM5xxxMA2CompactResult msm5xxx_ma2_compact_parser_feed(
    MSM5xxxMA2CompactParser *parser,
    uint8_t value,
    MSM5xxxMA2CompactEvent *event);
MSM5xxxMA2CompactResult msm5xxx_ma2_adpcm_parser_feed(
    MSM5xxxMA2CompactParser *parser,
    uint8_t value,
    MSM5xxxMA2CompactEvent *event);
void msm5xxx_ma2_adpcm_decoder_reset(MSM5xxxMA2AdpcmDecoder *decoder);
bool msm5xxx_ma2_adpcm_decode_byte(MSM5xxxMA2AdpcmDecoder *decoder,
                                   uint8_t value,
                                   int16_t samples[2]);

#endif
