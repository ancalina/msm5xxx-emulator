/*
 * Minimal MSM5xxx CPU/MMIO boundary probe.
 *
 * This is an experimental QEMU machine used to measure whether TCG can
 * preserve ARMv4T privileged state while servicing detector-admitted native
 * MSM5xxx device classes. Unclassified behavior retains native backing.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "qemu/audio.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qemu/units.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "exec/cpu-common.h"
#include "exec/icount.h"
#include "hw/arm/machines-qom.h"
#include "hw/block/flash.h"
#include "hw/boards.h"
#include "hw/irq.h"
#include "hw/i2c/bitbang_i2c.h"
#include "hw/i2c/i2c.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/sysbus.h"
#include "system/block-backend.h"
#include "system/address-spaces.h"
#include "system/cpus.h"
#include "system/reset.h"
#include "target/arm/cpu.h"
#include "target/arm/cpu-qom.h"

#include "msm5xxx-ma2-audio.h"
#include "msm5xxx-audio-synth.h"

#define TYPE_MSM5XXX_POC_MACHINE MACHINE_TYPE_NAME("msm5xxx-poc")
OBJECT_DECLARE_SIMPLE_TYPE(MSM5xxxPOCMachineState, MSM5XXX_POC_MACHINE)

#define TYPE_MSM5XXX_24LCXX "msm5xxx-24lcxx"
OBJECT_DECLARE_SIMPLE_TYPE(MSM5xxx24LCxxState, MSM5XXX_24LCXX)

#define MSM5XXX_POC_MMIO_BASE 0x10000000
#define MSM5XXX_POC_MMIO_SIZE 0x1000
#define MSM5XXX_POC_NOR_SIZE (16 * MiB)
#define MSM5XXX_POC_NOR_MAX_SIZE (32 * MiB)
#define MSM5XXX_POC_NOR_MAX_REGIONS 4
#define MSM5XXX_POC_UPPER_NOR_BASE 0x02800000
#define MSM5XXX_POC_UPPER_NOR_SIZE (8 * MiB)
#define MSM5XXX_POC_UPPER_NOR_SECTOR_SIZE 0x10000
#define MSM5XXX_POC_RAM_BASE 0x01000000
#define MSM5XXX_POC_BOOTSTRAP_BASE 0x04800000
#define MSM5XXX_POC_BOOTSTRAP_SIZE 0x1000
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define MSM5XXX_POC_MSM_SIZE (16 * MiB)
#define MSM5XXX_POC_IRAM_BASE 0x03800000
#define MSM5XXX_POC_IRAM_SIZE (2 * MiB)
#define MSM5XXX_POC_SBI_BASE 0x03000780
#define MSM5XXX_POC_SBI_SIZE 0x11
#define MSM5XXX_POC_DC0_BASE 0x03000dc4
#define MSM5XXX_POC_DC0_SIZE 0x0e
#define MSM5XXX_POC_DC0_DATA_OFFSET 0x08
#define MSM5XXX_POC_DC0_START_OFFSET 0x0c
#define MSM5XXX_POC_LCD_APERTURE_BASE 0x02000000
#define MSM5XXX_POC_LCD_APERTURE_SIZE (8 * MiB)
#define MSM5XXX_POC_LCD_SIZE 0x1000
#define MSM5XXX_POC_LCD_PORTS 4
#define MSM5XXX_POC_AUDIO_MAX_PORTS 16
#define MSM5XXX_POC_AUDIO_MAX_SITES 64
#define MSM5XXX_POC_LCD_TRACE_BASE 0x10001000
#define MSM5XXX_POC_LCD_TRACE_RECORD_SIZE 12
#define MSM5XXX_POC_LCD_TRACE_CAPACITY 65536
#define MSM5XXX_POC_LCD_TRACE_SIZE \
    (MSM5XXX_POC_LCD_TRACE_RECORD_SIZE * MSM5XXX_POC_LCD_TRACE_CAPACITY)
#define MSM5XXX_POC_LCD_STREAM_RECORD_SIZE 16
/* One split-lane 128x160 scanout can precede the first 33 ms virtual flush. */
#define MSM5XXX_POC_LCD_STREAM_CAPACITY 131072
#define MSM5XXX_POC_LCD_STREAM_SIZE \
    (MSM5XXX_POC_LCD_STREAM_RECORD_SIZE * MSM5XXX_POC_LCD_STREAM_CAPACITY)
#define MSM5XXX_POC_LCD_STREAM_WRITE 1
#define MSM5XXX_POC_LCD_STREAM_TELEMETRY 2
#define MSM5XXX_POC_DEVICE_STREAM_TELEMETRY 3
#define MSM5XXX_POC_INPUT_STREAM_TELEMETRY 4
#define MSM5XXX_POC_AUDIO_STREAM_WRITE 5
#define MSM5XXX_POC_AUDIO_STREAM_STATUS 6
#define MSM5XXX_POC_AUDIO_PCM_TELEMETRY 7
#define MSM5XXX_POC_AUDIO_TIMING_TELEMETRY 8
#define MSM5XXX_POC_AUDIO_REJECT_TELEMETRY 9
#define MSM5XXX_POC_AUDIO_STATUS_OVERFLOW 1
#define MSM5XXX_POC_AUDIO_STATUS_RESET 2
#define MSM5XXX_POC_AUDIO_STATUS_REJECTED 3
#define MSM5XXX_POC_AUDIO_STATUS_NATIVE 4
#define MSM5XXX_POC_AUDIO_REJECT_SYNTH_EVENT 0x100u
#define MSM5XXX_POC_AUDIO_REJECT_SYNTH_CLOCK 0x101u
#define MSM5XXX_POC_AUDIO_REJECT_DEADLINE 0x102u
#define MSM5XXX_POC_AUDIO_REJECT_COMMAND_QUEUE 0x103u
#define MSM5XXX_POC_AUDIO_COMMAND_QUEUE_CAPACITY 4096u
#define MSM5XXX_POC_AUDIO_PACKET_HEADER 32u
#define MSM5XXX_POC_AUDIO_PACKET_SIZE \
    (MSM5XXX_POC_AUDIO_PACKET_HEADER + MSM5XXX_AUDIO_CHUNK_FRAMES * 4u)
#define MSM5XXX_POC_HOST_INPUT 0x80
#define MSM5XXX_POC_HOST_INPUT_SIZE 4
#define MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW UINT8_MAX
#define MSM5XXX_POC_READY_POLL_DELAY 200000
#define MSM5XXX_POC_READY_POLL_MAX_SITES 8
#define MSM5XXX_POC_UART_SR_IDLE 0x0c
#define MSM5XXX_POC_PAUSE_TIMER_SIZE 4
#define MSM5XXX_POC_DMD5500_START 0x030f0124
#define MSM5XXX_POC_DMD5500_COMPLETION 0x030e01ae
#define MSM5XXX_POC_DMD5500_FIRST 0x030e0000
#define MSM5XXX_POC_DMD5500_SIZE 2
#define MSM5XXX_POC_DMD5500_ROUTINE_SIZE 0x54
#define MSM5XXX_POC_REX_CONTROLLER_SIZE 0x10
#define MSM5XXX_POC_REX_C80_CONTROLLER_SIZE 0x1a
#define MSM5XXX_POC_REX_C80_THREE_BANK_SIZE 0x4e
#define MSM5XXX_POC_REX_MAX_BANKS 3
#define MSM5XXX_POC_EEPROM_GPIO_SIZE 0x20
#define MSM5XXX_POC_24LC256_PAGE_SIZE 64
#define MSM5XXX_POC_RAW_NAND_DATA_BASE 0x02800000
#define MSM5XXX_POC_RAW_NAND_ADDRESS_BASE 0x02900000
#define MSM5XXX_POC_RAW_NAND_COMMAND_BASE 0x02a00000
#define MSM5XXX_POC_RAW_NAND_LOW_PORT_DATA_BASE 0x00800000
#define MSM5XXX_POC_RAW_NAND_LOW_PORT_ADDRESS_BASE 0x00900000
#define MSM5XXX_POC_RAW_NAND_LOW_PORT_COMMAND_BASE 0x00a00000
#define MSM5XXX_POC_RAW_NAND_DATA_SIZE (8 * MiB)
#define MSM5XXX_POC_RAW_NAND_PAGE_SIZE 0x200
#define MSM5XXX_POC_RAW_NAND_PAGES_PER_BLOCK 0x20
#define MSM5XXX_POC_RAW_NAND_BUS_WIDTH 2
#define MSM5XXX_POC_RAW_NAND_STATUS_READY 0xc0
#define MSM5XXX_POC_RAW_NAND_STATUS_FAILED 0xc1
#define MSM5XXX_POC_RAW_NAND_DRIVE "msm5xxx-raw-nand-main"

struct MSM5xxx24LCxxState {
    I2CSlave parent_obj;
    BlockBackend *blk;
    uint8_t *data;
    uint32_t capacity;
    uint16_t address;
    uint16_t write_page_base;
    unsigned address_bytes;
    uint32_t dirty_start;
    uint32_t dirty_end;
};

static const hwaddr msm5xxx_poc_lcd_bases[MSM5XXX_POC_LCD_PORTS] = {
    0x02000000, 0x02800000, 0x02c00000, 0x02200000,
};

typedef enum MSM5xxxPOCSBIStatus {
    MSM5XXX_POC_SBI_DISABLED,
    MSM5XXX_POC_SBI_OBSERVING,
    MSM5XXX_POC_SBI_CANDIDATE,
    MSM5XXX_POC_SBI_ACCEPTED,
    MSM5XXX_POC_SBI_REJECTED,
} MSM5xxxPOCSBIStatus;

typedef enum MSM5xxxPOCReadyPollStatus {
    MSM5XXX_POC_READY_DISABLED,
    MSM5XXX_POC_READY_OBSERVING,
    MSM5XXX_POC_READY_CANDIDATE,
    MSM5XXX_POC_READY_ACCEPTED,
    MSM5XXX_POC_READY_REJECTED,
} MSM5xxxPOCReadyPollStatus;

typedef enum MSM5xxxPOCRexGateStatus {
    MSM5XXX_POC_REX_GATE_DISABLED,
    MSM5XXX_POC_REX_GATE_VECTOR_WAIT,
    MSM5XXX_POC_REX_GATE_WRAPPER_WAIT,
    MSM5XXX_POC_REX_GATE_HANDLER_WAIT,
    MSM5XXX_POC_REX_GATE_CALLBACK_WAIT,
    MSM5XXX_POC_REX_GATE_ACCEPTED,
} MSM5xxxPOCRexGateStatus;

typedef enum MSM5xxxPOCRawNandMode {
    MSM5XXX_POC_RAW_NAND_IDLE,
    MSM5XXX_POC_RAW_NAND_STATUS,
    MSM5XXX_POC_RAW_NAND_READ_MAIN,
    MSM5XXX_POC_RAW_NAND_READ_SPARE,
    MSM5XXX_POC_RAW_NAND_PROGRAM_MAIN,
    MSM5XXX_POC_RAW_NAND_PROGRAM_SPARE,
    MSM5XXX_POC_RAW_NAND_ERASE,
} MSM5xxxPOCRawNandMode;

typedef struct MSM5xxxPOCLCDPort {
    MSM5xxxPOCMachineState *machine;
    unsigned index;
} MSM5xxxPOCLCDPort;

struct MSM5xxxPOCMachineState {
    MachineState parent_obj;

    ARMCPU *cpu;
    uint32_t reset_callbacks;
    uint32_t last_reset_callback_pc;
    uint32_t ram_base;
    uint32_t initial_sp;
    bool memory_profile_enabled;
    MemoryRegion nor;
    uint32_t primary_nor_size;
    bool primary_x16_nor_enabled;
    uint32_t primary_x16_nor_base;
    uint32_t primary_x16_nor_size;
    uint32_t primary_x16_nor_sector_size;
    uint32_t primary_x16_nor_region_count;
    uint32_t primary_x16_nor_block_count[MSM5XXX_POC_NOR_MAX_REGIONS];
    uint32_t primary_x16_nor_region_size[MSM5XXX_POC_NOR_MAX_REGIONS];
    uint16_t primary_x16_nor_id0;
    uint16_t primary_x16_nor_id1;
    bool primary_x16_write_while_suspended;
    bool record_x16_nor_enabled;
    uint32_t record_x16_nor_base;
    uint32_t record_x16_nor_size;
    uint32_t record_x16_nor_sector_size;
    MemoryRegion record_x16_nor_alias;
    bool mapped_primary_x16_nor_enabled;
    uint32_t mapped_primary_x16_nor_base;
    uint32_t mapped_primary_x16_nor_size;
    uint32_t mapped_primary_x16_nor_sector_size;
    /* The mutually exclusive direct CFI01/CFI02 profiles share geometry. */
    bool intel_x16_nor_enabled;
    uint32_t intel_x16_nor_base;
    uint32_t intel_x16_nor_size;
    uint32_t intel_x16_nor_sector_size;
    uint16_t intel_x16_nor_id0;
    uint16_t intel_x16_nor_id1;
    MemoryRegion intel_x16_nor_data_alias;
    bool amd_x16_nor_enabled;
    uint16_t amd_x16_nor_options;
    bool fujitsu_x16_nor_enabled;
    uint32_t secondary_primary_size;
    uint32_t secondary_nor_base;
    uint32_t secondary_nor_size;
    uint16_t secondary_nor_id0;
    uint16_t secondary_nor_id1;
    MemoryRegion secondary_nor_alias;
    bool upper_x8_nor_enabled;
    bool upper_x16_nor_enabled;
    bool raw_nand_main_enabled;
    uint32_t raw_nand_data_address;
    uint32_t raw_nand_address_address;
    uint32_t raw_nand_command_address;
    uint32_t raw_nand_data_size;
    uint32_t raw_nand_page_size;
    uint32_t raw_nand_pages_per_block;
    uint8_t raw_nand_bus_width;
    BlockBackend *raw_nand_blk;
    uint8_t *raw_nand_backing;
    uint8_t *raw_nand_program;
    MSM5xxxPOCRawNandMode raw_nand_mode;
    uint8_t raw_nand_status;
    uint8_t raw_nand_address_bytes[3];
    unsigned raw_nand_address_count;
    uint32_t raw_nand_cursor;
    uint32_t raw_nand_page_base;
    bool raw_nand_cursor_valid;
    bool raw_nand_spare_selected;
    uint64_t raw_nand_reads;
    uint64_t raw_nand_writes;
    uint64_t raw_nand_rejections;
    MemoryRegion raw_nand_data;
    MemoryRegion raw_nand_address;
    MemoryRegion raw_nand_command;
    MemoryRegion bootstrap;
    MemoryRegion msm;
    MemoryRegion sbi;
    MemoryRegion dc0;
    MemoryRegion lcd_aperture;
    MemoryRegion audio_opaque;
    MemoryRegion lcd[MSM5XXX_POC_LCD_PORTS];
    MemoryRegion lcd_trace;
    MemoryRegion ready_status;
    MemoryRegion ready_pulse;
    MemoryRegion ready_control;
    MemoryRegion pause_timer;
    MemoryRegion board_revision;
    MemoryRegion dmd_5500_start;
    MemoryRegion dmd_5500_completion;
    MemoryRegion board_status_input;
    MemoryRegion matrix_input;
    MemoryRegion mmio;
    qemu_irq cpu_irq;
    uint32_t value;
    uint64_t reads;
    uint64_t writes;
    bool irq_level;
    bool sbi_enabled;
    bool sbi_bootstrap_only;
    uint8_t sbi_backing[MSM5XXX_POC_SBI_SIZE];
    MSM5xxxPOCSBIStatus sbi_status;
    unsigned sbi_bootstrap_phase;
    unsigned sbi_validation_phase;
    uint16_t sbi_control;
    bool sbi_started;
    bool sbi_read_pending;
    bool sbi_read_full;
    uint32_t board_adc_value;
    uint32_t dc0_board_adc_value;
    unsigned sbi_board_adc_phase;
    uint16_t sbi_board_adc_selector;
    uint64_t sbi_board_adc_responses;
    uint64_t sbi_reads;
    uint64_t sbi_writes;
    uint8_t dc0_backing[MSM5XXX_POC_DC0_SIZE];
    unsigned dc0_board_adc_phase;
    uint64_t dc0_board_adc_responses;
    uint8_t lcd_aperture_backing[MSM5XXX_POC_LCD_APERTURE_SIZE];
    uint64_t lcd_aperture_reads;
    uint64_t lcd_aperture_writes;
    MSM5xxxPOCLCDPort lcd_port[MSM5XXX_POC_LCD_PORTS];
    uint8_t lcd_backing[MSM5XXX_POC_LCD_PORTS][MSM5XXX_POC_LCD_SIZE];
    uint64_t lcd_reads[MSM5XXX_POC_LCD_PORTS];
    uint64_t lcd_writes[MSM5XXX_POC_LCD_PORTS];
    bool lcd_trace_enabled;
    bool lcd_trace_overflow;
    uint32_t lcd_trace_count;
    uint8_t *lcd_trace_backing;
    char *lcd_trace_chardev;
    CharFrontend lcd_trace_chr;
    char *input_chardev;
    CharFrontend input_chr;
    GByteArray *lcd_trace_buffer;
    QEMUTimer *lcd_trace_timer;
    bool ready_poll_enabled;
    bool ready_poll_control_enabled;
    bool ready_poll_lcd_enabled;
    uint32_t ready_status_address;
    uint8_t ready_status_mask;
    uint32_t ready_pulse_address;
    uint32_t ready_control_address;
    uint16_t ready_control_value;
    uint32_t ready_poll_entry;
    uint32_t ready_poll_sites[MSM5XXX_POC_READY_POLL_MAX_SITES];
    unsigned ready_poll_site_count;
    uint32_t ready_poll_active_entry;
    uint32_t ready_status_pc_offset;
    uint32_t ready_pulse_set_pc_offset;
    uint32_t ready_pulse_clear_pc_offset;
    uint32_t ready_uart_rx_empty_read_pc_offset;
    uint32_t ready_uart_rx_empty_frame_read_pc_offset;
    bool ready_uart_rx_empty_enabled;
    uint32_t ready_control_pc_offset;
    uint8_t ready_status_backing;
    uint8_t ready_pulse_backing;
    uint8_t ready_control_backing;
    MSM5xxxPOCReadyPollStatus ready_poll_status;
    unsigned ready_poll_phase;
    uint64_t ready_poll_first_icount;
    uint64_t ready_poll_reads;
    uint64_t ready_poll_cycles;
    uint64_t ready_poll_responses;
    bool pause_timer_enabled;
    bool pause_timer_rejected;
    uint32_t pause_timer_address;
    uint32_t pause_timer_count_hz;
    uint32_t pause_timer_helper_start;
    uint32_t pause_timer_helper_end;
    uint8_t pause_timer_backing[MSM5XXX_POC_PAUSE_TIMER_SIZE];
    uint64_t pause_timer_writes;
    uint64_t pause_timer_fallbacks;
    uint64_t pause_timer_added_ns;
    bool board_revision_enabled;
    uint32_t board_revision_address;
    uint32_t board_revision_value;
    bool dmd_5500_enabled;
    bool dmd_5500_pending;
    uint32_t dmd_5500_entry;
    uint16_t dmd_5500_expected_first;
    uint64_t dmd_5500_starts;
    uint64_t dmd_5500_responses;
    uint64_t dmd_5500_rejections;
    bool board_status_input_enabled;
    uint32_t board_status_input_address;
    uint8_t board_status_input_mask;
    uint8_t board_status_input_default;
    uint8_t board_status_input_backing;
    bool matrix_input_enabled;
    uint32_t matrix_input_address;
    uint32_t matrix_input_sense_site;
    uint8_t matrix_input_no_key;
    uint8_t matrix_input_reset;
    uint8_t matrix_input_backing;
    bool matrix_input_host_enabled;
    uint8_t matrix_input_row_register;
    uint8_t matrix_input_rows;
    uint8_t matrix_input_sideband_mask;
    uint16_t matrix_input_sense_bitmap;
    bool matrix_input_pressed;
    uint8_t matrix_input_row;
    uint8_t matrix_input_sense;
    uint8_t matrix_input_buffer[MSM5XXX_POC_HOST_INPUT_SIZE];
    unsigned matrix_input_buffer_length;
    uint8_t matrix_input_ack[MSM5XXX_POC_LCD_STREAM_RECORD_SIZE];
    unsigned matrix_input_ack_length;
    unsigned matrix_input_ack_offset;
    guint matrix_input_ack_watch;
    uint64_t matrix_input_host_events;
    uint64_t matrix_input_active_reads;
    uint64_t matrix_input_rejections;
    bool audio_enabled;
    bool audio_ma2;
    bool audio_pcm_enabled;
    uint32_t audio_base;
    uint8_t audio_data_offset;
    uint8_t audio_index;
    uint8_t audio_backing[MSM5XXX_POC_AUDIO_MAX_PORTS];
    uint8_t audio_command_pending[MSM5XXX_MA2_FM_FIFO_COUNT]
                                 [MSM5XXX_POC_AUDIO_COMMAND_QUEUE_CAPACITY];
    uint16_t audio_command_pending_read[MSM5XXX_MA2_FM_FIFO_COUNT];
    uint16_t audio_command_pending_write[MSM5XXX_MA2_FM_FIFO_COUNT];
    uint16_t audio_command_pending_count[MSM5XXX_MA2_FM_FIFO_COUNT];
    bool audio_site_write[MSM5XXX_POC_AUDIO_MAX_SITES];
    uint8_t audio_site_port[MSM5XXX_POC_AUDIO_MAX_SITES];
    uint32_t audio_site_pc[MSM5XXX_POC_AUDIO_MAX_SITES];
    unsigned audio_site_count;
    bool audio_sites_enabled;
    uint32_t audio_stream_order;
    uint32_t audio_stream_dropped;
    uint32_t audio_stream_reject_code;
    uint64_t audio_stream_reset_epoch;
    uint8_t audio_stream_status_pending;
    bool audio_stream_started;
    bool audio_stream_rejected;
    bool audio_reset_initialized;
    char *audio_stream_chardev;
    CharFrontend audio_stream_chr;
    uint8_t audio_pcm_packet[MSM5XXX_POC_AUDIO_PACKET_SIZE];
    unsigned audio_pcm_length;
    unsigned audio_pcm_offset;
    bool audio_pcm_failed;
    AudioBackend *audio_backend;
    SWVoiceOut *audio_voice;
    int16_t audio_backend_pcm[MSM5XXX_AUDIO_CHUNK_FRAMES][2];
    unsigned audio_backend_pcm_length;
    unsigned audio_backend_pcm_offset;
    QemuMutex audio_synth_lock;
    QemuMutex audio_core_lock;
    bool audio_synth_lock_initialized;
    bool audio_core_lock_initialized;
    bool audio_output_started;
    MSM5xxxAudioSynth audio_synth;
    MSM5xxxMA2Audio ma2_audio;
    QEMUTimer *ma2_audio_timer;
    uint64_t ma2_audio_events;
    uint64_t ma2_audio_gate_offs;
    uint64_t ma2_audio_ends;
    bool ma2_audio_timer_rejected;
    bool rex_irq_enabled;
    bool rex_irq_c80;
    bool rex_irq_read_consume;
    uint32_t rex_irq_status_address;
    uint32_t rex_irq_enable_address;
    uint32_t rex_irq_arm_address;
    uint16_t rex_irq_mask;
    uint32_t rex_irq_interval;
    uint32_t rex_idle_address;
    uint32_t rex_irq_controller_size;
    uint8_t rex_irq_bank_count;
    uint32_t rex_irq_vector_target;
    uint32_t rex_irq_wrapper_address;
    uint32_t rex_irq_handler_slot;
    uint32_t rex_irq_handler_address;
    uint32_t rex_irq_handler_size;
    uint32_t rex_irq_callback_slot;
    uint32_t rex_irq_callback_address;
    MemoryRegion rex_irq_controller;
    MemoryRegion rex_irq_arm;
    uint8_t rex_irq_backing[MSM5XXX_POC_REX_C80_THREE_BANK_SIZE];
    uint8_t rex_irq_arm_backing;
    uint16_t rex_irq_pending[MSM5XXX_POC_REX_MAX_BANKS];
    bool rex_irq_armed;
    bool rex_irq_level;
    bool rex_irq_route_active;
    bool rex_idle_seen;
    uint32_t rex_idle_gate_pc;
    MSM5xxxPOCRexGateStatus rex_irq_gate_status;
    int64_t rex_irq_next;
    QEMUTimer *rex_irq_timer;
    uint64_t rex_irq_ticks;
    uint64_t rex_irq_assertions;
    uint64_t rex_irq_gate_attempts;
    uint64_t rex_irq_acks;
    bool eeprom_gpio_enabled;
    uint32_t eeprom_gpio_base;
    uint8_t eeprom_data_offset;
    uint8_t eeprom_data_mask;
    uint8_t eeprom_clock_offset;
    uint8_t eeprom_clock_mask;
    uint8_t eeprom_direction_offset;
    uint32_t eeprom_capacity;
    MemoryRegion eeprom_gpio;
    uint8_t eeprom_gpio_backing[MSM5XXX_POC_EEPROM_GPIO_SIZE];
    bitbang_i2c_interface eeprom_i2c;
    int eeprom_sda;
};

static bool msm5xxx_24lcxx_flush(MSM5xxx24LCxxState *s)
{
    int ret;

    if (s->dirty_start >= s->dirty_end) {
        return true;
    }
    ret = blk_pwrite(s->blk, s->dirty_start, s->dirty_end - s->dirty_start,
                     s->data + s->dirty_start, 0);
    if (ret < 0) {
        error_report("24LCxx state update failed: %s", strerror(-ret));
        return false;
    }
    s->dirty_start = s->capacity;
    s->dirty_end = 0;
    return true;
}

static int msm5xxx_24lcxx_event(I2CSlave *i2c, enum i2c_event event)
{
    MSM5xxx24LCxxState *s = MSM5XXX_24LCXX(i2c);

    if (event == I2C_START_SEND) {
        if (!msm5xxx_24lcxx_flush(s)) {
            return 1;
        }
        s->address = 0;
        s->address_bytes = 0;
    } else if (event == I2C_FINISH) {
        msm5xxx_24lcxx_flush(s);
    }
    return 0;
}

static int msm5xxx_24lcxx_send(I2CSlave *i2c, uint8_t value)
{
    MSM5xxx24LCxxState *s = MSM5XXX_24LCXX(i2c);

    if (s->address_bytes < 2) {
        s->address = (s->address << 8) | value;
        s->address_bytes++;
        if (s->address_bytes == 2) {
            s->write_page_base =
                s->address & ~(MSM5XXX_POC_24LC256_PAGE_SIZE - 1);
        }
        return 0;
    }
    s->address %= s->capacity;
    s->data[s->address] = value;
    s->dirty_start = MIN(s->dirty_start, s->address);
    s->dirty_end = MAX(s->dirty_end, (uint32_t)s->address + 1);
    s->address = s->write_page_base |
        ((s->address + 1) & (MSM5XXX_POC_24LC256_PAGE_SIZE - 1));
    return 0;
}

static uint8_t msm5xxx_24lcxx_recv(I2CSlave *i2c)
{
    MSM5xxx24LCxxState *s = MSM5XXX_24LCXX(i2c);
    uint8_t value;

    s->address %= s->capacity;
    value = s->data[s->address];
    s->address = (s->address + 1) % s->capacity;
    return value;
}

static void msm5xxx_24lcxx_reset(DeviceState *dev)
{
    MSM5xxx24LCxxState *s = MSM5XXX_24LCXX(dev);

    msm5xxx_24lcxx_flush(s);
    s->address = 0;
    s->write_page_base = 0;
    s->address_bytes = 0;
}

static void msm5xxx_24lcxx_realize(DeviceState *dev, Error **errp)
{
    MSM5xxx24LCxxState *s = MSM5XXX_24LCXX(dev);
    int64_t length;
    int ret;

    if (!s->blk || !s->capacity) {
        error_setg(errp, "24LCxx requires a raw state drive and capacity");
        return;
    }
    ret = blk_set_perm(s->blk,
                       BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                       BLK_PERM_ALL, errp);
    if (ret < 0) {
        return;
    }
    length = blk_getlength(s->blk);
    if (length != s->capacity) {
        error_setg(errp, "24LCxx state is 0x%" PRIx64
                   " bytes, expected 0x%x", length, s->capacity);
        return;
    }
    s->data = g_malloc(s->capacity);
    ret = blk_pread(s->blk, 0, s->capacity, s->data, 0);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "24LCxx state read failed");
        g_clear_pointer(&s->data, g_free);
        return;
    }
    s->dirty_start = s->capacity;
}

static void msm5xxx_24lcxx_unrealize(DeviceState *dev)
{
    MSM5xxx24LCxxState *s = MSM5XXX_24LCXX(dev);

    msm5xxx_24lcxx_flush(s);
    g_clear_pointer(&s->data, g_free);
}

static const Property msm5xxx_24lcxx_properties[] = {
    DEFINE_PROP_DRIVE("drive", MSM5xxx24LCxxState, blk),
};

static void msm5xxx_24lcxx_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    I2CSlaveClass *isc = I2C_SLAVE_CLASS(oc);

    dc->realize = msm5xxx_24lcxx_realize;
    dc->unrealize = msm5xxx_24lcxx_unrealize;
    device_class_set_legacy_reset(dc, msm5xxx_24lcxx_reset);
    device_class_set_props(dc, msm5xxx_24lcxx_properties);
    isc->event = msm5xxx_24lcxx_event;
    isc->send = msm5xxx_24lcxx_send;
    isc->recv = msm5xxx_24lcxx_recv;
}

static const TypeInfo msm5xxx_24lcxx_typeinfo = {
    .name = TYPE_MSM5XXX_24LCXX,
    .parent = TYPE_I2C_SLAVE,
    .instance_size = sizeof(MSM5xxx24LCxxState),
    .class_init = msm5xxx_24lcxx_class_init,
};

static uint64_t msm5xxx_poc_backing_read(const uint8_t *backing,
                                         hwaddr offset, unsigned size)
{
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < size; i++) {
        value |= (uint64_t)backing[offset + i] << (i * 8);
    }
    return value;
}

static void msm5xxx_poc_backing_write(uint8_t *backing, hwaddr offset,
                                      uint64_t value, unsigned size)
{
    unsigned i;

    for (i = 0; i < size; i++) {
        backing[offset + i] = value >> (i * 8);
    }
}

static bool msm5xxx_poc_lcd_stream_append(MSM5xxxPOCMachineState *s,
                                          uint8_t kind, uint8_t size,
                                          uint32_t address, uint32_t value,
                                          uint32_t auxiliary)
{
    uint8_t record[MSM5XXX_POC_LCD_STREAM_RECORD_SIZE] = { kind, size };

    if (s->lcd_trace_buffer->len + sizeof(record) >
        MSM5XXX_POC_LCD_STREAM_SIZE) {
        s->lcd_trace_overflow = true;
        return false;
    }
    msm5xxx_poc_backing_write(record, 4, address, 4);
    msm5xxx_poc_backing_write(record, 8, value, 4);
    msm5xxx_poc_backing_write(record, 12, auxiliary, 4);
    g_byte_array_append(s->lcd_trace_buffer, record, sizeof(record));
    return true;
}

static gboolean msm5xxx_poc_input_stream_flush(void *unused,
                                                GIOCondition condition,
                                                void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    int written;

    s->matrix_input_ack_watch = 0;
    if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
        s->matrix_input_host_enabled = false;
        s->matrix_input_ack_length = 0;
        s->matrix_input_ack_offset = 0;
        return G_SOURCE_REMOVE;
    }
    written = qemu_chr_fe_write(
        &s->input_chr,
        s->matrix_input_ack + s->matrix_input_ack_offset,
        s->matrix_input_ack_length - s->matrix_input_ack_offset
    );
    if (written > 0) {
        s->matrix_input_ack_offset += written;
    }
    if (s->matrix_input_ack_offset == s->matrix_input_ack_length) {
        s->matrix_input_ack_length = 0;
        s->matrix_input_ack_offset = 0;
        qemu_chr_fe_accept_input(&s->input_chr);
        return G_SOURCE_REMOVE;
    }
    s->matrix_input_ack_watch = qemu_chr_fe_add_watch(
        &s->input_chr, G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
        msm5xxx_poc_input_stream_flush, s
    );
    if (!s->matrix_input_ack_watch) {
        s->matrix_input_host_enabled = false;
        s->matrix_input_ack_length = 0;
        s->matrix_input_ack_offset = 0;
    }
    return G_SOURCE_REMOVE;
}

static void msm5xxx_poc_input_stream_write(MSM5xxxPOCMachineState *s)
{
    uint8_t *record = s->matrix_input_ack;

    assert(!s->matrix_input_ack_length);
    memset(record, 0, MSM5XXX_POC_LCD_STREAM_RECORD_SIZE);
    record[0] = MSM5XXX_POC_INPUT_STREAM_TELEMETRY;
    record[1] = s->matrix_input_pressed;

    msm5xxx_poc_backing_write(
        record, 4,
        s->matrix_input_row | (s->matrix_input_sense << 8) |
        (MIN(s->matrix_input_rejections, UINT16_MAX) << 16), 4);
    msm5xxx_poc_backing_write(
        record, 8, s->matrix_input_host_events, 4);
    msm5xxx_poc_backing_write(
        record, 12, s->matrix_input_active_reads, 4);
    s->matrix_input_ack_length = MSM5XXX_POC_LCD_STREAM_RECORD_SIZE;
    s->matrix_input_ack_offset = 0;
    msm5xxx_poc_input_stream_flush(NULL, G_IO_OUT, s);
}

static void msm5xxx_poc_audio_stream_status(MSM5xxxPOCMachineState *s)
{
    uint8_t status = s->audio_stream_status_pending;

    if (!status || !s->lcd_trace_buffer) {
        return;
    }
    if (msm5xxx_poc_lcd_stream_append(
            s, MSM5XXX_POC_AUDIO_STREAM_STATUS, status,
            status == MSM5XXX_POC_AUDIO_STATUS_RESET ?
                (uint32_t)s->audio_stream_reset_epoch :
            (status == MSM5XXX_POC_AUDIO_STATUS_OVERFLOW ||
             status == MSM5XXX_POC_AUDIO_STATUS_REJECTED) ?
                s->audio_stream_order : 0,
            status == MSM5XXX_POC_AUDIO_STATUS_RESET ?
                (uint32_t)(s->audio_stream_reset_epoch >> 32u) :
            (status == MSM5XXX_POC_AUDIO_STATUS_OVERFLOW ||
             status == MSM5XXX_POC_AUDIO_STATUS_REJECTED) ?
                s->audio_stream_dropped : 0,
            status == MSM5XXX_POC_AUDIO_STATUS_REJECTED ?
                s->audio_stream_reject_code : 0)) {
        s->audio_stream_status_pending = 0;
    }
}

static void msm5xxx_poc_audio_pcm_telemetry(MSM5xxxPOCMachineState *s)
{
    uint32_t underflow;
    uint32_t overflow;
    uint32_t epoch;
    uint32_t late_events;
    uint32_t collapsed_events;
    uint32_t max_lateness_ns;

    if (!s->lcd_trace_buffer || !s->audio_synth_lock_initialized) {
        return;
    }
    qemu_mutex_lock(&s->audio_synth_lock);
    underflow = s->audio_synth.underflow_frames > UINT32_MAX ?
                UINT32_MAX : s->audio_synth.underflow_frames;
    overflow = s->audio_synth.overflow_frames > UINT32_MAX ?
               UINT32_MAX : s->audio_synth.overflow_frames;
    epoch = s->audio_synth.epoch > UINT32_MAX ?
            UINT32_MAX : s->audio_synth.epoch;
    late_events = s->audio_synth.late_events > UINT32_MAX ?
                  UINT32_MAX : s->audio_synth.late_events;
    collapsed_events = s->audio_synth.collapsed_events > UINT32_MAX ?
                       UINT32_MAX : s->audio_synth.collapsed_events;
    max_lateness_ns = s->audio_synth.max_lateness_ns > UINT32_MAX ?
                      UINT32_MAX : s->audio_synth.max_lateness_ns;
    qemu_mutex_unlock(&s->audio_synth_lock);
    msm5xxx_poc_lcd_stream_append(
        s, MSM5XXX_POC_AUDIO_PCM_TELEMETRY, 0,
        underflow, overflow, epoch
    );
    msm5xxx_poc_lcd_stream_append(
        s, MSM5XXX_POC_AUDIO_TIMING_TELEMETRY, 0,
        late_events, collapsed_events, max_lateness_ns
    );
}

static void msm5xxx_poc_lcd_trace_flush(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUClass *cc = CPU_GET_CLASS(s->cpu);
    uint64_t instructions = icount_get_raw();
    int written;

    msm5xxx_poc_audio_stream_status(s);
    msm5xxx_poc_lcd_stream_append(
        s, MSM5XXX_POC_LCD_STREAM_TELEMETRY, 0,
        cc->get_pc(CPU(s->cpu)), instructions, instructions >> 32
    );
    msm5xxx_poc_lcd_stream_append(
        s, MSM5XXX_POC_DEVICE_STREAM_TELEMETRY, s->ready_poll_status,
        s->ready_poll_phase | (s->ready_poll_cycles << 8),
        s->ready_poll_reads, s->ready_poll_responses
    );
    msm5xxx_poc_audio_pcm_telemetry(s);
    if (s->lcd_trace_buffer->len) {
        written = qemu_chr_fe_write(&s->lcd_trace_chr,
                                    s->lcd_trace_buffer->data,
                                    s->lcd_trace_buffer->len);
        if (written > 0) {
            g_byte_array_remove_range(s->lcd_trace_buffer, 0, written);
            msm5xxx_poc_audio_stream_status(s);
        }
    }
    timer_mod(s->lcd_trace_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 33);
}

static int msm5xxx_poc_host_input_can_read(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;

    return s->matrix_input_host_enabled && !s->matrix_input_ack_length ?
        MSM5XXX_POC_HOST_INPUT_SIZE - s->matrix_input_buffer_length : 0;
}

static void msm5xxx_poc_host_input_read(void *opaque, const uint8_t *buf,
                                         int size)
{
    MSM5xxxPOCMachineState *s = opaque;

    while (size > 0) {
        unsigned available = MSM5XXX_POC_HOST_INPUT_SIZE -
            s->matrix_input_buffer_length;
        unsigned consumed = MIN((unsigned)size, available);
        const uint8_t *record;

        memcpy(s->matrix_input_buffer + s->matrix_input_buffer_length,
               buf, consumed);
        s->matrix_input_buffer_length += consumed;
        buf += consumed;
        size -= consumed;
        if (s->matrix_input_buffer_length != MSM5XXX_POC_HOST_INPUT_SIZE) {
            continue;
        }
        record = s->matrix_input_buffer;
        if (record[0] != MSM5XXX_POC_HOST_INPUT || record[1] > 1 ||
            (record[1] ? s->matrix_input_pressed :
                         !s->matrix_input_pressed) ||
            (!record[1] && (record[2] || record[3])) ||
            (record[1] &&
             (record[2] == MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW ?
              (!s->matrix_input_sideband_mask ||
               record[3] != s->matrix_input_sideband_mask) :
              (record[2] >= s->matrix_input_rows || record[3] > 0x0f ||
               !(s->matrix_input_sense_bitmap & (1U << record[3])))))) {
            s->matrix_input_rejections++;
        } else {
            s->matrix_input_pressed = record[1];
            if (record[1]) {
                s->matrix_input_row = record[2];
                s->matrix_input_sense = record[3];
            }
            s->matrix_input_host_events++;
        }
        s->matrix_input_buffer_length = 0;
        msm5xxx_poc_input_stream_write(s);
    }
}

static void msm5xxx_poc_ready_reject(MSM5xxxPOCMachineState *s)
{
    s->ready_poll_status = MSM5XXX_POC_READY_REJECTED;
    s->ready_poll_phase = 0;
}

static bool msm5xxx_poc_ready_site_for_pc(MSM5xxxPOCMachineState *s,
                                           uint32_t pc, uint32_t offset,
                                           uint32_t *entry)
{
    unsigned index;

    if (!s->ready_poll_site_count) {
        if (pc != s->ready_poll_entry + offset) {
            return false;
        }
        *entry = s->ready_poll_entry;
        return true;
    }
    for (index = 0; index < s->ready_poll_site_count; index++) {
        if (pc == s->ready_poll_sites[index] + offset) {
            *entry = s->ready_poll_sites[index];
            return true;
        }
    }
    return false;
}

static uint64_t msm5xxx_poc_ready_status_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUClass *cc = CPU_GET_CLASS(s->cpu);
    uint64_t now = icount_get_raw();
    uint32_t pc;
    uint32_t entry = 0;
    bool primary_read;

    if (offset || size != 1) {
        return 0;
    }
    pc = cc->get_pc(CPU(s->cpu));
    primary_read = msm5xxx_poc_ready_site_for_pc(
        s, pc, s->ready_status_pc_offset, &entry
    );
    if (s->ready_poll_status == MSM5XXX_POC_READY_ACCEPTED) {
        if (s->ready_uart_rx_empty_enabled &&
            (!s->ready_poll_control_enabled ||
             pc == s->ready_poll_entry +
                   s->ready_uart_rx_empty_read_pc_offset)) {
            s->ready_poll_reads++;
            s->ready_poll_responses++;
            return MSM5XXX_POC_UART_SR_IDLE;
        }
        if (!primary_read) {
            return s->ready_status_backing;
        }
        s->ready_poll_reads++;
        s->ready_poll_responses++;
        return s->ready_status_backing | s->ready_status_mask;
    }
    if (!primary_read) {
        return s->ready_status_backing;
    }
    s->ready_poll_reads++;
    if (s->ready_poll_status == MSM5XXX_POC_READY_OBSERVING) {
        s->ready_poll_status = MSM5XXX_POC_READY_CANDIDATE;
        s->ready_poll_active_entry = entry;
        s->ready_poll_phase = 1;
        s->ready_poll_first_icount = now;
    } else if (s->ready_poll_status == MSM5XXX_POC_READY_CANDIDATE) {
        unsigned expected_phase = s->ready_poll_control_enabled ? 4 : 3;

        if (entry != s->ready_poll_active_entry) {
            s->ready_poll_active_entry = entry;
            s->ready_poll_phase = 1;
            s->ready_poll_first_icount = now;
            return s->ready_status_backing;
        }
        if (s->ready_poll_phase != expected_phase) {
            s->ready_poll_phase = 1;
            return s->ready_status_backing;
        }
        s->ready_poll_phase = 1;
        if (now - s->ready_poll_first_icount >= MSM5XXX_POC_READY_POLL_DELAY) {
            s->ready_poll_status = MSM5XXX_POC_READY_ACCEPTED;
        }
    }
    if (s->ready_poll_status == MSM5XXX_POC_READY_ACCEPTED) {
        s->ready_poll_responses++;
        return s->ready_status_backing | s->ready_status_mask;
    }
    return s->ready_status_backing;
}

static void msm5xxx_poc_ready_status_write(void *opaque, hwaddr offset,
                                           uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset || size != 1) {
        msm5xxx_poc_ready_reject(s);
        return;
    }
    s->ready_status_backing = value;
}

static uint64_t msm5xxx_poc_ready_pulse_read(void *opaque, hwaddr offset,
                                             unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset || size != 1) {
        msm5xxx_poc_ready_reject(s);
        return 0;
    }
    return s->ready_pulse_backing;
}

static void msm5xxx_poc_ready_pulse_write(void *opaque, hwaddr offset,
                                          uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUClass *cc = CPU_GET_CLASS(s->cpu);
    uint32_t pc = cc->get_pc(CPU(s->cpu));

    if (offset || size != 1) {
        msm5xxx_poc_ready_reject(s);
        return;
    }
    if (s->ready_poll_status == MSM5XXX_POC_READY_CANDIDATE) {
        if (pc == s->ready_poll_active_entry +
                  s->ready_pulse_set_pc_offset) {
            if (value == 1) {
                s->ready_poll_phase = 2;
            } else {
                msm5xxx_poc_ready_reject(s);
            }
        } else if (pc == s->ready_poll_active_entry +
                         s->ready_pulse_clear_pc_offset) {
            if (value != 0) {
                msm5xxx_poc_ready_reject(s);
            } else if (s->ready_poll_phase == 2) {
                s->ready_poll_phase = 3;
                s->ready_poll_cycles++;
            } else {
                s->ready_poll_phase = 1;
            }
        }
    }
    s->ready_pulse_backing = value;
}

static const MemoryRegionOps msm5xxx_poc_ready_status_ops = {
    .read = msm5xxx_poc_ready_status_read,
    .write = msm5xxx_poc_ready_status_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
};

static const MemoryRegionOps msm5xxx_poc_ready_pulse_ops = {
    .read = msm5xxx_poc_ready_pulse_read,
    .write = msm5xxx_poc_ready_pulse_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
};

static uint64_t msm5xxx_poc_ready_control_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset || size != 1) {
        msm5xxx_poc_ready_reject(s);
        return 0;
    }
    return s->ready_control_backing;
}

static void msm5xxx_poc_ready_control_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUClass *cc = CPU_GET_CLASS(s->cpu);

    if (offset || size != 1) {
        msm5xxx_poc_ready_reject(s);
        return;
    }
    if (s->ready_poll_status == MSM5XXX_POC_READY_CANDIDATE &&
        cc->get_pc(CPU(s->cpu)) ==
            s->ready_poll_entry + s->ready_control_pc_offset) {
        if (value == s->ready_control_value && s->ready_poll_phase == 3) {
            s->ready_poll_phase = 4;
        } else {
            msm5xxx_poc_ready_reject(s);
        }
    }
    s->ready_control_backing = value;
}

static const MemoryRegionOps msm5xxx_poc_ready_control_ops = {
    .read = msm5xxx_poc_ready_control_read,
    .write = msm5xxx_poc_ready_control_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
};

static uint64_t msm5xxx_poc_dmd_5500_start_read(void *opaque,
                                                hwaddr offset,
                                                unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);

    return msm5xxx_poc_backing_read(
        msm, MSM5XXX_POC_DMD5500_START - MSM5XXX_POC_MSM_BASE + offset, size
    );
}

static bool msm5xxx_poc_dmd_5500_pc_is(MSM5xxxPOCMachineState *s,
                                        uint32_t offset)
{
    CPUState *cpu = current_cpu;
    CPUClass *cc;

    if (!qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running ||
        !cpu->neg.can_do_io) {
        return false;
    }
    cc = CPU_GET_CLASS(cpu);
    return (cc->get_pc(cpu) & ~1U) == s->dmd_5500_entry + offset;
}

static void msm5xxx_poc_dmd_5500_start_write(void *opaque, hwaddr offset,
                                              uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint8_t *start = msm + MSM5XXX_POC_DMD5500_START - MSM5XXX_POC_MSM_BASE;
    uint16_t old = msm5xxx_poc_backing_read(start, 0, 2);

    msm5xxx_poc_backing_write(start, offset, value, size);
    if (!msm5xxx_poc_dmd_5500_pc_is(s, 0x20)) {
        return;
    }
    if (!offset && size == 2 && value == 0 && old == UINT16_MAX &&
        msm5xxx_poc_backing_read(
            msm, MSM5XXX_POC_DMD5500_FIRST - MSM5XXX_POC_MSM_BASE, 2
        ) == s->dmd_5500_expected_first &&
        msm5xxx_poc_backing_read(
            msm, MSM5XXX_POC_DMD5500_COMPLETION - MSM5XXX_POC_MSM_BASE, 2
        ) == 0 && !s->dmd_5500_pending) {
        s->dmd_5500_pending = true;
        s->dmd_5500_starts++;
    } else {
        s->dmd_5500_rejections++;
    }
}

static uint64_t msm5xxx_poc_dmd_5500_completion_read(void *opaque,
                                                      hwaddr offset,
                                                      unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint8_t *completion =
        msm + MSM5XXX_POC_DMD5500_COMPLETION - MSM5XXX_POC_MSM_BASE;

    if (msm5xxx_poc_dmd_5500_pc_is(s, 0x32)) {
        if (!offset && size == 2 && s->dmd_5500_pending) {
            msm5xxx_poc_backing_write(completion, 0, UINT16_MAX, 2);
            s->dmd_5500_pending = false;
            s->dmd_5500_responses++;
        } else {
            s->dmd_5500_rejections++;
        }
    }
    return msm5xxx_poc_backing_read(completion, offset, size);
}

static void msm5xxx_poc_dmd_5500_completion_write(void *opaque,
                                                   hwaddr offset,
                                                   uint64_t value,
                                                   unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);

    msm5xxx_poc_backing_write(
        msm, MSM5XXX_POC_DMD5500_COMPLETION - MSM5XXX_POC_MSM_BASE + offset,
        value, size
    );
}

static const MemoryRegionOps msm5xxx_poc_dmd_5500_start_ops = {
    .read = msm5xxx_poc_dmd_5500_start_read,
    .write = msm5xxx_poc_dmd_5500_start_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 2,
    .impl.min_access_size = 1,
    .impl.max_access_size = 2,
};

static const MemoryRegionOps msm5xxx_poc_dmd_5500_completion_ops = {
    .read = msm5xxx_poc_dmd_5500_completion_read,
    .write = msm5xxx_poc_dmd_5500_completion_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 2,
    .impl.min_access_size = 1,
    .impl.max_access_size = 2,
};

static bool msm5xxx_poc_pause_timer_in_scope(MSM5xxxPOCMachineState *s)
{
    CPUState *cpu = current_cpu;
    CPUClass *cc;
    uint32_t pc;

    if (!qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running ||
        !cpu->neg.can_do_io) {
        return false;
    }
    cc = CPU_GET_CLASS(cpu);
    pc = cc->get_pc(cpu) & ~1U;

    return pc >= s->pause_timer_helper_start &&
           pc < s->pause_timer_helper_end;
}

static uint64_t msm5xxx_poc_pause_timer_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset + size > MSM5XXX_POC_PAUSE_TIMER_SIZE) {
        return 0;
    }
    if (msm5xxx_poc_pause_timer_in_scope(s)) {
        s->pause_timer_rejected = true;
    }
    s->pause_timer_fallbacks++;
    return msm5xxx_poc_backing_read(s->pause_timer_backing, offset, size);
}

static void msm5xxx_poc_pause_timer_write(void *opaque, hwaddr offset,
                                           uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t ns;
    uint16_t count;

    if (offset + size > MSM5XXX_POC_PAUSE_TIMER_SIZE) {
        if (msm5xxx_poc_pause_timer_in_scope(s)) {
            s->pause_timer_rejected = true;
        }
        s->pause_timer_fallbacks++;
        return;
    }
    msm5xxx_poc_backing_write(s->pause_timer_backing, offset, value, size);
    if (!msm5xxx_poc_pause_timer_in_scope(s)) {
        s->pause_timer_fallbacks++;
        return;
    }
    if (s->pause_timer_rejected || offset || size != 2) {
        s->pause_timer_rejected = true;
        s->pause_timer_fallbacks++;
        return;
    }

    count = value & 0x03ff;
    if (!count) {
        s->pause_timer_writes++;
        return;
    }
    ns = ((uint64_t)count * NANOSECONDS_PER_SECOND +
          s->pause_timer_count_hz / 2) / s->pause_timer_count_hz;
    if (!icount_advance_ns(ns)) {
        s->pause_timer_rejected = true;
        s->pause_timer_fallbacks++;
        return;
    }
    s->pause_timer_writes++;
    s->pause_timer_added_ns += ns;
}

static const MemoryRegionOps msm5xxx_poc_pause_timer_ops = {
    .read = msm5xxx_poc_pause_timer_read,
    .write = msm5xxx_poc_pause_timer_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

static uint64_t msm5xxx_poc_board_revision_read(void *opaque, hwaddr offset,
                                                unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t mask = size == 4 ? UINT32_MAX : (1u << (size * 8)) - 1u;

    return ((uint64_t)s->board_revision_value >> (offset * 8)) & mask;
}

static void msm5xxx_poc_board_revision_write(void *opaque, hwaddr offset,
                                              uint64_t value, unsigned size)
{
    /* Fixed device identity: match the existing per-read refresh contract. */
}

static const MemoryRegionOps msm5xxx_poc_board_revision_ops = {
    .read = msm5xxx_poc_board_revision_read,
    .write = msm5xxx_poc_board_revision_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

static uint64_t msm5xxx_poc_board_status_input_read(void *opaque,
                                                     hwaddr offset,
                                                     unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    return !offset && size == 1 ? s->board_status_input_backing : 0;
}

static void msm5xxx_poc_board_status_input_write(void *opaque, hwaddr offset,
                                                  uint64_t value,
                                                  unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (!offset && size == 1) {
        s->board_status_input_backing =
            (value & ~s->board_status_input_mask) |
            (s->board_status_input_backing & s->board_status_input_mask);
    }
}

static const MemoryRegionOps msm5xxx_poc_board_status_input_ops = {
    .read = msm5xxx_poc_board_status_input_read,
    .write = msm5xxx_poc_board_status_input_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
};

static uint64_t msm5xxx_poc_matrix_input_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUClass *cc = CPU_GET_CLASS(s->cpu);

    if (offset || size != 1) {
        return 0;
    }
    if (s->matrix_input_pressed &&
        s->matrix_input_row == MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW) {
        s->matrix_input_active_reads++;
        return s->matrix_input_backing & ~s->matrix_input_sense;
    }
    if (cc->get_pc(CPU(s->cpu)) == s->matrix_input_sense_site + 2) {
        uint8_t sense = s->matrix_input_no_key;

        if (s->matrix_input_pressed &&
            (s->cpu->env.regs[s->matrix_input_row_register] & 0xff) ==
            s->matrix_input_row) {
            sense = s->matrix_input_sense;
            s->matrix_input_active_reads++;
        }
        return (s->matrix_input_backing & 0xf0) | sense;
    }
    return s->matrix_input_backing;
}

static void msm5xxx_poc_matrix_input_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (!offset && size == 1) {
        s->matrix_input_backing = value;
    }
}

static const MemoryRegionOps msm5xxx_poc_matrix_input_ops = {
    .read = msm5xxx_poc_matrix_input_read,
    .write = msm5xxx_poc_matrix_input_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
};

static void msm5xxx_poc_audio_backend_callback(void *opaque, int available)
{
    MSM5xxxPOCMachineState *s = opaque;

    while (available > 0) {
        unsigned remaining;
        size_t written;

        if (s->audio_backend_pcm_offset == s->audio_backend_pcm_length) {
            size_t frames = MSM5XXX_AUDIO_CHUNK_FRAMES;

            qemu_mutex_lock(&s->audio_synth_lock);
            if (!msm5xxx_audio_synth_active(&s->audio_synth) &&
                s->audio_synth.ring_count < frames) {
                frames = s->audio_synth.ring_count;
            }
            if (frames != 0u) {
                msm5xxx_audio_synth_read(
                    &s->audio_synth, s->audio_backend_pcm, frames,
                    NULL, NULL, NULL);
            }
            qemu_mutex_unlock(&s->audio_synth_lock);
            memset(&s->audio_backend_pcm[frames], 0,
                   (MSM5XXX_AUDIO_CHUNK_FRAMES - frames) *
                   sizeof(s->audio_backend_pcm[0]));
            s->audio_backend_pcm_offset = 0u;
            s->audio_backend_pcm_length = sizeof(s->audio_backend_pcm);
        }
        remaining = s->audio_backend_pcm_length -
                    s->audio_backend_pcm_offset;
        remaining = MIN(remaining, (unsigned)available);
        written = AUD_write(s->audio_voice,
                            (uint8_t *)s->audio_backend_pcm +
                            s->audio_backend_pcm_offset,
                            remaining);
        if (written == 0u) {
            break;
        }
        s->audio_backend_pcm_offset += written;
        available -= written;
    }
}

static void msm5xxx_poc_audio_pcm_prepare(MSM5xxxPOCMachineState *s)
{
    int16_t pcm[MSM5XXX_AUDIO_CHUNK_FRAMES][2];
    uint64_t epoch;
    uint64_t sequence;
    uint64_t start_frame;
    size_t frame;

    if (s->audio_pcm_length || !s->audio_stream_chardev ||
        s->audio_stream_rejected || !s->audio_output_started) {
        return;
    }
    qemu_mutex_lock(&s->audio_synth_lock);
    if (s->audio_synth.ring_count < MSM5XXX_AUDIO_CHUNK_FRAMES) {
        qemu_mutex_unlock(&s->audio_synth_lock);
        return;
    }
    msm5xxx_audio_synth_read(&s->audio_synth, pcm,
                             MSM5XXX_AUDIO_CHUNK_FRAMES,
                             &epoch, &sequence, &start_frame);
    qemu_mutex_unlock(&s->audio_synth_lock);

    memcpy(s->audio_pcm_packet, "M5P2", 4u);
    msm5xxx_poc_backing_write(s->audio_pcm_packet, 4u, 2u, 4u);
    msm5xxx_poc_backing_write(s->audio_pcm_packet, 8u, epoch, 8u);
    msm5xxx_poc_backing_write(s->audio_pcm_packet, 16u, sequence, 8u);
    msm5xxx_poc_backing_write(s->audio_pcm_packet, 24u, start_frame, 8u);
    for (frame = 0u; frame < MSM5XXX_AUDIO_CHUNK_FRAMES; frame++) {
        msm5xxx_poc_backing_write(s->audio_pcm_packet,
                                  MSM5XXX_POC_AUDIO_PACKET_HEADER + frame * 4u,
                                  (uint16_t)pcm[frame][0], 2u);
        msm5xxx_poc_backing_write(s->audio_pcm_packet,
                                  MSM5XXX_POC_AUDIO_PACKET_HEADER +
                                  frame * 4u + 2u,
                                  (uint16_t)pcm[frame][1], 2u);
    }
    s->audio_pcm_length = sizeof(s->audio_pcm_packet);
    s->audio_pcm_offset = 0u;
}

static void msm5xxx_poc_audio_pcm_reject(MSM5xxxPOCMachineState *s)
{
    s->audio_pcm_length = 0u;
    s->audio_pcm_offset = 0u;
    s->audio_stream_rejected = true;
    s->audio_stream_status_pending = MSM5XXX_POC_AUDIO_STATUS_REJECTED;
    s->audio_output_started = false;
    qemu_mutex_lock(&s->audio_synth_lock);
    msm5xxx_audio_synth_resync(&s->audio_synth);
    qemu_mutex_unlock(&s->audio_synth_lock);
}

static int msm5xxx_poc_audio_pcm_flush(MSM5xxxPOCMachineState *s)
{
    int written;

    while (true) {
        msm5xxx_poc_audio_pcm_prepare(s);
        if (!s->audio_pcm_length) {
            return 1;
        }
        while (s->audio_pcm_offset < s->audio_pcm_length) {
            written = qemu_chr_fe_write(
                &s->audio_stream_chr,
                s->audio_pcm_packet + s->audio_pcm_offset,
                s->audio_pcm_length - s->audio_pcm_offset);
            if (written > 0) {
                s->audio_pcm_offset += written;
                continue;
            }
            if (written < 0 && errno == EAGAIN) {
                return 0;
            }
            return -1;
        }
        s->audio_pcm_length = 0u;
        s->audio_pcm_offset = 0u;
    }
}

static bool msm5xxx_poc_ma2_timbre(const MSM5xxxPOCMachineState *s,
                                   const MSM5xxxMA2FMChannel *channel,
                                   MSM5xxxAudioEvent *event)
{
    static const uint8_t descriptor[] = {
        16u, 0u, 0u, 1u, 1u, 5u,
        3u, 0u, 0u, 1u, 3u, 5u, 5u, 0u, 24u, 2u, 2u, 0u,
        2u, 0u, 7u, 0u, 0u, 0u,
        3u, 0u, 0u, 0u, 3u, 4u, 15u, 0u, 0u, 1u, 2u, 0u,
        2u, 0u, 1u, 0u, 0u, 0u,
        2u, 0u, 0u, 1u, 2u, 5u, 10u, 0u, 36u, 0u, 2u, 0u,
        2u, 0u, 13u, 0u, 0u, 0u,
        3u, 0u, 0u, 0u, 3u, 5u, 15u, 0u, 5u, 0u, 2u, 0u,
        2u, 0u, 1u, 0u, 0u, 0u,
    };
    static const uint8_t multiplier[] = {7u, 1u, 12u, 1u};
    static const uint8_t level[] = {24u, 0u, 36u, 5u};
    const MSM5xxxMA2FMVoice *voice;
    size_t index;

    if (!channel->key_on ||
        channel->active_voice_slot >= MSM5XXX_MA2_FM_VOICE_COUNT) {
        return false;
    }
    voice = &s->ma2_audio.fm_voice[channel->active_voice_slot];
    if (!voice->valid || voice->operator_count != 4u ||
        memcmp(voice->decoded, descriptor, sizeof(descriptor)) != 0) {
        return false;
    }

    /* ponytail: one proven descriptor; unmatched voices keep triangle. */
    event->timbre_valid = true;
    event->timbre_algorithm = 5u;
    event->timbre_operator_count = 4u;
    memcpy(event->timbre_multiplier, multiplier, sizeof(multiplier));
    memcpy(event->timbre_level, level, sizeof(level));
    for (index = 0u; index < MSM5XXX_AUDIO_TIMBRE_OPERATOR_COUNT; index++) {
        event->timbre_attack_step[index] = UINT32_C(0x0094f20a);
        event->timbre_decay_factor[index] = UINT32_C(0x40000000);
        event->timbre_sustain_factor[index] = UINT32_C(0x40000000);
        event->timbre_release_factor[index] = UINT32_C(0x3eb1aa70);
    }
    return true;
}

static bool msm5xxx_poc_ma2_synth_output(MSM5xxxPOCMachineState *s,
                                         const MSM5xxxMA2Output *output)
{
    const MSM5xxxMA2FMChannel *channel;
    MSM5xxxAudioEvent event;
    uint64_t timestamp_ns = output->timestamp_ns;

    if (output->stream >= MSM5XXX_MA2_FIFO_ADPCM_SEQUENCE ||
        output->channel >= MSM5XXX_MA2_FM_CHANNEL_COUNT) {
        return true;
    }
    channel = &s->ma2_audio.fm_channel[output->channel];
    memset(&event, 0, sizeof(event));
    event.voice_id = output->voice_id;
    event.channel = output->channel;
    event.note = output->note;
    event.velocity = 127u;
    event.volume = channel->volume;
    event.pan = channel->pan;
    event.expression = channel->expression;
    event.pitch_bend = channel->pitch_bend;
    if (output->kind == MSM5XXX_MA2_OUTPUT_GATE_OFF) {
        event.kind = MSM5XXX_AUDIO_EVENT_NOTE_OFF;
    } else if (output->kind == MSM5XXX_MA2_OUTPUT_EVENT &&
               output->event.kind == MSM5XXX_MA2_COMPACT_NOTE) {
        event.kind = MSM5XXX_AUDIO_EVENT_NOTE_ON;
        (void)msm5xxx_poc_ma2_timbre(s, channel, &event);
    } else if (output->kind == MSM5XXX_MA2_OUTPUT_EVENT &&
               output->event.kind == MSM5XXX_MA2_COMPACT_CONTROL) {
        event.kind = MSM5XXX_AUDIO_EVENT_CONTROL;
    } else {
        return true;
    }
    timestamp_ns = msm5xxx_audio_synth_clamp_event_timestamp(
        &s->audio_synth, timestamp_ns);
    return msm5xxx_audio_synth_event(&s->audio_synth, timestamp_ns, &event);
}

static bool msm5xxx_poc_ma2_synth_stop(MSM5xxxPOCMachineState *s)
{
    MSM5xxxAudioEvent event = {
        .kind = MSM5XXX_AUDIO_EVENT_ALL_OFF,
    };
    uint64_t timestamp_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    qemu_mutex_lock(&s->audio_synth_lock);
    if (s->audio_synth.clock_initialized &&
        timestamp_ns < s->audio_synth.clock_ns) {
        timestamp_ns = s->audio_synth.clock_ns;
    }
    if (!msm5xxx_audio_synth_event(&s->audio_synth, timestamp_ns, &event)) {
        qemu_mutex_unlock(&s->audio_synth_lock);
        return false;
    }
    qemu_mutex_unlock(&s->audio_synth_lock);
    return true;
}

static void msm5xxx_poc_ma2_pending_clear(MSM5xxxPOCMachineState *s)
{
    memset(s->audio_command_pending_read, 0,
           sizeof(s->audio_command_pending_read));
    memset(s->audio_command_pending_write, 0,
           sizeof(s->audio_command_pending_write));
    memset(s->audio_command_pending_count, 0,
           sizeof(s->audio_command_pending_count));
}

static bool msm5xxx_poc_ma2_pending_push(MSM5xxxPOCMachineState *s,
                                         unsigned fifo, uint8_t value)
{
    uint16_t write;

    if (fifo >= MSM5XXX_MA2_FM_FIFO_COUNT ||
        s->audio_command_pending_count[fifo] >=
        MSM5XXX_POC_AUDIO_COMMAND_QUEUE_CAPACITY) {
        return false;
    }
    write = s->audio_command_pending_write[fifo];
    s->audio_command_pending[fifo][write] = value;
    s->audio_command_pending_write[fifo] =
        (write + 1u) % MSM5XXX_POC_AUDIO_COMMAND_QUEUE_CAPACITY;
    s->audio_command_pending_count[fifo]++;
    return true;
}

static bool msm5xxx_poc_ma2_pending_refill(MSM5xxxPOCMachineState *s)
{
    uint8_t saved_index = s->ma2_audio.index;
    uint8_t saved_page = s->ma2_audio.page;
    unsigned fifo;
    bool moved = false;

    for (fifo = 0; fifo < MSM5XXX_MA2_FM_FIFO_COUNT; fifo++) {
        while (s->audio_command_pending_count[fifo] &&
               msm5xxx_ma2_fifo_occupancy(
                   &s->ma2_audio, (MSM5xxxMA2Fifo)fifo) <
               msm5xxx_ma2_fifo_capacity((MSM5xxxMA2Fifo)fifo)) {
            uint16_t read = s->audio_command_pending_read[fifo];

            s->ma2_audio.page = MSM5XXX_MA2_PAGE_REG0;
            s->ma2_audio.index = fifo;
            if (!msm5xxx_ma2_data_write(
                    &s->ma2_audio,
                    s->audio_command_pending[fifo][read])) {
                s->ma2_audio.page = saved_page;
                s->ma2_audio.index = saved_index;
                return false;
            }
            s->audio_command_pending_read[fifo] =
                (read + 1u) % MSM5XXX_POC_AUDIO_COMMAND_QUEUE_CAPACITY;
            s->audio_command_pending_count[fifo]--;
            moved = true;
        }
    }
    s->ma2_audio.page = saved_page;
    s->ma2_audio.index = saved_index;
    return moved;
}

static void msm5xxx_poc_ma2_audio_tick(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    MSM5xxxMA2Output output;
    uint64_t deadline;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    qemu_mutex_lock(&s->audio_core_lock);
    if (s->audio_pcm_failed) {
        s->audio_pcm_failed = false;
        msm5xxx_poc_audio_pcm_reject(s);
        qemu_mutex_unlock(&s->audio_core_lock);
        return;
    }
    for (;;) {
        if (!msm5xxx_poc_ma2_pending_refill(s) &&
            msm5xxx_ma2_rejected(&s->ma2_audio)) {
            s->audio_stream_reject_code =
                msm5xxx_ma2_reject_reason(&s->ma2_audio);
            s->ma2_audio_timer_rejected = true;
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending =
                MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            qemu_mutex_unlock(&s->audio_core_lock);
            return;
        }
        if (!msm5xxx_ma2_scheduler_step(&s->ma2_audio, now, &output)) {
            if (!s->audio_stream_reject_code) {
                s->audio_stream_reject_code =
                    msm5xxx_ma2_reject_reason(&s->ma2_audio) |
                    ((uint32_t)s->ma2_audio.page << 8) |
                    ((uint32_t)s->ma2_audio.index << 16) |
                    ((uint32_t)s->ma2_audio.control << 24);
            }
            s->ma2_audio_timer_rejected = true;
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending =
                MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            qemu_mutex_unlock(&s->audio_core_lock);
            return;
        }
        switch (output.kind) {
        case MSM5XXX_MA2_OUTPUT_EVENT:
            s->ma2_audio_events++;
            break;
        case MSM5XXX_MA2_OUTPUT_GATE_OFF:
            s->ma2_audio_gate_offs++;
            break;
        case MSM5XXX_MA2_OUTPUT_END:
            s->ma2_audio_ends++;
            break;
        case MSM5XXX_MA2_OUTPUT_NONE:
            break;
        }
        if (output.kind != MSM5XXX_MA2_OUTPUT_NONE) {
            if (s->audio_pcm_enabled) {
                qemu_mutex_lock(&s->audio_synth_lock);
                if (!msm5xxx_poc_ma2_synth_output(s, &output)) {
                    qemu_mutex_unlock(&s->audio_synth_lock);
                    s->ma2_audio_timer_rejected = true;
                    s->audio_stream_reject_code =
                        MSM5XXX_POC_AUDIO_REJECT_SYNTH_EVENT;
                    s->audio_stream_rejected = true;
                    s->audio_stream_status_pending =
                        MSM5XXX_POC_AUDIO_STATUS_REJECTED;
                    qemu_mutex_unlock(&s->audio_core_lock);
                    return;
                }
                qemu_mutex_unlock(&s->audio_synth_lock);
            }
        } else if (!msm5xxx_poc_ma2_pending_refill(s)) {
            break;
        }
    }

    if (s->audio_pcm_enabled) {
        qemu_mutex_lock(&s->audio_synth_lock);
        if (!msm5xxx_audio_synth_advance(&s->audio_synth, now)) {
            qemu_mutex_unlock(&s->audio_synth_lock);
            s->ma2_audio_timer_rejected = true;
            s->audio_stream_reject_code = MSM5XXX_POC_AUDIO_REJECT_SYNTH_CLOCK;
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending = MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            qemu_mutex_unlock(&s->audio_core_lock);
            return;
        }
        if (!s->audio_output_started &&
            s->audio_synth.ring_count >= MSM5XXX_AUDIO_TARGET_FRAMES) {
            if (s->audio_stream_chardev) {
                s->audio_output_started = true;
            } else if (s->audio_voice) {
                s->audio_output_started = true;
                AUD_set_active_out(s->audio_voice, true);
            }
        }
        qemu_mutex_unlock(&s->audio_synth_lock);
        if (s->audio_stream_chardev && !s->audio_stream_rejected &&
            msm5xxx_poc_audio_pcm_flush(s) < 0) {
            s->audio_pcm_failed = true;
        }
    }

    if (msm5xxx_ma2_scheduler_next_deadline(&s->ma2_audio, &deadline)) {
        if (deadline > INT64_MAX) {
            s->ma2_audio_timer_rejected = true;
            s->audio_stream_reject_code = MSM5XXX_POC_AUDIO_REJECT_DEADLINE;
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending =
                MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            qemu_mutex_unlock(&s->audio_core_lock);
            return;
        }
    } else {
        deadline = UINT64_MAX;
    }
    if (s->audio_pcm_enabled) {
        qemu_mutex_lock(&s->audio_synth_lock);
        if ((msm5xxx_audio_synth_active(&s->audio_synth) ||
             (s->audio_output_started && s->audio_stream_chardev)) &&
            now <= UINT64_MAX - 10000000u) {
            deadline = MIN(deadline, now + 10000000u);
        }
        qemu_mutex_unlock(&s->audio_synth_lock);
    }
    qemu_mutex_unlock(&s->audio_core_lock);
    if (deadline != UINT64_MAX) {
        timer_mod_ns(s->ma2_audio_timer, deadline);
    }
}

static void msm5xxx_poc_ma2_audio_kick(MSM5xxxPOCMachineState *s)
{
    bool rejected;
    bool stream_rejected;

    qemu_mutex_lock(&s->audio_core_lock);
    rejected = msm5xxx_ma2_rejected(&s->ma2_audio);
    stream_rejected = s->audio_stream_rejected;
    qemu_mutex_unlock(&s->audio_core_lock);
    if (s->ma2_audio_timer && !s->ma2_audio_timer_rejected && !rejected &&
        !stream_rejected) {
        timer_mod_ns(s->ma2_audio_timer,
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
}

static bool msm5xxx_poc_audio_site_owned(const MSM5xxxPOCMachineState *s,
                                         bool write, hwaddr offset,
                                         uint32_t pc)
{
    unsigned index;

    for (index = 0; index < s->audio_site_count; index++) {
        if (s->audio_site_write[index] == write &&
            s->audio_site_port[index] == offset &&
            s->audio_site_pc[index] == pc) {
            return true;
        }
    }
    return false;
}

static MemTxResult msm5xxx_poc_audio_opaque_read(
    void *opaque, hwaddr offset, uint64_t *value, unsigned size,
    MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUState *cpu = current_cpu;
    CPUClass *cc;
    uint32_t pc;

    (void)attrs;
    if (size != 1 || (offset != 0 && offset != s->audio_data_offset) ||
        !qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running ||
        !cpu->neg.can_do_io) {
        return MEMTX_ERROR;
    }
    cc = CPU_GET_CLASS(cpu);
    pc = cc->get_pc(cpu) & ~1U;
    if (!s->audio_sites_enabled ||
        !msm5xxx_poc_audio_site_owned(s, false, offset, pc)) {
        return MEMTX_ERROR;
    }
    *value = 0;
    return MEMTX_OK;
}

static MemTxResult msm5xxx_poc_audio_opaque_write(
    void *opaque, hwaddr offset, uint64_t value, unsigned size,
    MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUState *cpu = current_cpu;
    CPUClass *cc;
    uint32_t pc;

    (void)attrs;
    if (size != 1 || (offset != 0 && offset != s->audio_data_offset) ||
        !qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running ||
        !cpu->neg.can_do_io) {
        return MEMTX_ERROR;
    }
    cc = CPU_GET_CLASS(cpu);
    pc = cc->get_pc(cpu) & ~1U;
    if (!s->audio_sites_enabled ||
        !msm5xxx_poc_audio_site_owned(s, true, offset, pc)) {
        return MEMTX_ERROR;
    }
    s->audio_backing[offset] = value;
    return MEMTX_OK;
}

static const MemoryRegionOps msm5xxx_poc_audio_opaque_ops = {
    .read_with_attrs = msm5xxx_poc_audio_opaque_read,
    .write_with_attrs = msm5xxx_poc_audio_opaque_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
    .impl.min_access_size = 1,
    .impl.max_access_size = 1,
};

static bool msm5xxx_poc_audio_write_owned(MSM5xxxPOCMachineState *s,
                                          hwaddr offset, uint64_t value,
                                          unsigned size)
{
    CPUState *cpu = current_cpu;
    CPUClass *cc;
    uint32_t pc = 0;
    bool in_vcpu;
    bool native_site;
    bool accepted = false;
    bool reject_telemetry = false;
    uint8_t selected_page = 0;
    uint8_t selected_index = 0;
    uint8_t selected_control = 0;

    if (size != 1 || offset > s->audio_data_offset) {
        return false;
    }
    in_vcpu = qemu_in_vcpu_thread() && cpu == CPU(s->cpu) && cpu->running &&
               cpu->neg.can_do_io;
    if (in_vcpu) {
        cc = CPU_GET_CLASS(cpu);
        pc = cc->get_pc(cpu) & ~1U;
    }
    native_site = in_vcpu && s->audio_sites_enabled &&
                  msm5xxx_poc_audio_site_owned(s, true, offset, pc);
    if (!native_site) {
        return false;
    }
    s->audio_backing[offset] = value;
    qemu_mutex_lock(&s->audio_core_lock);
    if (s->audio_ma2) {
        selected_page = s->ma2_audio.page;
        selected_index = s->ma2_audio.index;
        selected_control = s->ma2_audio.control;
    }
    if (s->audio_ma2 && !msm5xxx_ma2_rejected(&s->ma2_audio) && !offset) {
        s->audio_index = value;
        accepted = msm5xxx_ma2_index_write(&s->ma2_audio, value);
    } else if (s->audio_ma2 && !msm5xxx_ma2_rejected(&s->ma2_audio) &&
               offset == s->audio_data_offset) {
        if (s->ma2_audio.page == MSM5XXX_MA2_PAGE_REG0 &&
            s->ma2_audio.index < MSM5XXX_MA2_FM_FIFO_COUNT &&
            (s->audio_command_pending_count[s->ma2_audio.index] ||
             msm5xxx_ma2_fifo_occupancy(
                 &s->ma2_audio,
                 (MSM5xxxMA2Fifo)s->ma2_audio.index) >=
             msm5xxx_ma2_fifo_capacity(
                 (MSM5xxxMA2Fifo)s->ma2_audio.index))) {
            accepted = msm5xxx_poc_ma2_pending_push(
                s, s->ma2_audio.index, value
            );
            if (!accepted) {
                s->audio_stream_reject_code =
                    MSM5XXX_POC_AUDIO_REJECT_COMMAND_QUEUE;
                s->audio_stream_rejected = true;
                s->audio_stream_status_pending =
                    MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            }
        } else {
            bool clear_fm =
                s->ma2_audio.page == MSM5XXX_MA2_PAGE_REG1 &&
                s->ma2_audio.index == MSM5XXX_MA2_FIFO_CONTROL &&
                (value & MSM5XXX_MA2_FM_FIFO_CLEAR);

            accepted = msm5xxx_ma2_data_write(&s->ma2_audio, value);
            if (accepted && msm5xxx_ma2_take_fm_stop(&s->ma2_audio) &&
                s->audio_pcm_enabled &&
                !msm5xxx_poc_ma2_synth_stop(s)) {
                accepted = false;
                s->audio_stream_reject_code =
                    MSM5XXX_POC_AUDIO_REJECT_SYNTH_EVENT;
                s->audio_stream_rejected = true;
                s->audio_stream_status_pending =
                    MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            }
            if (accepted && clear_fm) {
                msm5xxx_poc_ma2_pending_clear(s);
            }
        }
    }
    if (!accepted && s->audio_ma2 &&
        msm5xxx_ma2_rejected(&s->ma2_audio)) {
        reject_telemetry = !s->audio_stream_rejected;
        s->audio_stream_reject_code =
            msm5xxx_ma2_reject_reason(&s->ma2_audio) |
            ((uint32_t)s->ma2_audio.fifo_count[0] << 8) |
            ((uint32_t)s->ma2_audio.fifo_count[1] << 16) |
            ((uint32_t)s->ma2_audio.fifo_count[2] << 24);
        s->audio_stream_rejected = true;
        s->audio_stream_status_pending =
            MSM5XXX_POC_AUDIO_STATUS_REJECTED;
    }
    qemu_mutex_unlock(&s->audio_core_lock);
    if (accepted) {
        msm5xxx_poc_ma2_audio_kick(s);
    }
    s->audio_stream_started = true;
    s->audio_stream_order++;
    if (reject_telemetry && s->lcd_trace_buffer) {
        msm5xxx_poc_lcd_stream_append(
            s, MSM5XXX_POC_AUDIO_REJECT_TELEMETRY, selected_control, pc,
            s->audio_stream_order,
            (uint32_t)offset | ((uint32_t)(value & UINT8_MAX) << 8) |
            ((uint32_t)selected_page << 16) |
            ((uint32_t)selected_index << 24));
    }
    if (s->audio_stream_rejected) {
        if (s->audio_stream_dropped != UINT32_MAX) {
            s->audio_stream_dropped++;
        }
        return true;
    }
    if (!s->lcd_trace_buffer || !msm5xxx_poc_lcd_stream_append(
            s, MSM5XXX_POC_AUDIO_STREAM_WRITE, size, pc,
            offset | ((value & UINT8_MAX) << 8),
            s->audio_stream_order)) {
        s->audio_stream_rejected = true;
        s->audio_stream_dropped = 1;
        s->audio_stream_status_pending = MSM5XXX_POC_AUDIO_STATUS_OVERFLOW;
    }
    return true;
}

static bool msm5xxx_poc_audio_read_owned(MSM5xxxPOCMachineState *s,
                                         hwaddr offset, unsigned size,
                                         uint64_t *value)
{
    CPUState *cpu = current_cpu;
    CPUClass *cc;
    uint8_t data;
    uint32_t pc;

    if (size != 1 || offset != s->audio_data_offset || !s->audio_ma2 ||
        !qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running ||
        !cpu->neg.can_do_io) {
        return false;
    }
    cc = CPU_GET_CLASS(cpu);
    pc = cc->get_pc(cpu) & ~1U;
    if (!s->audio_sites_enabled ||
        !msm5xxx_poc_audio_site_owned(s, false, offset, pc)) {
        return false;
    }
    qemu_mutex_lock(&s->audio_core_lock);
    if (s->ma2_audio.page == MSM5XXX_MA2_PAGE_REG0 &&
        (s->ma2_audio.index <= MSM5XXX_MA2_ADPCM_WAVE_DATA ||
         s->ma2_audio.index == MSM5XXX_MA2_STATUS1 ||
         s->ma2_audio.index == MSM5XXX_MA2_WAVE_STATUS)) {
        qemu_mutex_unlock(&s->audio_core_lock);
        return false;
    }
    if (!msm5xxx_ma2_data_read(&s->ma2_audio, &data)) {
        if (msm5xxx_ma2_rejected(&s->ma2_audio)) {
            s->audio_stream_reject_code =
                msm5xxx_ma2_reject_reason(&s->ma2_audio) |
                ((uint32_t)s->ma2_audio.page << 8) |
                ((uint32_t)s->ma2_audio.index << 16) |
                ((uint32_t)s->ma2_audio.control << 24);
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending =
                MSM5XXX_POC_AUDIO_STATUS_REJECTED;
        }
        qemu_mutex_unlock(&s->audio_core_lock);
        return false;
    }
    *value = data;
    qemu_mutex_unlock(&s->audio_core_lock);
    return true;
}

static bool msm5xxx_poc_arm_b_target(uint32_t word, uint32_t address,
                                    uint32_t *target)
{
    uint32_t displacement;

    if ((word & 0xff000000) != 0xea000000) {
        return false;
    }
    displacement = (word & 0x00ffffff) << 2;
    if (displacement & (1U << 25)) {
        displacement -= 1U << 26;
    }
    *target = address + 8 + displacement;
    return true;
}

static uint32_t msm5xxx_poc_guest_u32(hwaddr address)
{
    uint32_t value;

    cpu_physical_memory_read(address, &value, sizeof(value));
    return le32_to_cpu(value);
}

static bool msm5xxx_poc_rex_static_gate(MSM5xxxPOCMachineState *s)
{
    uint32_t target;

    s->rex_irq_gate_attempts++;
    if (!msm5xxx_poc_arm_b_target(msm5xxx_poc_guest_u32(0x18), 0x18,
                                  &target) ||
        target != s->rex_irq_vector_target) {
        s->rex_irq_gate_status = MSM5XXX_POC_REX_GATE_VECTOR_WAIT;
        return false;
    }
    if (!msm5xxx_poc_arm_b_target(msm5xxx_poc_guest_u32(target), target,
                                  &target) ||
        target != s->rex_irq_wrapper_address) {
        s->rex_irq_gate_status = MSM5XXX_POC_REX_GATE_WRAPPER_WAIT;
        return false;
    }
    if (msm5xxx_poc_guest_u32(s->rex_irq_handler_slot) !=
        (s->rex_irq_handler_address | 1)) {
        s->rex_irq_gate_status = MSM5XXX_POC_REX_GATE_HANDLER_WAIT;
        return false;
    }
    if (msm5xxx_poc_guest_u32(s->rex_irq_callback_slot) !=
        (s->rex_irq_callback_address | 1)) {
        s->rex_irq_gate_status = MSM5XXX_POC_REX_GATE_CALLBACK_WAIT;
        return false;
    }
    s->rex_irq_route_active = true;
    s->rex_irq_gate_status = MSM5XXX_POC_REX_GATE_ACCEPTED;
    return true;
}

static bool msm5xxx_poc_rex_irq_shadow_active(MSM5xxxPOCMachineState *s)
{
    CPUState *cpu = current_cpu;
    CPUClass *cc;
    uint32_t pc;

    if (!s->rex_irq_c80) {
        return true;
    }
    if (!s->rex_irq_route_active) {
        return false;
    }
    if (!qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running ||
        !cpu->neg.can_do_io) {
        return false;
    }
    cc = CPU_GET_CLASS(cpu);
    pc = cc->get_pc(cpu) & ~1U;
    return pc >= s->rex_irq_handler_address &&
           pc < s->rex_irq_handler_address + s->rex_irq_handler_size;
}

static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s)
{
    hwaddr offset = s->rex_irq_enable_address - s->rex_irq_status_address;
    uint16_t enabled = msm5xxx_poc_backing_read(
        s->rex_irq_backing, offset, 2
    );
    bool level = (!s->rex_irq_c80 || s->rex_irq_route_active) &&
                 enabled & s->rex_irq_pending[0];

    if (level && !s->rex_irq_level) {
        s->rex_irq_assertions++;
    }
    s->rex_irq_level = level;
    qemu_set_irq(s->cpu_irq, s->irq_level || s->rex_irq_level);
}

static void msm5xxx_poc_rex_irq_schedule(MSM5xxxPOCMachineState *s)
{
    int64_t now;

    if (!s->rex_irq_armed || s->rex_irq_pending[0] & s->rex_irq_mask) {
        return;
    }
    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    timer_mod(s->rex_irq_timer, MAX(now, s->rex_irq_next));
}

static void msm5xxx_poc_rex_irq_tick(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint32_t pc;

    if (!s->rex_irq_armed || s->rex_irq_pending[0] & s->rex_irq_mask) {
        return;
    }
    if (s->rex_irq_c80 && !s->rex_irq_route_active) {
        msm5xxx_poc_rex_static_gate(s);
        s->rex_irq_next = now + s->rex_irq_interval;
        msm5xxx_poc_rex_irq_schedule(s);
        return;
    }
    if (s->rex_idle_address && !s->rex_idle_seen) {
        pc = s->cpu->env.regs[15];
        s->rex_idle_gate_pc = pc;
        if (pc != s->rex_idle_address) {
            s->rex_irq_next = now + s->rex_irq_interval;
            msm5xxx_poc_rex_irq_schedule(s);
            return;
        }
        s->rex_idle_seen = true;
    }
    s->rex_irq_pending[0] |= s->rex_irq_mask;
    s->rex_irq_ticks++;
    s->rex_irq_next = now + s->rex_irq_interval;
    msm5xxx_poc_rex_irq_update(s);
}

static const hwaddr msm5xxx_poc_rex_irq_status_offsets[] = {
    0, 4, 0x30,
};

static const hwaddr msm5xxx_poc_rex_irq_clear_offsets[] = {
    0, 4, 0x4c,
};

static uint64_t msm5xxx_poc_rex_irq_read(void *opaque, hwaddr offset,
                                         unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t value;
    bool shadow;
    bool touched = false;
    bool consumed = false;
    unsigned i;

    if (offset + size > s->rex_irq_controller_size) {
        return 0;
    }
    shadow = msm5xxx_poc_rex_irq_shadow_active(s);
    value = msm5xxx_poc_backing_read(s->rex_irq_backing, offset, size);
    if (!shadow) {
        return value;
    }
    if (!s->rex_irq_read_consume) {
        for (i = 0; i < s->rex_irq_bank_count; i++) {
            msm5xxx_poc_backing_write(
                s->rex_irq_backing, msm5xxx_poc_rex_irq_status_offsets[i],
                s->rex_irq_pending[i], 2
            );
        }
        return msm5xxx_poc_backing_read(s->rex_irq_backing, offset, size);
    }
    for (i = 0; i < size; i++) {
        hwaddr byte = offset + i;
        unsigned bank;

        for (bank = 0; bank < s->rex_irq_bank_count; bank++) {
            hwaddr status = msm5xxx_poc_rex_irq_status_offsets[bank];

            if (byte >= status && byte < status + 2) {
                uint8_t pending =
                    s->rex_irq_pending[bank] >> ((byte - status) * 8);

                value &= ~(UINT64_C(0xff) << (i * 8));
                value |= (uint64_t)pending << (i * 8);
                break;
            }
        }
    }
    for (i = 0; i < s->rex_irq_bank_count; i++) {
        hwaddr status = msm5xxx_poc_rex_irq_status_offsets[i];

        if (offset < status + 2 && offset + size > status) {
            touched = true;
            consumed |= s->rex_irq_pending[i] != 0;
            s->rex_irq_pending[i] = 0;
        }
    }
    if (consumed) {
        s->rex_irq_acks++;
    }
    if (touched) {
        msm5xxx_poc_rex_irq_update(s);
        msm5xxx_poc_rex_irq_schedule(s);
    }
    return value;
}

static void msm5xxx_poc_rex_irq_write(void *opaque, hwaddr offset,
                                      uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    unsigned i;
    uint16_t pending_before = s->rex_irq_pending[0];

    if (offset + size > s->rex_irq_controller_size) {
        return;
    }
    if (!msm5xxx_poc_rex_irq_shadow_active(s) || s->rex_irq_read_consume) {
        msm5xxx_poc_backing_write(s->rex_irq_backing, offset, value, size);
        msm5xxx_poc_rex_irq_update(s);
        return;
    }
    for (i = 0; i < size; i++) {
        hwaddr byte = offset + i;
        uint8_t incoming = value >> (i * 8);
        unsigned bank;
        bool clear = false;

        for (bank = 0; bank < s->rex_irq_bank_count; bank++) {
            hwaddr status = msm5xxx_poc_rex_irq_clear_offsets[bank];

            if (byte >= status && byte < status + 2) {
                s->rex_irq_pending[bank] &=
                    ~((uint16_t)incoming << ((byte - status) * 8));
                clear = true;
                break;
            }
        }
        if (!clear) {
            s->rex_irq_backing[byte] = incoming;
        }
    }
    if (pending_before & s->rex_irq_mask &&
        !(s->rex_irq_pending[0] & s->rex_irq_mask)) {
        s->rex_irq_acks++;
    }
    msm5xxx_poc_rex_irq_update(s);
    msm5xxx_poc_rex_irq_schedule(s);
}

static uint64_t msm5xxx_poc_rex_irq_arm_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    return !offset && size == 1 ? s->rex_irq_arm_backing : 0;
}

static void msm5xxx_poc_rex_irq_arm_write(void *opaque, hwaddr offset,
                                           uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset || size != 1) {
        return;
    }
    s->rex_irq_arm_backing = value;
    if (value == 0x02 && !s->rex_irq_armed) {
        s->rex_irq_armed = true;
        s->rex_irq_next = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          s->rex_irq_interval;
        msm5xxx_poc_rex_irq_schedule(s);
    }
}

static const MemoryRegionOps msm5xxx_poc_rex_irq_ops = {
    .read = msm5xxx_poc_rex_irq_read,
    .write = msm5xxx_poc_rex_irq_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

static const MemoryRegionOps msm5xxx_poc_rex_irq_arm_ops = {
    .read = msm5xxx_poc_rex_irq_arm_read,
    .write = msm5xxx_poc_rex_irq_arm_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
};

static void msm5xxx_poc_eeprom_gpio_update(MSM5xxxPOCMachineState *s)
{
    bool output = s->eeprom_gpio_backing[s->eeprom_direction_offset] &
                  s->eeprom_data_mask;
    bool data = !output ||
                (s->eeprom_gpio_backing[s->eeprom_data_offset] &
                 s->eeprom_data_mask);
    bool clock = s->eeprom_gpio_backing[s->eeprom_clock_offset] &
                 s->eeprom_clock_mask;

    s->eeprom_sda = bitbang_i2c_set(
        &s->eeprom_i2c, BITBANG_I2C_SDA, data
    );
    s->eeprom_sda = bitbang_i2c_set(
        &s->eeprom_i2c, BITBANG_I2C_SCL, clock
    );
}

static uint64_t msm5xxx_poc_eeprom_gpio_read(void *opaque, hwaddr offset,
                                             unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t value;

    if (offset + size > MSM5XXX_POC_EEPROM_GPIO_SIZE) {
        return 0;
    }
    value = msm5xxx_poc_backing_read(s->eeprom_gpio_backing, offset, size);
    if (offset <= s->eeprom_data_offset &&
        s->eeprom_data_offset < offset + size) {
        unsigned shift = (s->eeprom_data_offset - offset) * 8;

        value &= ~((uint64_t)s->eeprom_data_mask << shift);
        if (s->eeprom_sda) {
            value |= (uint64_t)s->eeprom_data_mask << shift;
        }
    }
    return value;
}

static void msm5xxx_poc_eeprom_gpio_write(void *opaque, hwaddr offset,
                                          uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset + size > MSM5XXX_POC_EEPROM_GPIO_SIZE) {
        return;
    }
    msm5xxx_poc_backing_write(s->eeprom_gpio_backing, offset, value, size);
    msm5xxx_poc_eeprom_gpio_update(s);
}

static const MemoryRegionOps msm5xxx_poc_eeprom_gpio_ops = {
    .read = msm5xxx_poc_eeprom_gpio_read,
    .write = msm5xxx_poc_eeprom_gpio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

static uint16_t msm5xxx_poc_sbi_status_value(MSM5xxxPOCMachineState *s)
{
    return ((s->sbi_control & 0x00c0) << 8) |
           ((s->sbi_control & 0x003f) << 8) |
           ((s->sbi_control & 0x0600) >> 3) |
           ((s->sbi_control & 0x0800) >> 6) |
           (s->sbi_read_full ? 0x02 : 0);
}

static void msm5xxx_poc_sbi_reject(MSM5xxxPOCMachineState *s)
{
    s->sbi_status = MSM5XXX_POC_SBI_REJECTED;
    s->sbi_read_pending = false;
    s->sbi_read_full = false;
}

static uint64_t msm5xxx_poc_sbi_read(void *opaque, hwaddr offset,
                                     unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t backing;
    bool became_accepted = false;

    if (offset + size > MSM5XXX_POC_SBI_SIZE) {
        return 0;
    }
    s->sbi_reads++;
    backing = msm5xxx_poc_backing_read(s->sbi_backing, offset, size);

    if (s->sbi_status == MSM5XXX_POC_SBI_CANDIDATE) {
        if (offset != 0 || size != 2) {
            msm5xxx_poc_sbi_reject(s);
            return backing;
        }
        if (s->sbi_validation_phase == 0) {
            s->sbi_validation_phase = 1;
        } else if (s->sbi_validation_phase == 2) {
            s->sbi_status = MSM5XXX_POC_SBI_ACCEPTED;
            s->sbi_validation_phase = 3;
            became_accepted = true;
        } else {
            msm5xxx_poc_sbi_reject(s);
            return backing;
        }
    }

    if (s->sbi_bootstrap_only &&
        s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED && !became_accepted) {
        msm5xxx_poc_sbi_reject(s);
        return backing;
    }

    if (offset == 0 && size == 2 &&
        (s->sbi_status == MSM5XXX_POC_SBI_CANDIDATE ||
         s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED)) {
        if (s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED) {
            if (s->sbi_board_adc_phase == 4 ||
                s->sbi_board_adc_phase == 6 ||
                s->sbi_board_adc_phase == 8) {
                s->sbi_board_adc_phase++;
            } else if (s->sbi_board_adc_phase != 5 &&
                       s->sbi_board_adc_phase != 7 &&
                       s->sbi_board_adc_phase != 9) {
                s->sbi_board_adc_phase = 0;
            }
        }
        return msm5xxx_poc_sbi_status_value(s);
    }
    if (offset == 0x0c && size == 2 &&
        s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED) {
        if (s->sbi_board_adc_phase == 9 && s->board_adc_value <= UINT8_MAX) {
            backing = (backing & 0xff00) | s->board_adc_value;
            s->sbi_board_adc_responses++;
        }
        s->sbi_board_adc_phase = 0;
        s->sbi_board_adc_selector = 0;
        s->sbi_read_full = false;
    }
    return backing;
}

static void msm5xxx_poc_sbi_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{
    static const hwaddr bootstrap_offsets[] = { 0, 0, 4, 0x0c, 0x10, 0x10 };
    static const unsigned bootstrap_sizes[] = { 1, 1, 2, 2, 1, 1 };
    static const uint16_t bootstrap_values[] = {
        0x45, 0xc5, 0x085f, 0x041f, 0, 1,
    };
    MSM5xxxPOCMachineState *s = opaque;
    bool became_candidate = false;
    bool first_event;

    if (offset + size > MSM5XXX_POC_SBI_SIZE) {
        return;
    }
    s->sbi_writes++;
    first_event = offset == bootstrap_offsets[0] &&
                  size == bootstrap_sizes[0] &&
                  value == bootstrap_values[0];
    if (s->sbi_status == MSM5XXX_POC_SBI_OBSERVING) {
        unsigned phase = s->sbi_bootstrap_phase;

        if (offset == bootstrap_offsets[phase] &&
            size == bootstrap_sizes[phase] &&
            value == bootstrap_values[phase]) {
            if (++s->sbi_bootstrap_phase == G_N_ELEMENTS(bootstrap_offsets)) {
                s->sbi_status = MSM5XXX_POC_SBI_CANDIDATE;
                became_candidate = true;
            }
        } else {
            s->sbi_bootstrap_phase = first_event;
        }
    }

    if (s->sbi_status == MSM5XXX_POC_SBI_CANDIDATE && !became_candidate) {
        if (s->sbi_validation_phase == 1 &&
            offset == 0x0c && size == 2 && value == 0x0900) {
            s->sbi_validation_phase = 2;
        } else {
            msm5xxx_poc_sbi_reject(s);
        }
    }

    msm5xxx_poc_backing_write(s->sbi_backing, offset, value, size);
    if (s->sbi_bootstrap_only &&
        s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED) {
        msm5xxx_poc_sbi_reject(s);
        return;
    }
    if (offset == 4 && size == 2) {
        s->sbi_control = value & 0x0fff;
        s->sbi_board_adc_selector = 0;
        s->sbi_board_adc_phase =
            s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED && value == 0x086a;
    } else if (offset == 0x0c && size == 2 &&
               s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED) {
        if (s->sbi_board_adc_phase == 1 &&
            (value & 0xff80) == 0x0a80) {
            s->sbi_board_adc_selector = value;
            s->sbi_board_adc_phase++;
        } else if ((s->sbi_board_adc_phase == 5 &&
                    value == (s->sbi_board_adc_selector & ~0x0080)) ||
                   (s->sbi_board_adc_phase == 7 && value == 0x8b00)) {
            s->sbi_board_adc_phase++;
        } else {
            s->sbi_board_adc_phase = 0;
        }
        s->sbi_read_pending = value & 0x8000;
        if (s->sbi_read_pending && s->sbi_started) {
            s->sbi_read_pending = false;
            s->sbi_read_full = true;
        }
    } else if (offset == 0x10 && size == 1) {
        if ((s->sbi_board_adc_phase == 2 && value == 0) ||
            (s->sbi_board_adc_phase == 3 && value == 1)) {
            s->sbi_board_adc_phase++;
        } else {
            s->sbi_board_adc_phase = 0;
        }
        s->sbi_started = value & 1;
        if (s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED &&
            s->sbi_started && s->sbi_read_pending) {
            s->sbi_read_pending = false;
            s->sbi_read_full = true;
        }
    }
}

static const MemoryRegionOps msm5xxx_poc_sbi_ops = {
    .read = msm5xxx_poc_sbi_read,
    .write = msm5xxx_poc_sbi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 2,
    .impl.min_access_size = 1,
    .impl.max_access_size = 2,
};

static uint64_t msm5xxx_poc_dc0_read(void *opaque, hwaddr offset,
                                     unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset + size > MSM5XXX_POC_DC0_SIZE) {
        return 0;
    }
    return msm5xxx_poc_backing_read(s->dc0_backing, offset, size);
}

static void msm5xxx_poc_dc0_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset + size > MSM5XXX_POC_DC0_SIZE) {
        return;
    }
    msm5xxx_poc_backing_write(s->dc0_backing, offset, value, size);
    if (size != 2) {
        return;
    }
    if (offset == 0) {
        s->dc0_board_adc_phase = value == 0x887e;
    } else if (offset == MSM5XXX_POC_DC0_DATA_OFFSET) {
        s->dc0_board_adc_phase =
            s->dc0_board_adc_phase == 1 && value == 0xb200 ? 2 : 0;
    } else if (offset == MSM5XXX_POC_DC0_START_OFFSET) {
        if (s->dc0_board_adc_phase == 2 && value == 0) {
            s->dc0_board_adc_phase = 3;
        } else if (s->dc0_board_adc_phase == 3 && value == 1) {
            msm5xxx_poc_backing_write(
                s->dc0_backing, MSM5XXX_POC_DC0_DATA_OFFSET,
                0xb200 | s->dc0_board_adc_value, 2
            );
            s->dc0_board_adc_phase = 0;
            s->dc0_board_adc_responses++;
        } else {
            s->dc0_board_adc_phase = 0;
        }
    }
}

static const MemoryRegionOps msm5xxx_poc_dc0_ops = {
    .read = msm5xxx_poc_dc0_read,
    .write = msm5xxx_poc_dc0_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 2,
    .impl.min_access_size = 1,
    .impl.max_access_size = 2,
};

static void msm5xxx_poc_lcd_trace_write(MSM5xxxPOCMachineState *s,
                                        hwaddr address, uint64_t value,
                                        unsigned size)
{
    CPUState *cpu = current_cpu;
    uint8_t record[MSM5XXX_POC_LCD_TRACE_RECORD_SIZE] = { 0 };
    uint32_t caller_lr = 0;

    if (!s->lcd_trace_enabled && !s->lcd_trace_buffer) {
        return;
    }
    if (qemu_in_vcpu_thread() && cpu == CPU(s->cpu) && cpu->running &&
        cpu->neg.can_do_io) {
        caller_lr = s->cpu->env.regs[14];
    }
    msm5xxx_poc_backing_write(record, 0, address, 4);
    msm5xxx_poc_backing_write(record, 4, value, 4);
    record[8] = size;
    if (s->lcd_trace_enabled) {
        if (s->lcd_trace_count < MSM5XXX_POC_LCD_TRACE_CAPACITY) {
            memcpy(s->lcd_trace_backing +
                   s->lcd_trace_count * MSM5XXX_POC_LCD_TRACE_RECORD_SIZE,
                   record, sizeof(record));
        } else {
            s->lcd_trace_overflow = true;
        }
    }
    if (s->lcd_trace_buffer) {
        /* Observer-only caller attribution; stream consumers may ignore it. */
        msm5xxx_poc_lcd_stream_append(
            s, MSM5XXX_POC_LCD_STREAM_WRITE, size, address, value,
            caller_lr
        );
    }
    s->lcd_trace_count++;
}

static void msm5xxx_poc_raw_nand_controller_reset(
    MSM5xxxPOCMachineState *s)
{
    s->raw_nand_mode = MSM5XXX_POC_RAW_NAND_IDLE;
    s->raw_nand_status = MSM5XXX_POC_RAW_NAND_STATUS_READY;
    s->raw_nand_address_count = 0;
    s->raw_nand_cursor = 0;
    s->raw_nand_page_base = 0;
    s->raw_nand_cursor_valid = false;
    s->raw_nand_spare_selected = false;
    if (s->raw_nand_program) {
        memset(s->raw_nand_program, UINT8_MAX, s->raw_nand_page_size);
    }
}

static void msm5xxx_poc_raw_nand_reject(MSM5xxxPOCMachineState *s)
{
    s->raw_nand_mode = MSM5XXX_POC_RAW_NAND_STATUS;
    s->raw_nand_status = MSM5XXX_POC_RAW_NAND_STATUS_FAILED;
    s->raw_nand_address_count = 0;
    s->raw_nand_cursor_valid = false;
    s->raw_nand_rejections++;
}

static bool msm5xxx_poc_raw_nand_latch_cursor(
    MSM5xxxPOCMachineState *s)
{
    uint32_t page;
    uint32_t column;

    if (s->raw_nand_address_count != 3) {
        return false;
    }
    page = s->raw_nand_address_bytes[1] |
           s->raw_nand_address_bytes[2] << 8;
    if (page >= s->raw_nand_data_size / s->raw_nand_page_size) {
        return false;
    }
    if (s->raw_nand_spare_selected) {
        if (s->raw_nand_address_bytes[0] != 0) {
            return false;
        }
        s->raw_nand_page_base = page * s->raw_nand_page_size;
        s->raw_nand_cursor = s->raw_nand_page_base;
    } else {
        column = s->raw_nand_address_bytes[0] * s->raw_nand_bus_width;
        if (column >= s->raw_nand_page_size) {
            return false;
        }
        s->raw_nand_page_base = page * s->raw_nand_page_size;
        s->raw_nand_cursor = s->raw_nand_page_base + column;
    }
    s->raw_nand_cursor_valid = true;
    return true;
}

static bool msm5xxx_poc_raw_nand_program_page(
    MSM5xxxPOCMachineState *s)
{
    unsigned index;
    int ret;

    if (!s->raw_nand_cursor_valid || s->raw_nand_spare_selected) {
        return false;
    }
    for (index = 0; index < s->raw_nand_page_size; index++) {
        s->raw_nand_program[index] &=
            s->raw_nand_backing[s->raw_nand_page_base + index];
    }
    ret = blk_pwrite(s->raw_nand_blk, s->raw_nand_page_base,
                     s->raw_nand_page_size, s->raw_nand_program, 0);
    if (ret < 0) {
        error_report("raw NAND program failed: %s", strerror(-ret));
        return false;
    }
    memcpy(s->raw_nand_backing + s->raw_nand_page_base,
           s->raw_nand_program, s->raw_nand_page_size);
    s->raw_nand_writes += s->raw_nand_page_size;
    return true;
}

static bool msm5xxx_poc_raw_nand_erase_block(
    MSM5xxxPOCMachineState *s)
{
    g_autofree uint8_t *erased = NULL;
    uint32_t page;
    uint32_t block_size =
        s->raw_nand_page_size * s->raw_nand_pages_per_block;
    uint32_t start;
    int ret;

    if (s->raw_nand_address_count != 2) {
        return false;
    }
    page = s->raw_nand_address_bytes[0] |
           s->raw_nand_address_bytes[1] << 8;
    start = page / s->raw_nand_pages_per_block * block_size;
    if (start > s->raw_nand_data_size - block_size) {
        return false;
    }
    erased = g_malloc(block_size);
    memset(erased, UINT8_MAX, block_size);
    ret = blk_pwrite(s->raw_nand_blk, start, block_size, erased, 0);
    if (ret < 0) {
        error_report("raw NAND erase failed: %s", strerror(-ret));
        return false;
    }
    memcpy(s->raw_nand_backing + start, erased, block_size);
    s->raw_nand_writes += block_size;
    return true;
}

static uint64_t msm5xxx_poc_raw_nand_control_read(
    void *opaque, hwaddr offset, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    msm5xxx_poc_raw_nand_reject(s);
    return UINT8_MAX;
}

static void msm5xxx_poc_raw_nand_command_write(
    void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t command = value;

    if (offset || size != 1) {
        msm5xxx_poc_raw_nand_reject(s);
        return;
    }
    switch (command) {
    case 0xff:
        msm5xxx_poc_raw_nand_controller_reset(s);
        break;
    case 0x70:
        s->raw_nand_mode = MSM5XXX_POC_RAW_NAND_STATUS;
        break;
    case 0x00:
    case 0x50:
        s->raw_nand_mode = command == 0x50 ?
            MSM5XXX_POC_RAW_NAND_READ_SPARE :
            MSM5XXX_POC_RAW_NAND_READ_MAIN;
        s->raw_nand_status = MSM5XXX_POC_RAW_NAND_STATUS_READY;
        s->raw_nand_spare_selected = command == 0x50;
        s->raw_nand_address_count = 0;
        s->raw_nand_cursor_valid = false;
        break;
    case 0x80:
        if (s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_READ_MAIN &&
            s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_READ_SPARE) {
            msm5xxx_poc_raw_nand_reject(s);
            break;
        }
        s->raw_nand_mode = s->raw_nand_spare_selected ?
            MSM5XXX_POC_RAW_NAND_PROGRAM_SPARE :
            MSM5XXX_POC_RAW_NAND_PROGRAM_MAIN;
        s->raw_nand_address_count = 0;
        s->raw_nand_cursor_valid = false;
        memset(s->raw_nand_program, UINT8_MAX, s->raw_nand_page_size);
        break;
    case 0x10:
        if ((s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_PROGRAM_MAIN &&
             s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_PROGRAM_SPARE) ||
            !msm5xxx_poc_raw_nand_program_page(s)) {
            msm5xxx_poc_raw_nand_reject(s);
            break;
        }
        s->raw_nand_mode = MSM5XXX_POC_RAW_NAND_STATUS;
        s->raw_nand_status = MSM5XXX_POC_RAW_NAND_STATUS_READY;
        break;
    case 0x60:
        s->raw_nand_mode = MSM5XXX_POC_RAW_NAND_ERASE;
        s->raw_nand_status = MSM5XXX_POC_RAW_NAND_STATUS_READY;
        s->raw_nand_spare_selected = false;
        s->raw_nand_address_count = 0;
        s->raw_nand_cursor_valid = false;
        break;
    case 0xd0:
        if (s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_ERASE ||
            !msm5xxx_poc_raw_nand_erase_block(s)) {
            msm5xxx_poc_raw_nand_reject(s);
            break;
        }
        s->raw_nand_mode = MSM5XXX_POC_RAW_NAND_STATUS;
        s->raw_nand_status = MSM5XXX_POC_RAW_NAND_STATUS_READY;
        break;
    default:
        msm5xxx_poc_raw_nand_reject(s);
        break;
    }
}

static void msm5xxx_poc_raw_nand_address_write(
    void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    unsigned expected = s->raw_nand_mode == MSM5XXX_POC_RAW_NAND_ERASE ? 2 : 3;

    if (offset || size != 1 ||
        (s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_READ_MAIN &&
         s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_READ_SPARE &&
         s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_PROGRAM_MAIN &&
         s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_PROGRAM_SPARE &&
         s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_ERASE) ||
        s->raw_nand_address_count >= expected) {
        msm5xxx_poc_raw_nand_reject(s);
        return;
    }
    s->raw_nand_address_bytes[s->raw_nand_address_count++] = value;
    if (expected == 3 && s->raw_nand_address_count == expected) {
        if (!msm5xxx_poc_raw_nand_latch_cursor(s)) {
            msm5xxx_poc_raw_nand_reject(s);
        } else if (s->raw_nand_mode == MSM5XXX_POC_RAW_NAND_READ_MAIN ||
                   s->raw_nand_mode == MSM5XXX_POC_RAW_NAND_READ_SPARE) {
        }
    }
}

static uint64_t msm5xxx_poc_raw_nand_data_read(
    void *opaque, hwaddr offset, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t value;

    if (offset || (s->raw_nand_mode == MSM5XXX_POC_RAW_NAND_STATUS &&
                   size != 1)) {
        msm5xxx_poc_raw_nand_reject(s);
        return size == 1 ? UINT8_MAX : UINT16_MAX;
    }
    if (s->raw_nand_mode == MSM5XXX_POC_RAW_NAND_STATUS) {
        return s->raw_nand_status;
    }
    if ((s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_READ_MAIN &&
         s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_READ_SPARE) ||
        size != 2 || !s->raw_nand_cursor_valid) {
        msm5xxx_poc_raw_nand_reject(s);
        return UINT16_MAX;
    }
    if (s->raw_nand_mode == MSM5XXX_POC_RAW_NAND_READ_SPARE) {
        s->raw_nand_reads += size;
        return UINT16_MAX;
    }
    if (s->raw_nand_cursor >
        s->raw_nand_page_base + s->raw_nand_page_size - size) {
        msm5xxx_poc_raw_nand_reject(s);
        return UINT16_MAX;
    }
    value = s->raw_nand_backing[s->raw_nand_cursor] |
            s->raw_nand_backing[s->raw_nand_cursor + 1] << 8;
    s->raw_nand_cursor += size;
    s->raw_nand_reads += size;
    return value;
}

static void msm5xxx_poc_raw_nand_data_write(
    void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint32_t column;

    if (offset || size != 2 ||
        s->raw_nand_mode != MSM5XXX_POC_RAW_NAND_PROGRAM_MAIN ||
        !s->raw_nand_cursor_valid ||
        s->raw_nand_cursor >
            s->raw_nand_page_base + s->raw_nand_page_size - size) {
        msm5xxx_poc_raw_nand_reject(s);
        return;
    }
    column = s->raw_nand_cursor - s->raw_nand_page_base;
    s->raw_nand_program[column] &= value;
    s->raw_nand_program[column + 1] &= value >> 8;
    s->raw_nand_cursor += size;
}

static const MemoryRegionOps msm5xxx_poc_raw_nand_command_ops = {
    .read = msm5xxx_poc_raw_nand_control_read,
    .write = msm5xxx_poc_raw_nand_command_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
    .impl.min_access_size = 1,
    .impl.max_access_size = 1,
};

static const MemoryRegionOps msm5xxx_poc_raw_nand_address_ops = {
    .read = msm5xxx_poc_raw_nand_control_read,
    .write = msm5xxx_poc_raw_nand_address_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
    .impl.min_access_size = 1,
    .impl.max_access_size = 1,
};

static const MemoryRegionOps msm5xxx_poc_raw_nand_data_ops = {
    .read = msm5xxx_poc_raw_nand_data_read,
    .write = msm5xxx_poc_raw_nand_data_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 2,
    .impl.min_access_size = 1,
    .impl.max_access_size = 2,
};

static uint64_t msm5xxx_poc_lcd_aperture_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    hwaddr address = MSM5XXX_POC_LCD_APERTURE_BASE + offset;
    uint64_t value;

    if (offset + size > MSM5XXX_POC_LCD_APERTURE_SIZE) {
        return 0;
    }
    if (s->audio_enabled && address >= s->audio_base &&
        address <= s->audio_base + s->audio_data_offset &&
        msm5xxx_poc_audio_read_owned(s, address - s->audio_base, size,
                                     &value)) {
        return value;
    }
    s->lcd_aperture_reads++;
    return msm5xxx_poc_backing_read(s->lcd_aperture_backing, offset, size);
}

static void msm5xxx_poc_lcd_aperture_write(void *opaque, hwaddr offset,
                                           uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    hwaddr address = MSM5XXX_POC_LCD_APERTURE_BASE + offset;

    if (offset + size > MSM5XXX_POC_LCD_APERTURE_SIZE) {
        return;
    }
    if (s->audio_enabled && address >= s->audio_base &&
        address <= s->audio_base + s->audio_data_offset &&
        msm5xxx_poc_audio_write_owned(s, address - s->audio_base,
                                      value, size)) {
        return;
    }
    s->lcd_aperture_writes++;
    msm5xxx_poc_lcd_trace_write(
        s, address, value, size
    );
    msm5xxx_poc_backing_write(
        s->lcd_aperture_backing, offset, value, size
    );
}

static const MemoryRegionOps msm5xxx_poc_lcd_aperture_ops = {
    .read = msm5xxx_poc_lcd_aperture_read,
    .write = msm5xxx_poc_lcd_aperture_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

static uint64_t msm5xxx_poc_lcd_read(void *opaque, hwaddr offset,
                                     unsigned size)
{
    MSM5xxxPOCLCDPort *port = opaque;
    MSM5xxxPOCMachineState *s = port->machine;
    uint64_t value;
    uint32_t address;
    CPUClass *cc;
    uint64_t now;

    if (offset + size > MSM5XXX_POC_LCD_SIZE) {
        return 0;
    }
    s->lcd_reads[port->index]++;
    value = msm5xxx_poc_backing_read(
        s->lcd_backing[port->index], offset, size
    );
    address = msm5xxx_poc_lcd_bases[port->index] + offset;
    if (!s->ready_poll_lcd_enabled || size != 2 ||
        address != s->ready_status_address || s->ready_poll_phase != 1) {
        return value;
    }
    cc = CPU_GET_CLASS(s->cpu);
    if (cc->get_pc(CPU(s->cpu)) !=
        s->ready_poll_entry + s->ready_status_pc_offset) {
        return value;
    }
    s->ready_poll_phase = 0;
    s->ready_poll_reads++;
    if (!(value & s->ready_status_mask)) {
        return value;
    }
    s->ready_poll_cycles++;
    now = icount_get_raw();
    if (s->ready_poll_status == MSM5XXX_POC_READY_OBSERVING) {
        s->ready_poll_status = MSM5XXX_POC_READY_CANDIDATE;
        s->ready_poll_first_icount = now;
    } else if (s->ready_poll_status == MSM5XXX_POC_READY_CANDIDATE &&
               now - s->ready_poll_first_icount >=
                   MSM5XXX_POC_READY_POLL_DELAY) {
        s->ready_poll_status = MSM5XXX_POC_READY_ACCEPTED;
    }
    if (s->ready_poll_status == MSM5XXX_POC_READY_ACCEPTED) {
        s->ready_poll_responses++;
        return value & ~s->ready_status_mask;
    }
    return value;
}

static void msm5xxx_poc_lcd_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{
    MSM5xxxPOCLCDPort *port = opaque;
    MSM5xxxPOCMachineState *s = port->machine;
    uint32_t address;

    if (offset + size > MSM5XXX_POC_LCD_SIZE) {
        return;
    }
    address = msm5xxx_poc_lcd_bases[port->index] + offset;
    if (s->ready_poll_lcd_enabled && size == 2 &&
        address == s->ready_control_address &&
        value == s->ready_control_value &&
        s->ready_poll_status != MSM5XXX_POC_READY_REJECTED) {
        CPUClass *cc = CPU_GET_CLASS(s->cpu);

        if (cc->get_pc(CPU(s->cpu)) ==
            s->ready_poll_entry + s->ready_control_pc_offset) {
            s->ready_poll_phase = 1;
        }
    }
    s->lcd_writes[port->index]++;
    msm5xxx_poc_lcd_trace_write(
        s, msm5xxx_poc_lcd_bases[port->index] + offset, value, size
    );
    msm5xxx_poc_backing_write(
        s->lcd_backing[port->index], offset, value, size
    );
}

static const MemoryRegionOps msm5xxx_poc_lcd_ops = {
    .read = msm5xxx_poc_lcd_read,
    .write = msm5xxx_poc_lcd_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

static uint64_t msm5xxx_poc_read(void *opaque, hwaddr offset, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    s->reads++;
    switch (offset) {
    case 0x00:
        return s->value;
    case 0x04:
        return s->reads;
    case 0x08:
        return s->writes;
    case 0x0c:
        return s->irq_level;
    case 0x10:
        return icount_get_raw();
    case 0x14:
        return s->sbi_status;
    case 0x18:
        return s->sbi_bootstrap_phase | (s->sbi_validation_phase << 8);
    case 0x1c:
        return s->sbi_reads;
    case 0x20:
        return s->sbi_writes;
    case 0x24:
        return s->lcd_writes[0] + s->lcd_writes[1] + s->lcd_writes[2] +
               s->lcd_writes[3] + s->lcd_aperture_writes;
    case 0x28:
    case 0x2c:
    case 0x30:
        return s->lcd_writes[(offset - 0x28) / 4];
    case 0x34:
        return s->sbi_board_adc_responses;
    case 0x38:
        return s->lcd_trace_count;
    case 0x3c:
        return s->lcd_trace_overflow;
    case 0x40:
        return s->ready_poll_status;
    case 0x44:
        return s->ready_poll_reads;
    case 0x48:
        return s->ready_poll_cycles;
    case 0x4c:
        return s->ready_poll_responses;
    case 0x50:
        return s->rex_irq_ticks;
    case 0x54:
        return s->rex_irq_assertions;
    case 0x58:
        return s->rex_idle_gate_pc;
    case 0x5c:
        return s->rex_idle_seen;
    case 0x60:
        return s->rex_irq_gate_status;
    case 0x64:
        return s->rex_irq_gate_attempts;
    case 0x68:
        return s->rex_irq_acks;
    case 0x6c:
        return s->rex_irq_pending[0];
    case 0x70:
        return s->dc0_board_adc_responses;
    case 0x74:
        return s->pause_timer_writes;
    case 0x78:
        return s->pause_timer_fallbacks;
    case 0x7c:
        return s->pause_timer_rejected;
    case 0x80:
        return (uint32_t)s->pause_timer_added_ns;
    case 0x84:
        return s->pause_timer_added_ns >> 32;
    case 0x88:
        return s->ma2_audio_events;
    case 0x8c:
        return s->ma2_audio_gate_offs;
    case 0x90:
        return s->ma2_audio_ends;
    case 0x94:
        return msm5xxx_ma2_reject_reason(&s->ma2_audio);
    case 0x98:
        return s->ma2_audio_timer_rejected;
    case 0x9c:
        return s->ma2_audio.fm_state_unhandled;
    case 0xa0:
        return s->dmd_5500_starts;
    case 0xa4:
        return s->dmd_5500_responses;
    case 0xa8:
        return s->dmd_5500_rejections;
    case 0xac:
        return s->raw_nand_reads;
    case 0xb0:
        return s->raw_nand_writes;
    case 0xb4:
        return s->raw_nand_rejections;
    case 0xb8:
        return (uint32_t)s->raw_nand_mode |
               (uint32_t)s->raw_nand_status << 8 |
               (uint32_t)s->raw_nand_address_count << 16 |
               (uint32_t)s->raw_nand_cursor_valid << 24 |
               (uint32_t)s->raw_nand_spare_selected << 25;
    case 0xbc:
        return s->reset_callbacks;
    case 0xc0:
        return s->last_reset_callback_pc;
    default:
        return 0;
    }
}

static void msm5xxx_poc_write(void *opaque, hwaddr offset,
                              uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    s->writes++;
    switch (offset) {
    case 0x00:
        s->value = value;
        break;
    case 0x0c:
        s->irq_level = value & 1;
        qemu_set_irq(s->cpu_irq, s->irq_level);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps msm5xxx_poc_ops = {
    .read = msm5xxx_poc_read,
    .write = msm5xxx_poc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

static void msm5xxx_poc_audio_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    bool warm_reset = s->audio_reset_initialized;
    bool core_locked = s->audio_core_lock_initialized;

    s->audio_reset_initialized = true;

    if (core_locked) {
        qemu_mutex_lock(&s->audio_core_lock);
    }
    if (s->ma2_audio_timer) {
        timer_del(s->ma2_audio_timer);
    }
    if (s->audio_voice) {
        AUD_set_active_out(s->audio_voice, false);
    }
    s->audio_pcm_length = 0u;
    s->audio_pcm_offset = 0u;
    s->audio_pcm_failed = false;
    s->audio_backend_pcm_length = 0u;
    s->audio_backend_pcm_offset = 0u;
    if (s->audio_synth_lock_initialized) {
        qemu_mutex_lock(&s->audio_synth_lock);
        msm5xxx_audio_synth_reset(&s->audio_synth);
        s->audio_output_started = false;
        s->audio_stream_reset_epoch = s->audio_synth.epoch;
        qemu_mutex_unlock(&s->audio_synth_lock);
    } else {
        s->audio_output_started = false;
    }
    s->audio_index = 0;
    memset(s->audio_backing, 0, sizeof(s->audio_backing));
    s->audio_stream_order = 0;
    s->audio_stream_dropped = 0;
    s->audio_stream_reject_code = 0;
    s->audio_stream_started = false;
    s->audio_stream_rejected = false;
    s->audio_stream_status_pending = warm_reset ?
        MSM5XXX_POC_AUDIO_STATUS_RESET :
        (s->audio_voice || s->audio_stream_chardev ?
         MSM5XXX_POC_AUDIO_STATUS_NATIVE : 0);
    s->ma2_audio_events = 0;
    s->ma2_audio_gate_offs = 0;
    s->ma2_audio_ends = 0;
    s->ma2_audio_timer_rejected = false;
    if (core_locked) {
        msm5xxx_poc_ma2_pending_clear(s);
        msm5xxx_ma2_reset(&s->ma2_audio);
    } else {
        msm5xxx_poc_ma2_pending_clear(s);
    }
    if (core_locked) {
        qemu_mutex_unlock(&s->audio_core_lock);
    }
    msm5xxx_poc_audio_stream_status(s);
}

static void msm5xxx_poc_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUARMState *env = &s->cpu->env;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    CPUClass *cc = CPU_GET_CLASS(s->cpu);

    s->reset_callbacks++;
    s->last_reset_callback_pc = cc->get_pc(CPU(s->cpu));
    if (s->rex_irq_timer) {
        timer_del(s->rex_irq_timer);
    }
    if (s->lcd_trace_timer) {
        timer_del(s->lcd_trace_timer);
    }
    s->value = 0;
    s->reads = 0;
    s->writes = 0;
    s->irq_level = false;
    memset(s->sbi_backing, 0, sizeof(s->sbi_backing));
    s->sbi_status = s->sbi_enabled ? MSM5XXX_POC_SBI_OBSERVING :
                                     MSM5XXX_POC_SBI_DISABLED;
    s->sbi_bootstrap_phase = 0;
    s->sbi_validation_phase = 0;
    s->sbi_control = 0;
    s->sbi_started = false;
    s->sbi_read_pending = false;
    s->sbi_read_full = false;
    s->sbi_board_adc_phase = 0;
    s->sbi_board_adc_selector = 0;
    s->sbi_board_adc_responses = 0;
    s->sbi_reads = 0;
    s->sbi_writes = 0;
    memset(s->dc0_backing, 0, sizeof(s->dc0_backing));
    s->dc0_board_adc_phase = 0;
    s->dc0_board_adc_responses = 0;
    memset(s->lcd_aperture_backing, 0,
           sizeof(s->lcd_aperture_backing));
    s->lcd_aperture_reads = 0;
    s->lcd_aperture_writes = 0;
    if (s->raw_nand_main_enabled) {
        msm5xxx_poc_raw_nand_controller_reset(s);
        s->raw_nand_reads = 0;
        s->raw_nand_writes = 0;
        s->raw_nand_rejections = 0;
    }
    memset(s->lcd_backing, 0, sizeof(s->lcd_backing));
    memset(s->lcd_reads, 0, sizeof(s->lcd_reads));
    memset(s->lcd_writes, 0, sizeof(s->lcd_writes));
    s->lcd_trace_overflow = false;
    s->lcd_trace_count = 0;
    if (s->lcd_trace_backing) {
        memset(s->lcd_trace_backing, 0, MSM5XXX_POC_LCD_TRACE_SIZE);
    }
    if (s->lcd_trace_buffer) {
        g_byte_array_set_size(s->lcd_trace_buffer, 0);
    }
    s->ready_status_backing = 0;
    s->ready_pulse_backing = 0;
    s->ready_control_backing = 0;
    s->ready_poll_status = s->ready_poll_enabled ?
        MSM5XXX_POC_READY_OBSERVING : MSM5XXX_POC_READY_DISABLED;
    s->ready_poll_active_entry = s->ready_poll_entry;
    s->ready_poll_phase = 0;
    s->ready_poll_first_icount = 0;
    s->ready_poll_reads = 0;
    s->ready_poll_cycles = 0;
    s->ready_poll_responses = 0;
    s->dmd_5500_pending = false;
    s->dmd_5500_starts = 0;
    s->dmd_5500_responses = 0;
    s->dmd_5500_rejections = 0;
    s->pause_timer_rejected = false;
    s->pause_timer_writes = 0;
    s->pause_timer_fallbacks = 0;
    s->pause_timer_added_ns = 0;
    s->board_status_input_backing =
        s->board_status_input_default & s->board_status_input_mask;
    s->matrix_input_backing = s->matrix_input_reset;
    s->matrix_input_pressed = false;
    s->matrix_input_row = 0;
    s->matrix_input_sense = 0;
    /* Chardev frames cross guest reset; preserve partial command and ACK. */
    s->matrix_input_host_events = 0;
    s->matrix_input_active_reads = 0;
    s->matrix_input_rejections = 0;
    msm5xxx_poc_audio_reset(s);
    memset(s->rex_irq_backing, 0, sizeof(s->rex_irq_backing));
    s->rex_irq_arm_backing = 0;
    memset(s->rex_irq_pending, 0, sizeof(s->rex_irq_pending));
    s->rex_irq_armed = (s->rex_irq_enabled && s->rex_irq_c80 &&
                        !s->rex_irq_read_consume);
    s->rex_irq_level = false;
    s->rex_irq_route_active = false;
    s->rex_idle_seen = false;
    s->rex_idle_gate_pc = 0;
    s->rex_irq_gate_status = s->rex_irq_c80 ?
        MSM5XXX_POC_REX_GATE_VECTOR_WAIT : MSM5XXX_POC_REX_GATE_DISABLED;
    s->rex_irq_next = 0;
    s->rex_irq_ticks = 0;
    s->rex_irq_assertions = 0;
    s->rex_irq_gate_attempts = 0;
    s->rex_irq_acks = 0;
    if (s->eeprom_gpio_enabled) {
        I2CBus *bus = s->eeprom_i2c.bus;

        if (s->eeprom_i2c.state != STOPPED &&
            s->eeprom_i2c.current_addr >= 0) {
            i2c_end_transfer(bus);
        }
        memset(s->eeprom_gpio_backing, 0,
               sizeof(s->eeprom_gpio_backing));
        memset(&s->eeprom_i2c, 0, sizeof(s->eeprom_i2c));
        bitbang_i2c_init(&s->eeprom_i2c, bus);
        s->eeprom_i2c.state = STOPPED;
        s->eeprom_i2c.current_addr = -1;
        s->eeprom_sda = 1;
    }
    memset(msm, 0, MSM5XXX_POC_MSM_SIZE);
    cpu_reset(CPU(s->cpu));
    cpsr_write(env, 0xd3, 0xffffffff, CPSRWriteByGDBStub);
    env->regs[13] = s->initial_sp;
    msm[0x694] = 0x10;
    msm[0x720] = 0xff;
    msm[0x721] = 0xff;
    msm[0x724] = 0xff;
    msm[0x725] = 0xff;
    msm[0x72c] = 0x14;
    msm[0x7ac] = 0x57;
    msm[0xc1c] = 0xff;
    if (s->eeprom_gpio_enabled) {
        memcpy(s->eeprom_gpio_backing,
               msm + s->eeprom_gpio_base - MSM5XXX_POC_MSM_BASE,
               sizeof(s->eeprom_gpio_backing));
        msm5xxx_poc_eeprom_gpio_update(s);
    }
    qemu_set_irq(s->cpu_irq, 0);
    if (s->rex_irq_armed) {
        s->rex_irq_next = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          s->rex_irq_interval;
        msm5xxx_poc_rex_irq_schedule(s);
    }
    if (s->lcd_trace_timer) {
        msm5xxx_poc_audio_stream_status(s);
        timer_mod(s->lcd_trace_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 33);
    }
}

static void msm5xxx_poc_init(MachineState *machine)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(machine);
    DriveInfo *dinfo;
    bool upper_nor_enabled = s->upper_x8_nor_enabled ||
                             s->upper_x16_nor_enabled;
    bool direct_x16_nor_enabled = s->intel_x16_nor_enabled ||
                                  s->amd_x16_nor_enabled;
    unsigned i;

    s->cpu = ARM_CPU(cpu_create(machine->cpu_type));
    s->cpu_irq = qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_IRQ);

    if (s->pause_timer_enabled &&
        (icount_enabled() != ICOUNT_PRECISE ||
         s->pause_timer_helper_end > s->primary_nor_size)) {
        error_report("pause-timer requires fixed-shift icount and a NOR scope");
        exit(EXIT_FAILURE);
    }

    if (s->upper_x8_nor_enabled && s->upper_x16_nor_enabled) {
        error_report("upper-x8-nor conflicts with upper-x16-nor");
        exit(EXIT_FAILURE);
    }
    if (s->intel_x16_nor_enabled && s->amd_x16_nor_enabled) {
        error_report("intel-x16-nor conflicts with amd-x16-nor");
        exit(EXIT_FAILURE);
    }
    if (s->primary_x16_write_while_suspended &&
            !s->primary_x16_nor_enabled) {
        error_report(
            "primary-x16-write-while-suspended requires primary-x16-nor"
        );
        exit(EXIT_FAILURE);
    }
    if (s->fujitsu_x16_nor_enabled) {
        uint64_t end = (uint64_t)s->secondary_nor_base +
                       s->secondary_nor_size;

        if (s->secondary_primary_size != s->primary_nor_size ||
                (s->secondary_nor_base < s->primary_nor_size ?
                 end > s->primary_nor_size :
                 s->secondary_nor_base >= s->ram_base || end > s->ram_base)) {
            error_report("fujitsu-x16-nor is outside final memory profile");
            exit(EXIT_FAILURE);
        }
    }
    if (s->memory_profile_enabled &&
            (machine->ram_size > 0x02000000 - s->ram_base ||
             s->initial_sp < s->ram_base ||
             s->initial_sp > s->ram_base + machine->ram_size - 4)) {
        error_report("memory-profile RAM range does not contain INITIAL_SP");
        exit(EXIT_FAILURE);
    }
    if (s->record_x16_nor_enabled) {
        uint64_t base = s->record_x16_nor_base;
        uint64_t end = base + s->record_x16_nor_size;

        if (!s->primary_x16_nor_enabled ||
                end != s->primary_x16_nor_base ||
                (uint64_t)s->primary_x16_nor_base +
                    s->primary_x16_nor_size != s->primary_nor_size ||
                (s->fujitsu_x16_nor_enabled &&
                 s->secondary_nor_base < s->primary_nor_size &&
                 base < (uint64_t)s->secondary_nor_base +
                        s->secondary_nor_size &&
                 end > s->secondary_nor_base)) {
            error_report(
                "record-x16-nor requires a disjoint adjacent primary tail"
            );
            exit(EXIT_FAILURE);
        }
    }
    if (s->mapped_primary_x16_nor_enabled) {
        uint64_t base = s->mapped_primary_x16_nor_base;
        uint64_t end = base + s->mapped_primary_x16_nor_size;
        uint64_t upper_end = end + s->mapped_primary_x16_nor_size;

        if (base < s->primary_nor_size || end != s->ram_base ||
                upper_end > s->ram_base + machine->ram_size ||
                (s->fujitsu_x16_nor_enabled &&
                 base < (uint64_t)s->secondary_nor_base +
                        s->secondary_nor_size &&
                 end > s->secondary_nor_base)) {
            error_report(
                "mapped-primary-x16-nor conflicts with the final memory map"
            );
            exit(EXIT_FAILURE);
        }
    }
    if (s->intel_x16_nor_enabled) {
        uint64_t base = s->intel_x16_nor_base;
        uint64_t windows = s->mapped_primary_x16_nor_enabled ? 2 : 1;
        uint64_t end = base + windows * s->intel_x16_nor_size;
        uint64_t ram_end = s->ram_base + machine->ram_size;
        uint64_t audio_end = s->audio_base + s->audio_data_offset + 1;

        if (base != ram_end || base < MSM5XXX_POC_LCD_APERTURE_BASE ||
                end > MSM5XXX_POC_LCD_APERTURE_BASE +
                      MSM5XXX_POC_LCD_APERTURE_SIZE ||
                upper_nor_enabled ||
                (s->audio_enabled && s->audio_base < end &&
                 audio_end > base)) {
            error_report("intel-x16-nor conflicts with the final memory map");
            exit(EXIT_FAILURE);
        }
    }
    if (s->amd_x16_nor_enabled) {
        uint64_t base = s->intel_x16_nor_base;
        uint64_t end = base + s->intel_x16_nor_size;
        uint64_t ram_end = s->ram_base + machine->ram_size;

        if (base < s->ram_base || end > ram_end) {
            error_report("amd-x16-nor must overlap the detected RAM aperture");
            exit(EXIT_FAILURE);
        }
    }
    if (s->raw_nand_main_enabled &&
        (upper_nor_enabled || s->eeprom_gpio_enabled)) {
        error_report("raw-nand-main conflicts with upper NOR or EEPROM MTD");
        exit(EXIT_FAILURE);
    }
    if (s->rex_irq_c80) {
        uint64_t ram_end = s->ram_base + machine->ram_size;
        bool handler_in_nor =
            s->rex_irq_handler_address < s->primary_nor_size &&
            s->rex_irq_handler_size <=
                s->primary_nor_size - s->rex_irq_handler_address;
        bool handler_in_iram =
            s->rex_irq_handler_address >= MSM5XXX_POC_IRAM_BASE &&
            s->rex_irq_handler_address <
                MSM5XXX_POC_IRAM_BASE + MSM5XXX_POC_IRAM_SIZE &&
            s->rex_irq_handler_size <=
                MSM5XXX_POC_IRAM_BASE + MSM5XXX_POC_IRAM_SIZE -
                s->rex_irq_handler_address;
        bool vector_invalid = s->rex_irq_vector_target < s->ram_base ||
            s->rex_irq_vector_target > ram_end - 4;

        if (vector_invalid ||
                s->rex_irq_wrapper_address >= s->primary_nor_size ||
                (!handler_in_nor && !handler_in_iram) ||
                s->rex_irq_callback_address >= s->primary_nor_size ||
                s->rex_irq_handler_slot < s->ram_base ||
                s->rex_irq_handler_slot > ram_end - 4 ||
                s->rex_irq_callback_slot < s->ram_base ||
                s->rex_irq_callback_slot > ram_end - 4) {
            error_report("rex-static route exceeds final memory-profile");
            exit(EXIT_FAILURE);
        }
    }

    memory_region_init_rom(&s->nor, NULL, "msm5xxx-poc.nor",
                           s->primary_nor_size, &error_fatal);
    memory_region_add_subregion(get_system_memory(), 0, &s->nor);
    if (s->primary_x16_nor_enabled) {
        DeviceState *dev = qdev_new(TYPE_PFLASH_CFI02);
        unsigned region;

        if (s->primary_x16_nor_base + s->primary_x16_nor_size >
            s->primary_nor_size) {
            error_report("primary-x16-nor exceeds primary NOR");
            exit(EXIT_FAILURE);
        }
        dinfo = drive_get(IF_PFLASH, 0, 0);
        if (!dinfo) {
            error_report("primary-x16-nor requires pflash unit 0");
            exit(EXIT_FAILURE);
        }
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo));
        if (s->primary_x16_nor_region_count) {
            for (region = 0; region < s->primary_x16_nor_region_count;
                 region++) {
                g_autofree char *blocks =
                    g_strdup_printf("num-blocks%u", region);
                g_autofree char *length =
                    g_strdup_printf("sector-length%u", region);

                qdev_prop_set_uint32(
                    dev, blocks, s->primary_x16_nor_block_count[region]
                );
                qdev_prop_set_uint32(
                    dev, length, s->primary_x16_nor_region_size[region]
                );
            }
        } else {
            qdev_prop_set_uint32(
                dev, "num-blocks",
                s->primary_x16_nor_size / s->primary_x16_nor_sector_size
            );
            qdev_prop_set_uint32(dev, "sector-length",
                                 s->primary_x16_nor_sector_size);
        }
        qdev_prop_set_uint8(dev, "width", 2);
        qdev_prop_set_uint8(dev, "mappings", 1);
        qdev_prop_set_uint8(dev, "big-endian", 0);
        qdev_prop_set_uint16(dev, "id0", s->primary_x16_nor_id0);
        qdev_prop_set_uint16(dev, "id1", s->primary_x16_nor_id1);
        qdev_prop_set_uint16(dev, "id2", 0);
        qdev_prop_set_uint16(dev, "id3", 0);
        qdev_prop_set_uint16(dev, "unlock-addr0", 0x555);
        qdev_prop_set_uint16(dev, "unlock-addr1", 0x2aa);
        if (s->primary_x16_write_while_suspended) {
            qdev_prop_set_bit(dev, "write-while-suspended", true);
        }
        qdev_prop_set_string(dev, "name", "msm5xxx-poc.primary-nor");
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        sysbus_mmio_map_overlap(SYS_BUS_DEVICE(dev), 0,
                                s->primary_x16_nor_base, 1);
    }
    if (s->record_x16_nor_enabled) {
        DeviceState *dev = qdev_new(TYPE_PFLASH_CFI02);
        unsigned unit = s->primary_x16_nor_enabled;
        uint32_t device_size = pow2ceil(s->record_x16_nor_size);

        dinfo = drive_get(IF_PFLASH, 0, unit);
        if (!dinfo) {
            error_report("record-x16-nor requires one pflash drive");
            exit(EXIT_FAILURE);
        }
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo));
        qdev_prop_set_uint32(
            dev, "num-blocks",
            device_size / s->record_x16_nor_sector_size
        );
        qdev_prop_set_uint32(dev, "sector-length",
                             s->record_x16_nor_sector_size);
        qdev_prop_set_uint8(dev, "width", 2);
        qdev_prop_set_uint8(dev, "mappings", 1);
        qdev_prop_set_uint8(dev, "big-endian", 0);
        qdev_prop_set_uint16(dev, "id0", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id1", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id2", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id3", UINT16_MAX);
        qdev_prop_set_uint16(dev, "unlock-addr0", 0x555);
        qdev_prop_set_uint16(dev, "unlock-addr1", 0x2aa);
        qdev_prop_set_string(dev, "name", "msm5xxx-poc.record-x16-nor");
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        memory_region_init_alias(
            &s->record_x16_nor_alias, OBJECT(machine),
            "msm5xxx-poc.record-x16-nor-aperture",
            sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0), 0,
            s->record_x16_nor_size
        );
        memory_region_add_subregion_overlap(
            get_system_memory(), s->record_x16_nor_base,
            &s->record_x16_nor_alias, 1
        );
    }
    if (s->mapped_primary_x16_nor_enabled) {
        DeviceState *dev = qdev_new(TYPE_PFLASH_CFI01);
        DeviceState *upper;
        unsigned unit = s->primary_x16_nor_enabled +
                        s->record_x16_nor_enabled;

        dinfo = drive_get(IF_PFLASH, 0, unit);
        if (!dinfo) {
            error_report("mapped-primary-x16-nor requires two pflash drives");
            exit(EXIT_FAILURE);
        }
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo));
        qdev_prop_set_uint32(
            dev, "num-blocks",
            s->mapped_primary_x16_nor_size /
            s->mapped_primary_x16_nor_sector_size
        );
        qdev_prop_set_uint64(dev, "sector-length",
                             s->mapped_primary_x16_nor_sector_size);
        qdev_prop_set_uint8(dev, "width", 2);
        qdev_prop_set_uint8(dev, "device-width", 2);
        qdev_prop_set_uint8(dev, "max-device-width", 2);
        qdev_prop_set_bit(dev, "big-endian", false);
        qdev_prop_set_uint16(dev, "id0", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id1", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id2", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id3", UINT16_MAX);
        qdev_prop_set_string(dev, "name",
                             "msm5xxx-poc.mapped-primary-x16-nor");
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        sysbus_mmio_map_overlap(SYS_BUS_DEVICE(dev), 0,
                                s->mapped_primary_x16_nor_base, 1);

        upper = qdev_new(TYPE_PFLASH_CFI01);
        dinfo = drive_get(IF_PFLASH, 0, unit + 1);
        if (!dinfo) {
            error_report("mapped-primary-x16-nor requires two pflash drives");
            exit(EXIT_FAILURE);
        }
        qdev_prop_set_drive(upper, "drive", blk_by_legacy_dinfo(dinfo));
        qdev_prop_set_uint32(
            upper, "num-blocks",
            s->mapped_primary_x16_nor_size /
            s->mapped_primary_x16_nor_sector_size
        );
        qdev_prop_set_uint64(upper, "sector-length",
                             s->mapped_primary_x16_nor_sector_size);
        qdev_prop_set_uint8(upper, "width", 2);
        qdev_prop_set_uint8(upper, "device-width", 2);
        qdev_prop_set_uint8(upper, "max-device-width", 2);
        qdev_prop_set_bit(upper, "big-endian", false);
        qdev_prop_set_uint16(upper, "id0", UINT16_MAX);
        qdev_prop_set_uint16(upper, "id1", UINT16_MAX);
        qdev_prop_set_uint16(upper, "id2", UINT16_MAX);
        qdev_prop_set_uint16(upper, "id3", UINT16_MAX);
        qdev_prop_set_string(
            upper, "name", "msm5xxx-poc.mapped-primary-x16-nor-upper"
        );
        sysbus_realize_and_unref(SYS_BUS_DEVICE(upper), &error_fatal);
        sysbus_mmio_map_overlap(
            SYS_BUS_DEVICE(upper), 0,
            s->mapped_primary_x16_nor_base + s->mapped_primary_x16_nor_size,
            1
        );
    }
    if (direct_x16_nor_enabled) {
        DeviceState *dev = qdev_new(
            s->amd_x16_nor_enabled ? TYPE_PFLASH_CFI02 : TYPE_PFLASH_CFI01
        );
        unsigned unit = s->primary_x16_nor_enabled +
                        s->record_x16_nor_enabled +
                        2 * s->mapped_primary_x16_nor_enabled;

        dinfo = drive_get(IF_PFLASH, 0, unit);
        if (!dinfo) {
            error_report("direct x16 NOR requires one pflash drive");
            exit(EXIT_FAILURE);
        }
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo));
        qdev_prop_set_uint32(
            dev, "num-blocks",
            s->intel_x16_nor_size / s->intel_x16_nor_sector_size
        );
        qdev_prop_set_uint64(dev, "sector-length",
                             s->intel_x16_nor_sector_size);
        if (s->amd_x16_nor_enabled) {
            qdev_prop_set_uint8(dev, "width", 2);
            qdev_prop_set_uint8(dev, "mappings", 1);
            qdev_prop_set_uint8(dev, "big-endian", 0);
            qdev_prop_set_uint16(dev, "unlock-addr0", 0x555);
            qdev_prop_set_uint16(dev, "unlock-addr1", 0x2aa);
            qdev_prop_set_bit(dev, "write-while-suspended",
                              s->amd_x16_nor_options & 1);
        } else {
            qdev_prop_set_uint8(dev, "width", 2);
            qdev_prop_set_uint8(dev, "device-width", 2);
            qdev_prop_set_uint8(dev, "max-device-width", 2);
            qdev_prop_set_bit(dev, "big-endian", false);
        }
        qdev_prop_set_uint16(dev, "id0", s->intel_x16_nor_id0);
        qdev_prop_set_uint16(dev, "id1", s->intel_x16_nor_id1);
        qdev_prop_set_uint16(dev, "id2", 0);
        qdev_prop_set_uint16(dev, "id3", 0);
        qdev_prop_set_string(
            dev, "name",
            s->amd_x16_nor_enabled ? "msm5xxx-poc.amd-x16-nor" :
                                     "msm5xxx-poc.intel-x16-nor"
        );
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        sysbus_mmio_map_overlap(SYS_BUS_DEVICE(dev), 0,
                                s->intel_x16_nor_base, 1);
        if (s->intel_x16_nor_enabled &&
                s->mapped_primary_x16_nor_enabled) {
            memory_region_init_alias(
                &s->intel_x16_nor_data_alias, OBJECT(machine),
                "msm5xxx-poc.intel-x16-nor-data-alias",
                sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0), 0,
                s->intel_x16_nor_size
            );
            memory_region_add_subregion_overlap(
                get_system_memory(),
                s->intel_x16_nor_base + s->intel_x16_nor_size,
                &s->intel_x16_nor_data_alias, 1
            );
        }
    }
    if (s->fujitsu_x16_nor_enabled) {
        DeviceState *dev = qdev_new(TYPE_PFLASH_CFI02);
        uint32_t device_size = pow2ceil(s->secondary_nor_size);
        uint32_t remaining;

        dinfo = drive_get(IF_PFLASH, 0,
                          s->primary_x16_nor_enabled +
                          s->record_x16_nor_enabled +
                          2 * s->mapped_primary_x16_nor_enabled +
                          direct_x16_nor_enabled);
        if (!dinfo) {
            error_report("fujitsu-x16-nor requires one pflash drive");
            exit(EXIT_FAILURE);
        }
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo));
        if (s->secondary_nor_id0 == 0x0004 &&
            s->secondary_nor_id1 == 0x005f) {
            qdev_prop_set_uint32(dev, "num-blocks0", 8);
            qdev_prop_set_uint32(dev, "sector-length0", 0x2000);
            remaining = s->secondary_nor_size - 0x10000;
            if (s->secondary_nor_size == 0x800000 &&
                s->secondary_nor_base < s->secondary_primary_size) {
                remaining -= 0x10000;
                qdev_prop_set_uint32(dev, "num-blocks2", 8);
                qdev_prop_set_uint32(dev, "sector-length2", 0x2000);
            }
            qdev_prop_set_uint32(dev, "num-blocks1", remaining / 0x10000);
            qdev_prop_set_uint32(dev, "sector-length1", 0x10000);
        } else {
            qdev_prop_set_uint32(dev, "num-blocks",
                                 device_size / 0x10000);
            qdev_prop_set_uint32(dev, "sector-length", 0x10000);
        }
        qdev_prop_set_uint8(dev, "width", 2);
        qdev_prop_set_uint8(dev, "mappings", 1);
        qdev_prop_set_uint8(dev, "big-endian", 0);
        qdev_prop_set_uint16(dev, "id0", s->secondary_nor_id0);
        qdev_prop_set_uint16(dev, "id1", s->secondary_nor_id1);
        qdev_prop_set_uint16(dev, "id2", 0);
        qdev_prop_set_uint16(dev, "id3", 0);
        qdev_prop_set_uint16(dev, "unlock-addr0", 0x555);
        qdev_prop_set_uint16(dev, "unlock-addr1", 0x2aa);
        qdev_prop_set_string(dev, "name", "msm5xxx-poc.secondary-nor");
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        if (device_size != s->secondary_nor_size) {
            memory_region_init_alias(
                &s->secondary_nor_alias, OBJECT(machine),
                "msm5xxx-poc.secondary-nor-aperture",
                sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0), 0,
                s->secondary_nor_size
            );
            memory_region_add_subregion(
                get_system_memory(), s->secondary_nor_base,
                &s->secondary_nor_alias
            );
        } else if (s->secondary_nor_base < s->primary_nor_size) {
            sysbus_mmio_map_overlap(SYS_BUS_DEVICE(dev), 0,
                                    s->secondary_nor_base, 1);
        } else {
            sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, s->secondary_nor_base);
        }
    }
    if (upper_nor_enabled) {
        DeviceState *dev = qdev_new(TYPE_PFLASH_CFI02);
        unsigned unit = s->primary_x16_nor_enabled +
                        s->record_x16_nor_enabled +
                        2 * s->mapped_primary_x16_nor_enabled +
                        direct_x16_nor_enabled +
                        s->fujitsu_x16_nor_enabled;

        dinfo = drive_get(IF_PFLASH, 0, unit);
        if (!dinfo) {
            error_report("upper NOR requires one pflash drive");
            exit(EXIT_FAILURE);
        }
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo));
        qdev_prop_set_uint32(
            dev, "num-blocks",
            MSM5XXX_POC_UPPER_NOR_SIZE /
            MSM5XXX_POC_UPPER_NOR_SECTOR_SIZE
        );
        qdev_prop_set_uint32(dev, "sector-length",
                             MSM5XXX_POC_UPPER_NOR_SECTOR_SIZE);
        qdev_prop_set_uint8(dev, "width",
                           s->upper_x16_nor_enabled ? 2 : 1);
        qdev_prop_set_uint8(dev, "mappings", 1);
        qdev_prop_set_uint8(dev, "big-endian", 0);
        qdev_prop_set_uint16(dev, "id0", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id1", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id2", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id3", UINT16_MAX);
        qdev_prop_set_uint16(dev, "unlock-addr0",
                            s->upper_x16_nor_enabled ? 0x555 : 0xaaa);
        qdev_prop_set_uint16(dev, "unlock-addr1",
                            s->upper_x16_nor_enabled ? 0x2aa : 0x554);
        qdev_prop_set_string(dev, "name", "msm5xxx-poc.upper-nor");
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0,
                        MSM5XXX_POC_UPPER_NOR_BASE);
    }
    memory_region_add_subregion(get_system_memory(), s->ram_base,
                                machine->ram);
    memory_region_init_ram(&s->bootstrap, NULL, "msm5xxx-poc.bootstrap",
                           MSM5XXX_POC_BOOTSTRAP_SIZE, &error_fatal);
    memory_region_add_subregion(get_system_memory(), MSM5XXX_POC_BOOTSTRAP_BASE,
                                &s->bootstrap);
    if (s->pause_timer_enabled) {
        memory_region_init_io(&s->pause_timer, OBJECT(machine),
                              &msm5xxx_poc_pause_timer_ops, s,
                              "msm5xxx-poc.pause-timer",
                              MSM5XXX_POC_PAUSE_TIMER_SIZE);
        memory_region_add_subregion_overlap(
            get_system_memory(), s->pause_timer_address,
            &s->pause_timer, 1
        );
    }
    memory_region_init_ram(&s->msm, NULL, "msm5xxx-poc.msm",
                           MSM5XXX_POC_MSM_SIZE, &error_fatal);
    memory_region_add_subregion(get_system_memory(), MSM5XXX_POC_MSM_BASE,
                                &s->msm);
    if (s->board_revision_enabled) {
        memory_region_init_io(&s->board_revision, OBJECT(machine),
                              &msm5xxx_poc_board_revision_ops, s,
                              "msm5xxx-poc.board-revision", 4);
        memory_region_add_subregion_overlap(
            get_system_memory(), s->board_revision_address,
            &s->board_revision, 1
        );
    }
    if (s->dmd_5500_enabled) {
        memory_region_init_io(&s->dmd_5500_start, OBJECT(machine),
                              &msm5xxx_poc_dmd_5500_start_ops, s,
                              "msm5xxx-poc.dmd-5500-start",
                              MSM5XXX_POC_DMD5500_SIZE);
        memory_region_add_subregion_overlap(
            get_system_memory(), MSM5XXX_POC_DMD5500_START,
            &s->dmd_5500_start, 1
        );
        memory_region_init_io(&s->dmd_5500_completion, OBJECT(machine),
                              &msm5xxx_poc_dmd_5500_completion_ops, s,
                              "msm5xxx-poc.dmd-5500-completion",
                              MSM5XXX_POC_DMD5500_SIZE);
        memory_region_add_subregion_overlap(
            get_system_memory(), MSM5XXX_POC_DMD5500_COMPLETION,
            &s->dmd_5500_completion, 1
        );
    }
    if (s->raw_nand_main_enabled) {
        int64_t length;
        int ret;

        s->raw_nand_blk = blk_by_name(MSM5XXX_POC_RAW_NAND_DRIVE);
        if (!s->raw_nand_blk) {
            error_report("raw-nand-main requires drive "
                         MSM5XXX_POC_RAW_NAND_DRIVE);
            exit(EXIT_FAILURE);
        }
        ret = blk_set_perm(s->raw_nand_blk,
                           BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                           BLK_PERM_ALL, &error_fatal);
        if (ret < 0) {
            exit(EXIT_FAILURE);
        }
        length = blk_getlength(s->raw_nand_blk);
        if (length < 0) {
            error_report("raw NAND state length failed: %s",
                         strerror(-length));
            exit(EXIT_FAILURE);
        }
        if (length != s->raw_nand_data_size) {
            error_report("raw NAND state is 0x%" PRIx64
                         " bytes, expected 0x%x", length,
                         s->raw_nand_data_size);
            exit(EXIT_FAILURE);
        }
        s->raw_nand_backing = g_malloc(s->raw_nand_data_size);
        s->raw_nand_program = g_malloc(s->raw_nand_page_size);
        ret = blk_pread(s->raw_nand_blk, 0, s->raw_nand_data_size,
                        s->raw_nand_backing, 0);
        if (ret < 0) {
            error_report("raw NAND state read failed: %s", strerror(-ret));
            exit(EXIT_FAILURE);
        }
        msm5xxx_poc_raw_nand_controller_reset(s);
    }
    if (s->eeprom_gpio_enabled) {
        DeviceState *dev = qdev_new(TYPE_MSM5XXX_24LCXX);
        MSM5xxx24LCxxState *eeprom = MSM5XXX_24LCXX(dev);
        I2CBus *bus = i2c_init_bus(DEVICE(s->cpu), "eeprom-i2c");
        DriveInfo *eeprom_dinfo = drive_get(IF_MTD, 0, 0);

        if (!eeprom_dinfo) {
            error_report("eeprom-24lcxx-gpio requires one MTD drive");
            exit(EXIT_FAILURE);
        }
        eeprom->capacity = s->eeprom_capacity;
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(eeprom_dinfo));
        qdev_prop_set_uint8(dev, "address", 0x50);
        qdev_realize_and_unref(dev, BUS(bus), &error_fatal);
        bitbang_i2c_init(&s->eeprom_i2c, bus);
        s->eeprom_sda = 1;
        memory_region_init_io(&s->eeprom_gpio, OBJECT(machine),
                              &msm5xxx_poc_eeprom_gpio_ops, s,
                              "msm5xxx-poc.eeprom-gpio",
                              MSM5XXX_POC_EEPROM_GPIO_SIZE);
        memory_region_add_subregion_overlap(
            get_system_memory(), s->eeprom_gpio_base,
            &s->eeprom_gpio, 1
        );
    }
    if (s->rex_irq_enabled) {
        s->rex_irq_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                        msm5xxx_poc_rex_irq_tick, s);
        memory_region_init_io(&s->rex_irq_controller, OBJECT(machine),
                              &msm5xxx_poc_rex_irq_ops, s,
                              "msm5xxx-poc.rex-irq",
                              s->rex_irq_controller_size);
        memory_region_add_subregion_overlap(
            get_system_memory(), s->rex_irq_status_address,
            &s->rex_irq_controller, 1
        );
        if (s->rex_irq_c80 && !s->rex_irq_read_consume) {
            s->rex_irq_armed = true;
            s->rex_irq_next = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                              s->rex_irq_interval;
            msm5xxx_poc_rex_irq_schedule(s);
        } else {
            memory_region_init_io(&s->rex_irq_arm, OBJECT(machine),
                                  &msm5xxx_poc_rex_irq_arm_ops, s,
                                  "msm5xxx-poc.rex-irq-arm", 1);
            memory_region_add_subregion_overlap(
                get_system_memory(), s->rex_irq_arm_address,
                &s->rex_irq_arm, 1
            );
        }
    }
    s->sbi_status = s->sbi_enabled ? MSM5XXX_POC_SBI_OBSERVING :
                                     MSM5XXX_POC_SBI_DISABLED;
    if (s->sbi_enabled) {
        memory_region_init_io(&s->sbi, OBJECT(machine), &msm5xxx_poc_sbi_ops,
                              s, "msm5xxx-poc.sbi", MSM5XXX_POC_SBI_SIZE);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            MSM5XXX_POC_SBI_BASE,
                                            &s->sbi, 1);
    }
    if (s->dc0_board_adc_value <= UINT8_MAX) {
        memory_region_init_io(&s->dc0, OBJECT(machine), &msm5xxx_poc_dc0_ops,
                              s, "msm5xxx-poc.dc0", MSM5XXX_POC_DC0_SIZE);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            MSM5XXX_POC_DC0_BASE,
                                            &s->dc0, 1);
    }
    if (s->raw_nand_main_enabled) {
        memory_region_init_io(&s->raw_nand_data, OBJECT(machine),
                              &msm5xxx_poc_raw_nand_data_ops, s,
                              "msm5xxx-poc.raw-nand-data", 2);
        memory_region_add_subregion(get_system_memory(),
                                    s->raw_nand_data_address,
                                    &s->raw_nand_data);
        memory_region_init_io(&s->raw_nand_address, OBJECT(machine),
                              &msm5xxx_poc_raw_nand_address_ops, s,
                              "msm5xxx-poc.raw-nand-address", 1);
        memory_region_add_subregion(get_system_memory(),
                                    s->raw_nand_address_address,
                                    &s->raw_nand_address);
        memory_region_init_io(&s->raw_nand_command, OBJECT(machine),
                              &msm5xxx_poc_raw_nand_command_ops, s,
                              "msm5xxx-poc.raw-nand-command", 1);
        memory_region_add_subregion(get_system_memory(),
                                    s->raw_nand_command_address,
                                    &s->raw_nand_command);
    }
    memory_region_init_io(&s->lcd_aperture, OBJECT(machine),
                          &msm5xxx_poc_lcd_aperture_ops, s,
                          "msm5xxx-poc.lcd-aperture",
                          MSM5XXX_POC_LCD_APERTURE_SIZE);
    memory_region_add_subregion_overlap(
        get_system_memory(), MSM5XXX_POC_LCD_APERTURE_BASE,
        &s->lcd_aperture, -1
    );
    for (i = 0; i < MSM5XXX_POC_LCD_PORTS; i++) {
        if ((upper_nor_enabled &&
             msm5xxx_poc_lcd_bases[i] >= MSM5XXX_POC_UPPER_NOR_BASE) ||
            (direct_x16_nor_enabled &&
             msm5xxx_poc_lcd_bases[i] >= s->intel_x16_nor_base &&
             msm5xxx_poc_lcd_bases[i] <
                 s->intel_x16_nor_base + s->intel_x16_nor_size) ||
            (s->raw_nand_main_enabled &&
             msm5xxx_poc_lcd_bases[i] == s->raw_nand_data_address)) {
            continue;
        }
        s->lcd_port[i].machine = s;
        s->lcd_port[i].index = i;
        memory_region_init_io(&s->lcd[i], OBJECT(machine),
                              &msm5xxx_poc_lcd_ops, &s->lcd_port[i],
                              "msm5xxx-poc.lcd", MSM5XXX_POC_LCD_SIZE);
        memory_region_add_subregion(get_system_memory(),
                                    msm5xxx_poc_lcd_bases[i],
                                    &s->lcd[i]);
    }
    if (s->lcd_trace_enabled) {
        memory_region_init_ram(&s->lcd_trace, NULL,
                               "msm5xxx-poc.lcd-trace",
                               MSM5XXX_POC_LCD_TRACE_SIZE, &error_fatal);
        s->lcd_trace_backing = memory_region_get_ram_ptr(&s->lcd_trace);
        memory_region_add_subregion(get_system_memory(),
                                    MSM5XXX_POC_LCD_TRACE_BASE,
                                    &s->lcd_trace);
    }
    if (s->lcd_trace_chardev) {
        Chardev *chr = qemu_chr_find(s->lcd_trace_chardev);

        if (!chr) {
            error_report("lcd-trace-chardev '%s' not found",
                         s->lcd_trace_chardev);
            exit(EXIT_FAILURE);
        }
        qemu_chr_fe_init(&s->lcd_trace_chr, chr, &error_fatal);
        s->lcd_trace_buffer = g_byte_array_sized_new(4096);
        s->lcd_trace_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                          msm5xxx_poc_lcd_trace_flush, s);
        timer_mod(s->lcd_trace_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 33);
    }
    if (s->input_chardev) {
        Chardev *chr = qemu_chr_find(s->input_chardev);

        if (!chr) {
            error_report("input-chardev '%s' not found", s->input_chardev);
            exit(EXIT_FAILURE);
        }
        qemu_chr_fe_init(&s->input_chr, chr, &error_fatal);
        qemu_chr_fe_set_handlers(
            &s->input_chr, msm5xxx_poc_host_input_can_read,
            msm5xxx_poc_host_input_read, NULL, NULL, s, NULL, true
        );
    } else if (s->matrix_input_host_enabled) {
        error_report("matrix-input requires input-chardev");
        exit(EXIT_FAILURE);
    }
    if (s->audio_stream_chardev) {
        Chardev *chr = qemu_chr_find(s->audio_stream_chardev);

        if (!chr) {
            error_report("audio-stream-chardev '%s' not found",
                         s->audio_stream_chardev);
            exit(EXIT_FAILURE);
        }
        qemu_chr_fe_init(&s->audio_stream_chr, chr, &error_fatal);
    }
    s->ready_poll_status = s->ready_poll_enabled ?
        MSM5XXX_POC_READY_OBSERVING : MSM5XXX_POC_READY_DISABLED;
    if (s->ready_poll_enabled && !s->ready_poll_lcd_enabled) {
        memory_region_init_io(&s->ready_status, OBJECT(machine),
                              &msm5xxx_poc_ready_status_ops, s,
                              "msm5xxx-poc.ready-status", 1);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            s->ready_status_address,
                                            &s->ready_status, 1);
        memory_region_init_io(&s->ready_pulse, OBJECT(machine),
                              &msm5xxx_poc_ready_pulse_ops, s,
                              "msm5xxx-poc.ready-pulse", 1);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            s->ready_pulse_address,
                                            &s->ready_pulse, 1);
        if (s->ready_poll_control_enabled) {
            memory_region_init_io(&s->ready_control, OBJECT(machine),
                                  &msm5xxx_poc_ready_control_ops, s,
                                  "msm5xxx-poc.ready-control", 1);
            memory_region_add_subregion_overlap(get_system_memory(),
                                                s->ready_control_address,
                                                &s->ready_control, 1);
        }
    }
    if (s->board_status_input_enabled) {
        s->board_status_input_backing =
            s->board_status_input_default & s->board_status_input_mask;
        memory_region_init_io(&s->board_status_input, OBJECT(machine),
                              &msm5xxx_poc_board_status_input_ops, s,
                              "msm5xxx-poc.board-status-input", 1);
        memory_region_add_subregion_overlap(
            get_system_memory(), s->board_status_input_address,
            &s->board_status_input, 2
        );
    }
    if (s->matrix_input_enabled) {
        memory_region_init_io(&s->matrix_input, OBJECT(machine),
                              &msm5xxx_poc_matrix_input_ops, s,
                              "msm5xxx-poc.matrix-input", 1);
        memory_region_add_subregion_overlap(
            get_system_memory(), s->matrix_input_address,
            &s->matrix_input, 1
        );
    }
    if (s->audio_sites_enabled) {
        bool have_index_site = false;
        bool have_data_site = false;
        unsigned index;

        for (index = 0; index < s->audio_site_count; index++) {
            if (!s->audio_enabled ||
                s->audio_site_port[index] > s->audio_data_offset) {
                error_report("audio-sites port is outside audio-aperture");
                exit(EXIT_FAILURE);
            }
            have_index_site |= s->audio_site_write[index] &&
                               s->audio_site_port[index] == 0;
            have_data_site |= s->audio_site_write[index] &&
                              s->audio_site_port[index] ==
                              s->audio_data_offset;
        }
        if (!have_index_site || !have_data_site) {
            error_report("audio-sites requires index and data write sites");
            exit(EXIT_FAILURE);
        }
    }
    if (s->audio_enabled && !s->audio_ma2 && !s->audio_sites_enabled) {
        error_report("opaque audio-aperture requires audio-sites");
        exit(EXIT_FAILURE);
    }
    if (s->audio_enabled) {
        if (s->audio_ma2 && s->audio_sites_enabled) {
            struct audsettings settings = {
                MSM5XXX_AUDIO_SAMPLE_RATE, 2, AUDIO_FORMAT_S16, 0
            };

            qemu_mutex_init(&s->audio_synth_lock);
            qemu_mutex_init(&s->audio_core_lock);
            s->audio_synth_lock_initialized = true;
            s->audio_core_lock_initialized = true;
            if (s->audio_pcm_enabled && !s->audio_stream_chardev) {
                Error *audio_error = NULL;

                s->audio_backend = machine->audiodev ?
                    audio_be_by_name(machine->audiodev, &audio_error) :
                    audio_get_default_audio_be(&audio_error);
                if (s->audio_backend) {
                    s->audio_voice = AUD_open_out(
                        s->audio_backend, NULL, "msm5xxx-audio", s,
                        msm5xxx_poc_audio_backend_callback, &settings);
                }
                if (!s->audio_voice) {
                    if (audio_error) {
                        error_report_err(audio_error);
                    } else {
                        warn_report("MSM5xxx audio backend unavailable");
                    }
                } else {
                    AUD_set_active_out(s->audio_voice, false);
                }
            }
            s->ma2_audio_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                              msm5xxx_poc_ma2_audio_tick, s);
        } else if (!s->audio_ma2) {
            if (upper_nor_enabled) {
                error_report("opaque audio-aperture overlaps upper NOR");
                exit(EXIT_FAILURE);
            }
            memory_region_init_io(
                &s->audio_opaque, OBJECT(machine),
                &msm5xxx_poc_audio_opaque_ops, s,
                "msm5xxx-poc.audio-opaque", s->audio_data_offset + 1
            );
            memory_region_add_subregion(get_system_memory(), s->audio_base,
                                        &s->audio_opaque);
        }
    }
    memory_region_init_io(&s->mmio, OBJECT(machine), &msm5xxx_poc_ops, s,
                          "msm5xxx-poc.mmio", MSM5XXX_POC_MMIO_SIZE);
    memory_region_add_subregion(get_system_memory(), MSM5XXX_POC_MMIO_BASE,
                                &s->mmio);
    if (s->memory_profile_enabled) {
        qemu_register_reset(msm5xxx_poc_reset, s);
        msm5xxx_poc_reset(s);
    } else if (s->audio_enabled) {
        qemu_register_reset(msm5xxx_poc_audio_reset, s);
        msm5xxx_poc_audio_reset(s);
    }
}

static bool msm5xxx_poc_get_sbi(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->sbi_enabled;
}

static bool msm5xxx_poc_get_audio_pcm(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->audio_pcm_enabled;
}

static void msm5xxx_poc_set_audio_pcm(Object *obj, bool value, Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->audio_pcm_enabled = value;
}

static void msm5xxx_poc_set_sbi(Object *obj, bool value, Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->sbi_enabled = value;
}

static bool msm5xxx_poc_get_sbi_bootstrap_only(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->sbi_bootstrap_only;
}

static void msm5xxx_poc_set_sbi_bootstrap_only(Object *obj, bool value,
                                                Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->sbi_bootstrap_only = value;
}

static bool msm5xxx_poc_get_upper_x8_nor(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->upper_x8_nor_enabled;
}

static void msm5xxx_poc_set_upper_x8_nor(Object *obj, bool value,
                                         Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->upper_x8_nor_enabled = value;
}

static bool msm5xxx_poc_get_upper_x16_nor(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->upper_x16_nor_enabled;
}

static void msm5xxx_poc_set_upper_x16_nor(Object *obj, bool value,
                                          Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->upper_x16_nor_enabled = value;
}

static bool msm5xxx_poc_get_lcd_trace(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->lcd_trace_enabled;
}

static void msm5xxx_poc_set_lcd_trace(Object *obj, bool value, Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->lcd_trace_enabled = value;
}

static char *msm5xxx_poc_get_lcd_trace_chardev(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->lcd_trace_chardev);
}

static void msm5xxx_poc_set_lcd_trace_chardev(Object *obj, const char *value,
                                               Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    g_free(s->lcd_trace_chardev);
    s->lcd_trace_chardev = g_strdup(value);
}

static char *msm5xxx_poc_get_input_chardev(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->input_chardev);
}

static void msm5xxx_poc_set_input_chardev(Object *obj, const char *value,
                                           Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    g_free(s->input_chardev);
    s->input_chardev = g_strdup(value);
}

static char *msm5xxx_poc_get_audio_stream_chardev(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->audio_stream_chardev);
}

static void msm5xxx_poc_set_audio_stream_chardev(Object *obj,
                                                  const char *value,
                                                  Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    g_free(s->audio_stream_chardev);
    s->audio_stream_chardev = g_strdup(value);
}

static char *msm5xxx_poc_get_ready_poll(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->ready_poll_enabled || s->ready_poll_control_enabled ||
        s->ready_poll_lcd_enabled || s->ready_poll_site_count) {
        return g_strdup("");
    }
    if (s->ready_uart_rx_empty_enabled &&
        s->ready_uart_rx_empty_frame_read_pc_offset) {
        return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x:%x:%x",
                               s->ready_status_address,
                               s->ready_status_mask,
                               s->ready_pulse_address,
                               s->ready_poll_entry,
                               s->ready_status_pc_offset,
                               s->ready_pulse_set_pc_offset,
                               s->ready_pulse_clear_pc_offset,
                               s->ready_uart_rx_empty_read_pc_offset,
                               s->ready_uart_rx_empty_frame_read_pc_offset);
    }
    if (s->ready_uart_rx_empty_enabled) {
        return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x:%x",
                               s->ready_status_address,
                               s->ready_status_mask,
                               s->ready_pulse_address,
                               s->ready_poll_entry,
                               s->ready_status_pc_offset,
                               s->ready_pulse_set_pc_offset,
                               s->ready_pulse_clear_pc_offset,
                               s->ready_uart_rx_empty_read_pc_offset);
    }
    if (s->ready_status_pc_offset != 2 ||
        s->ready_pulse_set_pc_offset != 12 ||
        s->ready_pulse_clear_pc_offset != 16) {
        return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x",
                               s->ready_status_address,
                               s->ready_status_mask,
                               s->ready_pulse_address,
                               s->ready_poll_entry,
                               s->ready_status_pc_offset,
                               s->ready_pulse_set_pc_offset,
                               s->ready_pulse_clear_pc_offset);
    }
    return g_strdup_printf("%x:%x:%x:%x", s->ready_status_address,
                           s->ready_status_mask, s->ready_pulse_address,
                           s->ready_poll_entry);
}

static void msm5xxx_poc_set_ready_poll(Object *obj, const char *value,
                                       Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned status, mask, pulse, entry;
    unsigned read_offset, set_offset, clear_offset, rx_empty_offset;
    unsigned rx_empty_frame_offset;
    unsigned max_offset;
    int fields;
    char trailing;

    rx_empty_offset = 0;
    rx_empty_frame_offset = 0;
    fields = sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x:%x%c",
                    &status, &mask, &pulse, &entry, &read_offset,
                    &set_offset, &clear_offset, &rx_empty_offset,
                    &rx_empty_frame_offset, &trailing);
    if (fields != 9) {
        fields = sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x%c",
                    &status, &mask, &pulse, &entry, &read_offset,
                    &set_offset, &clear_offset, &rx_empty_offset,
                    &trailing);
    }
    if (fields != 8) {
        fields = sscanf(value, "%x:%x:%x:%x:%x:%x:%x%c",
                        &status, &mask, &pulse, &entry, &read_offset,
                        &set_offset, &clear_offset, &trailing);
    }
    if (fields != 7 && fields != 8) {
        fields = sscanf(value, "%x:%x:%x:%x%c", &status, &mask, &pulse,
                        &entry, &trailing);
        read_offset = 2;
        set_offset = 12;
        clear_offset = 16;
    }
    max_offset = MAX(read_offset, MAX(set_offset, clear_offset));
    if (fields == 8 || fields == 9) {
        max_offset = MAX(max_offset, rx_empty_offset);
    }
    if (fields == 9) {
        max_offset = MAX(max_offset, rx_empty_frame_offset);
    }
    if (s->ready_poll_enabled ||
            (fields != 4 && fields != 7 && fields != 8 && fields != 9)
            || status < MSM5XXX_POC_MSM_BASE
            || status >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE
            || pulse < MSM5XXX_POC_MSM_BASE
            || pulse >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE
            || status == pulse || !mask || mask > UINT8_MAX
            || (mask & (mask - 1)) || (entry & 1)
            || (read_offset & 1) || (set_offset & 1) || (clear_offset & 1)
            || set_offset >= clear_offset || read_offset == set_offset
            || read_offset == clear_offset || max_offset > 0x1000
            || ((fields == 8 || fields == 9) && ((rx_empty_offset & 1)
                                || rx_empty_offset <= clear_offset))
            || (fields == 9 && ((rx_empty_frame_offset & 1)
                                || rx_empty_frame_offset <= rx_empty_offset))
            || s->primary_nor_size < 22
            || entry > s->primary_nor_size - 22
            || max_offset + 2 > s->primary_nor_size
            || entry > s->primary_nor_size - max_offset - 2) {
        error_setg(errp,
                   "ready-poll must be STATUS:ONE_BIT_MASK:PULSE:ENTRY"
                   "[:READ_OFF:SET_OFF:CLEAR_OFF[:RX_EMPTY_READ_OFF"
                   "[:RX_EMPTY_FRAME_READ_OFF]]]");
        return;
    }
    s->ready_status_address = status;
    s->ready_status_mask = mask;
    s->ready_pulse_address = pulse;
    s->ready_poll_entry = entry;
    s->ready_status_pc_offset = read_offset;
    s->ready_pulse_set_pc_offset = set_offset;
    s->ready_pulse_clear_pc_offset = clear_offset;
    s->ready_uart_rx_empty_read_pc_offset = rx_empty_offset;
    s->ready_uart_rx_empty_frame_read_pc_offset = rx_empty_frame_offset;
    s->ready_uart_rx_empty_enabled = fields == 8 || fields == 9;
    s->ready_poll_enabled = true;
}

static char *msm5xxx_poc_get_ready_poll_sites(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    GString *value;
    unsigned index;

    if (!s->ready_poll_site_count) {
        return g_strdup("");
    }
    value = g_string_new(NULL);
    g_string_printf(value, "%x:%x:%x:", s->ready_status_address,
                    s->ready_status_mask, s->ready_pulse_address);
    for (index = 0; index < s->ready_poll_site_count; index++) {
        g_string_append_printf(value, "%s%x", index ? ";" : "",
                               s->ready_poll_sites[index]);
    }
    return g_string_free(value, false);
}

static void msm5xxx_poc_set_ready_poll_sites(Object *obj, const char *value,
                                              Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = NULL;
    g_auto(GStrv) entries = NULL;
    uint32_t parsed[3];
    uint32_t sites[MSM5XXX_POC_READY_POLL_MAX_SITES];
    size_t count;
    size_t index;

    if (!value || !*value || s->ready_poll_enabled) {
        goto invalid;
    }
    fields = g_strsplit(value, ":", -1);
    if (g_strv_length(fields) != 4) {
        goto invalid;
    }
    for (index = 0; index < 3; index++) {
        const char *end;
        unsigned long number;

        if (!*fields[index] ||
            qemu_strtoul(fields[index], &end, 16, &number) < 0 || *end ||
            number > UINT32_MAX) {
            goto invalid;
        }
        parsed[index] = (uint32_t)number;
    }
    entries = g_strsplit(fields[3], ";", -1);
    count = g_strv_length(entries);
    if (count < 2 || count > MSM5XXX_POC_READY_POLL_MAX_SITES ||
        parsed[0] < MSM5XXX_POC_MSM_BASE ||
        parsed[0] >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
        parsed[2] < MSM5XXX_POC_MSM_BASE ||
        parsed[2] >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
        parsed[0] == parsed[2] || !parsed[1] || parsed[1] > UINT8_MAX ||
        (parsed[1] & (parsed[1] - 1)) || s->primary_nor_size < 22) {
        goto invalid;
    }
    for (index = 0; index < count; index++) {
        const char *end;
        unsigned long number;
        size_t prior;

        if (!*entries[index] ||
            qemu_strtoul(entries[index], &end, 16, &number) < 0 || *end ||
            number > UINT32_MAX || (number & 1) ||
            number > s->primary_nor_size - 22) {
            goto invalid;
        }
        sites[index] = (uint32_t)number;
        for (prior = 0; prior < index; prior++) {
            if (sites[prior] == sites[index]) {
                goto invalid;
            }
        }
    }
    s->ready_status_address = parsed[0];
    s->ready_status_mask = parsed[1];
    s->ready_pulse_address = parsed[2];
    memcpy(s->ready_poll_sites, sites, count * sizeof(sites[0]));
    s->ready_poll_site_count = (unsigned)count;
    s->ready_poll_entry = sites[0];
    s->ready_poll_active_entry = sites[0];
    s->ready_status_pc_offset = 2;
    s->ready_pulse_set_pc_offset = 12;
    s->ready_pulse_clear_pc_offset = 16;
    s->ready_poll_enabled = true;
    return;

invalid:
    error_setg(errp,
               "ready-poll-sites must be STATUS:ONE_BIT_MASK:PULSE:"
               "ENTRY;ENTRY[;ENTRY...] for 2..%u unique even sites",
               MSM5XXX_POC_READY_POLL_MAX_SITES);
}

static char *msm5xxx_poc_get_ready_poll_control(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->ready_poll_control_enabled) {
        return g_strdup("");
    }
    if (s->ready_uart_rx_empty_enabled) {
        return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
                               s->ready_status_address, s->ready_status_mask,
                               s->ready_pulse_address, s->ready_control_address,
                               s->ready_control_value, s->ready_poll_entry,
                               s->ready_status_pc_offset,
                               s->ready_pulse_set_pc_offset,
                               s->ready_pulse_clear_pc_offset,
                               s->ready_control_pc_offset,
                               s->ready_uart_rx_empty_read_pc_offset);
    }
    return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
                           s->ready_status_address, s->ready_status_mask,
                           s->ready_pulse_address, s->ready_control_address,
                           s->ready_control_value, s->ready_poll_entry,
                           s->ready_status_pc_offset,
                           s->ready_pulse_set_pc_offset,
                           s->ready_pulse_clear_pc_offset,
                           s->ready_control_pc_offset);
}

static void msm5xxx_poc_set_ready_poll_control(Object *obj, const char *value,
                                               Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned status, mask, pulse, control, control_value, entry;
    unsigned read_offset, set_offset, clear_offset, control_offset;
    unsigned rx_empty_offset = 0;
    int fields;
    char trailing;

    fields = sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x%c",
                    &status, &mask, &pulse, &control, &control_value, &entry,
                    &read_offset, &set_offset, &clear_offset, &control_offset,
                    &rx_empty_offset, &trailing);
    if (fields != 11) {
        fields = sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x%c",
                        &status, &mask, &pulse, &control, &control_value,
                        &entry, &read_offset, &set_offset, &clear_offset,
                        &control_offset, &trailing);
    }
    if (s->ready_poll_enabled || (fields != 10 && fields != 11) ||
            status < MSM5XXX_POC_MSM_BASE ||
            status >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            pulse < MSM5XXX_POC_MSM_BASE ||
            pulse >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            control < MSM5XXX_POC_MSM_BASE ||
            control >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            status == pulse || status == control || pulse == control ||
            !mask || mask > UINT8_MAX || mask & (mask - 1) ||
            control_value > UINT8_MAX || entry & 1 ||
            read_offset & 1 || set_offset & 1 || clear_offset & 1 ||
            control_offset & 1 || read_offset >= set_offset ||
            set_offset >= clear_offset || clear_offset >= control_offset ||
            control_offset > 0x1000 ||
            (fields == 11 && ((rx_empty_offset & 1) ||
                              rx_empty_offset <= control_offset ||
                              rx_empty_offset > 0x1000 ||
                              rx_empty_offset + 2 > s->primary_nor_size ||
                              entry > s->primary_nor_size -
                                      rx_empty_offset - 2)) ||
            control_offset + 2 > s->primary_nor_size ||
            entry > s->primary_nor_size - control_offset - 2) {
        error_setg(
            errp,
            "ready-poll-control must be STATUS:ONE_BIT_MASK:PULSE:CONTROL:"
            "CONTROL_VALUE:ENTRY:READ_OFF:SET_OFF:CLEAR_OFF:CONTROL_OFF"
            "[:RX_EMPTY_READ_OFF]"
        );
        return;
    }
    s->ready_status_address = status;
    s->ready_status_mask = mask;
    s->ready_pulse_address = pulse;
    s->ready_control_address = control;
    s->ready_control_value = control_value;
    s->ready_poll_entry = entry;
    s->ready_status_pc_offset = read_offset;
    s->ready_pulse_set_pc_offset = set_offset;
    s->ready_pulse_clear_pc_offset = clear_offset;
    s->ready_control_pc_offset = control_offset;
    s->ready_uart_rx_empty_read_pc_offset = rx_empty_offset;
    s->ready_uart_rx_empty_enabled = fields == 11;
    s->ready_poll_control_enabled = true;
    s->ready_poll_enabled = true;
}

static char *msm5xxx_poc_get_lcd_status_poll(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->ready_poll_lcd_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x",
                           s->ready_status_address, s->ready_status_mask,
                           s->ready_control_address, s->ready_control_value,
                           s->ready_poll_entry, s->ready_status_pc_offset,
                           s->ready_control_pc_offset);
}

static void msm5xxx_poc_set_lcd_status_poll(Object *obj, const char *value,
                                            Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned status, mask, command, command_value, entry;
    unsigned read_offset, write_offset, i;
    char trailing;

    if (s->ready_poll_enabled ||
        sscanf(value, "%x:%x:%x:%x:%x:%x:%x%c", &status, &mask,
               &command, &command_value, &entry, &read_offset,
               &write_offset, &trailing) != 7 ||
        (status & 1) || (command & 1) || status != command + 4 ||
        !mask || mask > UINT8_MAX || (mask & (mask - 1)) ||
        command_value > UINT16_MAX || (entry & 1) ||
        (read_offset & 1) || (write_offset & 1) ||
        write_offset >= read_offset || read_offset > 0x1000 ||
        read_offset + 2 > s->primary_nor_size ||
        entry > s->primary_nor_size - read_offset - 2) {
        error_setg(
            errp,
            "lcd-status-poll must be STATUS:ONE_BIT_MASK:COMMAND:"
            "COMMAND_VALUE:ENTRY:READ_OFF:WRITE_OFF"
        );
        return;
    }
    for (i = 0; i < MSM5XXX_POC_LCD_PORTS; i++) {
        hwaddr base = msm5xxx_poc_lcd_bases[i];

        if (command >= base && command <= base + MSM5XXX_POC_LCD_SIZE - 2 &&
            status >= base && status <= base + MSM5XXX_POC_LCD_SIZE - 2) {
            break;
        }
    }
    if (i == MSM5XXX_POC_LCD_PORTS) {
        error_setg(errp, "lcd-status-poll addresses must share one LCD port");
        return;
    }
    s->ready_status_address = status;
    s->ready_status_mask = mask;
    s->ready_control_address = command;
    s->ready_control_value = command_value;
    s->ready_poll_entry = entry;
    s->ready_status_pc_offset = read_offset;
    s->ready_control_pc_offset = write_offset;
    s->ready_poll_lcd_enabled = true;
    s->ready_poll_enabled = true;
}

static char *msm5xxx_poc_get_pause_timer(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->pause_timer_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x:%x", s->pause_timer_address,
                           s->pause_timer_count_hz,
                           s->pause_timer_helper_start,
                           s->pause_timer_helper_end);
}

static void msm5xxx_poc_set_pause_timer(Object *obj, const char *value,
                                         Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned address, count_hz, helper_start, helper_end;
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x%c", &address, &count_hz,
               &helper_start, &helper_end, &trailing) != 4 ||
        s->pause_timer_enabled || (address & 1) ||
        address < MSM5XXX_POC_BOOTSTRAP_BASE ||
        address > MSM5XXX_POC_BOOTSTRAP_BASE +
                  MSM5XXX_POC_BOOTSTRAP_SIZE - MSM5XXX_POC_PAUSE_TIMER_SIZE ||
        !count_hz || count_hz > NANOSECONDS_PER_SECOND ||
        (helper_start & 1) || (helper_end & 1) ||
        helper_start >= helper_end || helper_end > s->primary_nor_size) {
        error_setg(
            errp,
            "pause-timer must be ADDRESS:COUNT_HZ:HELPER_START:HELPER_END"
        );
        return;
    }
    s->pause_timer_address = address;
    s->pause_timer_count_hz = count_hz;
    s->pause_timer_helper_start = helper_start;
    s->pause_timer_helper_end = helper_end;
    s->pause_timer_enabled = true;
}

static char *msm5xxx_poc_get_fujitsu_x16_nor(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->fujitsu_x16_nor_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x:%x:%x", s->primary_nor_size,
                           s->secondary_nor_base, s->secondary_nor_size,
                           s->secondary_nor_id0, s->secondary_nor_id1);
}

static char *msm5xxx_poc_get_primary_x16_nor(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    GString *value;
    unsigned region;

    if (!s->primary_x16_nor_enabled) {
        return g_strdup("");
    }
    value = g_string_new(NULL);
    g_string_printf(value, "%x:%x:%x:%x:%x", s->primary_x16_nor_base,
                    s->primary_x16_nor_size,
                    s->primary_x16_nor_sector_size,
                    s->primary_x16_nor_id0,
                    s->primary_x16_nor_id1);
    for (region = 0; region < s->primary_x16_nor_region_count; region++) {
        g_string_append_printf(
            value, ":%x:%x", s->primary_x16_nor_block_count[region],
            s->primary_x16_nor_region_size[region]
        );
    }
    return g_string_free(value, false);
}

static bool msm5xxx_poc_get_primary_x16_write_while_suspended(
    Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->primary_x16_write_while_suspended;
}

static void msm5xxx_poc_set_primary_x16_write_while_suspended(
    Object *obj, bool value, Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->primary_x16_write_while_suspended = value;
}

static char *msm5xxx_poc_get_record_x16_nor(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->record_x16_nor_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x", s->record_x16_nor_base,
                           s->record_x16_nor_size,
                           s->record_x16_nor_sector_size);
}

static char *msm5xxx_poc_get_intel_x16_nor(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->intel_x16_nor_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x:%x:%x", s->intel_x16_nor_base,
                           s->intel_x16_nor_size,
                           s->intel_x16_nor_sector_size,
                           s->intel_x16_nor_id0, s->intel_x16_nor_id1);
}

static char *msm5xxx_poc_get_amd_x16_nor(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->amd_x16_nor_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x:%x:%x:%x", s->intel_x16_nor_base,
                           s->intel_x16_nor_size,
                           s->intel_x16_nor_sector_size,
                           s->intel_x16_nor_id0, s->intel_x16_nor_id1,
                           s->amd_x16_nor_options);
}

static char *msm5xxx_poc_get_mapped_primary_x16_nor(Object *obj,
                                                     Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->mapped_primary_x16_nor_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x", s->mapped_primary_x16_nor_base,
                           s->mapped_primary_x16_nor_size,
                           s->mapped_primary_x16_nor_sector_size);
}

static char *msm5xxx_poc_get_matrix_input(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->matrix_input_enabled) {
        return g_strdup("");
    }
    if (s->matrix_input_host_enabled) {
        return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x:%x",
                               s->matrix_input_address,
                               s->matrix_input_sense_site,
                               s->matrix_input_no_key, s->matrix_input_reset,
                               s->matrix_input_row_register,
                               s->matrix_input_rows,
                               s->matrix_input_sideband_mask,
                               s->matrix_input_sense_bitmap);
    }
    return g_strdup_printf("%x:%x:%x:%x", s->matrix_input_address,
                           s->matrix_input_sense_site,
                           s->matrix_input_no_key, s->matrix_input_reset);
}

static char *msm5xxx_poc_get_board_status_input(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->board_status_input_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x", s->board_status_input_address,
                           s->board_status_input_mask,
                           s->board_status_input_default);
}

static char *msm5xxx_poc_get_board_revision(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->board_revision_enabled ?
        g_strdup_printf("%x:%x", s->board_revision_address,
                        s->board_revision_value) : g_strdup("");
}

static void msm5xxx_poc_set_board_revision(Object *obj, const char *value,
                                            Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned address, revision;
    char trailing;

    if (s->board_revision_enabled ||
            sscanf(value, "%x:%x%c", &address, &revision, &trailing) != 2 ||
            address & 3 || address < MSM5XXX_POC_MSM_BASE ||
            address > MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE - 4) {
        error_setg(errp, "board-revision must be aligned ADDRESS:VALUE");
        return;
    }
    s->board_revision_address = address;
    s->board_revision_value = revision;
    s->board_revision_enabled = true;
}

static char *msm5xxx_poc_get_dmd_5500(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->dmd_5500_enabled ?
        g_strdup_printf("%x:%x", s->dmd_5500_entry,
                        s->dmd_5500_expected_first) : g_strdup("");
}

static void msm5xxx_poc_set_dmd_5500(Object *obj, const char *value,
                                     Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    const char *separator = value ? strchr(value, ':') : NULL;
    const char *end;
    uint64_t entry;
    uint64_t expected_first;

    if (s->dmd_5500_enabled || !separator || separator == value ||
        !separator[1] || strchr(separator + 1, ':') ||
        qemu_strtou64(value, &end, 16, &entry) < 0 || end != separator ||
        qemu_strtou64(separator + 1, &end, 16, &expected_first) < 0 || *end ||
        entry > UINT32_MAX || expected_first > UINT16_MAX || (entry & 1) ||
        s->primary_nor_size < MSM5XXX_POC_DMD5500_ROUTINE_SIZE ||
        entry > s->primary_nor_size - MSM5XXX_POC_DMD5500_ROUTINE_SIZE) {
        error_setg(errp, "dmd-5500 must be even ENTRY:EXPECTED_FIRST");
        return;
    }
    s->dmd_5500_entry = entry;
    s->dmd_5500_expected_first = expected_first;
    s->dmd_5500_enabled = true;
}

static void msm5xxx_poc_set_board_status_input(Object *obj, const char *value,
                                                Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned address, mask, default_value;
    char trailing;

    if (sscanf(value, "%x:%x:%x%c", &address, &mask, &default_value,
               &trailing) != 3 || address < MSM5XXX_POC_MSM_BASE ||
            address >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            !mask || mask > UINT8_MAX || default_value > UINT8_MAX ||
            default_value & ~mask) {
        error_setg(errp, "board-status-input must be ADDRESS:MASK:DEFAULT");
        return;
    }
    s->board_status_input_address = address;
    s->board_status_input_mask = mask;
    s->board_status_input_default = default_value;
    s->board_status_input_enabled = true;
}

static char *msm5xxx_poc_get_audio_aperture(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->audio_enabled ?
        g_strdup_printf("%x:%x:%s", s->audio_base, s->audio_data_offset,
                        s->audio_ma2 ? "ma2" :
                        s->audio_base == 0x02840000 ? "ma5" : "opaque") :
        g_strdup("");
}

static void msm5xxx_poc_set_audio_aperture(Object *obj, const char *value,
                                            Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned base, data_offset;
    char family[7];
    char trailing;
    bool legacy, tagged, ma2, ma5, opaque;
    bool ma2_valid, ma5_valid, opaque_valid;

    legacy = sscanf(value, "%x:%x%c", &base, &data_offset, &trailing) == 2;
    tagged = sscanf(value, "%x:%x:%6[a-z0-9]%c", &base, &data_offset,
                    family, &trailing) == 3;
    ma2 = legacy || (tagged && !strcmp(family, "ma2"));
    ma5 = tagged && !strcmp(family, "ma5");
    opaque = tagged && !strcmp(family, "opaque");
    ma2_valid = ma2 && base >= 0x02001000 &&
                base <= MSM5XXX_POC_LCD_APERTURE_BASE +
                        MSM5XXX_POC_LCD_APERTURE_SIZE - 3 &&
                data_offset == 2 &&
                (base + data_offset < msm5xxx_poc_lcd_bases[3] ||
                 base >= msm5xxx_poc_lcd_bases[3] + MSM5XXX_POC_LCD_SIZE);
    /* One static call-shape profile; other MA5 apertures stay native. */
    ma5_valid = ma5 && base == 0x02840000 && data_offset == 2;
    opaque_valid = opaque && base == 0x02880000 && data_offset == 2;
    if (!ma2_valid && !ma5_valid && !opaque_valid) {
        error_setg(errp,
                   "audio-aperture must be LCD-BASE:2[:ma2] or "
                   "02840000:2:ma5 or 02880000:2:opaque");
        return;
    }
    s->audio_base = base;
    s->audio_data_offset = data_offset;
    s->audio_ma2 = ma2;
    s->audio_enabled = true;
}

static char *msm5xxx_poc_get_audio_sites(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    GString *value;
    unsigned index;

    if (!s->audio_sites_enabled) {
        return g_strdup("");
    }
    value = g_string_new("");
    for (index = 0; index < s->audio_site_count; index++) {
        g_string_append_printf(value, "%s%c%x/%x", index ? ";" : "",
                               s->audio_site_write[index] ? 'w' : 'r',
                               s->audio_site_port[index],
                               s->audio_site_pc[index]);
    }
    return g_string_free(value, false);
}

static void msm5xxx_poc_set_audio_sites(Object *obj, const char *value,
                                        Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) entries = NULL;
    bool writes[MSM5XXX_POC_AUDIO_MAX_SITES];
    uint8_t ports[MSM5XXX_POC_AUDIO_MAX_SITES];
    uint32_t pcs[MSM5XXX_POC_AUDIO_MAX_SITES];
    size_t count;
    size_t index;

    if (!value || !*value) {
        s->audio_site_count = 0;
        s->audio_sites_enabled = false;
        return;
    }
    entries = g_strsplit(value, ";", -1);
    count = g_strv_length(entries);
    if (!count || count > MSM5XXX_POC_AUDIO_MAX_SITES) {
        error_setg(errp, "audio-sites must contain 1..%u sites",
                   MSM5XXX_POC_AUDIO_MAX_SITES);
        return;
    }
    for (index = 0; index < count; index++) {
        const char *slash = strchr(entries[index], '/');
        const char *end;
        uint64_t port;
        uint64_t pc;
        size_t prior;
        bool write = entries[index][0] == 'w';

        if ((entries[index][0] != 'r' && !write) || !slash ||
            slash == entries[index] + 1 || !slash[1] ||
            !g_ascii_isxdigit(entries[index][1]) ||
            !g_ascii_isxdigit(slash[1]) ||
            qemu_strtou64(entries[index] + 1, &end, 16, &port) < 0 ||
            end != slash ||
            qemu_strtou64(slash + 1, &end, 16, &pc) < 0 || *end ||
            port >= MSM5XXX_POC_AUDIO_MAX_PORTS || pc > UINT32_MAX ||
            (pc & 1)) {
            error_setg(errp, "audio-sites must be [rw]PORT/PC;... even hex");
            return;
        }
        for (prior = 0; prior < index; prior++) {
            if (pcs[prior] == pc) {
                error_setg(errp, "audio-sites contains a duplicate site");
                return;
            }
        }
        writes[index] = write;
        ports[index] = (uint8_t)port;
        pcs[index] = (uint32_t)pc;
    }
    memcpy(s->audio_site_write, writes, count * sizeof(writes[0]));
    memcpy(s->audio_site_port, ports, count * sizeof(ports[0]));
    memcpy(s->audio_site_pc, pcs, count * sizeof(pcs[0]));
    s->audio_site_count = (unsigned)count;
    s->audio_sites_enabled = true;
}

static void msm5xxx_poc_set_matrix_input(Object *obj, const char *value,
                                          Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned address, sense_site, no_key, reset, row_register, rows;
    unsigned sideband_mask = 0, sense_bitmap = 0;
    bool host_enabled;
    char trailing;

    host_enabled = sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x%c", &address,
                          &sense_site, &no_key, &reset, &row_register, &rows,
                          &sideband_mask, &sense_bitmap, &trailing) == 8;
    if (!host_enabled &&
        sscanf(value, "%x:%x:%x:%x%c", &address, &sense_site, &no_key,
               &reset, &trailing) != 4) {
        error_setg(errp,
                   "matrix-input must be "
                   "ADDRESS:SENSE_SITE:NO_KEY:RESET"
                   "[:ROW_REGISTER:ROWS:SIDEBAND_MASK:SENSE_BITMAP]");
        return;
    }
    if (
            address < MSM5XXX_POC_MSM_BASE ||
            address >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            sense_site & 1 || sense_site >= s->primary_nor_size - 2 ||
            no_key > 0x0f || reset > UINT8_MAX ||
            (host_enabled && (row_register > 7 || !rows ||
                              rows >= UINT8_MAX ||
                              !sense_bitmap || sense_bitmap > UINT16_MAX ||
                              sense_bitmap & (1U << no_key) ||
                              sideband_mask > UINT8_MAX ||
                              (sideband_mask &&
                               (sideband_mask & 0x0f ||
                                sideband_mask & (sideband_mask - 1) ||
                                (sideband_mask & reset) != sideband_mask))))) {
        error_setg(errp,
                   "matrix-input must be "
                   "ADDRESS:SENSE_SITE:NO_KEY:RESET"
                   "[:ROW_REGISTER:ROWS:SIDEBAND_MASK:SENSE_BITMAP]");
        return;
    }
    s->matrix_input_address = address;
    s->matrix_input_sense_site = sense_site;
    s->matrix_input_no_key = no_key;
    s->matrix_input_reset = reset;
    s->matrix_input_host_enabled = host_enabled;
    if (host_enabled) {
        s->matrix_input_row_register = row_register;
        s->matrix_input_rows = rows;
        s->matrix_input_sideband_mask = sideband_mask;
        s->matrix_input_sense_bitmap = sense_bitmap;
    }
    s->matrix_input_enabled = true;
}

static void msm5xxx_poc_set_fujitsu_x16_nor(Object *obj, const char *value,
                                             Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned primary, base, size, id0, id1;
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x:%x%c", &primary, &base, &size,
               &id0, &id1, &trailing) != 5 || !primary ||
            primary > MSM5XXX_POC_NOR_MAX_SIZE || !size ||
            base >= MSM5XXX_POC_LCD_APERTURE_BASE ||
            size > MSM5XXX_POC_LCD_APERTURE_BASE - base ||
            size < 0x10000 ||
            size % 0x10000 || id0 > UINT16_MAX || id1 > UINT16_MAX ||
            (base < primary &&
             (id0 != 0x0004 || id1 != 0x005f ||
              !((size == 0x200000 && base % 0x200000 == 0) ||
                (size == 0x800000 && base % 0x800000 == 0 &&
                 (uint64_t)base + size == primary))))) {
        error_setg(errp,
                   "fujitsu-x16-nor must be PRIMARY:BASE:SIZE:ID0:ID1");
        return;
    }
    s->secondary_primary_size = primary;
    if (!s->memory_profile_enabled) {
        s->primary_nor_size = primary;
    }
    s->secondary_nor_base = base;
    s->secondary_nor_size = size;
    s->secondary_nor_id0 = id0;
    s->secondary_nor_id1 = id1;
    s->fujitsu_x16_nor_enabled = true;
}

static void msm5xxx_poc_set_primary_x16_nor(Object *obj, const char *value,
                                             Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint32_t parsed[5 + MSM5XXX_POC_NOR_MAX_REGIONS * 2];
    uint32_t block_count[MSM5XXX_POC_NOR_MAX_REGIONS] = { 0 };
    uint32_t region_size[MSM5XXX_POC_NOR_MAX_REGIONS] = { 0 };
    uint64_t region_bytes = 0;
    size_t field_count = g_strv_length(fields);
    unsigned region_count;
    unsigned index;

    if (field_count != 5 &&
            (field_count < 7 || field_count > ARRAY_SIZE(parsed) ||
             (field_count - 5) % 2)) {
        error_setg(errp,
                   "primary-x16-nor must be BASE:SIZE:SECTOR:ID0:ID1"
                   "[:COUNT:LENGTH...]");
        return;
    }
    for (index = 0; index < field_count; index++) {
        unsigned long number;

        if (qemu_strtoul(fields[index], NULL, 16, &number) < 0 ||
                number > UINT32_MAX) {
            error_setg(errp, "invalid primary-x16-nor number");
            return;
        }
        parsed[index] = number;
    }
    region_count = (field_count - 5) / 2;
    if (!parsed[0] || !parsed[1] || parsed[0] >= s->primary_nor_size ||
            parsed[1] > s->primary_nor_size - parsed[0] ||
            parsed[2] < 0x1000 || parsed[2] & (parsed[2] - 1) ||
            parsed[0] % parsed[2] || parsed[3] > UINT16_MAX ||
            parsed[4] > UINT16_MAX) {
        error_setg(errp, "invalid primary-x16-nor geometry");
        return;
    }
    for (index = 0; index < region_count; index++) {
        uint32_t count = parsed[5 + index * 2];
        uint32_t length = parsed[6 + index * 2];

        if (!count || length < 0x1000 || length & (length - 1) ||
                region_bytes % length ||
                count > (UINT64_MAX - region_bytes) / length) {
            error_setg(errp, "invalid primary-x16-nor region geometry");
            return;
        }
        block_count[index] = count;
        region_size[index] = length;
        region_bytes += (uint64_t)count * length;
    }
    if ((region_count && (parsed[2] != region_size[0] ||
                          region_bytes != parsed[1])) ||
            (!region_count && parsed[1] % parsed[2])) {
        error_setg(errp, "primary-x16-nor regions do not match SIZE");
        return;
    }
    s->primary_x16_nor_base = parsed[0];
    s->primary_x16_nor_size = parsed[1];
    s->primary_x16_nor_sector_size = parsed[2];
    s->primary_x16_nor_region_count = region_count;
    memcpy(s->primary_x16_nor_block_count, block_count,
           sizeof(block_count));
    memcpy(s->primary_x16_nor_region_size, region_size,
           sizeof(region_size));
    s->primary_x16_nor_id0 = parsed[3];
    s->primary_x16_nor_id1 = parsed[4];
    s->primary_x16_nor_enabled = true;
}

static void msm5xxx_poc_set_record_x16_nor(Object *obj, const char *value,
                                            Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned base, size, sector_size;
    char trailing;

    if (sscanf(value, "%x:%x:%x%c", &base, &size, &sector_size,
               &trailing) != 3 || !base || !size ||
            base >= s->primary_nor_size ||
            size > s->primary_nor_size - base ||
            sector_size < 0x1000 || sector_size & (sector_size - 1) ||
            base % sector_size || size % sector_size) {
        error_setg(errp, "record-x16-nor must be BASE:SIZE:SECTOR");
        return;
    }
    s->record_x16_nor_base = base;
    s->record_x16_nor_size = size;
    s->record_x16_nor_sector_size = sector_size;
    s->record_x16_nor_enabled = true;
}

static void msm5xxx_poc_set_intel_x16_nor(Object *obj, const char *value,
                                           Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned base, size, sector_size, id0, id1;
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x:%x%c", &base, &size, &sector_size,
               &id0, &id1, &trailing) != 5 ||
            base < MSM5XXX_POC_LCD_APERTURE_BASE ||
            base >= MSM5XXX_POC_LCD_APERTURE_BASE +
                    MSM5XXX_POC_LCD_APERTURE_SIZE ||
            !size || size > MSM5XXX_POC_LCD_APERTURE_BASE +
                          MSM5XXX_POC_LCD_APERTURE_SIZE - base ||
            sector_size < 0x1000 || sector_size & (sector_size - 1) ||
            base % sector_size || size % sector_size ||
            id0 > UINT16_MAX || id1 > UINT16_MAX) {
        error_setg(errp,
                   "intel-x16-nor must be BASE:SIZE:SECTOR:ID0:ID1");
        return;
    }
    s->intel_x16_nor_base = base;
    s->intel_x16_nor_size = size;
    s->intel_x16_nor_sector_size = sector_size;
    s->intel_x16_nor_id0 = id0;
    s->intel_x16_nor_id1 = id1;
    s->intel_x16_nor_enabled = true;
}

static void msm5xxx_poc_set_amd_x16_nor(Object *obj, const char *value,
                                         Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned base, size, sector_size, id0, id1, options;
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x:%x:%x%c", &base, &size, &sector_size,
               &id0, &id1, &options, &trailing) != 6 || !base || !size ||
            size > UINT32_MAX - base || sector_size < 0x1000 ||
            sector_size & (sector_size - 1) || base % sector_size ||
            size % sector_size || id0 > UINT16_MAX || id1 > UINT16_MAX ||
            options > 1) {
        error_setg(errp,
                   "amd-x16-nor must be BASE:SIZE:SECTOR:ID0:ID1:OPTIONS");
        return;
    }
    s->intel_x16_nor_base = base;
    s->intel_x16_nor_size = size;
    s->intel_x16_nor_sector_size = sector_size;
    s->intel_x16_nor_id0 = id0;
    s->intel_x16_nor_id1 = id1;
    s->amd_x16_nor_options = options;
    s->amd_x16_nor_enabled = true;
}

static void msm5xxx_poc_set_mapped_primary_x16_nor(Object *obj,
                                                    const char *value,
                                                    Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned base, size, sector_size;
    char trailing;

    if (sscanf(value, "%x:%x:%x%c", &base, &size, &sector_size,
               &trailing) != 3 || !base || !size || size > UINT32_MAX - base ||
            sector_size < 0x1000 || sector_size & (sector_size - 1) ||
            base % sector_size || size % sector_size) {
        error_setg(errp,
                   "mapped-primary-x16-nor must be BASE:SIZE:SECTOR");
        return;
    }
    s->mapped_primary_x16_nor_base = base;
    s->mapped_primary_x16_nor_size = size;
    s->mapped_primary_x16_nor_sector_size = sector_size;
    s->mapped_primary_x16_nor_enabled = true;
}

static char *msm5xxx_poc_get_rex_irq(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->rex_irq_enabled) {
        return g_strdup("");
    }
    if (s->rex_idle_address) {
        return g_strdup_printf("%x:%x:%x:%x:%x:%x",
                               s->rex_irq_status_address,
                               s->rex_irq_enable_address,
                               s->rex_irq_arm_address, s->rex_irq_mask,
                               s->rex_irq_interval, s->rex_idle_address);
    }
    return g_strdup_printf("%x:%x:%x:%x:%x", s->rex_irq_status_address,
                           s->rex_irq_enable_address, s->rex_irq_arm_address,
                           s->rex_irq_mask, s->rex_irq_interval);
}

static void msm5xxx_poc_set_rex_irq(Object *obj, const char *value,
                                     Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned status, enable, arm, mask, interval, idle;
    char trailing;
    int fields;

    fields = sscanf(value, "%x:%x:%x:%x:%x:%x%c", &status, &enable, &arm,
                    &mask, &interval, &idle, &trailing);
    if (fields != 6) {
        idle = 0;
        fields = sscanf(value, "%x:%x:%x:%x:%x%c", &status, &enable, &arm,
                        &mask, &interval, &trailing);
    }
    if (s->rex_irq_enabled || (fields != 5 && fields != 6) ||
            status < MSM5XXX_POC_MSM_BASE || status & 3 ||
            status + MSM5XXX_POC_REX_CONTROLLER_SIZE >
                MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            enable < status || enable + 2 >
                status + MSM5XXX_POC_REX_CONTROLLER_SIZE ||
            arm < MSM5XXX_POC_MSM_BASE ||
            arm >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            !mask || mask > UINT16_MAX || mask & (mask - 1) || !interval ||
            (idle && idle < 46)) {
        error_setg(errp,
                   "rex-irq must be STATUS:ENABLE:ARM:MASK:INTERVAL[:IDLE]");
        return;
    }
    s->rex_irq_status_address = status;
    s->rex_irq_enable_address = enable;
    s->rex_irq_arm_address = arm;
    s->rex_irq_mask = mask;
    s->rex_irq_interval = interval;
    s->rex_idle_address = idle;
    s->rex_irq_controller_size = MSM5XXX_POC_REX_CONTROLLER_SIZE;
    s->rex_irq_bank_count = 2;
    s->rex_irq_enabled = true;
}

static char *msm5xxx_poc_get_rex_static_c80(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->rex_irq_c80) {
        return g_strdup("");
    }
    if (s->rex_irq_bank_count == 3) {
        return g_strdup_printf(
            "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:3",
            s->rex_irq_status_address, s->rex_irq_enable_address,
            s->rex_irq_mask, s->rex_irq_interval, s->rex_irq_vector_target,
            s->rex_irq_wrapper_address, s->rex_irq_handler_slot,
            s->rex_irq_handler_address, s->rex_irq_handler_size,
            s->rex_irq_callback_slot, s->rex_irq_callback_address
        );
    }
    return g_strdup_printf(
        "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
        s->rex_irq_status_address, s->rex_irq_enable_address,
        s->rex_irq_mask, s->rex_irq_interval, s->rex_irq_vector_target,
        s->rex_irq_wrapper_address, s->rex_irq_handler_slot,
        s->rex_irq_handler_address, s->rex_irq_handler_size,
        s->rex_irq_callback_slot, s->rex_irq_callback_address
    );
}

static void msm5xxx_poc_set_rex_static_c80(Object *obj, const char *value,
                                            Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned status, enable, mask, interval, vector_target, wrapper;
    unsigned handler_slot, handler, handler_size, callback_slot, callback;
    unsigned bank_count = 2;
    bool parsed = false;
    int fields;
    int consumed = -1;

    fields = sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x%n",
                    &status, &enable, &mask, &interval, &vector_target,
                    &wrapper, &handler_slot, &handler, &handler_size,
                    &callback_slot, &callback, &bank_count, &consumed);
    if (fields == 12 && consumed >= 0 && !value[consumed]) {
        parsed = true;
    } else {
        bank_count = 2;
        consumed = -1;
        fields = sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x%n",
                        &status, &enable, &mask, &interval, &vector_target,
                        &wrapper, &handler_slot, &handler, &handler_size,
                        &callback_slot, &callback, &consumed);
        parsed = fields == 11 && consumed >= 0 && !value[consumed];
    }
    if (!parsed || s->rex_irq_enabled ||
            status != 0x03000c80 || enable != status + 0x14 ||
            (bank_count != 2 && bank_count != 3) ||
            status + (bank_count == 3 ?
                      MSM5XXX_POC_REX_C80_THREE_BANK_SIZE :
                      MSM5XXX_POC_REX_C80_CONTROLLER_SIZE) >
                MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            mask != 0x0200 || !interval ||
            vector_target & 3 || wrapper & 3 || handler & 1 ||
            handler_size == 0 || callback & 1 || handler_slot & 3 ||
            callback_slot & 3) {
        error_setg(
            errp,
            "rex-static-c80 must be "
            "STATUS:ENABLE:MASK:INTERVAL:VECTOR_TARGET:WRAPPER:"
            "HANDLER_SLOT:HANDLER:HANDLER_SIZE:CALLBACK_SLOT:CALLBACK"
            "[:BANK_COUNT]"
        );
        return;
    }
    s->rex_irq_status_address = status;
    s->rex_irq_enable_address = enable;
    s->rex_irq_mask = mask;
    s->rex_irq_interval = interval;
    s->rex_irq_vector_target = vector_target;
    s->rex_irq_wrapper_address = wrapper;
    s->rex_irq_handler_slot = handler_slot;
    s->rex_irq_handler_address = handler;
    s->rex_irq_handler_size = handler_size;
    s->rex_irq_callback_slot = callback_slot;
    s->rex_irq_callback_address = callback;
    s->rex_irq_controller_size = bank_count == 3 ?
        MSM5XXX_POC_REX_C80_THREE_BANK_SIZE :
        MSM5XXX_POC_REX_C80_CONTROLLER_SIZE;
    s->rex_irq_bank_count = bank_count;
    s->rex_irq_gate_status = MSM5XXX_POC_REX_GATE_VECTOR_WAIT;
    s->rex_irq_c80 = true;
    s->rex_irq_enabled = true;
}

static char *msm5xxx_poc_get_rex_static_read_consume(Object *obj,
                                                      Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->rex_irq_read_consume) {
        return g_strdup("");
    }
    return g_strdup_printf(
        "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
        s->rex_irq_status_address, s->rex_irq_enable_address,
        s->rex_irq_arm_address, s->rex_irq_mask, s->rex_irq_interval,
        s->rex_irq_vector_target, s->rex_irq_wrapper_address,
        s->rex_irq_handler_slot, s->rex_irq_handler_address,
        s->rex_irq_handler_size, s->rex_irq_callback_slot,
        s->rex_irq_callback_address
    );
}

static void msm5xxx_poc_set_rex_static_read_consume(
    Object *obj, const char *value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned status, enable, arm, mask, interval, vector_target, wrapper;
    unsigned handler_slot, handler, handler_size, callback_slot, callback;
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x%c",
               &status, &enable, &arm, &mask, &interval, &vector_target,
               &wrapper, &handler_slot, &handler, &handler_size,
               &callback_slot, &callback, &trailing) != 12 ||
            s->rex_irq_enabled || status != 0x03000620 ||
            enable != status + 8 || arm != 0x030006e0 ||
            status + MSM5XXX_POC_REX_CONTROLLER_SIZE >
                MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            mask != 0x0200 || !interval || vector_target & 3 || wrapper & 3 ||
            handler & 1 || handler_size == 0 || callback & 1 ||
            handler_slot & 3 || callback_slot & 3) {
        error_setg(
            errp,
            "rex-static-read-consume must be "
            "STATUS:ENABLE:ARM:MASK:INTERVAL:VECTOR_TARGET:WRAPPER:"
            "HANDLER_SLOT:HANDLER:HANDLER_SIZE:CALLBACK_SLOT:CALLBACK"
        );
        return;
    }
    s->rex_irq_status_address = status;
    s->rex_irq_enable_address = enable;
    s->rex_irq_arm_address = arm;
    s->rex_irq_mask = mask;
    s->rex_irq_interval = interval;
    s->rex_irq_vector_target = vector_target;
    s->rex_irq_wrapper_address = wrapper;
    s->rex_irq_handler_slot = handler_slot;
    s->rex_irq_handler_address = handler;
    s->rex_irq_handler_size = handler_size;
    s->rex_irq_callback_slot = callback_slot;
    s->rex_irq_callback_address = callback;
    s->rex_irq_controller_size = MSM5XXX_POC_REX_CONTROLLER_SIZE;
    s->rex_irq_bank_count = 2;
    s->rex_irq_gate_status = MSM5XXX_POC_REX_GATE_VECTOR_WAIT;
    s->rex_irq_read_consume = true;
    s->rex_irq_c80 = true;
    s->rex_irq_enabled = true;
}

static char *msm5xxx_poc_get_raw_nand_main(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->raw_nand_main_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x",
                           s->raw_nand_data_address,
                           s->raw_nand_address_address,
                           s->raw_nand_command_address,
                           s->raw_nand_data_size,
                           s->raw_nand_page_size,
                           s->raw_nand_pages_per_block,
                           s->raw_nand_bus_width);
}

static void msm5xxx_poc_set_raw_nand_main(Object *obj, const char *value,
                                           Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned data, address, command, data_size, page_size, pages_per_block;
    unsigned bus_width;
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x:%x:%x:%x%c",
               &data, &address, &command, &data_size, &page_size,
        &pages_per_block, &bus_width, &trailing) != 7 ||
        s->raw_nand_main_enabled ||
        ((data != MSM5XXX_POC_RAW_NAND_DATA_BASE ||
          address != MSM5XXX_POC_RAW_NAND_ADDRESS_BASE ||
          command != MSM5XXX_POC_RAW_NAND_COMMAND_BASE) &&
         (data != MSM5XXX_POC_RAW_NAND_LOW_PORT_DATA_BASE ||
          address != MSM5XXX_POC_RAW_NAND_LOW_PORT_ADDRESS_BASE ||
          command != MSM5XXX_POC_RAW_NAND_LOW_PORT_COMMAND_BASE)) ||
        data_size != MSM5XXX_POC_RAW_NAND_DATA_SIZE ||
        page_size != MSM5XXX_POC_RAW_NAND_PAGE_SIZE ||
        pages_per_block != MSM5XXX_POC_RAW_NAND_PAGES_PER_BLOCK ||
        bus_width != MSM5XXX_POC_RAW_NAND_BUS_WIDTH) {
        error_setg(
            errp,
            "raw-nand-main must be DATA:ADDRESS:COMMAND:DATA_SIZE:"
            "PAGE_SIZE:PAGES_PER_BLOCK:BUS_WIDTH for the closed x16 class"
        );
        return;
    }
    s->raw_nand_data_address = data;
    s->raw_nand_address_address = address;
    s->raw_nand_command_address = command;
    s->raw_nand_data_size = data_size;
    s->raw_nand_page_size = page_size;
    s->raw_nand_pages_per_block = pages_per_block;
    s->raw_nand_bus_width = bus_width;
    s->raw_nand_main_enabled = true;
}

static char *msm5xxx_poc_get_eeprom_gpio(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->eeprom_gpio_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x", s->eeprom_gpio_base,
                           s->eeprom_data_offset, s->eeprom_data_mask,
                           s->eeprom_clock_offset, s->eeprom_clock_mask,
                           s->eeprom_direction_offset, s->eeprom_capacity);
}

static void msm5xxx_poc_set_eeprom_gpio(Object *obj, const char *value,
                                         Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned base, data_offset, data_mask, clock_offset, clock_mask;
    unsigned direction_offset, capacity;
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x:%x:%x:%x%c", &base, &data_offset,
               &data_mask, &clock_offset, &clock_mask, &direction_offset,
               &capacity, &trailing) != 7 ||
            base < MSM5XXX_POC_MSM_BASE ||
            base >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            MSM5XXX_POC_EEPROM_GPIO_SIZE >
                MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE - base ||
            data_offset >= MSM5XXX_POC_EEPROM_GPIO_SIZE ||
            clock_offset >= MSM5XXX_POC_EEPROM_GPIO_SIZE ||
            direction_offset >= MSM5XXX_POC_EEPROM_GPIO_SIZE ||
            !data_mask || data_mask > UINT8_MAX ||
            data_mask & (data_mask - 1) ||
            !clock_mask || clock_mask > UINT8_MAX ||
            clock_mask & (clock_mask - 1) ||
            capacity < 0x100 || capacity > 0x10000) {
        error_setg(
            errp,
            "eeprom-24lcxx-gpio must be "
            "BASE:DATA_OFF:DATA_MASK:CLOCK_OFF:CLOCK_MASK:DIR_OFF:CAPACITY"
        );
        return;
    }
    s->eeprom_gpio_base = base;
    s->eeprom_data_offset = data_offset;
    s->eeprom_data_mask = data_mask;
    s->eeprom_clock_offset = clock_offset;
    s->eeprom_clock_mask = clock_mask;
    s->eeprom_direction_offset = direction_offset;
    s->eeprom_capacity = capacity;
    s->eeprom_gpio_enabled = true;
}

static void msm5xxx_poc_get_board_adc_value(Object *obj, Visitor *v,
                                             const char *name, void *opaque,
                                             Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t value = s->board_adc_value;

    visit_type_uint32(v, name, &value, errp);
}

static void msm5xxx_poc_set_board_adc_value(Object *obj, Visitor *v,
                                             const char *name, void *opaque,
                                             Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    if (value > UINT8_MAX) {
        error_setg(errp, "board-adc-value must be between 0 and 255");
        return;
    }
    s->board_adc_value = value;
}

static void msm5xxx_poc_get_dc0_board_adc_value(Object *obj, Visitor *v,
                                                 const char *name,
                                                 void *opaque, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t value = s->dc0_board_adc_value;

    visit_type_uint32(v, name, &value, errp);
}

static void msm5xxx_poc_set_dc0_board_adc_value(Object *obj, Visitor *v,
                                                 const char *name,
                                                 void *opaque, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    if (value > UINT8_MAX) {
        error_setg(errp, "dc0-board-adc-value must be between 0 and 255");
        return;
    }
    s->dc0_board_adc_value = value;
}

static char *msm5xxx_poc_get_memory_profile(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->memory_profile_enabled ?
        g_strdup_printf("%x:%x:%x", s->primary_nor_size, s->ram_base,
                        s->initial_sp) : g_strdup("");
}

static void msm5xxx_poc_set_memory_profile(Object *obj, const char *value,
                                            Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned flash_size, ram_base, initial_sp;
    char trailing;

    if (sscanf(value, "%x:%x:%x%c", &flash_size, &ram_base, &initial_sp,
               &trailing) != 3 || flash_size < 0x1000 ||
            flash_size > MSM5XXX_POC_NOR_MAX_SIZE || flash_size > ram_base ||
            ram_base < MSM5XXX_POC_RAM_BASE || ram_base >= 0x02000000 ||
            ram_base & 0xfff || initial_sp < ram_base || initial_sp & 3) {
        error_setg(errp,
                   "memory-profile must be FLASH_SIZE:RAM_BASE:INITIAL_SP");
        return;
    }
    s->primary_nor_size = flash_size;
    s->ram_base = ram_base;
    s->initial_sp = initial_sp;
    s->memory_profile_enabled = true;
}

static void msm5xxx_poc_instance_init(Object *obj)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    s->sbi_enabled = false;
    s->sbi_bootstrap_only = false;
    s->lcd_trace_enabled = false;
    s->audio_pcm_enabled = true;
    s->ram_base = MSM5XXX_POC_RAM_BASE;
    s->board_adc_value = UINT8_MAX + 1;
    s->dc0_board_adc_value = UINT8_MAX + 1;
    s->primary_nor_size = MSM5XXX_POC_NOR_SIZE;
    s->rex_irq_controller_size = MSM5XXX_POC_REX_CONTROLLER_SIZE;
    s->rex_irq_bank_count = 2;
}

static void msm5xxx_poc_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    machine_add_audiodev_property(mc);
    mc->desc = "MSM5xxx ARMv4T CPU/MMIO boundary probe";
    mc->init = msm5xxx_poc_init;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("ti925t");
    mc->default_cpus = 1;
    mc->max_cpus = 1;
    mc->default_ram_size = 16 * MiB;
    mc->default_ram_id = "msm5xxx-poc.ram";
    object_class_property_add_bool(oc, "sbi", msm5xxx_poc_get_sbi,
                                   msm5xxx_poc_set_sbi);
    object_class_property_set_description(
        oc, "sbi", "Enable detector-approved runtime-admitted SBI registers");
    object_class_property_add_bool(
        oc, "sbi-bootstrap-only", msm5xxx_poc_get_sbi_bootstrap_only,
        msm5xxx_poc_set_sbi_bootstrap_only
    );
    object_class_property_set_description(
        oc, "sbi-bootstrap-only",
        "Reject post-bootstrap SBI semantics after exact validation"
    );
    object_class_property_add_bool(oc, "lcd-trace", msm5xxx_poc_get_lcd_trace,
                                   msm5xxx_poc_set_lcd_trace);
    object_class_property_set_description(
        oc, "lcd-trace", "Capture LCD writes for batched host display replay");
    object_class_property_add_str(oc, "lcd-trace-chardev",
                                  msm5xxx_poc_get_lcd_trace_chardev,
                                  msm5xxx_poc_set_lcd_trace_chardev);
    object_class_property_set_description(
        oc, "lcd-trace-chardev", "Stream LCD writes in 33 ms host batches");
    object_class_property_add_str(oc, "input-chardev",
                                  msm5xxx_poc_get_input_chardev,
                                  msm5xxx_poc_set_input_chardev);
    object_class_property_set_description(
        oc, "input-chardev", "Exchange host input and acknowledgements");
    object_class_property_add_str(oc, "audio-stream-chardev",
                                  msm5xxx_poc_get_audio_stream_chardev,
                                  msm5xxx_poc_set_audio_stream_chardev);
    object_class_property_set_description(
        oc, "audio-stream-chardev", "Stream native M5P2 PCM chunks");
    object_class_property_add_bool(oc, "audio-pcm",
                                   msm5xxx_poc_get_audio_pcm,
                                   msm5xxx_poc_set_audio_pcm);
    object_class_property_set_description(
        oc, "audio-pcm", "Enable host PCM synthesis and output");
    object_class_property_add_str(oc, "memory-profile",
                                  msm5xxx_poc_get_memory_profile,
                                  msm5xxx_poc_set_memory_profile);
    object_class_property_set_description(
        oc, "memory-profile",
        "Detector-provided flash size, RAM base, and initial SP");
    object_class_property_add_str(oc, "ready-poll",
                                  msm5xxx_poc_get_ready_poll,
                                  msm5xxx_poc_set_ready_poll);
    object_class_property_set_description(
        oc, "ready-poll", "Detector-provided byte-ready/pulse protocol");
    object_class_property_add_str(oc, "ready-poll-sites",
                                  msm5xxx_poc_get_ready_poll_sites,
                                  msm5xxx_poc_set_ready_poll_sites);
    object_class_property_set_description(
        oc, "ready-poll-sites",
        "Detector-provided shared byte-ready/pulse protocol sites");
    object_class_property_add_str(oc, "ready-poll-control",
                                  msm5xxx_poc_get_ready_poll_control,
                                  msm5xxx_poc_set_ready_poll_control);
    object_class_property_set_description(
        oc, "ready-poll-control",
        "Detector-provided byte-ready/pulse/control protocol");
    object_class_property_add_str(oc, "lcd-status-poll",
                                  msm5xxx_poc_get_lcd_status_poll,
                                  msm5xxx_poc_set_lcd_status_poll);
    object_class_property_set_description(
        oc, "lcd-status-poll",
        "Detector-provided LCD halfword busy-status protocol");
    object_class_property_add_str(oc, "pause-timer",
                                  msm5xxx_poc_get_pause_timer,
                                  msm5xxx_poc_set_pause_timer);
    object_class_property_set_description(
        oc, "pause-timer",
        "Detector-scoped noninterruptible pause-timer writes");
    object_class_property_add_str(oc, "board-revision",
                                  msm5xxx_poc_get_board_revision,
                                  msm5xxx_poc_set_board_revision);
    object_class_property_set_description(
        oc, "board-revision", "Detector-provided fixed revision readback");
    object_class_property_add_str(oc, "dmd-5500",
                                  msm5xxx_poc_get_dmd_5500,
                                  msm5xxx_poc_set_dmd_5500);
    object_class_property_set_description(
        oc, "dmd-5500", "Detector-provided exact DMD completion protocol");
    object_class_property_add_str(oc, "board-status-input",
                                  msm5xxx_poc_get_board_status_input,
                                  msm5xxx_poc_set_board_status_input);
    object_class_property_set_description(
        oc, "board-status-input",
        "Detector-provided persistent board-status bits");
    object_class_property_add_str(oc, "matrix-input",
                                  msm5xxx_poc_get_matrix_input,
                                  msm5xxx_poc_set_matrix_input);
    object_class_property_set_description(
        oc, "matrix-input", "Detector-provided direct matrix input state");
    object_class_property_add_str(oc, "audio-aperture",
                                  msm5xxx_poc_get_audio_aperture,
                                  msm5xxx_poc_set_audio_aperture);
    object_class_property_set_description(
        oc, "audio-aperture", "Detector-provided audio transport aperture");
    object_class_property_add_str(oc, "audio-sites",
                                  msm5xxx_poc_get_audio_sites,
                                  msm5xxx_poc_set_audio_sites);
    object_class_property_set_description(
        oc, "audio-sites", "Detector-provided audio bus access PCs");
    object_class_property_add_str(oc, "primary-x16-nor",
                                  msm5xxx_poc_get_primary_x16_nor,
                                  msm5xxx_poc_set_primary_x16_nor);
    object_class_property_set_description(
        oc, "primary-x16-nor",
        "Detector-provided writable primary x16 NOR tail");
    object_class_property_add_bool(
        oc, "primary-x16-write-while-suspended",
        msm5xxx_poc_get_primary_x16_write_while_suspended,
        msm5xxx_poc_set_primary_x16_write_while_suspended);
    object_class_property_set_description(
        oc, "primary-x16-write-while-suspended",
        "Permit primary x16 NOR programming during erase suspend");
    object_class_property_add_str(oc, "record-x16-nor",
                                  msm5xxx_poc_get_record_x16_nor,
                                  msm5xxx_poc_set_record_x16_nor);
    object_class_property_set_description(
        oc, "record-x16-nor",
        "Detector-provided descriptor-mapped Record x16 NOR");
    object_class_property_add_str(oc, "intel-x16-nor",
                                  msm5xxx_poc_get_intel_x16_nor,
                                  msm5xxx_poc_set_intel_x16_nor);
    object_class_property_set_description(
        oc, "intel-x16-nor",
        "Detector-provided external direct-command Intel x16 NOR");
    object_class_property_add_str(oc, "amd-x16-nor",
                                  msm5xxx_poc_get_amd_x16_nor,
                                  msm5xxx_poc_set_amd_x16_nor);
    object_class_property_set_description(
        oc, "amd-x16-nor",
        "Detector-provided RAM-overlap direct-command AMD x16 NOR");
    object_class_property_add_str(oc, "mapped-primary-x16-nor",
                                  msm5xxx_poc_get_mapped_primary_x16_nor,
                                  msm5xxx_poc_set_mapped_primary_x16_nor);
    object_class_property_set_description(
        oc, "mapped-primary-x16-nor",
        "Detector-provided mapped primary Intel x16 NOR aperture");
    object_class_property_add_str(oc, "fujitsu-x16-nor",
                                  msm5xxx_poc_get_fujitsu_x16_nor,
                                  msm5xxx_poc_set_fujitsu_x16_nor);
    object_class_property_set_description(
        oc, "fujitsu-x16-nor",
        "Detector-provided primary/secondary Fujitsu x16 NOR layout");
    object_class_property_add_bool(oc, "upper-x8-nor",
                                   msm5xxx_poc_get_upper_x8_nor,
                                   msm5xxx_poc_set_upper_x8_nor);
    object_class_property_set_description(
        oc, "upper-x8-nor",
        "Enable the detector-admitted fixed upper x8 AMD NOR class");
    object_class_property_add_bool(oc, "upper-x16-nor",
                                   msm5xxx_poc_get_upper_x16_nor,
                                   msm5xxx_poc_set_upper_x16_nor);
    object_class_property_set_description(
        oc, "upper-x16-nor",
        "Enable the detector-admitted fixed upper x16 AMD NOR class");
    object_class_property_add_str(oc, "rex-irq", msm5xxx_poc_get_rex_irq,
                                  msm5xxx_poc_set_rex_irq);
    object_class_property_set_description(
        oc, "rex-irq", "Detector-provided REX periodic IRQ route");
    object_class_property_add_str(oc, "rex-static-c80",
                                  msm5xxx_poc_get_rex_static_c80,
                                  msm5xxx_poc_set_rex_static_c80);
    object_class_property_set_description(
        oc, "rex-static-c80",
        "Explicit detector- and runtime-gated C80 periodic IRQ route");
    object_class_property_add_str(
        oc, "rex-static-read-consume",
        msm5xxx_poc_get_rex_static_read_consume,
        msm5xxx_poc_set_rex_static_read_consume);
    object_class_property_set_description(
        oc, "rex-static-read-consume",
        "Explicit detector-, arm-, and runtime-gated read-consume IRQ route");
    object_class_property_add_str(oc, "raw-nand-main",
                                  msm5xxx_poc_get_raw_nand_main,
                                  msm5xxx_poc_set_raw_nand_main);
    object_class_property_set_description(
        oc, "raw-nand-main",
        "Detector-provided main-area-only small-page x16 NAND route");
    object_class_property_add_str(oc, "eeprom-24lcxx-gpio",
                                  msm5xxx_poc_get_eeprom_gpio,
                                  msm5xxx_poc_set_eeprom_gpio);
    object_class_property_set_description(
        oc, "eeprom-24lcxx-gpio",
        "Detector-provided bit-banged 24LCxx GPIO route");
    object_class_property_add(oc, "board-adc-value", "uint32",
                              msm5xxx_poc_get_board_adc_value,
                              msm5xxx_poc_set_board_adc_value, NULL, NULL);
    object_class_property_set_description(
        oc, "board-adc-value", "Detector-provided board ADC byte");
    object_class_property_add(oc, "dc0-board-adc-value", "uint32",
                              msm5xxx_poc_get_dc0_board_adc_value,
                              msm5xxx_poc_set_dc0_board_adc_value,
                              NULL, NULL);
    object_class_property_set_description(
        oc, "dc0-board-adc-value", "Detector-provided DC0 board ADC byte");
}

static const TypeInfo msm5xxx_poc_machine_typeinfo = {
    .name = TYPE_MSM5XXX_POC_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(MSM5xxxPOCMachineState),
    .instance_init = msm5xxx_poc_instance_init,
    .class_init = msm5xxx_poc_machine_class_init,
    .interfaces = arm_machine_interfaces,
};

static void msm5xxx_poc_machine_register_types(void)
{
    type_register_static(&msm5xxx_24lcxx_typeinfo);
    type_register_static(&msm5xxx_poc_machine_typeinfo);
}

type_init(msm5xxx_poc_machine_register_types)
