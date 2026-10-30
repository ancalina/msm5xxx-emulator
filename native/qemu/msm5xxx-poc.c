/*
 * Minimal MSM5xxx CPU/MMIO boundary probe.
 *
 * This is an experimental QEMU machine used to measure whether TCG can
 * preserve ARMv4T privileged state while servicing detector-admitted native
 * MSM5xxx device classes. Unclassified behavior retains native backing.
 * Modified 2026-10-01: admit the optional SBI ADC setup transaction.
 * Modified 2026-10-02: add opt-in provisional audio request readback.
 * Modified 2026-10-04: add opt-in bounded command-2 packet consumption.
 * Modified 2026-10-16: add a default-off, one-packet native search transport probe.
 * Modified 2026-10-17: consume bounded encoder FIFO packets without changing backing.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <math.h>
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/audio.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qemu/units.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "exec/cpu-common.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "tcg/insn-start-words.h"
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
#include "system/runstate.h"
#include "system/qtest.h"
#include "target/arm/cpu.h"
#include "target/arm/cpu-qom.h"
#include "msm5xxx-search2.h"
#include "msm5xxx-ma5-audio.h"
#include "msm5xxx-small-page-nand.h"
#include "msm5xxx-spi-nv.h"
#include "msm5xxx-protected-nor.h"
#include "msm5xxx-ma5-wt-engine.h"
#include "msm5xxx-ma5-pcm-output.h"

#include "msm5xxx-ma2-audio.h"
#include "msm5xxx-audio-synth.h"
#include "msm5xxx-audio-request.h"

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
#define MSM5XXX_POC_HIGH_RAM_BASE 0x14000000
#define MSM5XXX_POC_HIGH_RAM_END 0x14800000
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
#define MSM5XXX_POC_AUDIO_MAX_PORTS 256
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
#define MSM5XXX_POC_BOARD_STATUS_TELEMETRY 10
#define MSM5XXX_POC_HOST_BOARD_STATUS 0x81
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

typedef struct MSM5xxxPOCReadyPollSite {
    uint32_t entry;
    uint32_t read_offset;
    uint32_t set_offset;
    uint32_t clear_offset;
    uint32_t rx_empty_offset;
    uint32_t rx_frame_offset;
} MSM5xxxPOCReadyPollSite;

typedef struct {
    MSM5xxxPOCMachineState *machine;
    unsigned index;
} MSM5xxxPOCDMD5100Port;

enum {
    DMD5100_IDLE, DMD5100_HOLD, DMD5100_PROGRAM, DMD5100_FULL,
    DMD5100_MODE, DMD5100_EVEN, DMD5100_EVEN_DONE, DMD5100_ODD,
    DMD5100_ODD_DONE, DMD5100_CLOSED, DMD5100_REJECTED
};
static const hwaddr dmd5100_ports[] = {
    0x0300004c, 0x03000050, 0x0300005c, 0x030007e8, 0x030007ec
};

struct MSM5xxxPOCMachineState {
    MachineState parent_obj;

    ARMCPU *cpu;
    uint32_t reset_callbacks;
    uint32_t last_reset_callback_pc;
    uint32_t ram_base;
    uint32_t initial_sp;
    uint32_t watchdog_register;
    uint32_t watchdog_mask;
    uint32_t watchdog_timeout_ms;
    uint8_t watchdog_backing;
    bool watchdog_high;
    bool watchdog_armed;
    int64_t watchdog_last_edge_ns;
    QEMUTimer *watchdog_timer;
    MemoryRegion watchdog_region;
    bool memory_profile_enabled;
    uint32_t ram_reserved_base, ram_reserved_size;
    MemoryRegion ram_low_alias, ram_high_alias;
    MemoryRegion nor;
    uint32_t primary_nor_size;
    bool whole_primary_x16_enabled, whole_primary_x16_realized;
    uint32_t whole_primary_x16_size, whole_primary_x16_sector;
    uint16_t whole_primary_x16_id0, whole_primary_x16_id1;
    uint32_t whole_primary_x16_region_count;
    uint32_t whole_primary_x16_block_count[MSM5XXX_POC_NOR_MAX_REGIONS];
    uint32_t whole_primary_x16_region_size[MSM5XXX_POC_NOR_MAX_REGIONS];
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
    bool record_x16_nor_explicit_ids;
    uint16_t record_x16_nor_id0;
    uint16_t record_x16_nor_id1;
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
    bool small_nand_enabled;
    uint32_t small_nand_data, small_nand_ale, small_nand_cle;
    uint32_t small_nand_ready_address, small_nand_ready_mask;
    uint32_t small_nand_idle_reset_ns;
    MSM5xxxSmallPageNand small_nand;
    BlockBackend *small_nand_blk;
    uint8_t *small_nand_raw;
    QEMUTimer *small_nand_timer;
    MemoryRegion small_nand_io, small_nand_ready_io;
    uint64_t small_nand_persisted, small_nand_errors, small_nand_persists;
    uint64_t small_nand_trace_count;
    uint32_t small_nand_ready_trace_count;
    MemoryRegion sbi;
    MemoryRegion decoder_output_region, combiner_position_region;
    char *decoder_sync_description;
    bool decoder_sync_enabled, decoder_sync_have_frame, combiner_position_latched;
    uint32_t combiner_position_reader, combiner_roll_isr, decoder_sync_consumer;
    uint64_t decoder_sync_epoch, decoder_sync_roll, decoder_sync_frames;
    uint64_t decoder_sync_reads, decoder_sync_overruns, combiner_position_latches;
    uint16_t decoder_sync_words[14], combiner_position_snapshot;
    uint8_t decoder_sync_message[MSM5XXX_SYNC_MAX_BYTES], decoder_sync_message_length;
    unsigned decoder_sync_cursor;
    char *decoder_traffic_description;
    char *decoder_traffic_frame_description;
    bool decoder_traffic_enabled;
    bool decoder_traffic_frame_enabled;
    bool decoder_traffic_response_enabled, decoder_traffic_response_seen;
    MSM5xxxTrafficResponse decoder_traffic_response;
    uint64_t decoder_traffic_acks, decoder_traffic_ack_rejections;
    uint64_t decoder_traffic_response_frames;
    bool traffic_service_enabled, traffic_service_request_valid, traffic_service_tx_seen;
    uint32_t traffic_service_route[4], traffic_service_reject_reason;
    uint8_t traffic_service_request_sequence, traffic_service_next_sequence;
    uint8_t traffic_service_revision;
    uint16_t traffic_service_option;
    uint64_t traffic_service_requests, traffic_service_rejections, traffic_service_duplicates;
    char *traffic_service_description;
    uint8_t tx_traffic_bytes[24], tx_traffic_length;
    bool tx_traffic_open;
    uint8_t decoder_traffic_frame[24];
    uint32_t decoder_traffic_route[8], decoder_traffic_reject_reason;
    uint16_t decoder_traffic_words[MSM5XXX_TRAFFIC_MAX_WORDS];
    unsigned decoder_traffic_count;
    uint64_t decoder_traffic_frames, decoder_traffic_reads;
    uint64_t decoder_traffic_crc_passes, decoder_traffic_crc_failures;
    uint64_t decoder_traffic_frame_rejections;
    char *decoder_paging_description;
    bool decoder_paging_enabled, decoder_paging_started;
    uint32_t decoder_paging_isr, decoder_paging_reader, decoder_paging_status;
    uint32_t decoder_paging_initializer, decoder_paging_count, decoder_paging_consumer;
    uint32_t decoder_paging_cache, decoder_paging_layout;
    uint8_t decoder_paging_messages[MSM5XXX_PAGING_MESSAGES][MSM5XXX_PAGING_MAX_BYTES];
    uint8_t decoder_paging_lengths[MSM5XXX_PAGING_MESSAGES];
    uint64_t decoder_radio_tick, decoder_paging_frames, decoder_paging_bootstraps;
    MemoryRegion decoder_init_region;
    QEMUTimer *decoder_init_timer;
    char *decoder_init_description;
    bool decoder_init_enabled, decoder_init_active, decoder_init_done;
    uint32_t decoder_init_reader, decoder_init_write_pc, decoder_init_isr;
    uint32_t decoder_init_mask, decoder_init_reject_reason;
    uint64_t decoder_init_delay_ns, decoder_init_fires, decoder_init_rejections;
    char *tx_init_description;
    QEMUTimer *tx_init_timer;
    uint32_t tx_init_route[7];
    uint64_t tx_init_delay_ns, tx_init_fires, tx_init_cancels;
    uint64_t tx_frame_period_ns, tx_frame_fires, tx_frame_overruns;
    int64_t tx_init_deadline;
    bool tx_init_enabled, tx_init_active, tx_init_seen, tx_init_owned_pending;
    bool tx_frame_running;
    uint8_t tx_init_last_mode;
    MemoryRegion tx_fifo_region;
    MSM5xxxAccess tx_access;
    uint32_t tx_fifo_mode_base, tx_fifo_writer;
    uint32_t tx_fifo_reject_reason, tx_fifo_reject_pc;
    uint64_t tx_fifo_rejections;
    uint8_t tx_fifo_bytes[12], tx_fifo_length;
    bool tx_fifo_enabled, tx_fifo_open, tx_fifo_rejected;
    MSM5xxxPagingStream access_paging;
    uint64_t access_ack_queued, access_ack_encoded, access_ack_rejections;
    uint64_t access_ack_resets;
    uint32_t access_ack_reject_reason;
    uint8_t access_station_sequence, access_assignment_code;
    bool access_response_probe, access_response_blocked;
    MSM5xxxFingers fingers;
    MemoryRegion finger_region;
    char *finger_description;
    bool finger_enabled;
    uint32_t finger_read_pc, finger_masks_i, finger_masks_q;
    uint64_t finger_latches, finger_reads, finger_fallback_writes;
    MemoryRegion search1_region;
    QEMUTimer *search1_timer;
    char *search1_description;
    bool search1_enabled, search1_active, search1_have_results, search1_rejected;
    uint32_t search1_first_store, search1_result_loop;
    uint32_t search1_position, search1_pending_position;
    uint8_t search1_packet[MSM5XXX_SEARCH1_PARAMETERS];
    bool search1_conditional, search1_config_valid;
    bool search1_config_known;
    uint8_t search1_verified_config[4];
    unsigned search1_sub, search1_selector;
    uint16_t search1_results[8], search1_pending_results[8];
    uint64_t search1_submits, search1_completions, search1_result_reads;
    uint64_t search1_rejections;
    uint32_t search1_reject_reason, search1_reject_pc;
    uint32_t search1_reject_access, search1_reject_value;
    uint32_t search1_abort_pc;
    uint64_t search1_aborts;
    MemoryRegion search2_region;
    MSM5xxxSearch2 search2;
    QEMUTimer *search2_timer;
    char *search2_probe_description;
    char *search2_virtual_description;
    bool search2_virtual;
    uint32_t search2_position, search2_pending_position, search2_pilot_phase;
    uint16_t search2_peak_energy;
    uint32_t search2_route[9];
    uint16_t search2_samples[8];
    uint64_t search2_delay_ns;
    uint64_t search2_submits, search2_completions, search2_result_reads;
    uint64_t search2_rejections;
    uint32_t search2_reject_pc, search2_reject_value;
    uint32_t search2_reject_reason, search2_reject_expected_pc;
    bool search2_probe_done, search2_probe_rejected;
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
    bool dmd5100_enabled, dmd5100_mapped, dmd5100_ram_verified;
    bool dmd5100_barrier, dmd5100_half_pending;
    uint32_t dmd5100_entry, dmd5100_descriptor, dmd5100_payload, dmd5100_count;
    uint32_t dmd5100_phase, dmd5100_pairs, dmd5100_even_reads, dmd5100_odd_reads;
    uint64_t dmd5100_rejections;
    bool dmd5100_first_rejection, dmd5100_rejection_write, dmd5100_rejection_value_valid;
    uint32_t dmd5100_rejection_port, dmd5100_rejection_size, dmd5100_rejection_result;
    uint32_t dmd5100_rejection_phase, dmd5100_rejection_pairs;
    uint32_t dmd5100_rejection_pc, dmd5100_rejection_lr, dmd5100_rejection_regs[8];
    bool dmd5100_rejection_recovered_pc_valid;
    uint32_t dmd5100_rejection_recovered_pc;
    uint32_t dmd5100_rejection_cpsr, dmd5100_rejection_fcse_ns, dmd5100_rejection_fcse_s;
    uint64_t dmd5100_rejection_offset, dmd5100_rejection_value, dmd5100_rejection_sctlr;
    uint16_t *dmd5100_even, *dmd5100_odd;
    MemoryRegion dmd5100_region[5];
    MSM5xxxPOCDMD5100Port dmd5100_port[5];
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
    bool sbi_raw_input_enabled, sbi_raw_input_realized, sbi_raw_input_registered;
    uint32_t sbi_raw_input_pc, sbi_raw_input_last_pc;
    uint8_t sbi_raw_input_mask, sbi_raw_input_value;
    const char *sbi_raw_input_reject_reason;
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
    bool uart_console_enabled, uart_console_mapped, uart_console_rejected;
    bool uart_console_realized;
    bool uart_console_probe_enabled, uart_console_probe_lf, uart_console_probe_rx_empty;
    bool uart_console_probe_ffcc;
    bool uart_console_rearm_enabled, uart_console_rearm_mapped, uart_console_rearm_pending;
    uint8_t uart_console_rearm_step, uart_console_rearm_ready;
    uint32_t uart_console_rearm_pc[2], uart_console_rearm_sr;
    uint32_t uart_console_rearm_root_lr, uart_console_rearm_config_lr;
    uint64_t uart_console_rearms;
    MemoryRegion uart_console_rearm_region;
    /* FF/DD seals at 5; FF/CC/99 adds LF/RX at 5, drains/config at 6/7, seal 8. */
    uint8_t uart_console_probe_stage, uart_console_probe_step, uart_console_probe_drains;
    bool uart_console_initialized, uart_console_tx_enabled, uart_console_rx_enabled;
    bool uart_console_empty;
    uint32_t uart_console_base;
    uint8_t uart_console_config, uart_console_cr_step;
    uint8_t uart_console_mr2, uart_console_csr, uart_console_imr;
    uint8_t uart_console_register_width, uart_console_tfwr_width, uart_console_expected_csr;
    uint16_t uart_console_mr1, uart_console_tfwr, uart_console_rfwr;
    uint64_t uart_console_accepted;
    uint8_t uart_console_last_byte;
    const char *uart_console_reject_reason;
    MemoryRegion uart_console_region;
    bool ready_poll_enabled;
    bool ready_poll_control_enabled;
    bool ready_poll_lcd_enabled;
    uint32_t ready_status_address;
    uint8_t ready_status_mask;
    uint32_t ready_pulse_address;
    uint32_t ready_control_address;
    uint16_t ready_control_value;
    uint32_t ready_poll_entry;
    MSM5xxxPOCReadyPollSite ready_poll_sites[MSM5XXX_POC_READY_POLL_MAX_SITES];
    bool ready_poll_sites_explicit;
    unsigned ready_poll_site_count;
    uint32_t ready_poll_active_entry;
    uint32_t ready_poll_active_set_offset;
    uint32_t ready_poll_active_clear_offset;
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
    uint32_t board_status_input_descriptor;
    uint8_t board_status_input_mask;
    uint8_t board_status_input_default;
    uint8_t board_status_input_backing;
    uint8_t board_status_input_level;
    uint32_t board_status_input_events;
    uint32_t board_status_input_rejections;
    bool matrix_input_gpio;
    uint32_t matrix_input_gpio_port[3];
    uint8_t matrix_input_gpio_mask[3];
    bool matrix_input_halfword;
    bool matrix_input_low5;
    bool matrix_input_row734, matrix_row734_boot_seen;
    uint32_t matrix_row734_presence2, matrix_row734_sense2, matrix_row734_boot_site;
    uint32_t matrix_row734_row_tables[2];
    uint64_t matrix_row734_boot_reads, matrix_row734_normal_reads;
    uint8_t matrix_row734_reason;
    bool matrix_input_loop;
    uint32_t matrix_input_contact_site;
    bool experimental_matrix_contact_enabled;
    uint32_t experimental_matrix_contact_site;
    uint8_t experimental_matrix_contact_level;
    bool experimental_matrix_status_enabled;
    uint32_t experimental_matrix_status_site;
    uint8_t experimental_matrix_status_level;
    uint16_t matrix_input_row_mask; /* Zero retains the legacy six-row class. */
    uint32_t matrix_input_descriptor;
    uint32_t matrix_input_presence_site;
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
    uint32_t matrix_input_sense_bitmap;
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
    uint32_t audio_irq_route[10];
    bool audio_irq_configured;
    bool audio_irq_asserted;
    uint32_t audio_irq_gate_status;
    uint32_t audio_irq_assertions;
    bool audio_enabled;
    bool audio_ma2;
    bool audio_ma5;
    bool audio_shared_lcd;
    uint64_t ma5_byte_ns;
    uint64_t ma5_clki_hz;
    uint64_t ma5_target_rate_hz;
    bool ma5_pcm_output_enabled;
    bool ma5_pcm_output_failed;
    bool ma5_pcm_output_reported;
    bool ma5_pcm_resync_pending;
    bool ma5_pcm_initialized;
    uint64_t ma5_pcm_timeline_gaps;
    uint64_t ma5_fm_admitted_logged, ma5_fm_skipped_logged;
    uint64_t ma5_fm_wave_uploads_logged, ma5_fm_wave_rejects_logged;
    int16_t ma5_pcm_storage[MSM5XXX_AUDIO_MAX_FRAMES][2];
    MSM5xxxMA5PCMOutput ma5_pcm_output;
    MA5WTEngine *ma5_wt_engine;
    MSM5xxxMA5Device ma5_device;
    uint32_t ma5_irq_route[18];
    bool ma5_irq_configured, ma5_irq_qualified, ma5_irq_level;
    uint16_t ma5_gpio_pending[3], ma5_parent_pending;
    uint32_t ma5_commit_traces;
    uint32_t ma5_irq_gate_status, ma5_irq_assertions, ma5_gpio_acks, ma5_parent_acks, ma5_chip_reads;
    MemoryRegion ma5_trigger_region;
    bool audio_pcm_enabled;
    bool experimental_audio_readback;
    bool audio_readback_rejection_reported;
    MSM5xxxAudioReadback audio_readback;
    uint32_t audio_packet_begin;
    MSM5xxxAudioPacketSink audio_packet_sink;
    uint8_t audio_packet_index, audio_packet_control;
    uint8_t audio_packet_mode, audio_packet_init[4][2];
    uint8_t audio_packet_init_valid;
    bool audio_packet_fault, audio_packet_reported, audio_packet_gate_reported;
    bool audio_packet_fifo_empty_known;
    bool audio_packet_sequence, audio_packet_reset_armed, audio_packet_ready;
    bool audio_packet_clear_pulse, audio_packet_clear_armed;
    unsigned audio_packet_trace_count;
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
    guint audio_pcm_watch;
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
    QEMUTimer *ma5_audio_timer;
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
    bool boot_keysense_enabled, boot_keysense_realized, boot_keysense_rejected;
    uint32_t boot_keysense_pc[3], boot_keysense_phase, boot_keysense_reason;
    uint64_t boot_keysense_reads, boot_keysense_releases, boot_keysense_rejections;
    MemoryRegion boot_keysense_region;
    uint32_t spi_nv_source_geometry;
    bool spi_nv_geometry_ready;
    uint64_t spi_nv_geometry_mismatches;
    uint32_t spi_nv_geometry_reason;
    uint64_t spi_nv_write_ns;
    MSM5xxxSPINV spi_nv;
    MemoryRegion spi_nv_gpio;
    BlockBackend *spi_nv_blk;
    QEMUTimer *spi_nv_timer;
    bool spi_nv_qualified, spi_nv_revoked, spi_nv_realized;
    uint32_t spi_nv_route_reason, spi_nv_reject_pc, spi_nv_reject_address;
    unsigned spi_nv_reject_width;
    uint64_t spi_nv_reject_value;
    bool protected_nor_enabled, protected_nor_realized;
    uint32_t protected_nor_base, protected_nor_length, msm5xxx_protected_nor_sector;
    uint32_t protected_nor_ticks;
    int64_t protected_nor_clock;
    MSM5xxxProtectedNOR protected_nor;
    MemoryRegion protected_nor_region;
    BlockBackend *protected_nor_blk;
    uint64_t protected_nor_persist_writes, protected_nor_persist_skips;
    bool protected_nor_source_enabled;
    uint32_t protected_nor_source[6], protected_nor_source_reason;
    uint64_t protected_nor_source_checks, protected_nor_source_rejections;
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

/* Independent physical input: never occupies the held-key slot. */
static void msm5xxx_poc_board_status_stream_write(MSM5xxxPOCMachineState *s)
{
    uint8_t *record = s->matrix_input_ack;

    assert(!s->matrix_input_ack_length);
    memset(record, 0, MSM5XXX_POC_LCD_STREAM_RECORD_SIZE);
    record[0] = MSM5XXX_POC_BOARD_STATUS_TELEMETRY;
    record[1] = s->board_status_input_level;
    record[2] = s->board_status_input_mask;
    msm5xxx_poc_backing_write(record, 4, s->board_status_input_address, 4);
    msm5xxx_poc_backing_write(record, 8, s->board_status_input_events, 4);
    msm5xxx_poc_backing_write(record, 12, s->board_status_input_rejections, 4);
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
    if (s->ma5_pcm_initialized) {
        underflow = s->ma5_pcm_output.underflow_frames > UINT32_MAX ?
                    UINT32_MAX : s->ma5_pcm_output.underflow_frames;
        overflow = s->ma5_pcm_output.dropped_frames > UINT32_MAX ?
                   UINT32_MAX : s->ma5_pcm_output.dropped_frames;
        epoch = s->ma5_pcm_output.queue.epoch > UINT32_MAX ?
                UINT32_MAX : s->ma5_pcm_output.queue.epoch;
    } else {
        underflow = s->audio_synth.underflow_frames > UINT32_MAX ?
                    UINT32_MAX : s->audio_synth.underflow_frames;
        overflow = s->audio_synth.overflow_frames > UINT32_MAX ?
                   UINT32_MAX : s->audio_synth.overflow_frames;
        epoch = s->audio_synth.epoch > UINT32_MAX ?
                UINT32_MAX : s->audio_synth.epoch;
    }
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

    return (s->matrix_input_host_enabled || s->board_status_input_enabled) &&
        !s->matrix_input_ack_length ?
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
        if (record[0] == MSM5XXX_POC_HOST_BOARD_STATUS &&
            s->board_status_input_enabled) {
            if ((record[1] & ~s->board_status_input_mask) ||
                record[2] || record[3]) {
                s->board_status_input_rejections++;
            } else {
                s->board_status_input_level = record[1];
                s->board_status_input_backing =
                    (s->board_status_input_backing & ~s->board_status_input_mask) |
                    s->board_status_input_level;
                s->board_status_input_events++;
            }
            s->matrix_input_buffer_length = 0;
            msm5xxx_poc_board_status_stream_write(s);
            continue;
        }
        if (!s->matrix_input_host_enabled ||
            record[0] != MSM5XXX_POC_HOST_INPUT || record[1] > 1 ||
            (record[1] ? s->matrix_input_pressed :
                         !s->matrix_input_pressed) ||
            (!record[1] && (record[2] || record[3])) ||
            (record[1] &&
             (record[2] == MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW ?
              (!s->matrix_input_sideband_mask || s->matrix_input_low5 ||
               record[3] != s->matrix_input_sideband_mask) :
              (record[2] >= s->matrix_input_rows ||
               record[3] > ((s->matrix_input_low5 || s->matrix_input_loop || s->matrix_input_row734) ? 0x1f : 0x0f) ||
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
                                           uint32_t pc, uint32_t *entry,
                                           uint32_t *set_offset,
                                           uint32_t *clear_offset)
{
    unsigned index;

    if (!s->ready_poll_site_count) {
        if (pc != s->ready_poll_entry + s->ready_status_pc_offset) {
            return false;
        }
        *entry = s->ready_poll_entry;
        *set_offset = s->ready_pulse_set_pc_offset;
        *clear_offset = s->ready_pulse_clear_pc_offset;
        return true;
    }
    for (index = 0; index < s->ready_poll_site_count; index++) {
        const MSM5xxxPOCReadyPollSite *site = &s->ready_poll_sites[index];

        if (pc == site->entry + site->read_offset) {
            *entry = site->entry;
            *set_offset = site->set_offset;
            *clear_offset = site->clear_offset;
            return true;
        }
    }
    return false;
}

static bool msm5xxx_poc_boot_storage_guest(MSM5xxxPOCMachineState *s);

/* Provisional isolated console: synchronous null TX sink, no physical baud,
 * FIFO depth, RX input or interrupt delivery is inferred. */
static void msm5xxx_poc_uart_console_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;

    s->uart_console_rearm_step = s->uart_console_rearm_ready = 0;
    s->uart_console_rearm_pending = false;
    s->uart_console_rearms = 0;
    if (s->uart_console_rearm_mapped) {
        memory_region_set_enabled(&s->uart_console_rearm_region, false);
    }
    s->uart_console_rejected = false;
    s->uart_console_initialized = false;
    s->uart_console_tx_enabled = s->uart_console_rx_enabled = false;
    s->uart_console_empty = true;
    s->uart_console_config = s->uart_console_cr_step = 0;
    s->uart_console_mr1 = s->uart_console_mr2 = s->uart_console_csr = 0;
    s->uart_console_imr = s->uart_console_tfwr = s->uart_console_rfwr = 0;
    s->uart_console_accepted = 0;
    s->uart_console_last_byte = 0;
    s->uart_console_reject_reason = NULL;
    if (s->uart_console_probe_enabled) {
        s->uart_console_probe_stage = s->uart_console_probe_step = 0;
        s->uart_console_probe_drains = 0;
        s->uart_console_probe_lf = s->uart_console_probe_rx_empty = false;
        s->uart_console_expected_csr = 0xff;
    }
    if (s->uart_console_mapped) {
        memory_region_set_enabled(&s->uart_console_region, true);
    }
}

static void msm5xxx_poc_uart_console_reject(MSM5xxxPOCMachineState *s,
                                           const char *reason)
{
    s->uart_console_rejected = true;
    s->uart_console_reject_reason = reason;
    /* Disable only this overlay before replaying the original bus access. */
    memory_region_set_enabled(&s->uart_console_region, false);
    if (s->uart_console_rearm_enabled) {
        s->uart_console_rearm_step = s->uart_console_rearm_ready = 0;
        s->uart_console_rearm_pending = false;
        if (s->uart_console_rearm_mapped) {
            memory_region_set_enabled(&s->uart_console_rearm_region, true);
        }
    }
}

static MemTxResult msm5xxx_poc_uart_console_forward(
    MSM5xxxPOCMachineState *s, hwaddr offset, uint64_t *value,
    unsigned size, MemTxAttrs attrs, bool write)
{
    uint8_t bytes[8] = {0};
    MemTxResult result;

    if (!size || size > sizeof(bytes)) {
        return MEMTX_ERROR;
    }
    if (write) {
        msm5xxx_poc_backing_write(bytes, 0, *value, size);
        return address_space_write(&address_space_memory,
                                   (hwaddr)s->uart_console_base + offset,
                                   attrs, bytes, size);
    }
    result = address_space_read(&address_space_memory,
                                (hwaddr)s->uart_console_base + offset,
                                attrs, bytes, size);
    if (result == MEMTX_OK) {
        *value = msm5xxx_poc_backing_read(bytes, 0, size);
    }
    return result;
}

static MemTxResult msm5xxx_poc_uart_console_mirror(
    MSM5xxxPOCMachineState *s, hwaddr offset, uint64_t value,
    unsigned size, MemTxAttrs attrs)
{
    MemoryRegionSection section;
    MemTxResult result;
    bool passive;

    memory_region_set_enabled(&s->uart_console_region, false);
    section = memory_region_find(get_system_memory(),
                                  (hwaddr)s->uart_console_base + offset, size);
    passive = (section.mr == &s->msm ||
               (offset == 8 && size == 1 && section.mr == &s->ready_status &&
                s->ready_status_address == s->uart_console_base + offset)) &&
              int128_ge(section.size, int128_make64(size));
    if (section.mr) {
        memory_region_unref(section.mr);
    }
    if (!passive) {
        msm5xxx_poc_uart_console_reject(s, "unsupported-passive-underlay");
        return msm5xxx_poc_uart_console_forward(s, offset, &value, size, attrs, true);
    }
    result = msm5xxx_poc_uart_console_forward(s, offset, &value, size, attrs, true);
    if (result != MEMTX_OK) {
        msm5xxx_poc_uart_console_reject(s, "passive-underlay-write-error");
        return result;
    }
    memory_region_set_enabled(&s->uart_console_region, true);
    return MEMTX_OK;
}

static uint8_t msm5xxx_poc_uart_console_isr(MSM5xxxPOCMachineState *s)
{
    unsigned pending = !s->uart_console_empty;

    return s->uart_console_tx_enabled && s->uart_console_empty &&
           pending <= s->uart_console_tfwr ? 1 : 0;
}

static MemTxResult msm5xxx_poc_uart_console_read_fixed(void *opaque, hwaddr offset,
                                                uint64_t *value, unsigned size,
                                                MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (s->uart_console_rejected) {
        return msm5xxx_poc_uart_console_forward(s, offset, value, size, attrs, false);
    }
    if (offset == 0 && size == s->uart_console_register_width) {
        *value = s->uart_console_mr1;
    } else if (offset == 4 && size == 1) {
        *value = s->uart_console_mr2;
    } else if (offset == 8 && size == 1) {
        *value = (s->uart_console_empty ? 8 : 0) |
                 (s->uart_console_tx_enabled && s->uart_console_empty ? 4 : 0);
    } else if (offset == 0x0c && size == 1) {
        *value = 0; /* The isolated console has no RX source. */
    } else if (offset == 0x10 && size == 1) {
        *value = msm5xxx_poc_uart_console_isr(s) & s->uart_console_imr;
    } else if (offset == 0x14 && size == 1) {
        *value = msm5xxx_poc_uart_console_isr(s);
    } else if (offset == 0x1c && size == s->uart_console_tfwr_width &&
               s->uart_console_tfwr_width == s->uart_console_register_width) {
        *value = s->uart_console_tfwr;
    } else if (offset == 0x20 && size == s->uart_console_register_width) {
        *value = s->uart_console_rfwr;
    } else {
        msm5xxx_poc_uart_console_reject(s, "unsupported-read-width-or-register");
        return msm5xxx_poc_uart_console_forward(s, offset, value, size, attrs, false);
    }
    return MEMTX_OK;
}

static MemTxResult msm5xxx_poc_uart_console_write_fixed(void *opaque, hwaddr offset,
                                                 uint64_t value, unsigned size,
                                                 MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    static const uint8_t init_cr[] = {0x30, 0x10, 0x10, 0x20, 0x20, 1, 4};
    const char *reason = "unsupported-config-width-or-register";
    uint8_t *byte_latch = NULL;
    uint16_t *wide_latch = NULL;
    unsigned config_bit = 0;

    if (s->uart_console_rejected) {
        return msm5xxx_poc_uart_console_forward(s, offset, &value, size, attrs, true);
    }
    if (offset == 0 && size == s->uart_console_register_width && value == 0) {
        wide_latch = &s->uart_console_mr1;
        config_bit = 1;
    } else if (offset == 4 && size == 1 && value == 0x34) {
        byte_latch = &s->uart_console_mr2;
        config_bit = 2;
    } else if (offset == 8 && size == 1 && value == s->uart_console_expected_csr) {
        byte_latch = &s->uart_console_csr;
        config_bit = 4;
    } else if (offset == 0x14 && size == 1 && value == 0) {
        byte_latch = &s->uart_console_imr;
        config_bit = 8;
    } else if (offset == 0x1c && size == s->uart_console_tfwr_width && value == 30) {
        wide_latch = &s->uart_console_tfwr;
        config_bit = 16;
    } else if (offset == 0x20 && size == s->uart_console_register_width && value == 0) {
        wide_latch = &s->uart_console_rfwr;
        config_bit = 32;
    } else if (offset == 0x10 && size == 1 &&
               (value == 0x10 || value == 0x20 || value == 0x30 ||
                value == 1 || value == 4)) {
        if (!s->uart_console_initialized) {
            if (s->uart_console_config == 63) {
                if (s->uart_console_cr_step >= sizeof(init_cr) ||
                    value != init_cr[s->uart_console_cr_step]) {
                    reason = "unsupported-init-control-order";
                    goto reject;
                }
                s->uart_console_cr_step++;
                s->uart_console_initialized =
                    s->uart_console_cr_step == sizeof(init_cr);
            } else if (value == 1 || value == 4) {
                reason = "enable-before-complete-config";
                goto reject;
            }
        }
        if (value == 0x20) {
            s->uart_console_empty = true;
        } else if (value == 1) {
            s->uart_console_rx_enabled = true;
        } else if (value == 4) {
            s->uart_console_tx_enabled = true;
        }
    } else if (offset == 0x0c && size == 1 && value <= UINT8_MAX) {
        if (!s->uart_console_initialized || !s->uart_console_tx_enabled ||
            !s->uart_console_empty) {
            reason = "tx-before-initialized-capacity";
            goto reject;
        }
        s->uart_console_empty = false;
        s->uart_console_last_byte = value;
        if (s->uart_console_accepted != UINT64_MAX) {
            s->uart_console_accepted++;
        }
        /* Acceptance by the provisional synchronous sink completes this byte. */
        s->uart_console_empty = true;
    } else {
        goto reject;
    }
    if (config_bit) {
        MemTxResult result = msm5xxx_poc_uart_console_mirror(s, offset, value,
                                                           size, attrs);

        if (result != MEMTX_OK || s->uart_console_rejected) {
            return result;
        }
        if (byte_latch) {
            *byte_latch = value;
        } else {
            *wide_latch = value;
        }
        s->uart_console_config |= config_bit;
    }
    return MEMTX_OK;

reject:
    msm5xxx_poc_uart_console_reject(s, reason);
    return msm5xxx_poc_uart_console_forward(s, offset, &value, size, attrs, true);
}



/* Finite FF/DD or FF/CC/99 source initialization. Existing latches/readback
 * stay in the fixed core; this adds no RX source or physical timing. */
static bool msm5xxx_poc_uart_console_probe_next(
    MSM5xxxPOCMachineState *s, hwaddr offset, uint64_t value, unsigned size,
    uint8_t *stage, uint8_t *step, uint8_t *drains, bool *lf)
{
    static const uint8_t offsets[] = {
        0x14, 0x20, 0x1c, 0, 4, 8, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10
    };
    static const uint8_t widths[] = {1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    static const uint8_t values[] = {0, 0, 30, 0, 0x34, 0, 0x30, 0x10, 0x10,
                                    0x20, 0x20, 1, 4};
    if (*stage == 0 || *stage == 3 || (s->uart_console_probe_ffcc && *stage == 6)) {
        unsigned limit = *stage == 0 || (s->uart_console_probe_ffcc && *stage == 3) ? 4 : 2;
        if (offset == 0x10 && size == 1 && value == 0x20 && *drains < limit) {
            (*drains)++;
            return true;
        }
        if (offset == 0x14 && size == 1 && value == 0 && *drains == limit) {
            (*stage)++;
            *step = 1;
            return true;
        }
        return false;
    }
    if (*stage == 1 || *stage == 4 || (s->uart_console_probe_ffcc && *stage == 7)) {
        unsigned expected;
        if (*step >= sizeof(offsets)) {
            return false;
        }
        expected = *step == 5 ? (*stage == 1 ? 0xff :
            (*stage == 4 ? (s->uart_console_probe_ffcc ? 0xcc : 0xdd) : 0x99)) : values[*step];
        if (offset != offsets[*step] || size != widths[*step] || value != expected) {
            return false;
        }
        if (++*step == sizeof(offsets)) {
            *stage = *stage == 1 ? 2 : (*stage == 4 ? 5 : 8);
            *step = *drains = 0;
        }
        return true;
    }
    if (*stage == 2 || (s->uart_console_probe_ffcc && *stage == 5)) {
        if (offset == 0x0c && size == 1 && value == 0x0a && !*lf) {
            *lf = true;
            return true;
        }
        if (offset == 0x10 && size == 1 && value == 0x20 &&
            *lf && s->uart_console_probe_rx_empty) {
            *stage = *stage == 2 ? 3 : 6;
            *drains = 1;
            return true;
        }
    }
    return false;
}

static bool msm5xxx_poc_uart_rearm_guest(MSM5xxxPOCMachineState *s)
{
    return msm5xxx_poc_boot_storage_guest(s) && s->cpu->env.thumb &&
           !(s->cpu->env.cp15.sctlr_el[1] & 1) &&
           !s->cpu->env.cp15.fcseidr_ns && !s->cpu->env.cp15.fcseidr_s;
}

static bool msm5xxx_poc_uart_rearm_context(MSM5xxxPOCMachineState *s,
                                           unsigned index, uint32_t lr)
{
    return index < 2 && msm5xxx_poc_uart_rearm_guest(s) &&
           s->cpu->env.regs[15] == s->uart_console_rearm_pc[index] &&
           s->cpu->env.regs[14] == lr;
}

static void msm5xxx_poc_uart_rearm_observe(MSM5xxxPOCMachineState *s,
                                          hwaddr offset, uint64_t value,
                                          unsigned size)
{
    if (!msm5xxx_poc_boot_storage_guest(s)) {
        return;
    }
    if (offset || size != 1 || value != 0x20) {
        s->uart_console_rearm_step = 0;
    } else if (msm5xxx_poc_uart_rearm_context(s, 0, s->uart_console_rearm_root_lr)) {
        s->uart_console_rearm_step = 1;
    } else if (s->uart_console_rearm_step == 1 &&
               msm5xxx_poc_uart_rearm_context(s, 1, s->uart_console_rearm_root_lr)) {
        s->uart_console_rearm_step = s->uart_console_rearm_ready = 0;
        s->uart_console_rearm_pending = true;
        s->uart_console_rejected = false;
        s->uart_console_reject_reason = NULL;
        s->uart_console_initialized = false;
        s->uart_console_tx_enabled = s->uart_console_rx_enabled = false;
        s->uart_console_empty = true;
        s->uart_console_config = s->uart_console_cr_step = 0;
        s->uart_console_expected_csr = 0xff;
        s->uart_console_probe_stage = s->uart_console_probe_step = 0;
        s->uart_console_probe_drains = 2;
        s->uart_console_probe_lf = s->uart_console_probe_rx_empty = false;
        if (s->uart_console_rearms != UINT64_MAX) {
            s->uart_console_rearms++;
        }
        memory_region_set_enabled(&s->uart_console_rearm_region, false);
        memory_region_set_enabled(&s->uart_console_region, true);
    } else {
        s->uart_console_rearm_step = 0;
    }
}

static MemTxResult msm5xxx_poc_uart_rearm_read(void *opaque, hwaddr offset,
                                              uint64_t *value, unsigned size,
                                              MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint32_t at = s->uart_console_base + 0x10 - MSM5XXX_POC_MSM_BASE + offset;

    if (!size || offset >= 4 || size > 4 - offset) {
        if (msm5xxx_poc_boot_storage_guest(s)) {
            s->uart_console_rearm_step = 0;
        }
        return MEMTX_ERROR;
    }
    *value = msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm), at, size);
    if (msm5xxx_poc_boot_storage_guest(s)) {
        s->uart_console_rearm_step = 0;
    }
    return MEMTX_OK;
}

static MemTxResult msm5xxx_poc_uart_rearm_write(void *opaque, hwaddr offset,
                                               uint64_t value, unsigned size,
                                               MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint32_t at = s->uart_console_base + 0x10 - MSM5XXX_POC_MSM_BASE + offset;

    if (!size || offset >= 4 || size > 4 - offset) {
        if (msm5xxx_poc_boot_storage_guest(s)) {
            s->uart_console_rearm_step = 0;
        }
        return MEMTX_ERROR;
    }
    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s->msm), at, value, size);
    memory_region_set_dirty(&s->msm, at, size);
    msm5xxx_poc_uart_rearm_observe(s, offset, value, size);
    return MEMTX_OK;
}

static const MemoryRegionOps msm5xxx_poc_uart_rearm_ops = {
    .read_with_attrs = msm5xxx_poc_uart_rearm_read,
    .write_with_attrs = msm5xxx_poc_uart_rearm_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4, .valid.unaligned = true,
    .impl.min_access_size = 1, .impl.max_access_size = 4, .impl.unaligned = true,
};

static MemTxResult msm5xxx_poc_uart_pending_forward(MSM5xxxPOCMachineState *s,
    hwaddr offset, uint64_t *value, unsigned size, MemTxAttrs attrs, bool write)
{
    MemTxResult result;

    memory_region_set_enabled(&s->uart_console_region, false);
    result = msm5xxx_poc_uart_console_forward(s, offset, value, size, attrs, write);
    memory_region_set_enabled(&s->uart_console_region, true);
    return result;
}

static MemTxResult msm5xxx_poc_uart_console_read(void *opaque, hwaddr offset,
                                                uint64_t *value, unsigned size,
                                                MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    MemTxResult result;
    uint8_t ready = 0;

    if (s->uart_console_rearm_enabled) {
        if (s->uart_console_rearm_pending) {
            if (!msm5xxx_poc_boot_storage_guest(s)) {
                return msm5xxx_poc_uart_pending_forward(s, offset, value, size, attrs, false);
            }
            if (msm5xxx_poc_uart_rearm_guest(s) && !s->uart_console_rejected &&
                offset == 8 && size == 1 && s->uart_console_probe_stage == 0 &&
                s->cpu->env.regs[15] == s->uart_console_rearm_sr) {
                if (s->uart_console_probe_drains == 2 &&
                    s->cpu->env.regs[14] == s->uart_console_rearm_root_lr) {
                    ready = 1;
                } else if (s->uart_console_probe_drains == 4 &&
                           (s->uart_console_rearm_ready & 1) &&
                           s->cpu->env.regs[14] == s->uart_console_rearm_config_lr) {
                    ready = 2;
                }
            }
            if (!ready) {
                msm5xxx_poc_uart_console_reject(s, "unsupported-pending-source-read");
            }
        } else if (msm5xxx_poc_boot_storage_guest(s)) {
            s->uart_console_rearm_step = 0;
        }
    }
    /* Introspection may read fixed aliases but cannot grant or withdraw the
     * finite permission, including after the DD profile has sealed. */
    if (s->uart_console_probe_enabled && !msm5xxx_poc_boot_storage_guest(s)) {
        bool readable = (offset == 0 || offset == 0x1c || offset == 0x20) ?
            size == s->uart_console_register_width :
            size == 1 && (offset == 4 || offset == 8 || offset == 0x0c ||
                          offset == 0x10 || offset == 0x14);
        return readable ?
            msm5xxx_poc_uart_console_read_fixed(opaque, offset, value, size, attrs) :
            MEMTX_ERROR;
    }
    if (!s->uart_console_probe_enabled || s->uart_console_rejected ||
        s->uart_console_probe_stage == (s->uart_console_probe_ffcc ? 8 : 5)) {
        return msm5xxx_poc_uart_console_read_fixed(opaque, offset, value, size, attrs);
    }
    if (size != 1 || (offset != 8 && offset != 0x14)) {
        msm5xxx_poc_uart_console_reject(s, "unsupported-probe-read");
        return msm5xxx_poc_uart_console_read_fixed(opaque, offset, value, size, attrs);
    }
    result = msm5xxx_poc_uart_console_read_fixed(opaque, offset, value, size, attrs);
    if (ready) {
        if (result != MEMTX_OK || s->uart_console_rejected) {
            msm5xxx_poc_uart_console_reject(s, "pending-source-read-error");
            return result;
        }
        if (!(*value & 8)) {
            msm5xxx_poc_uart_console_reject(s, "pending-source-TX-not-empty");
            return msm5xxx_poc_uart_console_forward(s, offset, value, size, attrs, false);
        }
        s->uart_console_rearm_ready |= ready;
    }
    if (result == MEMTX_OK && !s->uart_console_rejected && offset == 8 &&
        (s->uart_console_probe_stage == 2 ||
         (s->uart_console_probe_ffcc && s->uart_console_probe_stage == 5)) &&
        s->uart_console_probe_lf &&
        !(*value & 1)) {
        s->uart_console_probe_rx_empty = true;
    }
    return result;
}

static MemTxResult msm5xxx_poc_uart_console_write(void *opaque, hwaddr offset,
                                                 uint64_t value, unsigned size,
                                                 MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t stage = s->uart_console_probe_stage;
    uint8_t step = s->uart_console_probe_step;
    uint8_t drains = s->uart_console_probe_drains;
    uint8_t previous_csr = s->uart_console_expected_csr;
    bool lf = s->uart_console_probe_lf;
    MemTxResult result;

    if (s->uart_console_rearm_enabled) {
        bool guest = msm5xxx_poc_boot_storage_guest(s);
        if (s->uart_console_rearm_pending && !guest) {
            return msm5xxx_poc_uart_pending_forward(s, offset, &value, size, attrs, true);
        }
        if (s->uart_console_rearm_pending &&
            (!msm5xxx_poc_uart_rearm_guest(s) ||
             !((stage == 0 && drains >= 2 && drains < 4 &&
                (s->uart_console_rearm_ready & 1) &&
                msm5xxx_poc_uart_rearm_context(s, drains - 2,
                                              s->uart_console_rearm_config_lr)) ||
               (((stage == 0 && drains == 4) || stage == 1) &&
                s->uart_console_rearm_ready == 3)))) {
            msm5xxx_poc_uart_console_reject(s, "unsupported-pending-source-write");
        } else if (!s->uart_console_rearm_pending && guest && stage == 5 &&
                   !s->uart_console_rejected) {
            bool reset = offset == 0x10 && size == 1 && value == 0x20 &&
                (msm5xxx_poc_uart_rearm_context(s, 0, s->uart_console_rearm_root_lr) ||
                 msm5xxx_poc_uart_rearm_context(s, 1, s->uart_console_rearm_root_lr));
            if (reset) {
                result = msm5xxx_poc_uart_console_write_fixed(opaque, offset, value, size, attrs);
                if (result == MEMTX_OK && !s->uart_console_rejected) {
                    msm5xxx_poc_uart_rearm_observe(s, 0, value, size);
                }
                return result;
            }
            s->uart_console_rearm_step = 0;
        }
    }
    if (!s->uart_console_probe_enabled || s->uart_console_rejected || stage == (s->uart_console_probe_ffcc ? 8 : 5)) {
        return msm5xxx_poc_uart_console_write_fixed(opaque, offset, value, size, attrs);
    }
    if (!msm5xxx_poc_uart_console_probe_next(s, offset, value, size,
                                          &stage, &step, &drains, &lf)) {
        msm5xxx_poc_uart_console_reject(s, "unsupported-probe-write-sequence");
        return msm5xxx_poc_uart_console_write_fixed(opaque, offset, value, size, attrs);
    }
    /* Only the source-declared second CSR event may change fixed permission. */
    if (s->uart_console_probe_stage == 4 && s->uart_console_probe_step == 5) {
        s->uart_console_expected_csr = s->uart_console_probe_ffcc ? 0xcc : 0xdd;
    } else if (s->uart_console_probe_ffcc &&
               s->uart_console_probe_stage == 7 && s->uart_console_probe_step == 5) {
        s->uart_console_expected_csr = 0x99;
    }
    result = msm5xxx_poc_uart_console_write_fixed(opaque, offset, value, size, attrs);
    if (result != MEMTX_OK || s->uart_console_rejected) {
        s->uart_console_expected_csr = previous_csr;
        return result;
    }
    if (s->uart_console_probe_ffcc && s->uart_console_probe_stage == 4 && stage == 5) {
        lf = false;
        s->uart_console_probe_rx_empty = false;
    }
    s->uart_console_probe_stage = stage;
    s->uart_console_probe_step = step;
    s->uart_console_probe_drains = drains;
    s->uart_console_probe_lf = lf;
    if (s->uart_console_rearm_pending && stage == 2) {
        s->uart_console_rearm_pending = false;
    }
    return result;
}

static const MemoryRegionOps msm5xxx_poc_uart_console_ops = {
    .read_with_attrs = msm5xxx_poc_uart_console_read,
    .write_with_attrs = msm5xxx_poc_uart_console_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
    .valid.unaligned = true,
    .impl.min_access_size = 1,
    .impl.max_access_size = 8,
    .impl.unaligned = true,
};

static char *msm5xxx_poc_get_uart_console(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->uart_console_enabled) {
        return g_strdup("");
    }
    if (s->uart_console_tfwr_width != s->uart_console_register_width) {
        return g_strdup_printf("%x:%x:%x:%x", s->uart_console_base,
                               s->uart_console_register_width,
                               s->uart_console_expected_csr,
                               s->uart_console_tfwr_width);
    }
    if (s->uart_console_register_width == 2 &&
        s->uart_console_expected_csr == 0x99) {
        return g_strdup_printf("%x", s->uart_console_base);
    }
    return g_strdup_printf("%x:%x:%x", s->uart_console_base,
                           s->uart_console_register_width,
                           s->uart_console_expected_csr);
}

static void msm5xxx_poc_set_uart_console(Object *obj, const char *value,
                                        Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned long base, width = 2, csr = 0x99, tfwr = 0;
    bool tfwr_explicit = false;
    const char *end;

    if (s->uart_console_realized || s->uart_console_enabled) {
        error_setg(errp, "uart-console cannot be changed after configuration or initialization");
        return;
    }
    if (!*value) {
        return;
    }
    if (!g_ascii_isxdigit(*value) || qemu_strtoul(value, &end, 16, &base)) {
        goto malformed;
    }
    if (*end == ':') {
        const char *part = end + 1;

        if (!g_ascii_isxdigit(*part) || qemu_strtoul(part, &end, 16, &width) ||
            *end != ':') {
            goto malformed;
        }
        part = end + 1;
        if (!g_ascii_isxdigit(*part) || qemu_strtoul(part, &end, 16, &csr)) {
            goto malformed;
        }
        if (*end == ':') {
            tfwr_explicit = true;
            part = end + 1;
            if (!g_ascii_isxdigit(*part) || qemu_strtoul(part, &end, 16, &tfwr)) {
                goto malformed;
            }
        }
    }
    if (!tfwr_explicit) {
        tfwr = width;
    }
    if (*end || base & 3 || base < MSM5XXX_POC_MSM_BASE ||
        base > MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE - 0x24 ||
        !((width == 2 && (csr == 0x99 || csr == 0xdd || csr == 0xff)) ||
          (width == 1 && csr == 0xff)) ||
        !(tfwr == width || (width == 1 && csr == 0xff && tfwr == 2))) {
        goto malformed;
    }
    s->uart_console_base = base;
    s->uart_console_register_width = width;
    s->uart_console_tfwr_width = tfwr;
    s->uart_console_expected_csr = csr;
    s->uart_console_enabled = true;
    return;

malformed:
    error_setg(errp, "uart-console requires hexadecimal BASE[:WIDTH:CSR[:TFWR_WIDTH]], "
                     "aligned in MSM with class 2:99, 2:dd or 1:ff");
}


static char *msm5xxx_poc_get_uart_console_probe(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    return s->uart_console_probe_enabled ?
        g_strdup_printf(s->uart_console_probe_ffcc ? "%x:ff:cc:99" : "%x:ff:dd",
                        s->uart_console_base) : g_strdup("");
}

static void msm5xxx_poc_set_uart_console_probe(Object *obj, const char *value,
                                               Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    const char *part = value, *end;
    unsigned long values[4];
    unsigned count = 0;

    if (s->uart_console_realized || s->uart_console_enabled || !part) {
        goto malformed;
    }
    while (count < 4) {
        if (!g_ascii_isxdigit(*part) || qemu_strtoul(part, &end, 16, &values[count])) {
            goto malformed;
        }
        count++;
        if (!*end) {
            break;
        }
        if (*end != ':' || count == 4) {
            goto malformed;
        }
        part = end + 1;
    }
    if ((count != 3 && count != 4) || values[0] != 0x03000f0c || values[1] != 0xff ||
        !((count == 3 && values[2] == 0xdd) ||
          (count == 4 && values[2] == 0xcc && values[3] == 0x99))) {
        goto malformed;
    }
    msm5xxx_poc_set_uart_console(obj, "3000f0c:2:ff", errp);
    if (s->uart_console_enabled) {
        s->uart_console_probe_enabled = true;
        s->uart_console_probe_ffcc = count == 4;
    }
    return;
malformed:
    error_setg(errp, "uart-console-probe requires 3000f0c:ff:dd or 3000f0c:ff:cc:99 before any UART configuration");
}

static char *msm5xxx_poc_get_uart_console_rearm(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    return s->uart_console_rearm_enabled ? g_strdup_printf("%x:%x:%x:%x:%x",
        s->uart_console_rearm_pc[0], s->uart_console_rearm_pc[1], s->uart_console_rearm_sr,
        s->uart_console_rearm_root_lr, s->uart_console_rearm_config_lr) : g_strdup("");
}

static void msm5xxx_poc_set_uart_console_rearm(Object *obj, const char *value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t v[5];
    const char *part = value, *end;
    unsigned long parsed;

    if (s->uart_console_realized || s->uart_console_rearm_enabled || !part) {
        goto malformed;
    }
    for (unsigned i = 0; i < 5; i++) {
        if (!g_ascii_isxdigit(*part) || qemu_strtoul(part, &end, 16, &parsed) ||
            parsed > UINT32_MAX || (i < 4 ? *end != ':' : *end != '\0')) {
            goto malformed;
        }
        v[i] = parsed;
        part = end + (i < 4);
    }
    if (!v[0] || ((v[0] | v[1] | v[2]) & 1) ||
        (uint64_t)v[0] + 2 != v[1] || (uint64_t)v[0] + 6 != v[2] ||
        !(v[3] & 1) || !(v[4] & 1) || v[3] == v[4]) {
        goto malformed;
    }
    memcpy(s->uart_console_rearm_pc, v, 2 * sizeof(v[0]));
    s->uart_console_rearm_sr = v[2];
    s->uart_console_rearm_root_lr = v[3];
    s->uart_console_rearm_config_lr = v[4];
    s->uart_console_rearm_enabled = true;
    return;
malformed:
    error_setg(errp, "uart-console-rearm requires ordered bounded PCs and Thumb caller LRs before realization");
}

static bool msm5xxx_poc_uart_rearm_valid(MSM5xxxPOCMachineState *s)
{
    MemoryRegionSection section;
    bool valid;
    uint32_t code[5];

    if (!s->memory_profile_enabled || !s->uart_console_probe_enabled ||
        s->uart_console_probe_ffcc || s->uart_console_base != 0x03000f0c ||
        s->uart_console_register_width != 2 ||
        (uint64_t)s->uart_console_rearm_sr + 2 > s->primary_nor_size ||
        (s->uart_console_rearm_root_lr & ~1u) < 4 ||
        (s->uart_console_rearm_config_lr & ~1u) < 4 ||
        (s->uart_console_rearm_root_lr & ~1u) > s->primary_nor_size ||
        (s->uart_console_rearm_config_lr & ~1u) > s->primary_nor_size) {
        return false;
    }
    memory_region_set_enabled(&s->uart_console_region, false);
    if (s->uart_console_rearm_mapped) {
        memory_region_set_enabled(&s->uart_console_rearm_region, false);
    }
    code[0] = s->uart_console_rearm_pc[0];
    code[1] = s->uart_console_rearm_pc[1];
    code[2] = s->uart_console_rearm_sr;
    code[3] = (s->uart_console_rearm_root_lr & ~1u) - 4;
    code[4] = (s->uart_console_rearm_config_lr & ~1u) - 4;
    valid = memory_region_is_rom(&s->nor);
    for (unsigned i = 0; valid && i < 5; i++) {
        unsigned width = i < 3 ? 2 : 4;
        if ((uint64_t)code[i] + width > s->primary_nor_size) {
            valid = false;
            break;
        }
        section = memory_region_find(get_system_memory(), code[i], width);
        valid = section.mr == &s->nor && section.offset_within_region == code[i] &&
                int128_eq(section.size, int128_make64(width));
        if (section.mr) {
            memory_region_unref(section.mr);
        }
    }
    if (valid) {
        section = memory_region_find(get_system_memory(), s->uart_console_base + 0x10, 4);
        valid = section.mr == &s->msm &&
            section.offset_within_region == s->uart_console_base + 0x10 - MSM5XXX_POC_MSM_BASE &&
            int128_eq(section.size, int128_make64(4));
        if (section.mr) {
            memory_region_unref(section.mr);
        }
    }
    memory_region_set_enabled(&s->uart_console_region, !s->uart_console_rejected);
    if (s->uart_console_rearm_mapped) {
        memory_region_set_enabled(&s->uart_console_rearm_region, s->uart_console_rejected);
    }
    return valid;
}

static char *msm5xxx_poc_get_uart_console_rearm_state(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    return g_strdup_printf("configured=%u step=%u pending=%u ready=%u count=%" G_GUINT64_FORMAT,
        s->uart_console_rearm_enabled, s->uart_console_rearm_step,
        s->uart_console_rearm_pending, s->uart_console_rearm_ready, s->uart_console_rearms);
}

static char *msm5xxx_poc_get_uart_console_probe_state(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    return g_strdup_printf("configured=%u stage=%u step=%u drains=%u LF=%u RXempty=%u",
        s->uart_console_probe_enabled, s->uart_console_probe_stage,
        s->uart_console_probe_step, s->uart_console_probe_drains,
        s->uart_console_probe_lf, s->uart_console_probe_rx_empty);
}

static char *msm5xxx_poc_get_uart_console_status(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return g_strdup_printf(
        "{\"policy\":\"provisional-uncalibrated-synchronous-null-tx-rx-empty\","
        "\"configured\":%s,\"initialized\":%s,\"rejected\":%s,"
        "\"classwidth\":%u,\"expectedcsr\":%u,"
        "\"txenabled\":%s,\"rxenabled\":%s,\"empty\":%s,"
        "\"acceptedcount\":%" G_GUINT64_FORMAT ",\"lastbyte\":%u,\"rejectreason\":\"%s\"}",
        s->uart_console_enabled ? "true" : "false",
        s->uart_console_initialized ? "true" : "false",
        s->uart_console_rejected ? "true" : "false",
        s->uart_console_register_width, s->uart_console_expected_csr,
        s->uart_console_tx_enabled ? "true" : "false",
        s->uart_console_rx_enabled ? "true" : "false",
        s->uart_console_empty ? "true" : "false", s->uart_console_accepted,
        s->uart_console_last_byte,
        s->uart_console_reject_reason ? s->uart_console_reject_reason : "");
}

static uint64_t msm5xxx_poc_ready_status_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUClass *cc = CPU_GET_CLASS(s->cpu);
    uint64_t now = icount_get_raw();
    uint32_t pc;
    uint32_t entry = 0;
    uint32_t set_offset = 0;
    uint32_t clear_offset = 0;
    bool primary_read;

    if (offset || size != 1) {
        return 0;
    }
    pc = cc->get_pc(CPU(s->cpu));
    primary_read = msm5xxx_poc_ready_site_for_pc(
        s, pc, &entry, &set_offset, &clear_offset
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
        s->ready_poll_active_set_offset = set_offset;
        s->ready_poll_active_clear_offset = clear_offset;
        s->ready_poll_phase = 1;
        s->ready_poll_first_icount = now;
    } else if (s->ready_poll_status == MSM5XXX_POC_READY_CANDIDATE) {
        unsigned expected_phase = s->ready_poll_control_enabled ? 4 : 3;

        if (entry != s->ready_poll_active_entry) {
            s->ready_poll_active_entry = entry;
            s->ready_poll_active_set_offset = set_offset;
            s->ready_poll_active_clear_offset = clear_offset;
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
                  s->ready_poll_active_set_offset) {
            if (value == 1) {
                s->ready_poll_phase = 2;
            } else {
                msm5xxx_poc_ready_reject(s);
            }
        } else if (pc == s->ready_poll_active_entry +
                         s->ready_poll_active_clear_offset) {
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

/* A detector-admitted high->low pulse starts/reloads this virtual watchdog.
 * QEMU_CLOCK_VIRTUAL advances with icount, independently of guest IRQ/FIQ.
 * No timer runs before the first complete pulse (or after a machine reset).
 */
static bool msm5xxx_poc_watchdog_valid(MSM5xxxPOCMachineState *s)
{
    return s->memory_profile_enabled &&
        s->watchdog_register >= MSM5XXX_POC_MSM_BASE &&
        s->watchdog_register < MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE &&
        s->watchdog_mask && s->watchdog_mask <= UINT8_MAX &&
        !(s->watchdog_mask & (s->watchdog_mask - 1)) &&
        s->watchdog_timeout_ms && s->watchdog_timeout_ms <= 3600000;
}

static void msm5xxx_poc_watchdog_expire(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    if (s->watchdog_armed) {
        s->watchdog_armed = false;
        /* Use the normal full reset: flash block devices and EEPROM device
         * contents survive; msm5xxx_poc_reset resets only their controllers. */
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }
}

static void msm5xxx_poc_watchdog_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    timer_del(s->watchdog_timer);
    s->watchdog_high = false;
    s->watchdog_armed = false;
    s->watchdog_backing = 0;
    s->watchdog_last_edge_ns = 0;
}

static void msm5xxx_poc_watchdog_pulse(MSM5xxxPOCMachineState *s,
                                       uint8_t value)
{
    bool high = (value & s->watchdog_mask) != 0;
    if (s->watchdog_high && !high) {
        s->watchdog_last_edge_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        s->watchdog_armed = true;
        timer_mod(s->watchdog_timer, s->watchdog_last_edge_ns +
                  (int64_t)s->watchdog_timeout_ms * 1000000);
    }
    s->watchdog_high = high;
    s->watchdog_backing = value;
}

static uint64_t msm5xxx_poc_watchdog_read(void *opaque, hwaddr offset,
                                          unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    if (s->ready_poll_enabled && !s->ready_poll_lcd_enabled &&
        s->ready_pulse_address == s->watchdog_register) {
        return msm5xxx_poc_ready_pulse_read(s, offset, size);
    }
    return s->watchdog_backing;
}

static void msm5xxx_poc_watchdog_write(void *opaque, hwaddr offset,
                                       uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    if (offset || size != 1) {
        return;
    }
    msm5xxx_poc_watchdog_pulse(s, value);
    if (s->ready_poll_enabled && !s->ready_poll_lcd_enabled &&
        s->ready_pulse_address == s->watchdog_register) {
        msm5xxx_poc_ready_pulse_write(s, offset, value, size);
    }
}

static const MemoryRegionOps msm5xxx_poc_watchdog_ops = {
    .read = msm5xxx_poc_watchdog_read,
    .write = msm5xxx_poc_watchdog_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 1,
};

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

static bool msm5xxx_poc_dmd5100_active(MSM5xxxPOCMachineState *s)
{
    return s->dmd5100_phase >= DMD5100_HOLD && s->dmd5100_phase <= DMD5100_ODD_DONE;
}

static void msm5xxx_poc_dmd5100_regions(MSM5xxxPOCMachineState *s, bool forwarding)
{
    if (s->dmd5100_mapped) {
        for (unsigned i = 0; i < 5; i++) {
            memory_region_set_enabled(&s->dmd5100_region[i],
                !forwarding && (i == 2 || msm5xxx_poc_dmd5100_active(s)));
        }
    }
}

static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState *s,
                                         uint32_t *pc)
{
    CPUState *cpu = CPU(s->cpu);
    uint64_t data[INSN_START_WORDS];
    uint32_t page_mask = qemu_target_page_mask();

    *pc = CPU_GET_CLASS(cpu)->get_pc(cpu) & ~1U;
    /* TCG may leave get_pc at an earlier instruction; unwind without restoring
     * CPU state or changing the instruction counter. */
    if (current_cpu != cpu || !cpu->mem_io_pc ||
        !cpu_unwind_state_data(cpu, cpu->mem_io_pc, data) || data[0] > UINT32_MAX) {
        return false;
    }
    if (tcg_cflags_has(cpu, CF_PCREL)) {
        if (data[0] & page_mask) {
            return false;
        }
        *pc = (*pc & page_mask) | data[0];
    } else {
        *pc = data[0];
    }
    *pc &= ~1U;
    return true;
}

static void msm5xxx_poc_dmd5100_record_rejection(MSM5xxxPOCMachineState *s,
    bool write, unsigned port, hwaddr offset, unsigned size, uint64_t value,
    MemTxResult result, unsigned phase, unsigned pairs)
{
    if (s->dmd5100_first_rejection || !s->cpu || !msm5xxx_poc_boot_storage_guest(s)) {
        return;
    }
    s->dmd5100_rejection_write = write;
    s->dmd5100_rejection_port = port;
    s->dmd5100_rejection_offset = offset;
    s->dmd5100_rejection_size = size;
    s->dmd5100_rejection_result = result;
    s->dmd5100_rejection_value_valid = write || result == MEMTX_OK;
    s->dmd5100_rejection_value = value;
    s->dmd5100_rejection_phase = phase;
    s->dmd5100_rejection_pairs = pairs;
    s->dmd5100_rejection_pc = s->cpu->env.regs[15];
    uint32_t recovered_pc = 0;
    s->dmd5100_rejection_recovered_pc_valid = msm5xxx_poc_mmio_access_pc(s, &recovered_pc);
    s->dmd5100_rejection_recovered_pc = s->dmd5100_rejection_recovered_pc_valid ? recovered_pc : 0;
    s->dmd5100_rejection_lr = s->cpu->env.regs[14];
    memcpy(s->dmd5100_rejection_regs, s->cpu->env.regs, sizeof(s->dmd5100_rejection_regs));
    s->dmd5100_rejection_cpsr = cpsr_read(&s->cpu->env);
    s->dmd5100_rejection_sctlr = s->cpu->env.cp15.sctlr_el[1];
    s->dmd5100_rejection_fcse_ns = s->cpu->env.cp15.fcseidr_ns;
    s->dmd5100_rejection_fcse_s = s->cpu->env.cp15.fcseidr_s;
    s->dmd5100_first_rejection = true;
}

static void msm5xxx_poc_dmd5100_reject(MSM5xxxPOCMachineState *s)
{
    s->dmd5100_phase = DMD5100_REJECTED;
    s->dmd5100_barrier = s->dmd5100_half_pending = false;
    if (s->dmd5100_rejections != UINT64_MAX) {
        s->dmd5100_rejections++;
    }
    msm5xxx_poc_dmd5100_regions(s, false);
}

static void msm5xxx_poc_dmd5100_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    s->dmd5100_phase = DMD5100_IDLE;
    s->dmd5100_pairs = s->dmd5100_even_reads = s->dmd5100_odd_reads = 0;
    s->dmd5100_rejections = 0;
    s->dmd5100_first_rejection = false;
    s->dmd5100_rejection_write = s->dmd5100_rejection_value_valid = false;
    s->dmd5100_rejection_port = s->dmd5100_rejection_size = s->dmd5100_rejection_result = 0;
    s->dmd5100_rejection_phase = s->dmd5100_rejection_pairs = 0;
    s->dmd5100_rejection_pc = s->dmd5100_rejection_lr = 0;
    s->dmd5100_rejection_recovered_pc_valid = false;
    s->dmd5100_rejection_recovered_pc = 0;
    memset(s->dmd5100_rejection_regs, 0, sizeof(s->dmd5100_rejection_regs));
    s->dmd5100_rejection_cpsr = s->dmd5100_rejection_fcse_ns = s->dmd5100_rejection_fcse_s = 0;
    s->dmd5100_rejection_offset = s->dmd5100_rejection_value = s->dmd5100_rejection_sctlr = 0;
    s->dmd5100_barrier = s->dmd5100_half_pending = false;
    msm5xxx_poc_dmd5100_regions(s, false);
}

static bool msm5xxx_poc_dmd5100_pc(MSM5xxxPOCMachineState *s, unsigned offset)
{
    uint32_t pc;
    return msm5xxx_poc_boot_storage_guest(s) && s->cpu->env.thumb &&
        !(s->cpu->env.cp15.sctlr_el[1] & 1) && !s->cpu->env.cp15.fcseidr_ns &&
        !s->cpu->env.cp15.fcseidr_s && msm5xxx_poc_mmio_access_pc(s, &pc) &&
        pc == s->dmd5100_entry + offset;
}

static MemTxResult msm5xxx_poc_dmd5100_forward(MSM5xxxPOCDMD5100Port *port,
    hwaddr offset, uint64_t *value, unsigned size, MemTxAttrs attrs, bool write)
{
    MSM5xxxPOCMachineState *s = port->machine;
    uint8_t bytes[8] = {0};
    MemTxResult result;
    if (port->index >= 5 || !size || size > sizeof(bytes) ||
        offset > UINT64_MAX - dmd5100_ports[port->index]) {
        return MEMTX_ERROR;
    }
    if (s->dmd5100_ram_verified && offset < 4 && size <= 4 - offset) {
        uint8_t *ram = memory_region_get_ram_ptr(&s->msm);
        uint64_t at = dmd5100_ports[port->index] - MSM5XXX_POC_MSM_BASE + offset;
        if (write) {
            msm5xxx_poc_backing_write(ram, at, *value, size);
            memory_region_set_dirty(&s->msm, at, size);
        } else {
            *value = msm5xxx_poc_backing_read(ram, at, size);
        }
        return MEMTX_OK;
    }
    msm5xxx_poc_dmd5100_regions(s, true);
    if (write) {
        msm5xxx_poc_backing_write(bytes, 0, *value, size);
        result = address_space_write(&address_space_memory,
            dmd5100_ports[port->index] + offset, attrs, bytes, size);
    } else {
        result = address_space_read(&address_space_memory,
            dmd5100_ports[port->index] + offset, attrs, bytes, size);
        if (result == MEMTX_OK) {
            *value = msm5xxx_poc_backing_read(bytes, 0, size);
        }
    }
    msm5xxx_poc_dmd5100_regions(s, false);
    return result;
}

static bool msm5xxx_poc_dmd5100_write_next(MSM5xxxPOCMachineState *s,
                                          unsigned port, uint64_t value, unsigned size)
{
    uint32_t *r = s->cpu->env.regs;
    uint32_t n = s->dmd5100_count, p = s->dmd5100_phase;
    if (port == 2 && size == 1 && value == 0 &&
        msm5xxx_poc_dmd5100_pc(s, 0x1a) && r[7] == 0) {
        s->dmd5100_phase = DMD5100_HOLD;
        s->dmd5100_pairs = s->dmd5100_even_reads = s->dmd5100_odd_reads = 0;
        s->dmd5100_barrier = s->dmd5100_half_pending = false;
    } else if (port == 0 && size == 2 && value == 0 && p == DMD5100_HOLD &&
               msm5xxx_poc_dmd5100_pc(s, 0x24) && r[3] == s->dmd5100_descriptor && !r[7]) {
        s->dmd5100_phase = DMD5100_PROGRAM;
    } else if (port == 1 && size == 2 && value <= UINT16_MAX && p == DMD5100_PROGRAM &&
               r[3] == s->dmd5100_descriptor && r[7] == 2 * s->dmd5100_pairs &&
               s->dmd5100_pairs < n) {
        if (!s->dmd5100_half_pending && msm5xxx_poc_dmd5100_pc(s, 0x3c)) {
            s->dmd5100_odd[s->dmd5100_pairs] = value;
            s->dmd5100_half_pending = true;
        } else if (s->dmd5100_half_pending && msm5xxx_poc_dmd5100_pc(s, 0x42) &&
                   r[2] == s->dmd5100_payload) {
            s->dmd5100_even[s->dmd5100_pairs++] = value;
            s->dmd5100_half_pending = false;
            if (s->dmd5100_pairs == n) {
                s->dmd5100_phase = DMD5100_FULL;
            }
        } else {
            return false;
        }
    } else if (port == 3 && size == 1 && value == 0x0e && p == DMD5100_FULL &&
               msm5xxx_poc_dmd5100_pc(s, 0x5e) && r[7] == 2 * n && r[6] == 0x030007e0) {
        s->dmd5100_phase = DMD5100_MODE;
    } else if (port == 4 && size == 1 && value == 0 && p == DMD5100_MODE &&
               msm5xxx_poc_dmd5100_pc(s, 0x62) && r[7] == 2 * n && r[6] == 0x030007e0) {
        s->dmd5100_phase = DMD5100_EVEN;
        s->dmd5100_barrier = false;
    } else if (port == 4 && size == 1 && value == 0 && p == DMD5100_EVEN_DONE &&
               msm5xxx_poc_dmd5100_pc(s, 0x8e) && r[7] == s->dmd5100_descriptor &&
               r[4] == 2 * n && r[2] == 0x030007e0) {
        s->dmd5100_phase = DMD5100_ODD;
        s->dmd5100_barrier = false;
    } else if (port == 3 && size == 1 && value == 0 && p == DMD5100_ODD_DONE &&
               msm5xxx_poc_dmd5100_pc(s, 0xb8) && r[7] == n &&
               r[4] == s->dmd5100_payload && r[1] == 2 * n && !r[0] && r[2] == 0x030007e0) {
        s->dmd5100_phase = DMD5100_CLOSED;
    } else if (!(port == 2 && size == 1 && value == 1 && p == DMD5100_CLOSED &&
                 msm5xxx_poc_dmd5100_pc(s, 0xc8) && r[7] == n && r[4] == s->dmd5100_payload)) {
        return false;
    }
    return true;
}

static MemTxResult msm5xxx_poc_dmd5100_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size, MemTxAttrs attrs)
{
    MSM5xxxPOCDMD5100Port *port = opaque;
    MSM5xxxPOCMachineState *s = port->machine;
    unsigned old_phase = s->dmd5100_phase, old_pairs = s->dmd5100_pairs;
    MemTxResult result = msm5xxx_poc_dmd5100_forward(port, offset, &value, size, attrs, true);
    if (msm5xxx_poc_boot_storage_guest(s)) {
        if (result != MEMTX_OK || offset ||
            !msm5xxx_poc_dmd5100_write_next(s, port->index, value, size)) {
            msm5xxx_poc_dmd5100_record_rejection(s, true, port->index, offset, size,
                value, result, old_phase, old_pairs);
            msm5xxx_poc_dmd5100_reject(s);
        }
        msm5xxx_poc_dmd5100_regions(s, false);
    }
    return result;
}

static MemTxResult msm5xxx_poc_dmd5100_read(void *opaque, hwaddr offset,
    uint64_t *value, unsigned size, MemTxAttrs attrs)
{
    MSM5xxxPOCDMD5100Port *port = opaque;
    MSM5xxxPOCMachineState *s = port->machine;
    unsigned p = s->dmd5100_phase, i = s->dmd5100_even_reads, j = s->dmd5100_odd_reads;
    unsigned old_pairs = s->dmd5100_pairs;
    uint32_t *r = s->cpu->env.regs;
    bool guest = msm5xxx_poc_boot_storage_guest(s);
    bool even = p == DMD5100_EVEN && port->index == 3 && i < s->dmd5100_count;
    bool odd = p == DMD5100_ODD && port->index == 4 && j < s->dmd5100_count;
    if (!offset && size == 2 && s->dmd5100_pairs == s->dmd5100_count && (even || odd)) {
        if (!guest) {
            *value = even ? s->dmd5100_even[i] : s->dmd5100_odd[j];
            return MEMTX_OK;
        }
        if (s->dmd5100_barrier &&
            ((even && msm5xxx_poc_dmd5100_pc(s, 0x78) && r[7] == s->dmd5100_descriptor &&
              r[2] == s->dmd5100_payload && r[4] == 2 * i && r[0] == i && r[3] == s->dmd5100_count) ||
             (odd && msm5xxx_poc_dmd5100_pc(s, 0xa4) && r[7] == s->dmd5100_count &&
              r[4] == s->dmd5100_payload && r[1] == 2 * j && r[0] == j && r[2] == 0x030007e0))) {
            *value = even ? s->dmd5100_even[i++] : s->dmd5100_odd[j++];
            s->dmd5100_even_reads = i;
            s->dmd5100_odd_reads = j;
            if (even && i == s->dmd5100_count) {
                s->dmd5100_phase = DMD5100_EVEN_DONE;
            } else if (odd && j == s->dmd5100_count) {
                s->dmd5100_phase = DMD5100_ODD_DONE;
            }
            return MEMTX_OK;
        }
    }
    MemTxResult result = msm5xxx_poc_dmd5100_forward(port, offset, value, size, attrs, false);
    if (guest && msm5xxx_poc_dmd5100_active(s)) {
        bool barrier = !offset && size == 1 && port->index == 3 && !s->dmd5100_barrier &&
            ((p == DMD5100_EVEN && !i && msm5xxx_poc_dmd5100_pc(s, 0x64) &&
              r[7] == 2 * s->dmd5100_count && r[6] == 0x030007e0) ||
             (p == DMD5100_ODD && !j && msm5xxx_poc_dmd5100_pc(s, 0x90) &&
              r[7] == s->dmd5100_descriptor && r[2] == 0x030007e0));
        if (result == MEMTX_OK && barrier) {
            s->dmd5100_barrier = true;
        } else {
            msm5xxx_poc_dmd5100_record_rejection(s, false, port->index, offset, size,
                result == MEMTX_OK ? *value : 0, result, p, old_pairs);
            msm5xxx_poc_dmd5100_reject(s);
        }
    }
    return result;
}

static const MemoryRegionOps msm5xxx_poc_dmd5100_ops = {
    .read_with_attrs = msm5xxx_poc_dmd5100_read,
    .write_with_attrs = msm5xxx_poc_dmd5100_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4, .valid.unaligned = true,
    .impl.min_access_size = 1, .impl.max_access_size = 4, .impl.unaligned = true,
};

static char *msm5xxx_poc_get_dmd5100(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    return s->dmd5100_enabled ? g_strdup_printf("%x:%x:%x:%x", s->dmd5100_entry,
        s->dmd5100_descriptor, s->dmd5100_payload, s->dmd5100_count) : g_strdup("");
}

static void msm5xxx_poc_set_dmd5100(Object *obj, const char *value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t v[4];
    const char *part = value, *end;
    unsigned long parsed;
    if (s->cpu || s->dmd5100_enabled || !part) {
        goto malformed;
    }
    for (unsigned i = 0; i < 4; i++) {
        if (!g_ascii_isxdigit(*part) || qemu_strtoul(part, &end, 16, &parsed) || parsed > UINT32_MAX ||
            (i < 3 ? *end != ':' : *end != '\0')) {
            goto malformed;
        }
        v[i] = parsed;
        part = end + (i < 3);
    }
    if (!v[0] || v[0] & 1 || v[1] & 3 || v[2] & 1 || !v[3] || v[3] > 0x7fff) {
        goto malformed;
    }
    s->dmd5100_entry = v[0]; s->dmd5100_descriptor = v[1];
    s->dmd5100_payload = v[2]; s->dmd5100_count = v[3]; s->dmd5100_enabled = true;
    return;
malformed:
    error_setg(errp, "dmd5100-program requires bounded ENTRY:DESCRIPTOR:PAYLOAD:PAIR_COUNT before realization");
}

static char *msm5xxx_poc_get_dmd5100_stats(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    return g_strdup_printf("phase=%u pairs=%u even=%u odd=%u rejections=%" G_GUINT64_FORMAT,
        s->dmd5100_phase, s->dmd5100_pairs, s->dmd5100_even_reads,
        s->dmd5100_odd_reads, s->dmd5100_rejections);
}

static char *msm5xxx_poc_get_dmd5100_rejection(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    if (!s->dmd5100_first_rejection) {
        return g_strdup("recorded=0");
    }
    return g_strdup_printf("recorded=1 op=%s port=%u offset=0x%" PRIx64
        " size=%u value_valid=%u value=0x%" PRIx64 " result=%u phase=%u pairs=%u"
        " pc=%08x recovered_pc_valid=%u recovered_pc=%08x lr=%08x"
        " r0=%08x r1=%08x r2=%08x r3=%08x r4=%08x r5=%08x r6=%08x r7=%08x"
        " cpsr=%08x sctlr=0x%" PRIx64 " fcse_ns=%08x fcse_s=%08x",
        s->dmd5100_rejection_write ? "write" : "read", s->dmd5100_rejection_port,
        s->dmd5100_rejection_offset, s->dmd5100_rejection_size,
        s->dmd5100_rejection_value_valid, s->dmd5100_rejection_value,
        s->dmd5100_rejection_result, s->dmd5100_rejection_phase, s->dmd5100_rejection_pairs,
        s->dmd5100_rejection_pc, s->dmd5100_rejection_recovered_pc_valid,
        s->dmd5100_rejection_recovered_pc, s->dmd5100_rejection_lr,
        s->dmd5100_rejection_regs[0], s->dmd5100_rejection_regs[1],
        s->dmd5100_rejection_regs[2], s->dmd5100_rejection_regs[3],
        s->dmd5100_rejection_regs[4], s->dmd5100_rejection_regs[5],
        s->dmd5100_rejection_regs[6], s->dmd5100_rejection_regs[7],
        s->dmd5100_rejection_cpsr, s->dmd5100_rejection_sctlr,
        s->dmd5100_rejection_fcse_ns, s->dmd5100_rejection_fcse_s);
}

static bool msm5xxx_poc_dmd5100_topology(MSM5xxxPOCMachineState *s)
{
    const uint32_t bases[] = {s->dmd5100_entry, s->dmd5100_descriptor, s->dmd5100_payload};
    const uint32_t lengths[] = {244, 8, 4 * s->dmd5100_count};
    if (!s->memory_profile_enabled || !memory_region_is_rom(&s->nor)) {
        return false;
    }
    for (unsigned i = 0; i < 8; i++) {
        uint64_t address = i < 3 ? bases[i] : dmd5100_ports[i - 3];
        unsigned length = i < 3 ? lengths[i] : 4;
        if (i < 3 && address + length > s->primary_nor_size) {
            return false;
        }
        MemoryRegionSection section = memory_region_find(get_system_memory(), address, length);
        bool valid = section.mr == (i < 3 ? &s->nor : &s->msm) &&
            section.offset_within_region == (i < 3 ? address : address - MSM5XXX_POC_MSM_BASE) &&
            int128_eq(section.size, int128_make64(length));
        if (section.mr) {
            memory_region_unref(section.mr);
        }
        if (!valid) {
            return false;
        }
    }
    return true;
}

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

/* Six active-low rows, four active-low sense lines. Other GPIO bits belong
 * to the firmware. This class is explicit opt-in until detector admission. */
static uint16_t msm5xxx_poc_halfword_sense(uint16_t backing, uint16_t output,
                                           bool pressed, unsigned row,
                                           unsigned sense)
{
    unsigned value = 0xf;

    if (pressed && row < 6 &&
        (sense == 0xe || sense == 0xd || sense == 0xb || sense == 7) &&
        !(output & (1U << (row + 8)))) {
        value = sense;
    }
    return (backing & 0xfff0) | value;
}

/* Temporary electrical approximation: opt-in active-low selector mapping.
 * Ascending mask bits identify host rows; other GPIO bits stay firmware-owned. */
static bool msm5xxx_poc_mapped_halfword_sense(uint16_t backing, uint16_t output,
                                             uint16_t mask, bool presence,
                                             bool pressed, unsigned row,
                                             unsigned sense, uint16_t *result)
{
    unsigned selected = (~output) & mask;
    unsigned bits = mask;
    unsigned row_bit;

    *result = backing;
    if (!mask || (presence ? selected != mask :
                  !selected || (selected & (selected - 1)))) {
        return false;
    }
    for (unsigned i = 0; i < row && bits; i++) {
        bits &= bits - 1;
    }
    row_bit = bits & -bits;
    if (pressed && (!row_bit ||
        !(sense == 0xe || sense == 0xd || sense == 0xb || sense == 7))) {
        return false;
    }
    *result = (backing & 0xfff0) |
        (pressed && (selected & row_bit) ? sense : 0xf);
    return true;
}

/* Temporary electrical approximation: firmware-qualified low-five-bit
 * no-key/single-key levels, not measured physical idle or clock fidelity.
 * Selector/backing bits outside this input plane remain firmware-owned. */
static bool msm5xxx_poc_low5_sense(uint16_t backing, uint16_t output728,
                                    uint16_t output724, bool presence,
                                    bool pressed, unsigned row, unsigned sense,
                                    uint16_t *result)
{
    unsigned low = output728 & 0x1f;
    unsigned selected;

    *result = backing;
    if (presence) {
        if (low || (output724 & 0x4000)) {
            return false;
        }
        selected = 0x3f; /* All six rows selected for the global sense. */
    } else {
        unsigned remaining;

        selected = (low ^ 0x1f) |
            ((output724 & 0x4000) ? 0 : 0x20);
        /* The row scanner selects its first anchor plus the current row. */
        remaining = selected & (selected - 1);
        if (!selected || (remaining & (remaining - 1))) {
            return false;
        }
    }
    if (pressed && (row >= 6 ||
        !(sense == 30 || sense == 29 || sense == 27 ||
          sense == 23 || sense == 15))) {
        return false;
    }
    *result = (backing & 0xffe0) |
        (pressed && (selected & (1U << row)) ? sense : 0x1f);
    return true;
}

/* Source-selected high one-hot rows; upper input/control bits stay native.
 * The boot transaction is restricted to the proven released-contact case. */
static bool msm5xxx_poc_row734_sense(uint16_t backing, uint16_t enable728,
        uint16_t output734, bool presence, bool boot, bool pressed,
        unsigned row, unsigned sense, uint16_t *result)
{
    unsigned selected = output734 & 0x9f;
    unsigned row_bit;
    *result = backing;
    if ((enable728 & 0x9f) || (presence && boot) ||
        (pressed && (row >= 6 ||
         !(sense == 30 || sense == 29 || sense == 27 ||
           sense == 23 || sense == 15)))) {
        return false;
    }
    if (boot) {
        if (selected != 0x1f || pressed) {
            return false;
        }
    } else if (presence) {
        if (selected != 0x9f) {
            return false;
        }
    } else if (!selected || (selected & (selected - 1))) {
        return false;
    }
    row_bit = row < 5 ? 1U << row : 0x80;
    *result = (backing & 0xffe0) |
        (pressed && (selected & row_bit) ? sense : 0x1f);
    return true;
}

/* Temporary opt-in electrical approximation, independent of control backing. */
static bool msm5xxx_poc_loop_sense(uint16_t backing, uint16_t output728,
                                  uint16_t output720, bool presence,
                                  bool pressed, unsigned row, unsigned sense,
                                  uint16_t *value)
{
    unsigned low = output728 & 31, selected = 6;
    bool all = presence && low == 0 && !(output720 & 32);

    *value = backing;
    if (!all) {
        if (presence) {
            if (low != 30 || !(output720 & 32)) {
                return false;
            }
            selected = 0;
        } else if (low == 31 && !(output720 & 32)) {
            selected = 5;
        } else if (output720 & 32) {
            for (unsigned i = 0; i < 5; i++) {
                if (low == (31u ^ (1u << i))) {
                    selected = i;
                }
            }
            if (selected == 6) {
                return false;
            }
        } else {
            return false;
        }
    }
    unsigned result = 31;
    if (pressed && row < 6 && (all || row == selected) &&
        (sense == 30 || sense == 29 || sense == 27 || sense == 23)) {
        result = sense;
    }
    *value = (backing & 0xffe0) | result;
    return true;
}

static uint32_t msm5xxx_poc_guest_u32(hwaddr address);
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s);
static void msm5xxx_poc_rex_irq_schedule(MSM5xxxPOCMachineState *s);
/* Experimental occupancy model: inclusive half-full or empty threshold.
 * Physical fetch timing and pin latch semantics remain approximations. */
static bool msm5xxx_poc_ma2_irq_gate(MSM5xxxPOCMachineState *s)
{
    const uint32_t *r = s->audio_irq_route;
    uint64_t end = (uint64_t)s->ram_base + MACHINE(s)->ram_size;
    uint32_t state;
    unsigned i;

    s->audio_irq_gate_status = 1;
    if (!s->audio_irq_configured || !s->audio_ma2 || !s->audio_enabled ||
        s->rex_irq_c80 || s->rex_irq_read_consume ||
        s->rex_irq_bank_count != 2 || s->rex_irq_status_address != 0x03000620 ||
        s->rex_irq_enable_address != 0x03000628 || s->audio_stream_rejected ||
        s->ma2_audio.adpcm_irq_ctrl || s->ma2_audio.soft_reset_mask ||
        (s->ma2_audio.control & (MSM5XXX_MA2_ADPCM_START | MSM5XXX_MA2_DIRECT_START)) ||
        msm5xxx_ma2_rejected(&s->ma2_audio)) {
        return false;
    }
    if (r[0] < s->ram_base || (uint64_t)r[0] + 28 > end ||
        r[7] < s->ram_base || (uint64_t)r[7] + 8 > end ||
        r[8] < s->ram_base || (uint64_t)r[8] + 16 > end ||
        r[4] < s->ram_base || (uint64_t)r[4] + 2 > end ||
        r[5] < s->ram_base || (uint64_t)r[5] + 2 > end) {
        return false;
    }
    s->audio_irq_gate_status = 2;
    for (i = 0; i < 5; i++) {
        if (msm5xxx_poc_guest_u32(r[0] + i * 4) != r[i + 1]) {
            return false;
        }
    }
    /* Descriptor +24 low halfword is a wrapping guest IRQ counter. */
    if (msm5xxx_poc_guest_u32(r[0] + 20) != (r[6] | 1) ||
        (msm5xxx_poc_guest_u32(r[0] + 24) >> 16) != 0) {
        return false;
    }
    s->audio_irq_gate_status = 3;
    state = msm5xxx_poc_guest_u32(r[7] + 4);
    if (((state >> 8) & 0xff) < 1 || ((state >> 8) & 0xff) > 4 ||
        (state >> 16) & ~0xfu) {
        return false;
    }
    for (i = 0; i < 4; i++) {
        if ((state & (1u << (16 + i))) &&
            msm5xxx_poc_guest_u32(r[8] + i * 4) == (r[9] | 1)) {
            s->audio_irq_gate_status = 4;
            return true;
        }
    }
    return false;
}

static uint8_t msm5xxx_poc_ma2_fifo_flags(MSM5xxxPOCMachineState *s)
{
    unsigned point = s->ma2_audio.fm_irq_ctrl & 7;
    uint8_t flags = 0;
    unsigned i;

    if (point != 0 && point != 3) {
        return 0;
    }
    for (i = 0; i < 4; i++) {
        if (!s->audio_command_pending_count[i] &&
            s->ma2_audio.fifo_count[i] <= (point == 3 ? 48 : 0)) {
            flags |= 1u << i;
        }
    }
    return flags;
}

static void msm5xxx_poc_ma2_irq_update(MSM5xxxPOCMachineState *s)
{
    bool level;
    uint16_t mask;

    if (!s->audio_irq_configured) {
        return;
    }
    mask = s->audio_irq_route[3];
    qemu_mutex_lock(&s->audio_core_lock);
    level = msm5xxx_poc_ma2_irq_gate(s) &&
            (s->ma2_audio.control & MSM5XXX_MA2_FM_START) &&
            (msm5xxx_poc_ma2_fifo_flags(s) & (s->ma2_audio.fm_irq_ctrl >> 4));
    qemu_mutex_unlock(&s->audio_core_lock);
    if (level) {
        s->rex_irq_pending[1] |= mask;
        if (!s->audio_irq_asserted) {
            s->audio_irq_assertions++;
        }
    } else if (s->audio_irq_asserted) {
        s->rex_irq_pending[1] &= ~mask;
    }
    s->audio_irq_asserted = level;
    msm5xxx_poc_rex_irq_update(s);
}


enum {
    MA5R_TABLE, MA5R_CALLBACKS, MA5R_PIN, MA5R_DESCRIPTOR,
    MA5R_STATUS, MA5R_ENABLE, MA5R_MASK, MA5R_SHADOW, MA5R_PRIORITY,
    MA5R_GPIO_DISPATCH, MA5R_SOC_DISPATCH, MA5R_EXCEPTION_SLOT,
    MA5R_DIRECT, MA5R_DEFERRED, MA5R_INSTALLED, MA5R_SELECT,
    MA5R_OVERRIDE, MA5R_CONTEXT, MA5R_COUNT
};

static bool msm5xxx_poc_ma5_irq_ram(MSM5xxxPOCMachineState *s,
                                    uint32_t address, unsigned size,
                                    unsigned alignment)
{
    uint64_t end = (uint64_t)s->ram_base + MACHINE(s)->ram_size;

    return !(address % alignment) && address >= s->ram_base &&
           (uint64_t)address + size <= end;
}

static uint16_t msm5xxx_poc_ma5_irq_guest(MSM5xxxPOCMachineState *s,
                                         uint32_t address, unsigned size)
{
    uint8_t bytes[2] = {0};

    (void)s;

    cpu_physical_memory_read(address, bytes, size);
    return bytes[0] | (uint16_t)bytes[1] << 8;
}

/* Returns a diagnostic gate, not a claim that auxiliary software is modeled. */
static unsigned msm5xxx_poc_ma5_irq_gate(MSM5xxxPOCMachineState *s)
{
    const uint32_t *r = s->ma5_irq_route;
    const unsigned fields[] = {MA5R_TABLE, MA5R_CALLBACKS, MA5R_DESCRIPTOR,
        MA5R_SHADOW, MA5R_PRIORITY, MA5R_EXCEPTION_SLOT, MA5R_INSTALLED,
        MA5R_CONTEXT};
    const unsigned sizes[] = {72, 192, 28, 2, 2, 4, 1, 4};
    const unsigned alignments[] = {4, 4, 4, 2, 2, 4, 1, 4};
    unsigned bank = r[MA5R_PIN] >> 4;
    uint16_t pin = 1u << (r[MA5R_PIN] & 15);
    uint32_t expected, context;
    uint16_t cached, hardware, parent;
    uint8_t *msm;

    if (!s->ma5_irq_configured || r[MA5R_PIN] >= 48 ||
        !s->ma5_byte_ns || (!s->ma5_clki_hz && !s->ma5_device.clki_hz) ||
        !s->rex_irq_enabled || !s->rex_irq_c80 || s->rex_irq_read_consume ||
        s->rex_irq_status_address != 0x03000c80 ||
        s->rex_irq_enable_address != 0x03000c94 ||
        s->rex_irq_handler_address != (r[MA5R_SOC_DISPATCH] & ~1u) ||
        s->rex_irq_handler_slot != r[MA5R_EXCEPTION_SLOT] ||
        (!r[MA5R_INSTALLED] &&
         (r[MA5R_DEFERRED] || r[MA5R_SELECT] || r[MA5R_OVERRIDE]))) {
        return 1;
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(fields); i++) {
        if (fields[i] == MA5R_INSTALLED && !r[MA5R_INSTALLED]) {
            continue;
        }
        if (!msm5xxx_poc_ma5_irq_ram(s, r[fields[i]], sizes[i], alignments[i])) {
            return 2;
        }
    }
    if (r[MA5R_DEFERRED] &&
        (!msm5xxx_poc_ma5_irq_ram(s, r[MA5R_SELECT], 1, 1) ||
         !msm5xxx_poc_ma5_irq_ram(s, r[MA5R_OVERRIDE], 1, 1))) {
        return 2;
    }
    for (unsigned i = 0; i < 5; i++) {
        if (msm5xxx_poc_guest_u32(r[MA5R_DESCRIPTOR] + 4 * i) != r[MA5R_STATUS + i]) {
            return 3;
        }
    }
    for (unsigned b = 0; b < 3; b++) {
        const uint32_t row[] = {0x03000c88 + b * 4, 0x03000ca4 + b * 4,
                               0x03000cb0 + b * 4, 0x0300074c + b * 4};
        for (unsigned i = 0; i < 4; i++) {
            if (msm5xxx_poc_guest_u32(r[MA5R_TABLE] + b * 24 + i * 4) != row[i]) {
                return 3;
            }
        }
    }
    if (msm5xxx_poc_guest_u32(r[MA5R_DESCRIPTOR] + 20) != r[MA5R_GPIO_DISPATCH] ||
        msm5xxx_poc_guest_u32(r[MA5R_EXCEPTION_SLOT]) != r[MA5R_SOC_DISPATCH]) {
        return 4;
    }
    /* Direct callback registration need not own a separate installed byte. */
    if (r[MA5R_INSTALLED] &&
        msm5xxx_poc_ma5_irq_guest(s, r[MA5R_INSTALLED], 1) != 1) {
        return 5;
    }
    context = msm5xxx_poc_guest_u32(r[MA5R_CONTEXT]);
    if (!msm5xxx_poc_ma5_irq_ram(s, context, 0x483, 4)) {
        return 5;
    }
    expected = r[MA5R_DIRECT];
    if (r[MA5R_DEFERRED] &&
        msm5xxx_poc_ma5_irq_guest(s, r[MA5R_SELECT], 1) &&
        !msm5xxx_poc_ma5_irq_guest(s, r[MA5R_OVERRIDE], 1)) {
        expected = r[MA5R_DEFERRED];
    }
    if (msm5xxx_poc_guest_u32(r[MA5R_CALLBACKS] + r[MA5R_PIN] * 4) != expected) {
        return 6;
    }
    msm = memory_region_get_ram_ptr(&s->msm);
    cached = msm5xxx_poc_ma5_irq_guest(s, r[MA5R_TABLE] + bank * 24 + 16, 2);
    hardware = msm5xxx_poc_backing_read(s->rex_irq_backing, 0x24 + bank * 4, 2);
    if ((cached ^ hardware) & pin) {
        return 7;
    }
    if ((msm5xxx_poc_ma5_irq_guest(s, r[MA5R_TABLE] + bank * 24 + 18, 2) |
         msm5xxx_poc_backing_read(s->rex_irq_backing, 0x30 + bank * 4, 2) |
         msm5xxx_poc_ma5_irq_guest(s, r[MA5R_TABLE] + bank * 24 + 20, 2) |
         msm5xxx_poc_backing_read(msm, 0x74c + bank * 4, 2)) & pin) {
        return 8;
    }
    parent = msm5xxx_poc_ma5_irq_guest(s, r[MA5R_SHADOW], 2) &
             msm5xxx_poc_ma5_irq_guest(s, r[MA5R_PRIORITY], 2);
    if ((parent ^ msm5xxx_poc_backing_read(s->rex_irq_backing, 0x18, 2)) &
        r[MA5R_MASK]) {
        return 7;
    }
    return 0;
}

static void msm5xxx_poc_ma5_irq_update(MSM5xxxPOCMachineState *s)
{
    const uint32_t *r = s->ma5_irq_route;
    unsigned status;
    bool parent = false;

    if (!s->ma5_irq_configured) {
        return;
    }
    status = msm5xxx_poc_ma5_irq_gate(s);
    s->ma5_irq_qualified = status == 0;
    if (status != s->ma5_irq_gate_status) {
        qemu_log_mask(LOG_GUEST_ERROR, "MA5 IRQ gate=%u\n", status);
        s->ma5_irq_gate_status = status;
    }
    if (s->ma5_irq_qualified) {
        if (msm5xxx_ma5_device_irq(&s->ma5_device)) {
            s->ma5_gpio_pending[r[MA5R_PIN] >> 4] |= 1u << (r[MA5R_PIN] & 15);
        }
        for (unsigned bank = 0; bank < 3; bank++) {
            parent |= (s->ma5_gpio_pending[bank] &
                       msm5xxx_poc_backing_read(s->rex_irq_backing,
                                                0x24 + bank * 4, 2)) != 0;
        }
        if (parent) {
            s->ma5_parent_pending |= r[MA5R_MASK];
        }
    }
    parent = s->ma5_irq_qualified &&
             (s->ma5_parent_pending & r[MA5R_MASK] &
              msm5xxx_poc_backing_read(s->rex_irq_backing, 0x18, 2));
    if (parent && !s->ma5_irq_level) {
        s->ma5_irq_assertions++;
        if (s->ma5_irq_assertions <= 16) {
            qemu_log_mask(LOG_GUEST_ERROR, "MA5 IRQ parent assert=%u pin=%u fifo=%u\n",
                          s->ma5_irq_assertions, r[MA5R_PIN],
                          s->ma5_device.delayed_count);
        }
    }
    s->ma5_irq_level = parent;
    msm5xxx_poc_rex_irq_update(s);
}

/* This admitted class has two SoC banks and three separate GPIO banks. */
static uint64_t msm5xxx_poc_ma5_irq_read(MSM5xxxPOCMachineState *s,
                                        hwaddr offset, unsigned size)
{
    uint64_t result = msm5xxx_poc_backing_read(s->rex_irq_backing, offset, size);

    msm5xxx_poc_ma5_irq_update(s);
    for (unsigned i = 0; i < size; i++) {
        hwaddr byte = offset + i;
        uint16_t pending = 0;
        unsigned shift = 0;
        bool status = false;

        if (byte < 2 || (byte >= 4 && byte < 6)) {
            unsigned bank = byte / 4;
            pending = s->rex_irq_pending[bank];
            if (bank == 1 && s->ma5_irq_qualified) {
                pending |= s->ma5_parent_pending;
            }
            shift = (byte % 4) * 8;
            status = true;
        } else {
            for (unsigned bank = 0; bank < 3; bank++) {
                hwaddr base = 8 + bank * 4;
                if (byte >= base && byte < base + 2) {
                    pending = s->ma5_gpio_pending[bank];
                    shift = (byte - base) * 8;
                    status = true;
                    break;
                }
            }
        }
        if (status) {
            result = (result & ~(UINT64_C(255) << (i * 8))) |
                     (uint64_t)((pending >> shift) & 255) << (i * 8);
        }
    }
    return result;
}

static void msm5xxx_poc_ma5_irq_write(MSM5xxxPOCMachineState *s,
                                     hwaddr offset, uint64_t value, unsigned size)
{
    uint16_t before = s->rex_irq_pending[0];
    uint32_t gpio_before = s->ma5_gpio_acks, parent_before = s->ma5_parent_acks;

    for (unsigned i = 0; i < size; i++) {
        hwaddr byte = offset + i;
        unsigned incoming = (value >> (i * 8)) & 255;
        bool status = false;

        if (byte < 2 || (byte >= 4 && byte < 6)) {
            unsigned bank = byte / 4;
            uint16_t ack = incoming << ((byte % 4) * 8);
            s->rex_irq_pending[bank] &= ~ack;
            if (bank == 1) {
                if (s->ma5_parent_pending & ack) {
                    s->ma5_parent_acks++;
                }
                s->ma5_parent_pending &= ~ack;
            }
            status = true;
        } else {
            for (unsigned bank = 0; bank < 3; bank++) {
                hwaddr base = 8 + bank * 4;
                if (byte >= base && byte < base + 2) {
                    uint16_t ack = incoming << ((byte - base) * 8);
                    if (s->ma5_gpio_pending[bank] & ack) {
                        s->ma5_gpio_acks++;
                    }
                    s->ma5_gpio_pending[bank] &= ~ack;
                    status = true;
                    break;
                }
            }
        }
        if (!status) {
            s->rex_irq_backing[byte] = incoming;
        }
    }
    if ((before & s->rex_irq_mask) && !(s->rex_irq_pending[0] & s->rex_irq_mask)) {
        s->rex_irq_acks++;
    }
    if ((gpio_before != s->ma5_gpio_acks || parent_before != s->ma5_parent_acks) &&
        s->ma5_gpio_acks + s->ma5_parent_acks <= 32) {
        qemu_log_mask(LOG_GUEST_ERROR, "MA5 IRQ ACK gpio=%u parent=%u fifo=%u\n",
                      s->ma5_gpio_acks, s->ma5_parent_acks, s->ma5_device.delayed_count);
    }
    msm5xxx_poc_ma5_irq_update(s);
    msm5xxx_poc_rex_irq_schedule(s);
}

static uint64_t msm5xxx_poc_ma5_trigger_read(void *opaque, hwaddr offset,
                                            unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset + size > 12) {
        return 0;
    }
    return msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm),
                                    0x74c + offset, size);
}

static void msm5xxx_poc_ma5_trigger_write(void *opaque, hwaddr offset,
                                         uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset + size > 12) {
        return;
    }
    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s->msm),
                             0x74c + offset, value, size);
    msm5xxx_poc_ma5_irq_update(s);
}

static const MemoryRegionOps msm5xxx_poc_ma5_trigger_ops = {
    .read = msm5xxx_poc_ma5_trigger_read,
    .write = msm5xxx_poc_ma5_trigger_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};


static bool msm5xxx_poc_loop_status_matches(MSM5xxxPOCMachineState *s)
{
    return s->matrix_input_loop && s->board_status_input_enabled &&
           s->board_status_input_descriptor == s->matrix_input_descriptor &&
           s->board_status_input_address == MSM5XXX_POC_MSM_BASE + 0x720 &&
           s->board_status_input_mask == 0x10;
}

/* Descriptor-gated status shares the original GPIO backing. Host status owns
 * only its mask; invalid/uninitialized descriptors retain native reads. */
static uint64_t msm5xxx_poc_board_status_halfword_read(void *opaque,
                                                       hwaddr offset,
                                                       unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint64_t backing = msm5xxx_poc_backing_read(msm,
        s->board_status_input_address - MSM5XXX_POC_MSM_BASE + offset, size);
    CPUState *cpu = current_cpu;

    if (offset || ((s->matrix_input_loop || s->matrix_input_row734) && size != 2) ||
        !qemu_in_vcpu_thread() || cpu != CPU(s->cpu) ||
        !cpu->running || !cpu->neg.can_do_io) {
        return backing;
    }
    if (s->matrix_input_row734) {
        uint32_t pc = CPU_GET_CLASS(cpu)->get_pc(cpu) & ~1U;
        uint32_t instruction;
        if (!s->cpu->env.thumb || s->primary_nor_size < 4 ||
            pc > s->primary_nor_size - 2) {
            return backing;
        }
        instruction = msm5xxx_poc_guest_u32(pc & ~3U) >> ((pc & 2) * 8);
        if ((instruction & 0xf800) != 0x8800) {
            return backing; /* Do not project this input onto split WORD reads. */
        }
    }
    if (msm5xxx_poc_guest_u32(s->board_status_input_descriptor + 4) !=
            s->board_status_input_address) {
        s->board_status_input_rejections++;
        return backing;
    }
    return (backing & ~(uint64_t)s->board_status_input_mask) |
           s->board_status_input_level;
}

static void msm5xxx_poc_board_status_halfword_write(void *opaque, hwaddr offset,
                                                     uint64_t value,
                                                     unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s->msm),
        s->board_status_input_address - MSM5XXX_POC_MSM_BASE + offset,
        value, size);
}

static const MemoryRegionOps msm5xxx_poc_board_status_halfword_ops = {
    .read = msm5xxx_poc_board_status_halfword_read,
    .write = msm5xxx_poc_board_status_halfword_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 2,
};


static uint64_t msm5xxx_poc_eeprom_gpio_read(void *opaque, hwaddr offset,
                                            unsigned size);
static void msm5xxx_poc_eeprom_gpio_write(void *opaque, hwaddr offset,
                                         uint64_t value, unsigned size);

/* Mapped halfword and distributed byte overlays retain the effective EEPROM
 * GPIO owner. Legacy classes keep their original backing and write behavior. */
static uint64_t msm5xxx_poc_halfword_backing_read(MSM5xxxPOCMachineState *s,
                                                 hwaddr offset, unsigned size)
{
    uint64_t address = MSM5XXX_POC_MSM_BASE + offset;

    if ((s->matrix_input_row_mask || s->matrix_input_gpio || s->matrix_input_loop) &&
        s->eeprom_gpio_enabled &&
        address >= s->eeprom_gpio_base &&
        address + size <= (uint64_t)s->eeprom_gpio_base +
                          MSM5XXX_POC_EEPROM_GPIO_SIZE) {
        return msm5xxx_poc_eeprom_gpio_read(s,
            address - s->eeprom_gpio_base, size);
    }
    return msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm),
                                   offset, size);
}

static void msm5xxx_poc_halfword_backing_write(MSM5xxxPOCMachineState *s,
                                               hwaddr offset, uint64_t value,
                                               unsigned size)
{
    uint64_t address = MSM5XXX_POC_MSM_BASE + offset;

    if ((s->matrix_input_row_mask || s->matrix_input_gpio || s->matrix_input_loop) &&
        s->eeprom_gpio_enabled &&
        address >= s->eeprom_gpio_base &&
        address + size <= (uint64_t)s->eeprom_gpio_base +
                          MSM5XXX_POC_EEPROM_GPIO_SIZE) {
        msm5xxx_poc_eeprom_gpio_write(s,
            address - s->eeprom_gpio_base, value, size);
        return;
    }
    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s->msm),
                              offset, value, size);
}

static uint16_t msm5xxx_poc_row734_u16(uint32_t address)
{
    return msm5xxx_poc_guest_u32(address & ~3U) >> ((address & 2) * 8);
}

static void msm5xxx_poc_matrix_row734_reset(MSM5xxxPOCMachineState *s)
{
    s->matrix_row734_boot_seen = false;
    s->matrix_row734_boot_reads = s->matrix_row734_normal_reads = 0;
    s->matrix_row734_reason = 0;
}

static uint16_t msm5xxx_poc_matrix_row734_read(MSM5xxxPOCMachineState *s,
                                               uint16_t backing, uint32_t pc)
{
    bool presence = pc == s->matrix_input_presence_site ||
                    pc == s->matrix_row734_presence2;
    bool row = pc == s->matrix_input_sense_site ||
               pc == s->matrix_row734_sense2;
    bool boot = pc == s->matrix_row734_boot_site;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint16_t enable = msm5xxx_poc_backing_read(msm, 0x728, 2);
    uint16_t drive = msm5xxx_poc_backing_read(msm, 0x734, 2);
    uint16_t pointer, opcode, value;
    uint32_t pool, descriptor = s->matrix_input_descriptor;
    unsigned reason = 0, reg;

    if (!presence && !row && !boot) {
        return backing;
    }
    if (boot && s->matrix_row734_boot_seen) {
        return backing;
    }
    if (!s->cpu->env.thumb || s->primary_nor_size < 4 ||
        pc < 2 || pc > s->primary_nor_size - 2) {
        reason = 1;
        goto reject;
    }
    pointer = msm5xxx_poc_row734_u16(pc - 2);
    opcode = msm5xxx_poc_row734_u16(pc);
    if (boot) {
        pool = ((pc + 2) & ~3U) + (pointer & 255) * 4;
        if ((pointer & 0xff00) != 0x4800 || opcode != 0x8980 ||
            s->cpu->env.regs[0] != MSM5XXX_POC_MSM_BASE + 0x720 ||
            pool > s->primary_nor_size - 4 ||
            msm5xxx_poc_guest_u32(pool) != MSM5XXX_POC_MSM_BASE + 0x720) {
            reason = 1;
            goto reject;
        }
        if (s->matrix_input_pressed) {
            reason = 5; /* Held boot contacts are not in the admitted transaction. */
            goto reject;
        }
    } else {
        reg = pointer & 7;
        if ((pointer & 0xf800) != 0x6800 || ((pointer >> 6) & 31) != 13 ||
            opcode != (0x8800 | (reg << 3) | reg)) {
            reason = 1;
            goto reject;
        }
        /* A self-overwriting pointer load has no recoverable pre-load base. */
        if (s->cpu->env.regs[reg] != MSM5XXX_POC_MSM_BASE + 0x72c ||
            (((pointer >> 3) & 7) != reg &&
             s->cpu->env.regs[(pointer >> 3) & 7] != descriptor)) {
            reason = 6;
            goto reject;
        }
        if (msm5xxx_poc_guest_u32(descriptor + 4) != MSM5XXX_POC_MSM_BASE + 0x720 ||
            msm5xxx_poc_guest_u32(descriptor + 0x20) != MSM5XXX_POC_MSM_BASE + 0x728 ||
            msm5xxx_poc_guest_u32(descriptor + 0x28) != MSM5XXX_POC_MSM_BASE + 0x734 ||
            msm5xxx_poc_guest_u32(descriptor + 0x34) != MSM5XXX_POC_MSM_BASE + 0x72c) {
            reason = 2;
            goto reject;
        }
        uint32_t row_table = s->matrix_row734_row_tables[
            pc == s->matrix_row734_presence2 || pc == s->matrix_row734_sense2];
        for (unsigned i = 0; i < 6; i++) {
            if (msm5xxx_poc_row734_u16(row_table + i * 2) !=
                (i < 5 ? 1U << i : 0x80)) {
                reason = 7;
                goto reject;
            }
        }
        if (((msm5xxx_poc_row734_u16(descriptor + 0x2c) ^ enable) & 0x9f) ||
            ((msm5xxx_poc_row734_u16(descriptor + 0x2e) ^ drive) & 0x9f)) {
            reason = 3;
            goto reject;
        }
    }
    if (!msm5xxx_poc_row734_sense(backing, enable, drive, presence, boot,
            s->matrix_input_pressed, s->matrix_input_row,
            s->matrix_input_sense, &value)) {
        reason = 4;
        goto reject;
    }
    if (boot) {
        s->matrix_row734_boot_seen = true;
        s->matrix_row734_boot_reads++;
    } else {
        s->matrix_row734_normal_reads++;
        if (s->matrix_input_pressed && (value & 31) != 31) {
            s->matrix_input_active_reads++;
        }
    }
    s->matrix_row734_reason = 0;
    return value;
reject:
    s->matrix_row734_reason = reason;
    s->matrix_input_rejections++;
    return backing;
}

static uint64_t msm5xxx_poc_matrix_halfword_read(void *opaque, hwaddr offset,
                                                  unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint64_t backing = msm5xxx_poc_halfword_backing_read(s, 0x72c + offset, size);
    CPUState *cpu = current_cpu;
    uint32_t pc;

    if (offset || size != 2 || !qemu_in_vcpu_thread() ||
        cpu != CPU(s->cpu) || !cpu->running || !cpu->neg.can_do_io) {
        return backing;
    }
    pc = CPU_GET_CLASS(cpu)->get_pc(cpu) & ~1U;
    if (s->matrix_input_row734) {
        return msm5xxx_poc_matrix_row734_read(s, backing, pc);
    }

    /* Explicit electrical approximation at one descriptor-qualified read only. */
    if (s->experimental_matrix_contact_enabled &&
        pc == s->experimental_matrix_contact_site) {
        if (msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 8) !=
                MSM5XXX_POC_MSM_BASE + 0x72c ||
            msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x34) !=
                MSM5XXX_POC_MSM_BASE + 0x72c) {
            s->matrix_input_rejections++;
            return backing;
        }
        return (backing & ~(uint64_t)0x10) |
               s->experimental_matrix_contact_level;
    }
    if (pc != s->matrix_input_presence_site &&
        pc != s->matrix_input_sense_site &&
        (!s->matrix_input_loop || pc != s->matrix_input_contact_site)) {
        return backing;
    }
    if (s->matrix_input_loop) {
        uint16_t value;

        if (msm5xxx_poc_guest_u32(s->matrix_input_descriptor) !=
                MSM5XXX_POC_MSM_BASE + 0x720 ||
            msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 8) !=
                MSM5XXX_POC_MSM_BASE + 0x72c ||
            msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x20) !=
                MSM5XXX_POC_MSM_BASE + 0x728 ||
            msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x34) !=
                MSM5XXX_POC_MSM_BASE + 0x72c) {
            s->matrix_input_rejections++;
            return backing;
        }
        /* Dedicated contact remains released; no host raw-contact support. */
        if (pc == s->matrix_input_contact_site) {
            return backing | 0x10;
        }
        if (!msm5xxx_poc_loop_sense(backing,
                msm5xxx_poc_halfword_backing_read(s, 0x728, 2),
                msm5xxx_poc_halfword_backing_read(s, 0x720, 2),
                pc == s->matrix_input_presence_site, s->matrix_input_pressed,
                s->matrix_input_row, s->matrix_input_sense, &value)) {
            s->matrix_input_rejections++;
            return backing;
        }
        if (s->matrix_input_pressed && (value & 31) != 31) {
            s->matrix_input_active_reads++;
        }
        return value;
    }
    if (s->matrix_input_low5) {
        uint16_t value;

        if (msm5xxx_poc_guest_u32(s->matrix_input_descriptor) !=
                MSM5XXX_POC_MSM_BASE + 0x720 ||
            msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x10) !=
                MSM5XXX_POC_MSM_BASE + 0x724 ||
            msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x20) !=
                MSM5XXX_POC_MSM_BASE + 0x728 ||
            msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x34) !=
                MSM5XXX_POC_MSM_BASE + 0x72c ||
            !msm5xxx_poc_low5_sense(backing,
                msm5xxx_poc_backing_read(msm, 0x728, 2),
                msm5xxx_poc_backing_read(msm, 0x724, 2),
                pc == s->matrix_input_presence_site, s->matrix_input_pressed,
                s->matrix_input_row, s->matrix_input_sense, &value)) {
            s->matrix_input_rejections++;
            return backing;
        }
        if (s->matrix_input_pressed && (value & 0x1f) != 0x1f) {
            s->matrix_input_active_reads++;
        }
        return value;
    }
    if (msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x10) !=
            MSM5XXX_POC_MSM_BASE + 0x724 ||
        msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x34) !=
            MSM5XXX_POC_MSM_BASE + 0x72c) {
        s->matrix_input_rejections++;
        return backing;
    }
    uint16_t value;
    uint16_t output = msm5xxx_poc_halfword_backing_read(s, 0x724, 2);

    if (s->matrix_input_row_mask) {
        if (!msm5xxx_poc_mapped_halfword_sense(backing, output,
                s->matrix_input_row_mask, pc == s->matrix_input_presence_site,
                s->matrix_input_pressed, s->matrix_input_row,
                s->matrix_input_sense, &value)) {
            s->matrix_input_rejections++;
            return backing;
        }
    } else {
        value = msm5xxx_poc_halfword_sense(backing, output,
            s->matrix_input_pressed, s->matrix_input_row, s->matrix_input_sense);
    }
    if (s->matrix_input_pressed && (value & 0xf) != 0xf) {
        s->matrix_input_active_reads++;
    }
    return value;
}

static void msm5xxx_poc_matrix_halfword_write(void *opaque, hwaddr offset,
                                               uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    msm5xxx_poc_halfword_backing_write(s, 0x72c + offset, value, size);
}

static const MemoryRegionOps msm5xxx_poc_matrix_halfword_ops = {
    .read = msm5xxx_poc_matrix_halfword_read,
    .write = msm5xxx_poc_matrix_halfword_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 2,
};

static bool msm5xxx_poc_matrix_gpio_conflict(MSM5xxxPOCMachineState *s)
{
    if (s->primary_nor_size < 2 ||
        s->matrix_input_presence_site > s->primary_nor_size - 2 ||
        s->matrix_input_sense_site > s->primary_nor_size - 2 ||
        s->board_status_input_descriptor) {
        return true;
    }
    for (unsigned i = 0; i < 4; i++) {
        uint32_t address = i == 3 ? s->matrix_input_address :
            s->matrix_input_gpio_port[i];
        unsigned mask = i == 3 ? (0xf | s->matrix_input_sideband_mask) :
                                s->matrix_input_gpio_mask[i];

        if (s->board_status_input_enabled &&
            s->board_status_input_address == address) {
            return true;
        }
        if (s->eeprom_gpio_enabled &&
            ((address == s->eeprom_gpio_base + s->eeprom_data_offset &&
              (mask & s->eeprom_data_mask)) ||
             (address == s->eeprom_gpio_base + s->eeprom_direction_offset &&
              (mask & s->eeprom_data_mask)) ||
             (address == s->eeprom_gpio_base + s->eeprom_clock_offset &&
              (mask & s->eeprom_clock_mask)))) {
            return true;
        }
    }
    return false;
}

/* Temporary electrical approximation: opt-in distributed active-low rows.
 * Port order and ascending mask bits define rows; unrelated pins stay owned. */
static uint64_t msm5xxx_poc_matrix_gpio_read(void *opaque, hwaddr offset,
                                            unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t backing;
    CPUState *cpu = current_cpu;
    uint16_t output = 0, result;
    unsigned row = 0;
    uint32_t pc;

    if (!size || size > sizeof(backing) ||
        offset > MSM5XXX_POC_MSM_SIZE ||
        (uint64_t)s->matrix_input_address + offset + size >
            (uint64_t)MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE) {
        return 0;
    }
    backing = msm5xxx_poc_halfword_backing_read(s,
        s->matrix_input_address - MSM5XXX_POC_MSM_BASE + offset, size);
    if (offset || size != 1 || !qemu_in_vcpu_thread() || cpu != CPU(s->cpu) ||
        !cpu->running || !cpu->neg.can_do_io) {
        return backing;
    }
    pc = CPU_GET_CLASS(cpu)->get_pc(cpu) & ~1U;
    if (s->matrix_input_sideband_mask) {
        backing |= s->matrix_input_sideband_mask;
        if (s->matrix_input_pressed &&
            s->matrix_input_row == MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW) {
            backing &= ~s->matrix_input_sideband_mask;
            s->matrix_input_active_reads++;
        }
    }
    if (pc != s->matrix_input_presence_site &&
        pc != s->matrix_input_sense_site) {
        return backing;
    }
    for (unsigned port = 0; port < 3; port++) {
        unsigned value = msm5xxx_poc_halfword_backing_read(s,
            s->matrix_input_gpio_port[port] - MSM5XXX_POC_MSM_BASE, 1);

        for (unsigned bit = 1; bit <= 0x80; bit <<= 1) {
            if (s->matrix_input_gpio_mask[port] & bit) {
                if (value & bit) {
                    output |= 1U << row;
                }
                row++;
            }
        }
    }
    if (!msm5xxx_poc_mapped_halfword_sense(backing, output, 0x3f,
            pc == s->matrix_input_presence_site,
            s->matrix_input_pressed &&
                s->matrix_input_row != MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW,
            s->matrix_input_row, s->matrix_input_sense, &result)) {
        s->matrix_input_rejections++;
        return backing;
    }
    if (s->matrix_input_pressed &&
        s->matrix_input_row != MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW &&
        (result & 0xf) != 0xf) {
        s->matrix_input_active_reads++;
    }
    return result;
}

static uint64_t msm5xxx_poc_matrix_input_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUClass *cc = CPU_GET_CLASS(s->cpu);

    if (s->matrix_input_gpio) {
        return msm5xxx_poc_matrix_gpio_read(opaque, offset, size);
    }
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

    if (s->matrix_input_gpio) {
        if (!offset && size == 1) {
            msm5xxx_poc_halfword_backing_write(s,
                s->matrix_input_address - MSM5XXX_POC_MSM_BASE, value, 1);
        }
        return;
    }
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
            if (s->ma5_pcm_initialized) {
                size_t provided;
                MSM5xxxMA5PCMMetadata metadata;

                if (s->ma5_pcm_output_failed ||
                    msm5xxx_ma5_pcm_output_read(
                        &s->ma5_pcm_output, &s->audio_backend_pcm[0][0],
                        frames, &provided, &metadata) != MSM5XXX_MA5_PCM_OK) {
                    frames = 0;
                } else {
                    frames = provided;
                }
            } else {
                if (!msm5xxx_audio_synth_active(&s->audio_synth) &&
                    s->audio_synth.ring_count < frames) {
                    frames = s->audio_synth.ring_count;
                }
                if (frames != 0u) {
                    msm5xxx_audio_synth_read(
                        &s->audio_synth, s->audio_backend_pcm, frames,
                        NULL, NULL, NULL);
                }
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
    MSM5xxxMA5PCMMetadata metadata;

    if (s->audio_pcm_length || !s->audio_stream_chardev ||
        s->audio_stream_rejected || !s->audio_output_started) {
        return;
    }
    qemu_mutex_lock(&s->audio_synth_lock);
    if (s->ma5_pcm_initialized) {
        size_t provided;

        if (s->ma5_pcm_output_failed ||
            s->ma5_pcm_output.queue.count < MSM5XXX_AUDIO_CHUNK_FRAMES ||
            msm5xxx_ma5_pcm_output_read(
                &s->ma5_pcm_output, &pcm[0][0],
                MSM5XXX_AUDIO_CHUNK_FRAMES, &provided, &metadata) !=
                MSM5XXX_MA5_PCM_OK || provided != MSM5XXX_AUDIO_CHUNK_FRAMES) {
            qemu_mutex_unlock(&s->audio_synth_lock);
            return;
        }
        epoch = metadata.epoch;
        sequence = metadata.sequence;
        start_frame = metadata.start_frame;
    } else {
        if (s->audio_synth.ring_count < MSM5XXX_AUDIO_CHUNK_FRAMES) {
            qemu_mutex_unlock(&s->audio_synth_lock);
            return;
        }
        msm5xxx_audio_synth_read(&s->audio_synth, pcm,
                                 MSM5XXX_AUDIO_CHUNK_FRAMES,
                                 &epoch, &sequence, &start_frame);
    }
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

/* The core lock serializes timer and writable retries of the same packet. */
static void msm5xxx_poc_audio_pcm_cancel_watch(MSM5xxxPOCMachineState *s)
{
    if (s->audio_pcm_watch) {
        g_source_remove(s->audio_pcm_watch);
        s->audio_pcm_watch = 0;
    }
}

static gboolean msm5xxx_poc_audio_pcm_writable(void *unused,
                                               GIOCondition condition,
                                               void *opaque);

static void msm5xxx_poc_audio_pcm_reject(MSM5xxxPOCMachineState *s)
{
    s->audio_pcm_length = 0u;
    s->audio_pcm_offset = 0u;
    msm5xxx_poc_audio_pcm_cancel_watch(s);
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
            msm5xxx_poc_audio_pcm_cancel_watch(s);
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
                if (!s->audio_pcm_watch) {
                    s->audio_pcm_watch = qemu_chr_fe_add_watch(
                        &s->audio_stream_chr,
                        G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
                        msm5xxx_poc_audio_pcm_writable, s);
                }
                /* A backend without watches retains the timer retry. */
                return 0;
            }
            msm5xxx_poc_audio_pcm_cancel_watch(s);
            return -1;
        }
        s->audio_pcm_length = 0u;
        s->audio_pcm_offset = 0u;
    }
}

static gboolean msm5xxx_poc_audio_pcm_writable(void *unused,
                                               GIOCondition condition,
                                               void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;

    qemu_mutex_lock(&s->audio_core_lock);
    s->audio_pcm_watch = 0;
    if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
        s->audio_pcm_failed = true;
    } else if (!s->audio_stream_rejected && !s->audio_pcm_failed &&
               s->audio_pcm_length &&
               msm5xxx_poc_audio_pcm_flush(s) < 0) {
        s->audio_pcm_failed = true;
    }
    qemu_mutex_unlock(&s->audio_core_lock);
    return G_SOURCE_REMOVE;
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
    static const uint8_t sine2_descriptor[] = {
        16u, 0u, 0u, 1u, 1u, 0u,
        0u, 0u, 0u, 0u, 10u, 1u, 6u, 6u, 25u, 2u, 2u, 0u, 2u, 0u, 1u, 0u, 0u, 6u,
        0u, 0u, 0u, 0u, 10u, 15u, 7u, 0u, 0u, 0u, 2u, 0u, 2u, 0u, 1u, 0u, 0u, 0u,
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
    if (!voice->valid) {
        return false;
    }
    if (voice->operator_count == 4u &&
        memcmp(voice->decoded, descriptor, sizeof(descriptor)) == 0) {
        event->timbre_algorithm = 5u;
        event->timbre_operator_count = 4u;
        event->timbre_feedback = 0u;
        memcpy(event->timbre_multiplier, multiplier, sizeof(multiplier));
        memcpy(event->timbre_level, level, sizeof(level));
    } else if (voice->operator_count == 2u &&
               memcmp(voice->decoded, sine2_descriptor,
                      sizeof(sine2_descriptor)) == 0) {
        /* Provisional normal-mode sine series; envelope rates are approximate. */
        event->timbre_algorithm = 0u;
        event->timbre_operator_count = 2u;
        event->timbre_feedback = 6u;
        event->timbre_decay_threshold_valid = true;
        for (index = 0u; index < 2u; index++) {
            event->timbre_multiplier[index] = 1u;
            event->timbre_level[index] = voice->decoded[14u + index * 18u];
        }
    } else {
        return false;
    }

    /* ponytail: bounded descriptor classes; unmatched voices keep triangle. */
    event->timbre_valid = true;
    for (index = 0u; index < event->timbre_operator_count; index++) {
        event->timbre_attack_step[index] = UINT32_C(0x0094f20a);
        event->timbre_decay_factor[index] = UINT32_C(0x40000000);
        event->timbre_sustain_factor[index] = UINT32_C(0x40000000);
        event->timbre_release_factor[index] = UINT32_C(0x3eb1aa70);
        if (event->timbre_decay_threshold_valid) {
            uint8_t rate = voice->decoded[11u + index * 18u];
            uint8_t release_rate = voice->decoded[10u + index * 18u];
            uint8_t level_code = voice->decoded[13u + index * 18u];
            double attenuation = level_code == 15u ? 93.0 : 3.0 * level_code;
            /* Provisional four-second slowest decay, doubling per raw rate.
             * Keyboard-rate correction is pending; this is not a chip clock. */
            double decay_rate = rate == 0u ? 0.0 : ldexp(0.25, rate - 1u);

            event->timbre_decay_factor[index] = (uint32_t)(
                exp(-decay_rate / MSM5XXX_AUDIO_SAMPLE_RATE) *
                1073741824.0 + 0.5);
            /* Exact admitted RR is nonzero. RR-only release is provisional;
             * channel mode/key correction and physical timing remain unverified. */
            event->timbre_release_factor[index] = (uint32_t)(
                exp(-ldexp(0.25, release_rate - 1u) /
                    MSM5XXX_AUDIO_SAMPLE_RATE) * 1073741824.0 + 0.5);
            event->timbre_decay_threshold[index] = (uint32_t)(
                pow(10.0, -attenuation / 20.0) * 2147483648.0 + 0.5);
        }
    }
    return true;
}

static bool msm5xxx_poc_ma2_synth_output(MSM5xxxPOCMachineState *s,
                                         const MSM5xxxMA2Output *output)
{
    const MSM5xxxMA2FMChannel *channel;
    MSM5xxxAudioEvent event;
    uint64_t timestamp_ns = output->timestamp_ns;
    bool accepted;

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
    accepted = msm5xxx_audio_synth_event(&s->audio_synth, timestamp_ns, &event);
    if (accepted && event.kind == MSM5XXX_AUDIO_EVENT_NOTE_ON &&
        event.timbre_valid) {
        qemu_log_mask(LOG_UNIMP,
            "msm5xxx-ma2 provisional-timbre algorithm=%u operators=%u "
            "feedback=%u channel=%u voice=%u note=%u time_ns=%" PRIu64 "\n",
            event.timbre_algorithm, event.timbre_operator_count,
            event.timbre_feedback, event.channel, event.voice_id, event.note,
            timestamp_ns);
    }
    return accepted;
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
        msm5xxx_poc_ma2_irq_update(s);
        return;
    }
    for (;;) {
        if (!msm5xxx_poc_ma2_pending_refill(s) &&
            msm5xxx_ma2_rejected(&s->ma2_audio)) {
            s->audio_stream_reject_code =
                msm5xxx_ma2_reject_reason(&s->ma2_audio);
            s->ma2_audio_timer_rejected = true;
            msm5xxx_poc_audio_pcm_cancel_watch(s);
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending =
                MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            qemu_mutex_unlock(&s->audio_core_lock);
            msm5xxx_poc_ma2_irq_update(s);
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
            msm5xxx_poc_audio_pcm_cancel_watch(s);
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending =
                MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            qemu_mutex_unlock(&s->audio_core_lock);
            msm5xxx_poc_ma2_irq_update(s);
            return;
        }
        /* Opt-in -d unimp diagnostics describe committed consumption, including
         * suppressed unassigned notes. FIFO writes alone cannot identify it. */
        if (output.unhandled_reason != MSM5XXX_MA2_UNHANDLED_NONE) {
            const MSM5xxxMA2FMChannel *channel =
                &s->ma2_audio.fm_channel[output.channel];

            qemu_log_mask(LOG_UNIMP,
                "msm5xxx-ma2 consumed reason=%u event=%u stream=%u "
                "channel=%u bank=%u program=%u slot=%u "
                "time_ns=%" PRIu64 " total=%" PRIu64 "\n",
                (unsigned)output.unhandled_reason, (unsigned)output.event.kind,
                (unsigned)output.stream, output.channel, channel->bank,
                channel->program, channel->active_voice_slot,
                output.timestamp_ns, s->ma2_audio.fm_state_unhandled);
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
                    msm5xxx_poc_audio_pcm_cancel_watch(s);
                    s->audio_stream_rejected = true;
                    s->audio_stream_status_pending =
                        MSM5XXX_POC_AUDIO_STATUS_REJECTED;
                    qemu_mutex_unlock(&s->audio_core_lock);
                    msm5xxx_poc_ma2_irq_update(s);
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
            msm5xxx_poc_audio_pcm_cancel_watch(s);
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending = MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            qemu_mutex_unlock(&s->audio_core_lock);
            msm5xxx_poc_ma2_irq_update(s);
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
            msm5xxx_poc_audio_pcm_cancel_watch(s);
            s->audio_stream_rejected = true;
            s->audio_stream_status_pending =
                MSM5XXX_POC_AUDIO_STATUS_REJECTED;
            qemu_mutex_unlock(&s->audio_core_lock);
            msm5xxx_poc_ma2_irq_update(s);
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
    msm5xxx_poc_ma2_irq_update(s);
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

static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState *s,
                                      uint32_t *pc);

static void msm5xxx_poc_ma5_commit_trace(void *opaque,
                                        const MSM5xxxMA5Commit *commit)
{
    MSM5xxxPOCMachineState *s = opaque;
    char kind = commit->kind == MSM5XXX_MA5_COMMIT_CONTROL ? 'C' :
                commit->kind == MSM5XXX_MA5_COMMIT_SRAM ? 'S' : 'B';

    if (!qemu_loglevel_mask(LOG_GUEST_ERROR) || s->ma5_commit_traces >= 16384) {
        return;
    }
    qemu_log_mask(LOG_GUEST_ERROR,
                  "MA5 commit n=%u t=%" PRIu64 " kind=%c address=%x value=%02x raw=%02x\n",
                  ++s->ma5_commit_traces, commit->time_ns, kind,
                  commit->address, commit->value, commit->raw);
    if (s->ma5_commit_traces == 16384) {
        qemu_log_mask(LOG_GUEST_ERROR, "MA5 commit trace-limit=16384\n");
    }
}

static bool msm5xxx_poc_ma5_pcm_emit(void *opaque, uint64_t first_frame,
                                     const int16_t *stereo, size_t frames)
{
    MSM5xxxPOCMachineState *s = opaque;
    MSM5xxxMA5PCMResult result;
    bool activate_output = false;
    bool accepted;

    if (!s->audio_core_lock_initialized || !s->audio_synth_lock_initialized) {
        return false;
    }
    qemu_mutex_lock(&s->audio_core_lock);
    if (!s->ma5_pcm_initialized || s->ma5_pcm_output_failed ||
        s->ma5_pcm_resync_pending || s->audio_pcm_failed) {
        qemu_mutex_unlock(&s->audio_core_lock);
        return false;
    }
    qemu_mutex_lock(&s->audio_synth_lock);
    result = msm5xxx_ma5_pcm_output_emit(
        &s->ma5_pcm_output, s->ma5_pcm_output.queue.epoch, first_frame,
        stereo, frames);
    if (result != MSM5XXX_MA5_PCM_OK) {
        s->ma5_pcm_output_failed = true;
    } else if (!s->audio_output_started &&
               s->ma5_pcm_output.queue.count >= MSM5XXX_AUDIO_TARGET_FRAMES) {
        s->audio_output_started = true;
        activate_output = s->audio_voice != NULL;
    }
    qemu_mutex_unlock(&s->audio_synth_lock);
    if (activate_output) {
        AUD_set_active_out(s->audio_voice, true);
    }
    accepted = result == MSM5XXX_MA5_PCM_OK;
    /* A render advance can emit many chunks before returning to the timer.
     * Drain M5P2 at each callback; prepare takes the synth lock itself. */
    if (accepted && s->audio_stream_chardev &&
        msm5xxx_poc_audio_pcm_flush(s) < 0) {
        s->audio_pcm_failed = true;
        accepted = false;
    }
    qemu_mutex_unlock(&s->audio_core_lock);
    return accepted;
}

static void msm5xxx_poc_ma5_commit_consume(void *opaque,
                                           const MSM5xxxMA5Commit *commit)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (s->ma5_wt_engine) {
        MA5WTStatus status;

        ma5_wt_engine_commit(s->ma5_wt_engine, commit);
        status = ma5_wt_engine_status(s->ma5_wt_engine);
        if (status.timeline_gaps > s->ma5_pcm_timeline_gaps) {
            s->ma5_pcm_timeline_gaps = status.timeline_gaps;
            s->ma5_pcm_resync_pending = true;
        }
        if (qemu_loglevel_mask(LOG_GUEST_ERROR) &&
            (status.fm_admitted != s->ma5_fm_admitted_logged ||
             status.fm_skipped != s->ma5_fm_skipped_logged ||
             status.fm_wave_uploads != s->ma5_fm_wave_uploads_logged ||
             status.fm_wave_upload_rejects != s->ma5_fm_wave_rejects_logged)) {
            s->ma5_fm_admitted_logged = status.fm_admitted;
            s->ma5_fm_skipped_logged = status.fm_skipped;
            s->ma5_fm_wave_uploads_logged = status.fm_wave_uploads;
            s->ma5_fm_wave_rejects_logged = status.fm_wave_upload_rejects;
            qemu_log_mask(LOG_GUEST_ERROR,
                          "MA5 FM experimental renderer: admitted=%" PRIu64
                          " skipped=%" PRIu64
                          " wave_upload=%" PRIu64 ",wave_reject=%" PRIu64
                          " reject(upload=%" PRIu64 ",rom=%" PRIu64
                          ",descriptor=%" PRIu64 ",control=%" PRIu64
                          ",mode=%" PRIu64 ",mutation=%" PRIu64
                          ",timeline=%" PRIu64 ")"
                          "; non-instant AR/KSL and B55=0xbc policy estimated\n",
                          status.fm_admitted, status.fm_skipped,
                          status.fm_wave_uploads, status.fm_wave_upload_rejects,
                          status.fm_skip_upload, status.fm_skip_rom,
                          status.fm_skip_descriptor, status.fm_skip_control,
                          status.fm_skip_mode, status.fm_skip_mutation,
                          status.fm_skip_timeline);
        }
    }
    msm5xxx_poc_ma5_commit_trace(opaque, commit);
}

static void msm5xxx_poc_ma5_sram_observe(MSM5xxxPOCMachineState *s,
                                           uint32_t pc, uint64_t before,
                                           uint64_t control_before,
                                           uint64_t reads_before)
{
    uint64_t after = s->ma5_device.backing.sram_writes;
    uint64_t controls = s->ma5_device.backing.control_writes;

    if (controls != control_before &&
        (control_before < 8u || control_before / 1024u != controls / 1024u)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "MA5 control-consume pc=%x writes=%" PRIu64
                      " last=%x raw=%02x\n", pc, controls,
                      s->ma5_device.backing.control_write_address,
                      s->ma5_device.backing.control_write_raw);
    }
    if (after != before && (before == 0 ||
        before / MSM5XXX_MA5_SRAM_SIZE != after / MSM5XXX_MA5_SRAM_SIZE ||
        (!s->ma5_device.count && !s->ma5_device.delayed_count))) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "MA5 SRAM-consume pc=%x bytes=%" PRIu64 "\n", pc, after);
    }
    if (s->ma5_device.reads != reads_before &&
        (reads_before < 64 || reads_before / 1024 != s->ma5_device.reads / 1024)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "MA5 read-complete pc=%x address=%x space=%s source=%s"
                      " latch=%02x reads=%" PRIu64
                      " queued=%u consumed=%" PRIu64 "\n", pc,
                      s->ma5_device.backing.read_address,
                      s->ma5_device.backing.read_from_sram ? "sram" : "control",
                      s->ma5_device.backing.read_from_sram ? "not-tracked" :
                      (s->ma5_device.backing.read_control_guest_written ?
                       "guest-write" : "unwritten-backing"),
                      s->ma5_device.backing.read_latch, s->ma5_device.reads,
                      s->ma5_device.count, s->ma5_device.consumed);
    }
}

static void msm5xxx_poc_ma5_audio_kick(MSM5xxxPOCMachineState *s)
{
    uint64_t deadline = UINT64_MAX;
    uint64_t device_deadline;
    bool have_deadline = false;

    if (!s->ma5_audio_timer) {
        return;
    }
    if (msm5xxx_ma5_device_next_deadline(&s->ma5_device, &device_deadline)) {
        deadline = device_deadline;
        have_deadline = true;
    }
    if (s->ma5_wt_engine && !s->ma5_pcm_output_failed &&
        !s->ma5_device.reject &&
        (s->ma5_pcm_resync_pending ||
         ma5_wt_engine_status(s->ma5_wt_engine).active)) {
        uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

        if (now <= INT64_MAX - 5000000u) {
            deadline = MIN(deadline, now + 5000000u);
            have_deadline = true;
        }
    }
    if (!have_deadline) {
        timer_del(s->ma5_audio_timer);
        return;
    }
    if (deadline > INT64_MAX) {
        s->ma5_device.reject = MSM5XXX_MA5_REJECT_CLOCK;
        timer_del(s->ma5_audio_timer);
        return;
    }
    if (timer_pending(s->ma5_audio_timer)) {
        deadline = MIN(deadline, timer_expire_time_ns(s->ma5_audio_timer));
    }
    timer_mod_ns(s->ma5_audio_timer, deadline);
}

static void msm5xxx_poc_ma5_audio_tick(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t sram_before = s->ma5_device.backing.sram_writes;
    uint64_t control_before = s->ma5_device.backing.control_writes;
    uint64_t reads_before = s->ma5_device.reads;

    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    bool activate_output = false;

    if (s->ma5_pcm_resync_pending && s->ma5_pcm_initialized) {
        msm5xxx_poc_audio_pcm_cancel_watch(s);
        s->audio_pcm_length = 0;
        s->audio_pcm_offset = 0;
        s->audio_backend_pcm_length = 0;
        s->audio_backend_pcm_offset = 0;
        if (s->audio_voice) {
            AUD_set_active_out(s->audio_voice, false);
        }
        qemu_mutex_lock(&s->audio_synth_lock);
        if (msm5xxx_ma5_pcm_output_reset(&s->ma5_pcm_output) ==
                MSM5XXX_MA5_PCM_OK) {
            s->ma5_pcm_output_failed = false;
            s->ma5_pcm_output_reported = false;
            s->audio_stream_reset_epoch = s->ma5_pcm_output.queue.epoch;
        } else {
            s->ma5_pcm_output_failed = true;
        }
        s->audio_output_started = false;
        qemu_mutex_unlock(&s->audio_synth_lock);
        s->audio_stream_status_pending = s->ma5_pcm_output_failed ?
            MSM5XXX_POC_AUDIO_STATUS_REJECTED : MSM5XXX_POC_AUDIO_STATUS_RESET;
        s->ma5_pcm_resync_pending = false;
    }
    if (s->ma5_pcm_initialized && s->audio_pcm_failed) {
        s->audio_pcm_failed = false;
        s->ma5_pcm_output_failed = true;
        s->audio_pcm_length = 0;
        s->audio_pcm_offset = 0;
        msm5xxx_poc_audio_pcm_cancel_watch(s);
        s->audio_stream_rejected = true;
        s->audio_stream_status_pending = MSM5XXX_POC_AUDIO_STATUS_REJECTED;
    }
    msm5xxx_ma5_device_advance(&s->ma5_device, now);
    if (s->ma5_wt_engine && !s->ma5_device.reject) {
        MA5WTStatus status;

        ma5_wt_engine_advance(s->ma5_wt_engine, now);
        status = ma5_wt_engine_status(s->ma5_wt_engine);
        if (status.timeline_gaps > s->ma5_pcm_timeline_gaps) {
            s->ma5_pcm_timeline_gaps = status.timeline_gaps;
            s->ma5_pcm_resync_pending = true;
        }
        qemu_mutex_lock(&s->audio_core_lock);
        qemu_mutex_lock(&s->audio_synth_lock);
        if (!s->ma5_pcm_output_failed && !s->audio_output_started &&
            s->ma5_pcm_output.queue.count >= MSM5XXX_AUDIO_TARGET_FRAMES) {
            s->audio_output_started = true;
            activate_output = s->audio_voice != NULL;
        }
        qemu_mutex_unlock(&s->audio_synth_lock);
        if (activate_output) {
            AUD_set_active_out(s->audio_voice, true);
        }
        if (s->audio_stream_chardev && !s->ma5_pcm_output_failed &&
            msm5xxx_poc_audio_pcm_flush(s) < 0) {
            s->audio_pcm_failed = true;
        }
        qemu_mutex_unlock(&s->audio_core_lock);
    }
    msm5xxx_poc_ma5_sram_observe(s, 0, sram_before, control_before, reads_before);
    msm5xxx_poc_ma5_audio_kick(s);
    msm5xxx_poc_ma5_irq_update(s);
    if (s->ma5_pcm_output_failed && !s->ma5_pcm_output_reported) {
        warn_report("experimental MA5 PCM output stopped; MA5 device state continues");
        s->ma5_pcm_output_reported = true;
        s->audio_stream_status_pending = MSM5XXX_POC_AUDIO_STATUS_REJECTED;
        if (s->audio_voice) {
            AUD_set_active_out(s->audio_voice, false);
        }
    }
    if (s->ma5_device.reject && !s->audio_readback_rejection_reported) {
        warn_report("experimental MA5 timer rejected: reason=%u index=%x",
                    s->ma5_device.reject, s->ma5_device.backing.index);
        s->audio_readback_rejection_reported = true;
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
        if (s->ma5_byte_ns && !s->audio_readback_rejection_reported) {
            warn_report("experimental MA5 bus guard rejected: size=%u offset=%" PRIx64,
                        size, (uint64_t)offset);
            s->audio_readback_rejection_reported = true;
        }
        return MEMTX_ERROR;
    }
    cc = CPU_GET_CLASS(cpu);
    pc = cc->get_pc(cpu) & ~1U;
    if (s->ma5_byte_ns && !msm5xxx_poc_mmio_access_pc(s, &pc)) {
        if (!s->audio_readback_rejection_reported) {
            warn_report("experimental MA5 precise access PC unavailable");
            s->audio_readback_rejection_reported = true;
        }
        return MEMTX_ERROR;
    }
    if (!s->audio_sites_enabled ||
        !msm5xxx_poc_audio_site_owned(s, false, offset, pc)) {
        if (s->ma5_byte_ns && !s->audio_readback_rejection_reported) {
            warn_report("experimental MA5 unowned read: pc=%x offset=%" PRIx64,
                        pc, (uint64_t)offset);
            s->audio_readback_rejection_reported = true;
        }
        return MEMTX_ERROR;
    }
    if (s->ma5_byte_ns) {
        uint8_t result;
        uint64_t reads_before = s->ma5_device.reads;
        uint64_t sram_before = s->ma5_device.backing.sram_writes;
        uint64_t control_before = s->ma5_device.backing.control_writes;
        bool ok = msm5xxx_ma5_device_read(
            &s->ma5_device, offset == 0, &result,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));

        msm5xxx_poc_ma5_sram_observe(s, pc, sram_before, control_before, reads_before);
        msm5xxx_poc_ma5_audio_kick(s);
        msm5xxx_poc_ma5_irq_update(s);
        ok &= s->ma5_device.reject == MSM5XXX_MA5_REJECT_NONE;
        if (!ok) {
            if (!s->audio_readback_rejection_reported) {
                warn_report("experimental MA5 rejected read: reason=%u pc=%x "
                            "index=%x queued=%u consumed=%" PRIu64,
                            s->ma5_device.reject, pc,
                            s->ma5_device.backing.index, s->ma5_device.count,
                            s->ma5_device.consumed);
                s->audio_readback_rejection_reported = true;
            }
            return MEMTX_ERROR;
        }
        if (s->ma5_irq_configured && offset && result &&
            (s->ma5_device.backing.index == 0 || s->ma5_device.backing.index == 16) &&
            s->ma5_chip_reads++ < 16) {
            qemu_log_mask(LOG_GUEST_ERROR, "MA5 IRQ chip-status pc=%x index=%x flags=%02x\n",
                          pc, s->ma5_device.backing.index, result);
        }
        *value = result;
        return MEMTX_OK;
    }
    if (s->experimental_audio_readback) {
        uint8_t result;
        if (offset == 0) {
            *value = msm5xxx_audio_readback_status(&s->audio_readback);
            return MEMTX_OK;
        }
        if (!msm5xxx_audio_readback_read(&s->audio_readback, &result)) {
            if (!s->audio_readback_rejection_reported) {
                warn_report("experimental audio readback: no modeled result "
                            "for index=%02x address=%x type=%u",
                            s->audio_readback.index,
                            s->audio_readback.request.address,
                            s->audio_readback.request.type);
                s->audio_readback_rejection_reported = true;
            }
            return MEMTX_ERROR;
        }
        *value = result;
        return MEMTX_OK;
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
        if (s->ma5_byte_ns && !s->audio_readback_rejection_reported) {
            warn_report("experimental MA5 bus guard rejected: size=%u offset=%" PRIx64,
                        size, (uint64_t)offset);
            s->audio_readback_rejection_reported = true;
        }
        return MEMTX_ERROR;
    }
    cc = CPU_GET_CLASS(cpu);
    pc = cc->get_pc(cpu) & ~1U;
    if (s->ma5_byte_ns && !msm5xxx_poc_mmio_access_pc(s, &pc)) {
        if (!s->audio_readback_rejection_reported) {
            warn_report("experimental MA5 precise access PC unavailable");
            s->audio_readback_rejection_reported = true;
        }
        return MEMTX_ERROR;
    }
    if (!s->audio_sites_enabled ||
        !msm5xxx_poc_audio_site_owned(s, true, offset, pc)) {
        if (s->ma5_byte_ns && !s->audio_readback_rejection_reported) {
            warn_report("experimental MA5 unowned write: pc=%x offset=%" PRIx64,
                        pc, (uint64_t)offset);
            s->audio_readback_rejection_reported = true;
        }
        return MEMTX_ERROR;
    }
    if (s->ma5_byte_ns) {
        uint64_t before = s->ma5_device.resets;
        uint64_t reads_before = s->ma5_device.reads;
        uint64_t sram_before = s->ma5_device.backing.sram_writes;
        uint64_t control_before = s->ma5_device.backing.control_writes;
        bool ok = msm5xxx_ma5_device_write(
            &s->ma5_device, offset == 0, value,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));

        msm5xxx_poc_ma5_audio_kick(s);
        msm5xxx_poc_ma5_irq_update(s);
        ok &= s->ma5_device.reject == MSM5XXX_MA5_REJECT_NONE;
        if (!ok && !s->audio_readback_rejection_reported) {
            warn_report("experimental MA5 rejected write: reason=%u pc=%x "
                        "index=%x value=%02x queued=%u consumed=%" PRIu64
                        " control=%" PRIu64 " sram=%" PRIu64
                        " pll=%02x:%02x ms_s=%u committed=%u reset=%u"
                        " resume_pending=%u running=%u",
                        s->ma5_device.reject, pc,
                        s->ma5_device.backing.index, (unsigned)value & 0xffu,
                        s->ma5_device.count, s->ma5_device.consumed,
                        s->ma5_device.backing.control_writes,
                        s->ma5_device.backing.sram_writes,
                        s->ma5_device.b[30], s->ma5_device.b[31],
                        s->ma5_device.ms_s, s->ma5_device.ms_s_committed,
                        s->ma5_device.counter_reset,
                        s->ma5_device.counter_needs_reset,
                        s->ma5_device.counter_running);
            s->audio_readback_rejection_reported = true;
        }
        if (s->ma5_device.resets != before) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "MA5 cold reset pc=%x PLL=%02x:%02x CLKI=%" PRIu64
                          " inferred=%u target=%" PRIu64 "\n", pc,
                          s->ma5_device.b[30], s->ma5_device.b[31],
                          s->ma5_device.clki_hz, s->ma5_device.clki_inferred,
                          s->ma5_device.target_rate_hz);
        }
        msm5xxx_poc_ma5_sram_observe(s, pc, sram_before, control_before, reads_before);
        return ok ? MEMTX_OK : MEMTX_ERROR;
    }
    s->audio_backing[offset] = value;
    if (s->experimental_audio_readback) {
        if (offset == 0) {
            msm5xxx_audio_readback_index(&s->audio_readback, value);
        } else if (!msm5xxx_audio_readback_write(&s->audio_readback, value)) {
            return MEMTX_ERROR;
        }
    }
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
                msm5xxx_poc_audio_pcm_cancel_watch(s);
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
                msm5xxx_poc_audio_pcm_cancel_watch(s);
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
        msm5xxx_poc_audio_pcm_cancel_watch(s);
        s->audio_stream_rejected = true;
        s->audio_stream_status_pending =
            MSM5XXX_POC_AUDIO_STATUS_REJECTED;
    }
    qemu_mutex_unlock(&s->audio_core_lock);
    if (accepted) {
        msm5xxx_poc_ma2_audio_kick(s);
        msm5xxx_poc_ma2_irq_update(s);
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
        qemu_mutex_lock(&s->audio_core_lock);
        msm5xxx_poc_audio_pcm_cancel_watch(s);
        s->audio_stream_rejected = true;
        s->audio_stream_dropped = 1;
        s->audio_stream_status_pending = MSM5XXX_POC_AUDIO_STATUS_OVERFLOW;
        qemu_mutex_unlock(&s->audio_core_lock);
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
    if (s->audio_irq_configured && s->ma2_audio.page == MSM5XXX_MA2_PAGE_REG0 &&
        s->ma2_audio.index == MSM5XXX_MA2_STATUS1 && msm5xxx_poc_ma2_irq_gate(s)) {
        *value = msm5xxx_poc_ma2_fifo_flags(s);
        qemu_mutex_unlock(&s->audio_core_lock);
        return true;
    }
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
            msm5xxx_poc_audio_pcm_cancel_watch(s);
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

    /* The legacy two-bank W1C controller has paired enable halfwords. */
    if (!s->rex_irq_c80 && !s->rex_irq_read_consume &&
        s->rex_irq_bank_count == 2 &&
        s->rex_irq_status_address == 0x03000620 && offset == 8) {
        uint16_t second_enabled = msm5xxx_poc_backing_read(
            s->rex_irq_backing, offset + 4, 2
        );

        level |= (second_enabled & s->rex_irq_pending[1]) != 0;
    }

    level |= s->ma5_irq_configured && s->ma5_irq_qualified &&
             s->rex_irq_route_active && s->ma5_irq_level;
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
    msm5xxx_poc_ma5_irq_update(s);
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
    if (s->ma5_irq_configured) {
        return msm5xxx_poc_ma5_irq_read(s, offset, size);
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
    if (s->ma5_irq_configured) {
        msm5xxx_poc_ma5_irq_write(s, offset, value, size);
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
    msm5xxx_poc_ma2_irq_update(s);
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
    /* Explicit diagnostic electrical approximation after the actual owner read. */
    if (s->experimental_matrix_status_enabled && size == 2 &&
        (uint64_t)s->eeprom_gpio_base + offset == MSM5XXX_POC_MSM_BASE + 0x728 &&
        qemu_in_vcpu_thread() && current_cpu == CPU(s->cpu) &&
        current_cpu->running && current_cpu->neg.can_do_io &&
        (CPU_GET_CLASS(current_cpu)->get_pc(current_cpu) & ~1U) ==
            s->experimental_matrix_status_site) {
        if (msm5xxx_poc_guest_u32(s->matrix_input_descriptor + 0x24) !=
                MSM5XXX_POC_MSM_BASE + 0x728) {
            s->matrix_input_rejections++;
            return value;
        }
        return (value & ~(uint64_t)2) | s->experimental_matrix_status_level;
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

static bool msm5xxx_poc_radio_irq_gate(MSM5xxxPOCMachineState *s)
{
    uint32_t target;
    uint64_t ram_size = MACHINE(s)->ram_size;

    if (!s->rex_irq_enabled || s->rex_irq_c80 || s->rex_irq_read_consume ||
        s->rex_irq_bank_count != 2 || s->rex_irq_status_address != 0x03000620 ||
        s->rex_irq_enable_address != 0x03000628 ||
        msm5xxx_poc_guest_u32(s->search2_route[5]) != (s->search2_route[6] | 1) ||
        !msm5xxx_poc_arm_b_target(msm5xxx_poc_guest_u32(0x18), 0x18, &target)) {
        return false;
    }
    if (target != s->search2_route[7]) {
        if (target < s->ram_base || ram_size < 4 ||
            target - s->ram_base > ram_size - 4 ||
            !msm5xxx_poc_arm_b_target(msm5xxx_poc_guest_u32(target), target,
                                      &target) || target != s->search2_route[7]) {
            return false;
        }
    }
    return true;
}

static bool msm5xxx_poc_search2_gate(MSM5xxxPOCMachineState *s)
{
    static const uint8_t writer[] = {
        0x8e,0x80,0x04,0x9a,0x8a,0x80,0x03,0x9a,0x8a,0x80,0x8c,0x80,
        0xc2,0x08,0x8a,0x80,0x3a,0x7a,0x40,0x03,0x92,0x02,0x10,0x43,
        0xba,0x7a,0x12,0x02,0x10,0x43,0x7a,0x7a,0x10,0x43,0x88,0x80,
    };
    static const uint8_t consumer[] = {
        0xb5,0x89,0x4a,0x00,0x12,0x18,0x95,0x85,0xb5,0x89,0x01,0x31,
        0x09,0x06,0x09,0x16,0x04,0x29,0x95,0x84,0xf4,0xdb,
    };
    uint8_t code[sizeof(writer)];
    uint32_t callback;

    if (!msm5xxx_poc_radio_irq_gate(s) || s->search2_probe_rejected) {
        return false;
    }
    callback = msm5xxx_poc_guest_u32(s->search2_route[2]);
    if (callback != (s->search2_route[3] | 1) &&
        callback != (s->search2_route[4] | 1)) {
        return false;
    }
    cpu_physical_memory_read(s->search2_route[0], code, sizeof(writer));
    if (memcmp(code, writer, sizeof(writer))) {
        return false;
    }
    cpu_physical_memory_read(s->search2_route[1], code, sizeof(consumer));
    return !memcmp(code, consumer, sizeof(consumer));
}

static void msm5xxx_poc_fingers_latch(MSM5xxxPOCMachineState *s);

enum {
    MSM5XXX_SEARCH2_REJECT_WRITER = 1,
    MSM5XXX_SEARCH2_REJECT_QUEUE,
    MSM5XXX_SEARCH2_REJECT_PARAMETERS,
    MSM5XXX_SEARCH2_REJECT_COMPLETION,
    MSM5XXX_SEARCH2_REJECT_CONTROL,
};

static void msm5xxx_poc_search2_reject(MSM5xxxPOCMachineState *s,
                                      uint32_t reason, uint32_t pc,
                                      uint32_t value, uint32_t expected_pc)
{
    s->search2_rejections++;
    s->search2_probe_rejected = true;
    s->search2_reject_reason = reason;
    s->search2_reject_pc = pc;
    s->search2_reject_value = value;
    s->search2_reject_expected_pc = expected_pc;
}

static void msm5xxx_poc_search2_start(MSM5xxxPOCMachineState *s)
{
    MSM5xxxSearch2Job job;
    MSM5xxxSearch2Parameters parameters;

    if (s->search2.active || !s->search2.queued_records ||
        s->search2.result_records == MSM5XXX_SEARCH2_DEPTH ||
        s->search2_probe_rejected) {
        return;
    }
    if (!msm5xxx_search2_begin(&s->search2, &job) ||
        !msm5xxx_search2_decode(&job, &parameters) ||
        (!s->search2_virtual && (!parameters.dump ||
                                !(s->search2.dump_enable & 2))) ||
        (s->search2_virtual &&
         !msm5xxx_search2_virtual_result(&parameters, s->search2_position,
                                         s->search2_pilot_phase,
                                         s->search2_peak_energy,
                                         s->search2_samples,
                                         &s->search2_pending_position))) {
        msm5xxx_poc_search2_reject(s, MSM5XXX_SEARCH2_REJECT_PARAMETERS,
                                  0, 0, 0);
        return;
    }
    timer_mod(s->search2_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->search2_delay_ns);
}

static void msm5xxx_poc_search2_complete(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (!msm5xxx_poc_search2_gate(s) ||
        !msm5xxx_search2_complete(&s->search2, &s->search2.job,
                                 s->search2_samples)) {
        msm5xxx_poc_search2_reject(s, MSM5XXX_SEARCH2_REJECT_COMPLETION,
                                  0, 0, 0);
        return;
    }
    s->search2_completions++;
    if (s->search2.job.parameters[0] & 0x8000) {
        msm5xxx_poc_fingers_latch(s);
    }
    if (s->search2_virtual) {
        s->search2_position = s->search2_pending_position;
    }
    if (msm5xxx_search2_dump_requested(&s->search2)) {
        /* Use the controller's normal pending/mask/W1C path. */
        s->rex_irq_pending[0] |= s->search2_route[8];
        msm5xxx_poc_rex_irq_update(s);
    }
    if (s->search2_virtual) {
        msm5xxx_poc_search2_start(s);
    }
}

static uint64_t msm5xxx_poc_search2_read(void *opaque, hwaddr offset,
                                        unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *backing = memory_region_get_ram_ptr(&s->msm);
    uint16_t value;

    if (s->search2_virtual && size == 2 && (offset == 0 || offset == 4) &&
        msm5xxx_poc_search2_gate(s)) {
        return offset == 0 ? s->search2_position & 0xffff : s->search2_position >> 16;
    }
    if (msm5xxx_poc_search2_gate(s) &&
        msm5xxx_search2_read(&s->search2, offset, size, &value)) {
        if (offset == 12) {
            s->search2_result_reads++;
            if (s->search2_virtual) {
                msm5xxx_poc_search2_start(s);
            }
        }
        return value;
    }
    return msm5xxx_poc_backing_read(backing, 0x800 + offset, size);
}

static void msm5xxx_poc_search2_write(void *opaque, hwaddr offset,
                                     uint64_t value, unsigned size)
{
    static const unsigned sites[] = {0, 4, 8, 10, 14, 34};
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *backing = memory_region_get_ram_ptr(&s->msm);
    uint32_t pc;
    bool precise_pc = msm5xxx_poc_mmio_access_pc(s, &pc);

    msm5xxx_poc_backing_write(backing, 0x800 + offset, value, size);
    if (offset == 4 && size == 2 &&
        (s->search2_virtual || !s->search2_probe_done) &&
        msm5xxx_poc_search2_gate(s)) {
        uint32_t expected_pc = s->search2_route[0] + sites[s->search2.queue_sub];

        if (!precise_pc || pc != expected_pc) {
            msm5xxx_poc_search2_reject(s, MSM5XXX_SEARCH2_REJECT_WRITER,
                                      pc, value, expected_pc);
            return;
        }
        if (!msm5xxx_search2_write(&s->search2, offset, size, value)) {
            msm5xxx_poc_search2_reject(s, MSM5XXX_SEARCH2_REJECT_QUEUE,
                                      pc, value, expected_pc);
            return;
        }
        if (!s->search2.queue_sub) {
            s->search2_submits++;
            s->search2_probe_done = true;
            s->search2.dump_enable = backing[0x814] & 3;
            msm5xxx_poc_search2_start(s);
        }
    } else if (offset == 20 && size == 1) {
        msm5xxx_search2_write(&s->search2, offset, size, value);
    } else if (offset == 0 && size == 1) {
        if (!s->search2.active && (value & 1)) {
            msm5xxx_poc_fingers_latch(s);
        }
        if (s->search2.active && value) {
            timer_del(s->search2_timer);
            msm5xxx_poc_search2_reject(s, MSM5XXX_SEARCH2_REJECT_CONTROL,
                                      pc, value, 0);
        } else {
            msm5xxx_search2_write(&s->search2, offset, size, value);
        }
    }
}

static const MemoryRegionOps msm5xxx_poc_search2_ops = {
    .read = msm5xxx_poc_search2_read,
    .write = msm5xxx_poc_search2_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
    .impl.min_access_size = 1, .impl.max_access_size = 4,
};

static const unsigned search1_sites[] = {
    0, 4, 10, 16, 42, 46, 52, 56, 118, 122, 138, 142, 144, 148, 166, 170, 174,
};
static const unsigned search1_offsets[] = {
    0x40, 0x44, 0x10, 0x3c, 4, 8, 12, 0x14, 0x18, 0x1c, 0x20, 0x24,
    0x28, 0x2c, 0x30, 0x34, 0x38,
};

static bool msm5xxx_poc_thumb_literal(MSM5xxxPOCMachineState *s,
                                       uint32_t pc, unsigned reg, uint32_t value)
{
    uint8_t bytes[2];
    uint16_t opcode;
    uint32_t address;

    cpu_physical_memory_read(pc, bytes, 2);
    opcode = bytes[0] | (bytes[1] << 8);
    address = ((pc + 4) & ~3U) + (opcode & 255) * 4;
    return (opcode & 0xf800) == 0x4800 && ((opcode >> 8) & 7) == reg &&
           address <= s->primary_nor_size - 4 &&
           msm5xxx_poc_guest_u32(address) == value;
}

static bool msm5xxx_poc_decoder_bl(MSM5xxxPOCMachineState *s, uint32_t pc, uint32_t *target);

static bool msm5xxx_poc_class_literal(MSM5xxxPOCMachineState *s,
    uint32_t pc, unsigned reg, uint32_t *value)
{
    uint8_t bytes[2]; uint16_t op; uint32_t pool;
    if (s->primary_nor_size < 4 || pc > s->primary_nor_size-2) return false;
    cpu_physical_memory_read(pc, bytes, 2);op=lduw_le_p(bytes);
    if ((op&0xff00)!=(0x4800u|(reg<<8))) return false;
    pool=((pc+4)&~3u)+(op&255u)*4;
    if (pool < pc || pool > s->primary_nor_size-4) return false;
    *value=msm5xxx_poc_guest_u32(pool);return true;
}

static bool msm5xxx_poc_private_writer_shape(MSM5xxxPOCMachineState *s,
    uint32_t entry)
{
    uint8_t code[390];
    uint32_t first=entry+0x54,cache,current,shadow,owner,peer,pending,put,get,target;
    const uint32_t ram=s->ram_base; uint64_t size=MACHINE(s)->ram_size;
    static const unsigned sites[]={0,4,10,16,78,82,88,94,170,174,190,194,196,200,212,216,220};
    static const uint16_t ops[]={0x700a,0x7108,0x7010,0x7308,0x7103,0x7203,0x7303,0x7118,0x7211,0x7310,0x7003,0x7102,0x7201,0x7301,0x7008,0x7108,0x7208};
    if (entry > s->primary_nor_size || sizeof(code)>s->primary_nor_size-entry ||
        entry > UINT32_MAX-390 || size<0x32 || s->search1_result_loop<0x32 ||
        s->search2_route[0]<20 || s->search2_route[1]<12) return false;
    cpu_physical_memory_read(entry,code,sizeof(code));
    if (lduw_le_p(code)!=0xb5f8 || lduw_le_p(code+388)!=0xbdf8) return false;
    for(unsigned i=0;i<G_N_ELEMENTS(sites);i++)
        if(lduw_le_p(code+0x54+sites[i])!=ops[i]) return false;
    { static const uint8_t block[]={0xcb,0x8d,0x10,0x78,0x83,0x42,0x0b,0xd1,0x03,0x28,0x09,0xd0,0x3b,0x79,0x03,0x2b,0x06,0xd0,0x08,0x8e,0x03,0x28,0x03,0xd0,0x05,0x2b,0x01,0xd0,0x05,0x28,0x14,0xd1}; if(memcmp(code+0x54+22,block,sizeof(block))) return false; }
    { static const uint8_t block[]={0xfc,0x23,0x45,0x88,0x2b,0x40,0xbd,0x7a,0xad,0x07,0xad,0x0f,0x2b,0x43,0x43,0x80,0x43,0x88}; if(memcmp(code+0x54+56,block,sizeof(block))) return false; }
    { static const uint8_t block[]={0x03,0x20,0x00,0x06}; if(memcmp(code+0x54+74,block,sizeof(block))) return false; }
    { static const uint8_t block[]={0xbb,0x8a}; if(memcmp(code+0x54+80,block,sizeof(block))) return false; }
    { static const uint8_t block[]={0xbb,0x8a,0x1b,0x0a}; if(memcmp(code+0x54+84,block,sizeof(block))) return false; }
    { static const uint8_t block[]={0xf8,0x8a}; if(memcmp(code+0x54+90,block,sizeof(block))) return false; }
    { static const uint8_t block[]={0x10,0x78,0x06,0x23,0xc8,0x85,0x38,0x79,0x08,0x86}; if(memcmp(code+0x54+96,block,sizeof(block))) return false; }
    if(!msm5xxx_poc_thumb_literal(s,first-4,1,0x3000040)) return false;
    if(!msm5xxx_poc_thumb_literal(s,first+8,2,0x3000010)) return false;
    if(!msm5xxx_poc_thumb_literal(s,first+14,1,0x3000030)) return false;
    if(!msm5xxx_poc_thumb_literal(s,first+92,3,0x3000010)) return false;
    if(!msm5xxx_poc_thumb_literal(s,first+168,2,0x3000010)) return false;
    if(!msm5xxx_poc_thumb_literal(s,first+186,0,0x3000020)) return false;
    if(!msm5xxx_poc_thumb_literal(s,first+204,1,0x3000030)) return false;
    if(!msm5xxx_poc_class_literal(s,first+18,1,&cache) ||
       !msm5xxx_poc_class_literal(s,first+20,2,&current) ||
       !msm5xxx_poc_class_literal(s,first+54,0,&shadow) ||
       cache<0x1000000 || cache>0x1ffffce || current<0x1000000 || current>0x1ffffff ||
       shadow<0x1000000 || shadow>0x1fffffc ||
       cache<ram || cache-ram>size-0x32 || current<ram || current-ram>=size ||
       shadow<ram || shadow-ram>size-4 ||
       (cache<current+1 && current<cache+0x32) ||
       (cache<shadow+4 && shadow<cache+0x32) ||
       (current<shadow+4 && shadow<current+1)) return false;
    for(unsigned i=0;i<2;i++) {
        if(!msm5xxx_poc_class_literal(s,s->search2_route[0]-20+i*4,1,&peer) ||
           peer>s->primary_nor_size || s->primary_nor_size-peer<1024 ||
           !msm5xxx_poc_thumb_literal(s,first+176+i*6,1,peer)) return false;
    }
    uint32_t consumer=s->search1_result_loop-0x32;
    if(!msm5xxx_poc_class_literal(s,consumer+12,5,&owner) ||
       owner<0x1000000 || owner>0x1ffffec || owner<ram || owner-ram>size-20 ||
       !msm5xxx_poc_thumb_literal(s,entry+12,6,owner) ||
       !msm5xxx_poc_class_literal(s,consumer+2,0,&pending) ||
       pending<0x1000000 || pending>0x1fffff4 || pending<ram || pending-ram>size-12 ||
       !msm5xxx_poc_decoder_bl(s,s->search2_route[0]+46,&put) ||
       !msm5xxx_poc_decoder_bl(s,s->search2_route[1]-12,&get) ||
       !msm5xxx_poc_decoder_bl(s,consumer+4,&target) || target!=get ||
       !msm5xxx_poc_decoder_bl(s,entry+4,&target) || target!=get) return false;
    unsigned puts=0;
    for(unsigned off=4;off+4<=sizeof(code);off+=2) {
        if(msm5xxx_poc_decoder_bl(s,entry+off,&target) && target==put &&
           msm5xxx_poc_thumb_literal(s,entry+off-4,0,pending) &&
           lduw_le_p(code+off-2)==0x1c39) puts++;
    }
    return puts==1;
}

static bool msm5xxx_poc_private_paging_shape(MSM5xxxPOCMachineState *s,
    uint32_t isr)
{
    uint8_t code[6]; uint32_t target;
    if (s->primary_nor_size < 0x1ee || isr > s->primary_nor_size-0x1ee) return false;
    cpu_physical_memory_read(isr,code,2);
    if(lduw_le_p(code)!=0xb5fc) return false;
    cpu_physical_memory_read(isr+0x15a,code,6);
    if(memcmp(code,"\xf8\x1d\x01\x30\x06\x1c",6)) return false;
    cpu_physical_memory_read(isr+0x1ba,code,4);
    if(memcmp(code,"\x02\x20\xb8\x80",4)) return false;
    cpu_physical_memory_read(isr+0x140,code,2);
    if(lduw_le_p(code)!=0xbdfc) return false;
    cpu_physical_memory_read(isr+0x1ec,code,2);
    if(lduw_le_p(code)!=0xe7a8 ||
       !msm5xxx_poc_decoder_bl(s,isr+0xd8,&target) || target!=s->decoder_paging_status ||
       !msm5xxx_poc_decoder_bl(s,isr+0x160,&target) || target!=s->decoder_paging_reader ||
       !msm5xxx_poc_decoder_bl(s,isr+0x1e0,&target) || target!=s->decoder_paging_initializer ||
       !msm5xxx_poc_decoder_bl(s,isr+0x1e8,&target) ||
       s->primary_nor_size<2 || target>s->primary_nor_size-2) return false;
    cpu_physical_memory_read(target,code,2);
    return lduw_le_p(code)==0x46f7;
}

static bool msm5xxx_poc_search1_gate(MSM5xxxPOCMachineState *s)
{
    static const uint16_t opcodes[] = {
        0x700a, 0x7108, 0x7010, 0x7308, 0x7101, 0x7201, 0x7301, 0x7110,
        0x7211, 0x7310, 0x7003, 0x7102, 0x7201, 0x7301, 0x7008, 0x7108, 0x7208,
    };
    static const uint8_t consumer[] = {
        0x08,0x72,0x8b,0x88,0x42,0x00,0xd2,0x19,0x93,0x85,0x8b,0x89,
        0x01,0x30,0x00,0x04,0x00,0x14,0x04,0x28,0x93,0x84,0xf3,0xdb,
    };
    uint8_t code[176];
    unsigned i;
    uint32_t first = s->search1_first_store;

    if (!s->search1_enabled || !s->search2_virtual || s->search1_rejected ||
        !msm5xxx_poc_search2_gate(s)) {
        return false;
    }
    s->search1_conditional = first >= 0x54 &&
        msm5xxx_poc_private_writer_shape(s, first - 0x54);
    if (s->search1_conditional) goto selected_consumer;
    cpu_physical_memory_read(first, code, sizeof(code));
    for (i = 0; i < G_N_ELEMENTS(search1_sites); i++) {
        unsigned at = search1_sites[i];
        if ((code[at] | (code[at + 1] << 8)) != opcodes[i]) {
            return false;
        }
    }
    if (!msm5xxx_poc_thumb_literal(s, first - 4, 1, 0x03000040) ||
        !msm5xxx_poc_thumb_literal(s, first + 8, 2, 0x03000010) ||
        !msm5xxx_poc_thumb_literal(s, first + 14, 1, 0x03000030) ||
        !msm5xxx_poc_thumb_literal(s, first + 112, 2, 0x03000010) ||
        !msm5xxx_poc_thumb_literal(s, first + 134, 0, 0x03000020) ||
        !msm5xxx_poc_thumb_literal(s, first + 152, 1, 0x03000030) ||
        memcmp(code + 38, "\x03\x20\x00\x06", 4)) {
        return false;
    }
selected_consumer:
    cpu_physical_memory_read(s->search1_result_loop, code, sizeof(consumer));
    return !memcmp(code, consumer, sizeof(consumer));
}

static void msm5xxx_poc_search1_reject(MSM5xxxPOCMachineState *s,
                                      unsigned reason, uint32_t pc,
                                      hwaddr offset, unsigned size, uint64_t value)
{
    timer_del(s->search1_timer);
    s->search1_rejected = true;
    s->search1_config_valid = false;
    s->search1_config_known = false;
    /* Preserve the first cause, before subsequent canceled completions. */
    if (!s->search1_rejections) {
        s->search1_reject_reason = reason;
        s->search1_reject_pc = pc;
        s->search1_reject_access = offset | (size << 16);
        s->search1_reject_value = value;
    }
    s->search1_rejections++;
}

static void msm5xxx_poc_search1_complete(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (!s->search1_active) {
        return;
    }
    if (!msm5xxx_poc_search1_gate(s)) {
        msm5xxx_poc_search1_reject(s, 1, 0, 0, 0, 0);
        return;
    }
    s->search1_position = s->search1_pending_position;
    s->search1_active = false;
    memcpy(s->search1_results, s->search1_pending_results, sizeof(s->search1_results));
    s->search1_have_results = true;
    s->search1_completions++;
    msm5xxx_poc_fingers_latch(s);
    s->search2.status |= 1;
    if (s->search2.dump_enable & 1) {
        s->rex_irq_pending[0] |= s->search2_route[8];
        msm5xxx_poc_rex_irq_update(s);
    }
}

static uint64_t msm5xxx_poc_search1_read(void *opaque, hwaddr offset, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *backing = memory_region_get_ram_ptr(&s->msm);
    uint32_t pc;

    if (msm5xxx_poc_search1_gate(s)) {
        if (offset == 0x30 && size == 2) {
            return s->search1_position & 0xffff;
        }
        if (offset == 0x38 && size == 1) {
            return s->search1_position >> 16;
        }
        if (s->search1_have_results && size == 2 &&
            msm5xxx_poc_mmio_access_pc(s, &pc) &&
            ((offset == 0x44 && pc == s->search1_result_loop + 2) ||
             (offset == 0x4c && pc == s->search1_result_loop + 10))) {
            s->search1_result_reads++;
            return s->search1_results[s->search1_selector * 2 + (offset == 0x4c)];
        }
    }
    return msm5xxx_poc_backing_read(backing, offset, size);
}

static bool msm5xxx_poc_search1_abort_gate(MSM5xxxPOCMachineState *s)
{
    uint8_t code[0x7c];
    uint32_t entry, literals[5], owner, targets[6];
    unsigned i;

    if (!s->search1_abort_pc) {
        return false;
    }
    entry = s->search1_abort_pc - 0x3e;
    cpu_physical_memory_read(entry, code, sizeof(code));
    static const struct { unsigned offset; uint16_t opcode; } fixed[] = {
        {0x0, 0xb5f0}, {0x4, 0x2700}, {0x6, 0x7920}, {0xc, 0x2800},
        {0xe, 0xd102}, {0x10, 0x7828}, {0x12, 0x2800}, {0x14, 0xd01e},
        {0x16, 0x706f}, {0x1c, 0x7829}, {0x1e, 0x0400}, {0x20, 0x0c00},
        {0x22, 0x2900}, {0x24, 0xd007}, {0x28, 0x2302}, {0x2a, 0x880a},
        {0x2c, 0x431a}, {0x2e, 0x7032}, {0x30, 0x8809}, {0x32, 0x4319},
        {0x34, 0x7031}, {0x36, 0x7921}, {0x38, 0x2900}, {0x3a, 0xd002},
        {0x3e, 0x700f}, {0x40, 0x710f}, {0x42, 0x2800}, {0x44, 0xd101},
        {0x4c, 0x2009}, {0x4e, 0x8008}, {0x50, 0x7127}, {0x52, 0x702f},
        {0x54, 0x7a30}, {0x5a, 0x2001}, {0x5c, 0x7068}, {0x60, 0x2101},
        {0x62, 0x1c28}, {0x6e, 0x2101}, {0x70, 0x02c9}, {0x72, 0x1c28},
        {0x78, 0x6027}, {0x7a, 0xbdf0},
    };
    for (i = 0; i < G_N_ELEMENTS(fixed); i++) {
        if (lduw_le_p(code + fixed[i].offset) != fixed[i].opcode) {
            return false;
        }
    }
    if (!msm5xxx_poc_thumb_literal(s, entry + 8, 6, 0x03000800) ||
        !msm5xxx_poc_thumb_literal(s, entry + 0x3c, 1, 0x03000040) ||
        !msm5xxx_poc_thumb_literal(s, entry + 0x4a, 1, 0x04800020)) {
        return false;
    }
    static const unsigned literal_at[] = {2, 0xa, 0x26, 0x68, 0x5e};
    static const unsigned literal_reg[] = {4, 5, 1, 0, 5};
    static const unsigned literal_span[] = {8, 8, 2, 0x14, 4};
    for (i = 0; i < G_N_ELEMENTS(literal_at); i++) {
        unsigned at = literal_at[i], reg = literal_reg[i];
        uint16_t opcode = lduw_le_p(code + at);
        uint32_t pool = ((entry + at + 4) & ~3U) + (opcode & 255) * 4;
        if ((opcode & 0xff00) != (0x4800 | (reg << 8)) ||
            pool > s->primary_nor_size - 4) {
            return false;
        }
        literals[i] = msm5xxx_poc_guest_u32(pool);
        if (literals[i] < s->ram_base || literals[i] - s->ram_base > MACHINE(s)->ram_size ||
            MACHINE(s)->ram_size - (literals[i] - s->ram_base) < literal_span[i]) {
            return false;
        }
    }
    static const unsigned call_at[] = {0x18, 0x46, 0x56, 0x64, 0x6a, 0x74};
    for (i = 0; i < G_N_ELEMENTS(call_at); i++) {
        if (!msm5xxx_poc_decoder_bl(s, entry + call_at[i], &targets[i])) {
            return false;
        }
    }
    if (targets[3] != targets[5]) {
        return false;
    }
    owner = msm5xxx_poc_guest_u32(literals[0]);
    return (msm5xxx_poc_guest_u32(literals[0] + 4) & 255) &&
           owner >= s->ram_base && owner - s->ram_base <= MACHINE(s)->ram_size &&
           MACHINE(s)->ram_size - (owner - s->ram_base) >= 0x98 &&
           msm5xxx_poc_thumb_literal(s, s->search1_result_loop - 0x26, 5, literals[0]) &&
           msm5xxx_poc_thumb_literal(s, s->search2_route[4] + 4, 1, literals[1]);
}

static void msm5xxx_poc_search1_write(void *opaque, hwaddr offset,
                                      uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *backing = memory_region_get_ram_ptr(&s->msm);
    uint32_t pc;
    static const unsigned conditional_sites[] = {
        0,4,10,16,78,82,88,94,170,174,190,194,196,200,212,216,220
    };
    const unsigned *sites;
    unsigned last;
    MSM5xxxSearch2Parameters parameters;

    static const unsigned config_offsets[] = {4,8,12,20};
    for (unsigned i=0; i<G_N_ELEMENTS(config_offsets); i++) {
        if (offset <= config_offsets[i] && config_offsets[i]-offset < size)
            s->search1_config_valid = false;
    }
    msm5xxx_poc_backing_write(backing, offset, value, size);
    if (offset == 4 && size == 1 && (value & 8) && !s->search1_active) {
        msm5xxx_poc_fingers_latch(s);
    }
    if (!msm5xxx_poc_search1_gate(s) || size != 1 ||
        !msm5xxx_poc_mmio_access_pc(s, &pc)) {
        return;
    }
    if (!value && ((offset == 0x40 && pc == s->search1_abort_pc) ||
                   (offset == 0x44 && pc == s->search1_abort_pc + 2)) &&
        msm5xxx_poc_search1_abort_gate(s)) {
        timer_del(s->search1_timer);
        if (s->search1_active || s->search1_have_results || s->search1_sub) {
            s->search1_aborts++;
        }
        s->search1_active = s->search1_have_results = false;
        s->search1_sub = s->search1_selector = 0;
        s->search1_config_valid = false;
        s->search2.status &= ~1u;
        /* Cancel this atomic search, preserving the PN position and shared IRQ. */
        return;
    }
    if (offset == 0x48 && pc == s->search1_result_loop && value < 4) {
        s->search1_selector = value;
        return;
    }
    sites = s->search1_conditional ? conditional_sites : search1_sites;
    last = s->search1_conditional ? 220 : 174;
    if (s->search1_conditional && s->search1_sub == 4 &&
        s->search1_config_known && pc == s->search1_first_store + sites[8] &&
        offset == search1_offsets[8]) {
        bool same = true;
        for (unsigned i=0; i<G_N_ELEMENTS(config_offsets); i++) {
            same &= backing[config_offsets[i]] == s->search1_verified_config[i];
        }
        if (same) {
            memcpy(s->search1_packet+4, s->search1_verified_config, 4);
            s->search1_config_valid = true;
            s->search1_sub = 8;
        }
    }
    if (pc < s->search1_first_store || pc > s->search1_first_store + last) {
        if (s->search1_active && ((offset == 4 && (value & 8)) ||
                                  offset == 0x40 || offset == 0x44)) {
            msm5xxx_poc_search1_reject(s, 2, pc, offset, size, value);
        }
        return;
    }
    if (s->search1_active || pc != s->search1_first_store + sites[s->search1_sub] ||
        offset != search1_offsets[s->search1_sub]) {
        msm5xxx_poc_search1_reject(s, 4, pc, offset, size, value);
        return;
    }
    s->search1_packet[s->search1_sub++] = value;
    if (s->search1_sub == MSM5XXX_SEARCH1_PARAMETERS) {
        s->search1_sub = 0;
        s->search1_submits++;
        if (!msm5xxx_search1_decode(s->search1_packet, &parameters) ||
            !msm5xxx_search2_virtual_result(&parameters, s->search1_position,
                                            s->search2_pilot_phase,
                                            s->search2_peak_energy,
                                            s->search1_pending_results,
                                            &s->search1_pending_position)) {
            msm5xxx_poc_search1_reject(s, 3, pc, offset, size, value);
            return;
        }
        memcpy(s->search1_verified_config, s->search1_packet+4, 4);
        s->search1_config_known = s->search1_config_valid = true;
        s->search1_active = true;
        timer_mod(s->search1_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                                   s->search2_delay_ns);
    }
}

static const MemoryRegionOps msm5xxx_poc_search1_ops = {
    .read = msm5xxx_poc_search1_read, .write = msm5xxx_poc_search1_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
    .impl.min_access_size = 1, .impl.max_access_size = 4,
};

static bool msm5xxx_poc_fingers_gate(MSM5xxxPOCMachineState *s)
{
    static const uint16_t words[34] = {
        0x899b,0x9301,0,0xae01,0x7836,0x78ab,0x401e,0xab01,0x701e,
        0x785b,0x878b,0x786d,0x9e01,0x40ae,0,0x1c33,0x42ab,0x9601,
        0xd800,0x9d01,0x9501,0xab01,0x785b,0x2508,0x4085,0x874b,
        0x1c2b,0x4013,0x3001,0x0400,0x0c00,0x870b,0x42b8,0xdbc1,
    };
    uint8_t code[68];
    uint32_t pc = s->finger_read_pc;
    unsigned i;

    if (!s->finger_enabled || !s->search2_virtual) {
        return false;
    }
    cpu_physical_memory_read(pc, code, sizeof(code));
    for (i = 0; i < G_N_ELEMENTS(words); i++) {
        if (words[i] && lduw_le_p(code + i * 2) != words[i]) {
            return false;
        }
    }
    return (lduw_le_p(code + 4) & 0xff00) == 0x4d00 &&
           msm5xxx_poc_thumb_literal(s, pc - 52, 3, 0x03000070) &&
           msm5xxx_poc_thumb_literal(s, pc - 48, 1, 0x030000a0) &&
           msm5xxx_poc_thumb_literal(s, pc - 32, 5, 0x030000b0) &&
           msm5xxx_poc_thumb_literal(s, pc - 2, 3, 0x03000080) &&
           msm5xxx_poc_thumb_literal(s, pc + 28, 5, 0xffff);
}

static void msm5xxx_poc_fingers_latch(MSM5xxxPOCMachineState *s)
{
    uint8_t raw[1024];
    uint16_t masks_i[512], masks_q[512];
    unsigned i;

    if (!msm5xxx_poc_fingers_gate(s)) {
        return;
    }
    cpu_physical_memory_read(s->finger_masks_i, raw, sizeof(raw));
    for (i = 0; i < 512; i++) {
        masks_i[i] = lduw_le_p(raw + i * 2);
    }
    cpu_physical_memory_read(s->finger_masks_q, raw, sizeof(raw));
    for (i = 0; i < 512; i++) {
        masks_q[i] = lduw_le_p(raw + i * 2);
    }
    msm5xxx_fingers_latch(&s->fingers, s->search2_pilot_phase,
                          s->search2_peak_energy, masks_i, masks_q);
    s->finger_latches++;
}

static uint64_t msm5xxx_poc_fingers_read(void *opaque, hwaddr offset, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *backing = memory_region_get_ram_ptr(&s->msm);
    uint16_t value;

    if (msm5xxx_poc_fingers_gate(s) &&
        msm5xxx_fingers_read(&s->fingers, offset + 0x60, size, &value)) {
        s->finger_reads++;
        return value;
    }
    return msm5xxx_poc_backing_read(backing, offset + 0x60, size);
}

static void msm5xxx_poc_fingers_write(void *opaque, hwaddr offset,
                                      uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *backing = memory_region_get_ram_ptr(&s->msm);

    msm5xxx_poc_backing_write(backing, offset + 0x60, value, size);
    if (msm5xxx_poc_fingers_gate(s) &&
        (size != 1 || !msm5xxx_fingers_write(&s->fingers, offset + 0x60, size, value))) {
        s->finger_fallback_writes++;
    }
}

static const MemoryRegionOps msm5xxx_poc_fingers_ops = {
    .read = msm5xxx_poc_fingers_read, .write = msm5xxx_poc_fingers_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
    .impl.min_access_size = 1, .impl.max_access_size = 4,
};

/* Bounded initialization handshake only; no decoded samples or service state. */
static bool msm5xxx_poc_decoder_bl(MSM5xxxPOCMachineState *s,
                                   uint32_t pc, uint32_t *target)
{
    uint8_t code[4];
    uint16_t hi, lo;
    uint32_t delta;

    if (pc & 1 || pc >= s->primary_nor_size || s->primary_nor_size - pc < 4) {
        return false;
    }
    cpu_physical_memory_read(pc, code, sizeof(code));
    hi = lduw_le_p(code);
    lo = lduw_le_p(code + 2);
    if ((hi & 0xf800) != 0xf000 || (lo & 0xf800) != 0xf800) {
        return false;
    }
    delta = ((hi & 0x7ff) << 12) | ((lo & 0x7ff) << 1);
    if (delta & 0x400000) {
        delta |= 0xff800000;
    }
    *target = pc + 4 + delta;
    return *target < s->primary_nor_size;
}

static bool msm5xxx_poc_decoder_init_gate(MSM5xxxPOCMachineState *s,
                                         uint32_t *mask)
{
    static const uint8_t copy_code[] = {
        0x90,0xb5,0x00,0x23,0x04,0xe0,0x04,0x88,0x1f,0x1c,
        0x7f,0x00,0xcc,0x53,0x01,0x33,0x93,0x42,0xf8,0xdb,0x90,0xbd,
    };
    uint8_t code[sizeof(copy_code)];
    uint32_t reader = s->decoder_init_reader, write = s->decoder_init_write_pc;
    uint32_t helper, target, slot;

    if (!s->decoder_init_enabled || !s->search2_virtual ||
        !msm5xxx_poc_radio_irq_gate(s) || s->search2_route[2] < s->ram_base + 48) {
        return false;
    }
    slot = s->search2_route[2] - 28;
    if (msm5xxx_poc_guest_u32(slot) != (s->decoder_init_isr | 1) ||
        msm5xxx_poc_guest_u32(slot - 20) != s->rex_irq_status_address ||
        msm5xxx_poc_guest_u32(slot - 16) != s->rex_irq_enable_address) {
        return false;
    }
    *mask = msm5xxx_poc_guest_u32(slot - 12);
    if (!*mask || *mask > UINT16_MAX || (*mask & (*mask - 1)) ||
        *mask == s->search2_route[8] || *mask == s->rex_irq_mask) {
        return false;
    }
    cpu_physical_memory_read(reader, code, 20);
    if (lduw_le_p(code) != 0xb500 || lduw_le_p(code + 4) != 0x2100 ||
        lduw_le_p(code + 6) != 0x8311 || lduw_le_p(code + 8) != 0x2206 ||
        lduw_le_p(code + 10) != 0x1c01 || lduw_le_p(code + 18) != 0xbd00 ||
        !msm5xxx_poc_thumb_literal(s, reader + 2, 2, 0x03000a40) ||
        !msm5xxx_poc_thumb_literal(s, reader + 12, 0, 0x03000a70) ||
        !msm5xxx_poc_decoder_bl(s, reader + 14, &helper) ||
        s->primary_nor_size - helper < sizeof(copy_code) ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_init_isr + 0x56, &target) ||
        target != reader) {
        return false;
    }
    cpu_physical_memory_read(helper, code, sizeof(code));
    if (memcmp(code, copy_code, sizeof(code))) {
        return false;
    }
    cpu_physical_memory_read(write - 0x22, code, 12);
    if (memcmp(code, "\x19\x40\x40\x23\x19\x43\xb9\x80\xb9\x88\x21\x81", 12)) {
        return false;
    }
    cpu_physical_memory_read(write - 10, code, 12);
    return lduw_le_p(code) == 0x88b9 &&
           lduw_le_p(code + 4) == 0x4019 &&
           lduw_le_p(code + 6) == 0x80b9 &&
           lduw_le_p(code + 8) == 0x88b9 &&
           lduw_le_p(code + 10) == 0x8121 &&
           msm5xxx_poc_thumb_literal(s, write - 8, 3, 0xfff8) &&
           msm5xxx_poc_thumb_literal(s, write - 0x24, 4, 0x03000a00);
}

static bool msm5xxx_poc_decoder_sync_gate(MSM5xxxPOCMachineState *s,
                                         uint32_t *roll_mask)
{
    uint8_t code[40];
    uint32_t target, slot = s->search2_route[2] - 5 * 28;
    uint32_t reader = s->combiner_position_reader;

    if (!s->decoder_sync_enabled || !msm5xxx_poc_radio_irq_gate(s) ||
        s->search2_route[2] < s->ram_base + 5 * 28 + 20 ||
        msm5xxx_poc_guest_u32(slot) != (s->combiner_roll_isr | 1) ||
        msm5xxx_poc_guest_u32(slot - 20) != s->rex_irq_status_address ||
        msm5xxx_poc_guest_u32(slot - 16) != s->rex_irq_enable_address) {
        return false;
    }
    *roll_mask = msm5xxx_poc_guest_u32(slot - 12);
    if (!*roll_mask || *roll_mask > UINT16_MAX || (*roll_mask & (*roll_mask - 1)) ||
        *roll_mask == s->decoder_init_mask || *roll_mask == s->rex_irq_mask ||
        *roll_mask == s->search2_route[8] ||
        !msm5xxx_poc_decoder_bl(s, s->combiner_roll_isr + 0x1aa, &target) ||
        target != reader ||
        !msm5xxx_poc_decoder_bl(s, s->combiner_roll_isr + 0x2a4, &target) ||
        target != reader) {
        return false;
    }
    uint32_t first, second;
    cpu_physical_memory_read(s->decoder_sync_consumer + 0x16, code, 16);
    if (memcmp(code, "\x48\x22\x00\x92\xf8\x1d\x01\x30\x2a\x1c\x18\x23\x00\x21\x06\x1c", 16)) {
        return false;
    }
    cpu_physical_memory_read(s->decoder_sync_consumer + 0x42, code, 12);
    if (memcmp(code, "\x18\x22\x00\x92\x00\x23\x48\x21\x30\x1c\x2a\x1c", 12) ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_sync_consumer + 0x26, &first) ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_sync_consumer + 0x4e, &second) || first != second ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_sync_consumer + 0x66, &first) ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_init_isr + 0xc, &second) || first != second) {
        return false;
    }
    cpu_physical_memory_read(reader, code, sizeof(code));
    return lduw_le_p(code) == 0xb508 &&
        !memcmp(code + 6, "\x01\x04\x09\x0c", 4) &&
        !memcmp(code + 12, "\x00\x22\x02\x71\x02\x7a\x00\xab\x1a\x70\x00\x7b\x58\x70\x00\x29\x01\xd1", 18) &&
        !memcmp(code + 34, "\x00\xa8\x00\x88\x08\xbd", 6) &&
        msm5xxx_poc_thumb_literal(s, reader + 10, 0, 0x030000f0);
}

static bool msm5xxx_poc_decoder_paging_gate(MSM5xxxPOCMachineState *s,
                                           uint32_t *mask)
{
    uint8_t code[32];
    uint32_t slot, helper, target, setter, queue, pool;
    unsigned shift;
    uint32_t reader = s->decoder_paging_reader;
    uint32_t status = s->decoder_paging_status;
    uint32_t init = s->decoder_paging_initializer;
    uint32_t isr = s->decoder_paging_isr;
    uint32_t consumer = s->decoder_paging_consumer;
    uint32_t cache = s->decoder_paging_cache, layout = s->decoder_paging_layout;

    if (!s->decoder_paging_enabled || !msm5xxx_poc_radio_irq_gate(s) ||
        s->search2_route[2] < s->ram_base + 48) {
        return false;
    }
    slot = s->search2_route[2] - 28;
    if (msm5xxx_poc_guest_u32(slot) != (isr | 1) ||
        msm5xxx_poc_guest_u32(slot - 20) != s->rex_irq_status_address ||
        msm5xxx_poc_guest_u32(slot - 16) != s->rex_irq_enable_address) {
        return false;
    }
    *mask = msm5xxx_poc_guest_u32(slot - 12);
    if (*mask != s->decoder_init_mask || !*mask) {
        return false;
    }
    cpu_physical_memory_read(reader, code, 22);
    if (lduw_le_p(code) != 0xb500 ||
        memcmp(code + 4, "\x00\x21\x11\x83", 4) ||
        memcmp(code + 10, "\x0a\x88\x01\x1c", 4) ||
        lduw_le_p(code + 20) != 0xbd00 ||
        !msm5xxx_poc_thumb_literal(s, reader + 2, 2, 0x03000a40) ||
        !msm5xxx_poc_thumb_literal(s, reader + 8, 1, s->decoder_paging_count) ||
        !msm5xxx_poc_thumb_literal(s, reader + 14, 0, 0x03000a70) ||
        !msm5xxx_poc_decoder_bl(s, reader + 16, &helper) ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_init_reader + 14, &target) || helper != target) {
        return false;
    }
    shift = msm5xxx_poc_private_paging_shape(s, isr) ? 2 : 0;
    cpu_physical_memory_read(status, code, 24);
    if (memcmp(code + 4, "\x09\x88\x11\x83", 4) ||
        memcmp(code + 10, "\x11\x8a\x41\x70\x09\x12\x01\x70\x11\x8a\x41\x80\xf7\x46", 14) ||
        !msm5xxx_poc_thumb_literal(s, status, 1, s->decoder_paging_count) ||
        !msm5xxx_poc_thumb_literal(s, status + 2, 2, 0x03000a40) ||
        !msm5xxx_poc_thumb_literal(s, status + 8, 2, 0x03000a60) ||
        !msm5xxx_poc_decoder_bl(s, isr + 0xda - shift, &target) || target != status ||
        !msm5xxx_poc_decoder_bl(s, isr + 0x162 - shift, &target) || target != reader ||
        !msm5xxx_poc_decoder_bl(s, isr + 0x1e2 - shift, &target) || target != init) {
        return false;
    }
    cpu_physical_memory_read(init + 0x10, code, 16);
    if (lduw_le_p(code) != 0x88a1 ||
        memcmp(code + 4, "\x19\x40\x20\x23\x19\x43\xa1\x80\xa1\x88\x29\x81", 12) ||
        !msm5xxx_poc_thumb_literal(s, init + 0x0e, 3, 0xff9f) ||
        !msm5xxx_poc_thumb_literal(s, init + 0x12, 5, 0x03000a00) ||
        !msm5xxx_poc_thumb_literal(s, init + 0x2e, 3, 0xfff8) ||
        !msm5xxx_poc_decoder_bl(s, init + 4, &setter) ||
        s->primary_nor_size - setter < 20) {
        return false;
    }
    cpu_physical_memory_read(init + 0x2c, code, 12);
    if (lduw_le_p(code) != 0x88a1 ||
        memcmp(code + 4, "\x19\x40\xa1\x80\xa1\x88\x29\x81", 8) ||
        !msm5xxx_poc_thumb_literal(s, setter + 2, 1, s->decoder_paging_count)) {
        return false;
    }
    cpu_physical_memory_read(setter + 4, code, 16);
    if (memcmp(code, "\x00\x28\x03\xd0\x01\x28\x04\xd1\x06\x20\x00\xe0\x0c\x20\x08\x80", 16)) {
        return false;
    }
    cpu_physical_memory_read(consumer + 0x46, code, 12);
    if (memcmp(code, "\xa2\x88\x00\x21\x28\x1c\x00\x92\x63\x88\x32\x1c", 12) ||
        !msm5xxx_poc_decoder_bl(s, consumer + 0x54, &helper) ||
        !msm5xxx_poc_decoder_bl(s, consumer + 0x86, &target) || helper != target ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_sync_consumer + 0x26, &target) || helper != target) {
        return false;
    }
    cpu_physical_memory_read(consumer + 0xe, code, 8);
    if (memcmp(code, "\xf5\x1f\x11\x3d\xec\x1d\x2f\x34", 8) ||
        !msm5xxx_poc_thumb_literal(s, consumer + 0xc, 6, cache + 0x22) ||
        !msm5xxx_poc_thumb_literal(s, consumer + 0x1a, 0, cache) ||
        !msm5xxx_poc_thumb_literal(s, consumer + 0x28, 1, cache) ||
        !msm5xxx_poc_thumb_literal(s, consumer + 0x30, 0, cache) ||
        !msm5xxx_poc_thumb_literal(s, consumer + 0x3e, 0, cache) ||
        !msm5xxx_poc_thumb_literal(s, consumer + 0x52, 7, cache) ||
        !msm5xxx_poc_thumb_literal(s, consumer + 0x96, 7, cache)) {
        return false;
    }
    cpu_physical_memory_read(consumer + 0x7a, code, 12);
    if (memcmp(code, "\x62\x88\x00\x23\x28\x1c\x00\x92\xa1\x88\x32\x1c", 12) ||
        !msm5xxx_poc_decoder_bl(s, consumer + 0xc6, &helper) ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_init_isr + 0xc, &target) || helper != target) {
        return false;
    }
    cpu_physical_memory_read(isr + 0x1c0 - shift, code, 2);
    pool = ((isr + 0x1c4 - shift) & ~3U) + (lduw_le_p(code) & 255) * 4;
    if (pool > s->primary_nor_size - 4) {
        return false;
    }
    queue = msm5xxx_poc_guest_u32(pool);
    if (queue < s->ram_base || queue - s->ram_base > MACHINE(s)->ram_size ||
        MACHINE(s)->ram_size - (queue - s->ram_base) < 12 ||
        !msm5xxx_poc_thumb_literal(s, isr + 0x1c0 - shift, 0, queue) ||
        !msm5xxx_poc_thumb_literal(s, consumer + 0xc4, 0, queue)) {
        return false;
    }
    cpu_physical_memory_read(consumer + 0x18, code, 10);
    if (lduw_le_p(code) != 0x1df9 ||
        memcmp(code + 4, "\x01\x31\x18\x22\x28\x1c", 6)) {
        return false;
    }
    cpu_physical_memory_read(layout, code, 32);
    if (memcmp(code, "\xc0\x20\x00\xe0\x60\x20\x48\x87", 8) ||
        lduw_le_p(code + 10) != 0x2048 ||
        memcmp(code + 14, "\xa8\x80\x48\x8f\x48\x38\x68\x80\x4e\x8f\x70\x08\x00\x04\x00\x0c\x88\x87", 18) ||
        !msm5xxx_poc_thumb_literal(s, layout - 6, 1, cache) ||
        !msm5xxx_poc_thumb_literal(s, layout + 8, 5, cache + 0x40) ||
        !msm5xxx_poc_thumb_literal(s, layout + 12, 1, cache)) {
        return false;
    }
    return true;
}

static bool msm5xxx_poc_traffic_shape(MSM5xxxPOCMachineState *s,
                                      uint32_t pc, const uint16_t *shape,
                                      unsigned count)
{
    uint8_t code[256];
    unsigned i;
    if (count > sizeof(code) / 2 || pc > s->primary_nor_size ||
        count * 2 > s->primary_nor_size - pc) {
        return false;
    }
    cpu_physical_memory_read(pc, code, count * 2);
    for (i = 0; i < count; i++) {
        if (shape[i] && lduw_le_p(code + 2 * i) != shape[i]) {
            return false;
        }
    }
    return true;
}

static bool msm5xxx_poc_decoder_traffic_gate(MSM5xxxPOCMachineState *s,
                                            uint32_t *mask)
{
    static const uint16_t reader_shape[] = {
        0xb5f0,0x1c04,0x1c17,0x0000,0x00c9,0x1808,0x1fc5,0x3d09,0x2a00,0x0000,
        0xd001,0x2f01,0xd10c,0x7a28,0x0840,0x8330,0x7b28,0x0840,0x0402,0x0c12,
        0x1c21,0x0000,0x0000,0x0000,0x2f00,0xd001,0x2f02,0xd10d,0x7a68,0x0840,
        0x8330,0x7b68,0x0840,0x0402,0x0c12,0x1de1,0x311d,0x0000,0x0000,0x0000,
        0x2f00,0xd001,0x2f03,0xd10d,0x7aa8,0x0840,0x8330,0x7ba8,0x0840,0x0402,
        0x0c12,0x1de1,0x312f,0x0000,0x0000,0x0000,0x2f00,0xd001,0x2f04,0xd10b,
        0x7ae8,0x0840,0x8330,0x7be8,0x0840,0x0402,0x0c12,0x1de1,0x3139,0x0000,
        0x0000,0x0000,0xbdf0
    };
    static const uint16_t metrics_shape[] = {
        0xb5b0,0x0000,0x00c0,0x1880,0x1fc2,0x3a09,0x7a50,0x0000,0x0840,0x3802,
        0x8318,0x0000,0x8a07,0x710f,0x123f,0x700f,0x8a07,0x810f,0x7a97,0x087f,
        0x3f02,0x831f,0x8a07,0x714f,0x123f,0x704f,0x8a07,0x814f,0x7ad7,0x087f,
        0x3f02,0x831f,0x8a07,0x718f,0x123f,0x708f,0x8a07,0x818f,0x7ad7,0x7bd2,
        0x087f,0x0852,0x18ba,0x831a,0x8a02,0x71ca,0x1212,0x70ca,0x8a00,0x81c8,
        0x7948,0x0040,0x7148,0x7988,0x0080,0x7188,0x79c8,0x00c0,0x71c8,0xbdb0
    };
    static const uint16_t init_shape[] = {
        0xb5b0,0x1c07,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x88a1,0x0000,
        0x4019,0x2320,0x4319,0x80a1,0x88a1,0x8129,0x2800,0xd101,0x0000,0x0000,
        0x0000,0x0000,0x88a1,0x0000,0x4019,0x80a1,0x88a1,0x8129,0x2800,0xd101,
        0x0000,0x0000,0x0000,0x0000,0x2f03,0xdb0c,0x0000,0x0000,0x8a21,0x0000,
        0x4019,0x2302,0x4319,0x8221,0x8a21,0x8029,0x2800,0xd10c,0xe009,0x0000,
        0x0000,0x8a21,0x0000,0x4019,0x8221,0x8a21,0x8029,0x2800,0xd101,0x0000,
        0x0000,0x0000,0x0000,0x0000,0x2800,0xd107,0x1c38,0x0000,0x0000,0x2101,
        0x1c38,0x0000,0x0000,0xbdb0,0x2100,0x7201,0x0000,0x7307,0x1c01,0x1c10,
        0x0000,0x0000,0xbdb0
    };
    static const uint16_t callback_shape[] = {
        0xb5f0, 0xb086, 0, 0x8800, 0x0684, 0x0ea4, 0x2c03,
    };
    static const uint16_t copy_shape[] = {
        0xb590, 0x2300, 0xe004, 0x8804, 0x1c1f, 0x007f,
        0x53cc, 0x3301, 0x4293, 0xdbf8, 0xbd90,
    };
    uint32_t *r = s->decoder_traffic_route, slot, helper, target, source, dest, size;
    uint8_t mode, descriptor[8], original[8];
    unsigned i;
    if (!s->decoder_traffic_enabled || !s->decoder_paging_enabled || !s->search2_virtual ||
        !msm5xxx_poc_radio_irq_gate(s) || s->search2_route[2] < s->ram_base + 48) {
        return false;
    }
    slot = s->search2_route[2] - 28;
    if (msm5xxx_poc_guest_u32(slot) != (r[0] | 1)) {
        return false;
    }
    s->decoder_traffic_reject_reason = 1;
    *mask = msm5xxx_poc_guest_u32(slot - 12);
    if (*mask != s->decoder_init_mask || !*mask ||
        msm5xxx_poc_guest_u32(slot - 20) != s->rex_irq_status_address ||
        msm5xxx_poc_guest_u32(slot - 16) != s->rex_irq_enable_address) {
        return false;
    }
    s->decoder_traffic_reject_reason = 2;
    cpu_physical_memory_read(r[4] + 1, &mode, 1);
    source = msm5xxx_poc_guest_u32(r[7]);
    dest = msm5xxx_poc_guest_u32(r[7] + 4);
    size = msm5xxx_poc_guest_u32(r[7] + 8);
    if (mode != 1 || size < 48 || source > s->primary_nor_size ||
        size > s->primary_nor_size - source || r[5] < dest ||
        r[5] - dest > size - 48 || r[6] != source + (r[5] - dest) ||
        msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm), 0xa08, 2) != 0x20) {
        return false;
    }
    cpu_physical_memory_read(r[5] + 8, descriptor, 8);
    cpu_physical_memory_read(r[6] + 8, original, 8);
    if (memcmp(descriptor, original, 8)) {
        return false;
    }
    s->decoder_traffic_reject_reason = 3;
    if (!msm5xxx_poc_traffic_shape(s, r[0], callback_shape, G_N_ELEMENTS(callback_shape)) ||
        !msm5xxx_poc_traffic_shape(s, r[1], reader_shape, G_N_ELEMENTS(reader_shape)) ||
        !msm5xxx_poc_traffic_shape(s, r[2], metrics_shape, G_N_ELEMENTS(metrics_shape)) ||
        !msm5xxx_poc_traffic_shape(s, r[3], init_shape, G_N_ELEMENTS(init_shape)) ||
        !msm5xxx_poc_thumb_literal(s, r[1] + 6, 0, r[5] + 8) ||
        !msm5xxx_poc_thumb_literal(s, r[1] + 0x12, 6, 0x03000a40) ||
        !msm5xxx_poc_thumb_literal(s, r[2] + 2, 2, r[5] + 8) ||
        !msm5xxx_poc_thumb_literal(s, r[2] + 0xe, 3, 0x03000a40) ||
        !msm5xxx_poc_thumb_literal(s, r[2] + 0x16, 0, 0x03000a60) ||
        !msm5xxx_poc_thumb_literal(s, r[3] + 0xe, 3, 0xffdf) ||
        !msm5xxx_poc_thumb_literal(s, r[3] + 0x12, 5, 0x03000a00) ||
        !msm5xxx_poc_thumb_literal(s, r[3] + 0x2e, 3, 0xfff8) ||
        !msm5xxx_poc_thumb_literal(s, r[3] + 0x40, 5, 0x03000a60) ||
        !msm5xxx_poc_thumb_literal(s, r[0] + 4, 0, 0x03000a60) ||
        !msm5xxx_poc_thumb_literal(s, r[0] + 0x18, 0, r[4]) ||
        !msm5xxx_poc_decoder_bl(s, r[0] + 0x1e, &target) || target != r[2] ||
        !msm5xxx_poc_decoder_bl(s, r[0] + 0x18c, &target) || target != r[1] ||
        !msm5xxx_poc_decoder_bl(s, s->decoder_init_reader + 14, &helper) ||
        !msm5xxx_poc_traffic_shape(s, helper, copy_shape, G_N_ELEMENTS(copy_shape))) {
        return false;
    }
    for (i = 0; i < 4; i++) {
        if (!msm5xxx_poc_thumb_literal(s, r[1] + 0x2a + i * 0x20, 0, 0x03000a70) ||
            !msm5xxx_poc_decoder_bl(s, r[1] + 0x2c + i * 0x20, &target) || target != helper) {
            return false;
        }
    }
    s->decoder_traffic_reject_reason = 0;
    return true;
}

static unsigned msm5xxx_poc_decoder_paging_words(MSM5xxxPOCMachineState *s)
{
    uint8_t bytes[2];
    cpu_physical_memory_read(s->decoder_paging_count, bytes, 2);
    return lduw_le_p(bytes);
}

static bool msm5xxx_poc_tx_traffic_callback(MSM5xxxPOCMachineState *state, uint32_t registered);

static void msm5xxx_poc_traffic_service_clear(MSM5xxxPOCMachineState *s)
{
    if (!s->traffic_service_enabled) {
        return;
    }
    s->traffic_service_request_valid = false;
    s->traffic_service_tx_seen = false;
    s->decoder_traffic_frame_enabled = false;
    s->decoder_traffic_response_seen = false;
    memset(s->decoder_traffic_frame, 0, sizeof(s->decoder_traffic_frame));
    memset(&s->decoder_traffic_response, 0, sizeof(s->decoder_traffic_response));
    memset(s->tx_traffic_bytes, 0, sizeof(s->tx_traffic_bytes));
    s->tx_traffic_open = false;
    s->tx_traffic_length = 0;
    s->traffic_service_option = 0xffff;
}

static bool msm5xxx_poc_traffic_service_addresses(MSM5xxxPOCMachineState *s)
{
    uint32_t *r = s->traffic_service_route;
    return r[0] <= s->primary_nor_size && s->primary_nor_size - r[0] >= 1648 &&
           r[1] <= s->primary_nor_size && s->primary_nor_size - r[1] >= 12 &&
           r[2] <= s->primary_nor_size && s->primary_nor_size - r[2] >= 92 &&
           r[3] >= s->ram_base && (uint64_t)(r[3] - s->ram_base) < MACHINE(s)->ram_size;
}

static bool msm5xxx_poc_traffic_service_layout(MSM5xxxPOCMachineState *s)
{
    static const uint8_t packer_prefix[] = {0xf7,0xb5,0x83,0xb0,0xd5,0x1d,0x29,0x35,0xe8,0x7b,0x14,0x1c,0x0f,0x1c,0x20,0x28,0x01,0xdd,0x01,0x20,0x7b,0xe0,0x68,0x46,0x39,0x1c,0x22,0x1c};
    static const uint8_t dispatch_prefix[] = {0x80,0xb5,0x17,0x78,0x0b,0x2f,0x27,0xd2,0x01,0xa3,0xdb,0x5d,0x5b,0x00,0x9f,0x44,0x23,0x05,0x08,0x0b,0x0e,0x11,0x14,0x17,0x1a,0x1d,0x20};
    uint32_t *r = s->traffic_service_route, revision, header_revision, target;
    uint8_t code[sizeof(packer_prefix)];
    if (!msm5xxx_poc_traffic_service_addresses(s) ||
        !msm5xxx_poc_class_literal(s, r[0] + 0x92, 6, &revision) || revision != r[3] ||
        !msm5xxx_poc_class_literal(s, r[1] + 4, 6, &header_revision) || header_revision != revision ||
        !msm5xxx_poc_decoder_bl(s, r[0] + 0x1c, &target) || target != r[1] ||
        !msm5xxx_poc_decoder_bl(s, r[2] + 0x2e, &target) || target != r[0]) {
        return false;
    }
    cpu_physical_memory_read(r[0], code, sizeof(code));
    if (memcmp(code, packer_prefix, sizeof(code))) {
        return false;
    }
    cpu_physical_memory_read(r[2], code, sizeof(dispatch_prefix));
    return !memcmp(code, dispatch_prefix, sizeof(dispatch_prefix));
}

static void msm5xxx_poc_traffic_service_request(MSM5xxxPOCMachineState *s)
{
    MSM5xxxServiceRequest request;
    MSM5xxxTrafficResponse response;
    uint8_t frame[24], revision;
    uint32_t traffic_callback;
    if (!s->traffic_service_enabled) {
        return;
    }
    /* This consumer is entered only from the access-channel FIFO callback. */
    if (s->traffic_service_request_valid && s->traffic_service_tx_seen) {
        msm5xxx_poc_traffic_service_clear(s);
    }
    /* Generic loader ROM contents become available after board initialization. */
    if (!msm5xxx_poc_traffic_service_layout(s)) {
        s->traffic_service_reject_reason = 5;
        s->traffic_service_rejections++;
        return;
    }
    if (!msm5xxx_poc_class_literal(s, s->tx_init_route[0] + 0x5a, 1, &traffic_callback) ||
        !msm5xxx_poc_tx_traffic_callback(s, traffic_callback)) {
        s->traffic_service_reject_reason = 6;
        s->traffic_service_rejections++;
        return;
    }
    cpu_physical_memory_read(s->traffic_service_route[3], &revision, 1);
    s->traffic_service_revision = revision;
    if (!msm5xxx_access_last_service_request(&s->tx_access, revision, &request)) {
        s->traffic_service_reject_reason = 1;
    } else if (request.service_option != 3) {
        /* An unsupported replacement must not inherit the previous response. */
        msm5xxx_poc_traffic_service_clear(s);
        s->traffic_service_reject_reason = 2;
    } else if (s->traffic_service_request_valid) {
        if (s->tx_access.last.sequence == s->traffic_service_request_sequence &&
            request.service_option == s->traffic_service_option) {
            s->traffic_service_duplicates++;
            return;
        }
        s->traffic_service_reject_reason = 3;
    } else if (!msm5xxx_traffic_service_response(request.service_option, 0,
                    s->traffic_service_next_sequence, frame) ||
               !msm5xxx_traffic_response_init(&response, frame, sizeof(frame))) {
        s->traffic_service_reject_reason = 4;
    } else {
        memcpy(s->decoder_traffic_frame, frame, sizeof(frame));
        s->decoder_traffic_frame_enabled = true;
        s->decoder_traffic_response = response;
        s->traffic_service_request_valid = true;
        s->traffic_service_tx_seen = false;
        s->decoder_traffic_response_seen = false;
        s->traffic_service_request_sequence = s->tx_access.last.sequence;
        s->traffic_service_next_sequence = (s->traffic_service_next_sequence + 1) & 7;
        s->traffic_service_option = request.service_option;
        s->traffic_service_reject_reason = 0;
        s->traffic_service_requests++;
        return;
    }
    s->traffic_service_rejections++;
}

static void msm5xxx_poc_access_response_reset(MSM5xxxPOCMachineState *s)
{
    msm5xxx_paging_stream_init(&s->access_paging);
    s->access_response_blocked = false;
    if (s->access_response_probe) {
        s->access_ack_resets++;
    }
}

static bool msm5xxx_poc_access_response_layout(MSM5xxxPOCMachineState *s)
{
    static const uint8_t lengths[MSM5XXX_PAGING_MESSAGES] = {33, 19, 9, 9};
    unsigned i;

    if (!s->decoder_sync_enabled || !s->decoder_paging_enabled ||
        s->decoder_sync_message_length != 26 || s->decoder_sync_message[1] != 1 ||
        s->decoder_sync_message[2] >= 6 ||
        memcmp(s->decoder_paging_lengths, lengths, sizeof(lengths))) {
        return false;
    }
    for (i = 0; i < MSM5XXX_PAGING_MESSAGES; i++) {
        if (s->decoder_paging_messages[i][1] != i + 1) {
            return false;
        }
    }
    return true;
}

static void msm5xxx_poc_access_response_queue(MSM5xxxPOCMachineState *s)
{
    uint8_t reply[MSM5XXX_ACCESS_ASSIGNMENT_BYTES];
    unsigned length = s->access_assignment_code ? MSM5XXX_ACCESS_ASSIGNMENT_BYTES :
                                                 MSM5XXX_ACCESS_ACK_BYTES;
    uint32_t reason = 0;

    if (!s->access_response_probe) {
        return;
    }
    if (s->access_response_blocked) {
        reason = 3;
    } else if (!(s->access_assignment_code ?
                 msm5xxx_access_assignment(&s->tx_access.last,
                    s->access_station_sequence, s->access_assignment_code, reply) :
                 msm5xxx_access_ack(&s->tx_access.last,
                    s->access_station_sequence, reply))) {
        reason = 1;
    } else if (!msm5xxx_paging_stream_queue_message(&s->access_paging, reply, length)) {
        reason = 2;
    } else {
        s->access_ack_queued++;
        s->access_station_sequence = (s->access_station_sequence + 1) & 7;
    }
    if (reason) {
        s->access_ack_rejections++;
        s->access_ack_reject_reason = reason;
    }
}

static void msm5xxx_poc_tx_fifo_cancel(MSM5xxxPOCMachineState *s)
{
    if (s->tx_fifo_enabled && (s->tx_fifo_open || s->tx_access.window_length)) {
        msm5xxx_access_gap(&s->tx_access);
    }
    memset(s->tx_fifo_bytes, 0, sizeof(s->tx_fifo_bytes));
    s->tx_fifo_length = 0;
    s->tx_fifo_open = s->tx_fifo_rejected = false;
    memset(s->tx_traffic_bytes, 0, sizeof(s->tx_traffic_bytes));
    s->tx_traffic_length = 0;
    s->tx_traffic_open = false;
}

static bool msm5xxx_poc_tx_context_ready(MSM5xxxPOCMachineState *s);

static void msm5xxx_poc_tx_fifo_begin(MSM5xxxPOCMachineState *s)
{
    if (!s->tx_fifo_enabled) {
        return;
    }
    if (msm5xxx_poc_guest_u32(s->tx_init_route[1]) != (s->tx_init_route[0] | 1)) {
        /* Traffic words are not access-channel pieces. */
        msm5xxx_poc_tx_fifo_cancel(s);
        if (s->decoder_traffic_response_enabled &&
            (s->decoder_traffic_response.pending ||
             (s->traffic_service_enabled && !s->traffic_service_tx_seen)) &&
            msm5xxx_poc_tx_traffic_callback(s, msm5xxx_poc_guest_u32(s->tx_init_route[1])) &&
            msm5xxx_poc_tx_context_ready(s)) {
            s->tx_traffic_open = s->decoder_traffic_response.pending;
            if (s->traffic_service_enabled) {
                s->traffic_service_tx_seen = true;
            }
        }
        return;
    }
    if (s->tx_fifo_open && !s->tx_fifo_rejected) {
        if (s->tx_fifo_length == sizeof(s->tx_fifo_bytes)) {
            /* The driver writes 12 bytes; only the first 88 bits form a piece. */
            if (msm5xxx_access_push(&s->tx_access, s->tx_fifo_bytes,
                                   MSM5XXX_ACCESS_PIECE_BYTES)) {
                msm5xxx_poc_traffic_service_request(s);
                msm5xxx_poc_access_response_queue(s);
            }
        } else {
            msm5xxx_access_gap(&s->tx_access);
        }
    }
    memset(s->tx_fifo_bytes, 0, sizeof(s->tx_fifo_bytes));
    s->tx_fifo_length = 0;
    s->tx_fifo_open = true;
    s->tx_fifo_rejected = false;
}

/* shortcut: explicit one-shot timing; replace after encoder clock/readback calibration. */
static void msm5xxx_poc_tx_init_cancel(MSM5xxxPOCMachineState *s)
{
    if (s->tx_init_timer) {
        timer_del(s->tx_init_timer);
    }
    if (s->tx_init_active) {
        s->tx_init_cancels++;
    }
    s->tx_init_active = s->tx_init_seen = s->tx_frame_running = false;
    s->tx_init_last_mode = UINT8_MAX;
    msm5xxx_poc_tx_fifo_cancel(s);
    if (s->tx_init_owned_pending) {
        s->rex_irq_pending[0] &= ~8U;
        s->tx_init_owned_pending = false;
        msm5xxx_poc_rex_irq_update(s);
    }
}

/* Known encoder handoff; auxiliary firmware code still executes in the guest. */
static bool msm5xxx_poc_tx_traffic_callback(MSM5xxxPOCMachineState *s,
                                           uint32_t registered)
{
    static const uint8_t shape[] = {0xf0,0xb5,0x86,0xb0,0x00,0x24,0x04,0xa8,0x00,0x00,0x00,0x00,0x00,0x4d,0x28,0x1c,0x00,0x00,0x00,0x00,0x07,0x1c,0x68,0x46,0x01,0x22,0x00,0x21,0x00,0x00,0x00,0x00,0x00,0x4e,0x24,0xe0,0x6a,0x46,0x39,0x1d,0x02,0xa8,0x00,0x00,0x00,0x00,0x04,0xa8,0x02,0xa9,0x00,0x00,0x00,0x00,0x00,0x28,0x1b,0xdb,0x28,0x1c,0x00,0x00,0x00,0x00,0x07,0x1c,0x20,0x30,0x00,0x78,0x16,0x28,0x03,0xd1,0xf8,0x1d,0x09,0x30,0x00,0x00,0x00,0x00,0x38,0x1c,0x39,0x1c,0x00,0x00,0x00,0x00,0x30,0x1c,0x39,0x1c,0x00,0x00,0x00,0x00,0x28,0x1c,0x00,0x00,0x00,0x00,0x07,0x1c,0x00,0x2c,0x01,0xd1,0x00,0x2f,0xd8,0xd1,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x4f,0x01,0x88,0x01,0x31,0x01,0x80,0x00,0x49,0x08,0x78,0x00,0x28,0x1a,0xdd,0x01,0x38,0x08,0x70,0x38,0x1c,0x00,0x00,0x00,0x00,0x10,0x22,0x38,0x1c,0x39,0x1c,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x4c,0x00,0x21,0x02,0x78,0x20,0x1c,0x00,0x00,0x00,0x00,0x38,0x1c,0x39,0x1c,0x22,0x1c,0x00,0x00,0x00,0x00,0x04,0x22,0x38,0x1c,0x39,0x1c,0x00,0x00,0x00,0x00,0x01,0x21,0x38,0x1c,0x00,0x00,0x00,0x00,0x00,0x48,0x04,0x21,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x78,0x03,0x28,0x10,0xdb,0x00,0x48,0x01,0x78,0x00,0x29,0x0c,0xd0,0x41,0x88,0x00,0x29,0x09,0xd1,0x01,0x70,0x01,0x20,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0xb0,0xf0,0xbd};
    static const unsigned calls[] = {0x8,0x10,0x1c,0x2a,0x32,0x3c,0x4e,0x56,0x5e,0x64,0x72,0x8e,0x98,0xa6,0xb0,0xba,0xc2,0xca,0xe8,0xee,0xf4};
    static const unsigned literals[] = {0xc,0x20,0x76,0x78,0x80,0x9c,0x9e,0xc6,0xce,0xd6,0xf2};
    static const unsigned registers[] = {5,6,0,7,1,0,4,0,0,0,0};
    uint32_t *r = s->tx_init_route, entry, registrar, target, setter, countdown;
    uint32_t values[G_N_ELEMENTS(literals)];
    uint8_t code[sizeof(shape)];
    unsigned i;

    if (!s->tx_frame_period_ns || !(registered & 1) ||
        !msm5xxx_poc_class_literal(s, r[0] + 0x5a, 1, &entry) ||
        entry != registered ||
        !msm5xxx_poc_decoder_bl(s, r[0] + 0x5e, &registrar) ||
        !msm5xxx_poc_decoder_bl(s, r[6], &target) || target != registrar) {
        return false;
    }
    cpu_physical_memory_read(r[0] + 0x5c, code, 2);
    if (lduw_le_p(code) != 0x2004 ||
        !msm5xxx_poc_class_literal(s, r[0] + 0x54, 1, &countdown)) {
        return false;
    }
    entry &= ~1u;
    if (entry > s->primary_nor_size ||
        sizeof(code) > s->primary_nor_size - entry) {
        return false;
    }
    cpu_physical_memory_read(entry, code, sizeof(code));
    for (i = 0; i < G_N_ELEMENTS(calls); i++) {
        if (!msm5xxx_poc_decoder_bl(s, entry + calls[i], &target)) {
            return false;
        }
        memset(code + calls[i], 0, 4);
    }
    for (i = 0; i < G_N_ELEMENTS(literals); i++) {
        if (!msm5xxx_poc_class_literal(s, entry + literals[i], registers[i], &values[i])) {
            return false;
        }
        code[literals[i]] = 0;
        if (i + 1 < G_N_ELEMENTS(literals) &&
            (values[i] < s->ram_base || MACHINE(s)->ram_size < 32 ||
             (uint64_t)(values[i] - s->ram_base) > MACHINE(s)->ram_size - 32)) {
            return false;
        }
    }
    return memcmp(code, shape, sizeof(code)) == 0 &&
        values[0] == r[2] + 0x154 && values[1] == values[0] + 12 &&
        values[2] == r[2] + 12 && values[3] == r[2] + 16 &&
        values[4] == countdown && values[5] == countdown + 63 &&
        values[6] == countdown + 0x1a0 && values[7] == r[3] &&
        values[8] == r[2] + 0x148 && values[9] == r[2] + 0xfe8 &&
        values[10] == 0xffff &&
        msm5xxx_poc_decoder_bl(s, r[4], &setter) &&
        msm5xxx_poc_decoder_bl(s, entry + 0xca, &target) && target == setter;
}

static bool msm5xxx_poc_tx_context_ready(MSM5xxxPOCMachineState *s)
{
    uint32_t *r = s->tx_init_route, target, registrar, signal_setter, roll_mask, traffic_mask;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint8_t code[8];

    if (!s->tx_init_enabled || !s->decoder_sync_enabled ||
        !s->decoder_init_active ||
        (!s->decoder_paging_started &&
         !msm5xxx_poc_decoder_traffic_gate(s, &traffic_mask)) ||
        (msm5xxx_poc_backing_read(msm, 0xe8, 2) & 0x20) ||
        (s->tx_frame_period_ns &&
         (msm5xxx_poc_backing_read(msm, 0x2a8, 2) & 0x80)) ||
        !msm5xxx_poc_decoder_sync_gate(s, &roll_mask) || s->search2_route[2] < 56 ||
        r[1] != s->search2_route[2] - 56 ||
        msm5xxx_poc_guest_u32(r[1] - 20) != s->rex_irq_status_address ||
        msm5xxx_poc_guest_u32(r[1] - 16) != s->rex_irq_enable_address ||
        msm5xxx_poc_guest_u32(r[1] - 12) != 8) {
        return false;
    }
    cpu_physical_memory_read(r[0], code, 2);
    if (lduw_le_p(code) != 0xb5f0 ||
        !msm5xxx_poc_thumb_literal(s, r[0] + 2, 4, r[2] + 12) ||
        !msm5xxx_poc_thumb_literal(s, r[0] + 0x14, 6, r[2]) ||
        !msm5xxx_poc_decoder_bl(s, r[0] + 0x20, &target) || target != r[5] ||
        !msm5xxx_poc_decoder_bl(s, r[6], &target) ||
        !msm5xxx_poc_decoder_bl(s, s->search2_route[3] + 0x22, &registrar) ||
        target != registrar ||
        !msm5xxx_poc_thumb_literal(s, r[6] - 4, 1, r[0] | 1) ||
        !msm5xxx_poc_thumb_literal(s, r[4] - 2, 0, r[3])) {
        return false;
    }
    cpu_physical_memory_read(r[6] - 2, code, 2);
    if (lduw_le_p(code) != 0x2004) {
        return false;
    }
    cpu_physical_memory_read(r[4] - 8, code, 6);
    if (memcmp(code, "\x00\x25\x35\x70\x10\x21", 6) ||
        !msm5xxx_poc_decoder_bl(s, r[4], &target) ||
        !msm5xxx_poc_decoder_bl(s, s->combiner_roll_isr + 0x3c6, &signal_setter) ||
        target != signal_setter) {
        return false;
    }
    if (s->tx_frame_period_ns) {
        static const uint8_t writer_shape[] = {
            0xb0,0xb5,0x00,0x23,0x57,0x08,0x7c,0x00,0x06,0xe0,
            0xcf,0x5c,0x5d,0x1c,0x6b,0x1c,0x4d,0x5d,0x2d,0x02,
            0x2f,0x43,0x07,0x80,0x9c,0x42,0xf6,0xdc,0x52,0x08,
            0x01,0xd3,0xc9,0x5c,0x01,0x80,0xb0,0xbd,
        };
        uint32_t delta = r[4] - r[0] == 0x74 ? 2 : 0;
        uint32_t data, writer;
        uint8_t shape[sizeof(writer_shape)];

        if ((r[4] - r[0] != 0x74 && r[4] - r[0] != 0x76) ||
            r[2] < 0x98 ||
            !msm5xxx_poc_thumb_literal(s, r[0] + 0x7c - delta, 7, r[2] - 0x98) ||
            !msm5xxx_poc_decoder_bl(s, r[0] + 0x8c - delta, &target) || target != r[5] ||
            !msm5xxx_poc_decoder_bl(s, r[0] + 0xa2 - delta, &data) ||
            !msm5xxx_poc_thumb_literal(s, data + 0x108, 0, 0x03000298) ||
            !msm5xxx_poc_decoder_bl(s, data + 0x10a, &writer) ||
            writer > s->primary_nor_size ||
            s->primary_nor_size - writer < sizeof(writer_shape)) {
            return false;
        }
        cpu_physical_memory_read(r[0] + 0x98 - delta, shape, 10);
        if (memcmp(shape, "\x01\x22\x00\x21\x78\x73\xf8\x1d\x1e\x30", 10)) {
            return false;
        }
        cpu_physical_memory_read(writer, shape, sizeof(shape));
        if (memcmp(shape, writer_shape, sizeof(shape))) {
            return false;
        }
        if (s->tx_fifo_enabled) {
            cpu_physical_memory_read(data + 6, code, 2);
            if (writer != s->tx_fifo_writer || lduw_le_p(code) != 0x7b30 ||
                !msm5xxx_poc_thumb_literal(s, data + 2, 6, s->tx_fifo_mode_base)) {
                return false;
            }
        }
    }
    if (msm5xxx_poc_guest_u32(r[1]) != (r[0] | 1) &&
        !msm5xxx_poc_tx_traffic_callback(s, msm5xxx_poc_guest_u32(r[1]))) {
        return false;
    }
    return true;
}

static bool msm5xxx_poc_tx_init_ready(MSM5xxxPOCMachineState *s)
{
    return msm5xxx_poc_tx_context_ready(s) &&
        (msm5xxx_poc_backing_read(s->rex_irq_backing, 8, 2) & 8);
}

/* Unknown mode retains the original init-only behavior. */
static uint8_t msm5xxx_poc_tx_init_mode(MSM5xxxPOCMachineState *s)
{
    uint32_t callback = s->tx_init_route[0], armed = s->tx_init_route[2];
    uint64_t ram_size = MACHINE(s)->ram_size;
    uint8_t code[10], tuple[2];

    if (!s->tx_frame_period_ns || callback > UINT32_MAX - 0x2e ||
        callback > s->primary_nor_size ||
        s->primary_nor_size - callback < 0x2e || ram_size < 2 ||
        armed < s->ram_base || armed - s->ram_base > ram_size - 2) {
        return UINT8_MAX;
    }
    cpu_physical_memory_read(callback + 0x24, code, sizeof(code));
    if (memcmp(code, "\x70\x78\x00\x28\x0a\xd0\x01\x28\x1a\xd1", sizeof(code))) {
        return UINT8_MAX;
    }
    cpu_physical_memory_read(armed, tuple, sizeof(tuple));
    return tuple[1] <= 1 ? tuple[1] : UINT8_MAX;
}

static uint64_t msm5xxx_poc_tx_fifo_read(void *opaque, hwaddr offset,
                                        unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);

    return msm5xxx_poc_backing_read(msm, 0x298 + offset, size);
}

static void msm5xxx_poc_tx_fifo_write(void *opaque, hwaddr offset,
                                     uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint32_t pc = 0, reason = 0;
    uint8_t mode;

    msm5xxx_poc_backing_write(msm, 0x298 + offset, value, size);
    if (s->tx_traffic_open) {
        cpu_physical_memory_read(s->tx_fifo_mode_base + 12, &mode, 1);
        if (offset || size != 2 || mode != 1 || !s->tx_frame_running ||
            !msm5xxx_poc_tx_context_ready(s) ||
            !msm5xxx_poc_mmio_access_pc(s, &pc) || pc != s->tx_fifo_writer + 0x16 ||
            s->tx_traffic_length > sizeof(s->tx_traffic_bytes) - 2) {
            s->decoder_traffic_ack_rejections++;
            s->tx_traffic_open = false;
            s->tx_traffic_length = 0;
            memset(s->tx_traffic_bytes, 0, sizeof(s->tx_traffic_bytes));
            return;
        }
        s->tx_traffic_bytes[s->tx_traffic_length++] = value;
        s->tx_traffic_bytes[s->tx_traffic_length++] = value >> 8;
        if (s->tx_traffic_length == sizeof(s->tx_traffic_bytes)) {
            if (msm5xxx_traffic_response_ack(&s->decoder_traffic_response,
                    s->tx_traffic_bytes, sizeof(s->tx_traffic_bytes))) {
                s->decoder_traffic_acks++;
            } else {
                s->decoder_traffic_ack_rejections++;
            }
            s->tx_traffic_open = false;
            s->tx_traffic_length = 0;
            memset(s->tx_traffic_bytes, 0, sizeof(s->tx_traffic_bytes));
        }
        return;
    }
    if (!s->tx_fifo_enabled || !s->tx_frame_running || !s->tx_fifo_open ||
        s->tx_fifo_rejected) {
        return;
    }
    cpu_physical_memory_read(s->tx_fifo_mode_base + 12, &mode, 1);
    /* The original ISR masks its IRQ while the callback writes the FIFO. */
    if (offset || size != 2) {
        reason = 1;
    } else if (mode != 1) {
        reason = 2;
    } else if (!msm5xxx_poc_tx_context_ready(s)) {
        reason = 3;
    } else if (!msm5xxx_poc_mmio_access_pc(s, &pc)) {
        reason = 4;
    } else if (pc != s->tx_fifo_writer + 0x16) {
        reason = 5;
    } else if (s->tx_fifo_length > sizeof(s->tx_fifo_bytes) - 2) {
        reason = 6;
    }
    if (reason) {
        s->tx_fifo_rejections++;
        s->tx_fifo_reject_reason = reason;
        s->tx_fifo_reject_pc = pc;
        msm5xxx_access_gap(&s->tx_access);
        memset(s->tx_fifo_bytes, 0, sizeof(s->tx_fifo_bytes));
        s->tx_fifo_length = 0;
        s->tx_fifo_rejected = true;
        return;
    }
    s->tx_fifo_bytes[s->tx_fifo_length++] = value;
    s->tx_fifo_bytes[s->tx_fifo_length++] = value >> 8;
}

static const MemoryRegionOps msm5xxx_poc_tx_fifo_ops = {
    .read = msm5xxx_poc_tx_fifo_read,
    .write = msm5xxx_poc_tx_fifo_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

static bool msm5xxx_poc_tx_frame_schedule(MSM5xxxPOCMachineState *s,
                                         int64_t base, int64_t now)
{
    uint64_t steps;

    if (base < 0 || now < base || !s->tx_frame_period_ns) {
        return false;
    }
    steps = (uint64_t)(now - base) / s->tx_frame_period_ns + 1;
    if (steps > (uint64_t)(INT64_MAX - base) / s->tx_frame_period_ns) {
        return false;
    }
    s->tx_frame_overruns += steps - 1;
    s->tx_init_deadline = base + (int64_t)(steps * s->tx_frame_period_ns);
    s->tx_init_active = true;
    timer_mod(s->tx_init_timer, s->tx_init_deadline);
    return true;
}

static void msm5xxx_poc_tx_init_fire(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t armed;

    if (!s->tx_init_active || qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) < s->tx_init_deadline) {
        return;
    }
    if (!msm5xxx_poc_tx_init_ready(s)) {
        msm5xxx_poc_tx_init_cancel(s);
        return;
    }
    cpu_physical_memory_read(s->tx_init_route[2], &armed, 1);
    if (s->tx_frame_running) {
        if (armed != 0) {
            msm5xxx_poc_tx_init_cancel(s);
            return;
        }
        if (s->rex_irq_pending[0] & 8) {
            s->tx_frame_overruns++;
            msm5xxx_poc_tx_fifo_cancel(s);
        } else {
            if ((uint64_t)(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->tx_init_deadline) >=
                s->tx_frame_period_ns) {
                msm5xxx_poc_tx_fifo_cancel(s);
            }
            msm5xxx_poc_tx_fifo_begin(s);
            s->tx_init_owned_pending = true;
            s->tx_frame_fires++;
            s->rex_irq_pending[0] |= 8;
            msm5xxx_poc_rex_irq_update(s);
        }
        if (!msm5xxx_poc_tx_frame_schedule(s, s->tx_init_deadline,
                                          qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL))) {
            msm5xxx_poc_tx_init_cancel(s);
        }
        return;
    }
    if (s->tx_init_last_mode != UINT8_MAX &&
        s->tx_init_last_mode != msm5xxx_poc_tx_init_mode(s)) {
        msm5xxx_poc_tx_init_cancel(s);
        return;
    }
    if (armed != 1 || (s->rex_irq_pending[0] & 8)) {
        msm5xxx_poc_tx_init_cancel(s);
        return;
    }
    s->tx_init_active = false;
    s->tx_init_owned_pending = true;
    s->tx_init_fires++;
    s->rex_irq_pending[0] |= 8;
    msm5xxx_poc_rex_irq_update(s);
}

static void msm5xxx_poc_tx_init_poll(MSM5xxxPOCMachineState *s)
{
    uint8_t armed;
    uint32_t traffic_mask;
    int64_t now;

    if (!s->tx_init_enabled) {
        return;
    }
    if (s->tx_init_owned_pending && !(s->rex_irq_pending[0] & 8)) {
        s->tx_init_owned_pending = false;
    }
    if (!msm5xxx_poc_tx_init_ready(s)) {
        msm5xxx_poc_tx_init_cancel(s);
        return;
    }
    cpu_physical_memory_read(s->tx_init_route[2], &armed, 1);
    if (s->tx_frame_period_ns && armed == 0 && s->tx_init_fires) {
        s->tx_init_seen = false;
        if (!s->tx_frame_running) {
            /* shortcut: explicit synthetic cadence; calibrate device phase before default activation. */
            s->tx_frame_running = true;
            now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
            if (!msm5xxx_poc_tx_frame_schedule(s, now, now)) {
                msm5xxx_poc_tx_init_cancel(s);
            }
        }
        return;
    }
    if (s->tx_frame_running) {
        msm5xxx_poc_tx_init_cancel(s);
    }
    if (armed != 1) {
        msm5xxx_poc_tx_init_cancel(s);
        return;
    }
    if (s->tx_init_seen && !s->tx_init_active && !s->tx_frame_running &&
        s->tx_init_last_mode == 1 && msm5xxx_poc_tx_init_mode(s) == 0 &&
        !s->tx_init_owned_pending && !(s->rex_irq_pending[0] & 8) &&
        msm5xxx_poc_decoder_traffic_gate(s, &traffic_mask)) {
        s->tx_init_seen = false;
    }
    if (s->tx_init_seen || (s->rex_irq_pending[0] & 8)) {
        return;
    }
    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (now < 0 || s->tx_init_delay_ns > (uint64_t)(INT64_MAX - now)) {
        return;
    }
    s->tx_init_seen = s->tx_init_active = true;
    s->tx_init_last_mode = msm5xxx_poc_tx_init_mode(s);
    s->tx_init_deadline = now + (int64_t)s->tx_init_delay_ns;
    timer_mod(s->tx_init_timer, s->tx_init_deadline);
}

static bool msm5xxx_poc_paging_frame(MSM5xxxPOCMachineState *s, unsigned rate)
{
    if (s->access_response_probe && !s->access_response_blocked) {
        uint64_t encoded = s->access_paging.replies_encoded;

        if (msm5xxx_paging_stream_frame(&s->access_paging,
                s->decoder_paging_messages, s->decoder_paging_lengths,
                rate, s->decoder_sync_words)) {
            s->access_ack_encoded += s->access_paging.replies_encoded - encoded;
            return true;
        }
        /* An unclassified rate change retains the original paging source. */
        s->access_response_blocked = true;
        s->access_ack_rejections++;
        s->access_ack_reject_reason = 3;
    }
    return msm5xxx_paging_decoder_frame(s->decoder_paging_messages,
        s->decoder_paging_lengths, rate, s->decoder_paging_frames,
        s->decoder_sync_words);
}

static void msm5xxx_poc_decoder_sync_tick(MSM5xxxPOCMachineState *s)
{
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint32_t roll_mask, decoder_mask, sync_mask;
    uint64_t deadline;

    if (!s->decoder_init_active) {
        msm5xxx_poc_traffic_service_clear(s);
        if (s->access_paging.initialized || s->access_paging.reply_pending ||
            s->access_paging.reply_active || s->access_response_blocked) {
            msm5xxx_poc_access_response_reset(s);
        }
        msm5xxx_poc_tx_init_cancel(s);
        return;
    }
    if ((msm5xxx_poc_backing_read(msm, 0xe8, 2) & 0x20) ||
        !msm5xxx_poc_decoder_sync_gate(s, &roll_mask)) {
        s->decoder_init_active = s->decoder_sync_have_frame = false;
        s->decoder_init_rejections++;
        s->decoder_init_reject_reason = 4;
        msm5xxx_poc_traffic_service_clear(s);
        msm5xxx_poc_access_response_reset(s);
        msm5xxx_poc_tx_init_cancel(s);
        return;
    }
    msm5xxx_poc_tx_init_poll(s);
    s->decoder_radio_tick++;
    if (!s->decoder_paging_enabled || !(s->decoder_radio_tick % 4)) {
        s->decoder_sync_roll++;
        s->rex_irq_pending[0] |= roll_mask;
    }
    bool sync_boundary = s->decoder_paging_enabled ?
                         !(s->decoder_radio_tick % 12) : !(s->decoder_sync_roll % 3);
    bool paging_callback = msm5xxx_poc_decoder_paging_gate(s, &decoder_mask);
    bool traffic_callback = msm5xxx_poc_decoder_traffic_gate(s, &decoder_mask);
    bool sync_callback = msm5xxx_poc_decoder_init_gate(s, &sync_mask) &&
                         sync_mask == s->decoder_init_mask;
    if (!paging_callback && !sync_callback && !traffic_callback) {
        s->rex_irq_pending[0] &= ~s->decoder_init_mask;
        s->decoder_sync_have_frame = false;
        s->decoder_paging_started = false;
        s->decoder_traffic_count = 0;
        if (s->access_paging.initialized || s->access_paging.reply_pending ||
            s->access_paging.reply_active || s->access_response_blocked) {
            msm5xxx_poc_access_response_reset(s);
        }
    }
    unsigned paging_words = paging_callback ? msm5xxx_poc_decoder_paging_words(s) : 0;
    if (!traffic_callback) {
        if (paging_callback && (s->decoder_traffic_response_seen || s->traffic_service_tx_seen)) {
            msm5xxx_poc_traffic_service_clear(s);
        }
        s->decoder_traffic_response_seen = false;
    }
    if (traffic_callback) {
        if (s->decoder_traffic_response_enabled && !s->decoder_traffic_response_seen) {
            if (s->decoder_traffic_frame_enabled && !s->traffic_service_enabled) {
                msm5xxx_traffic_response_init(&s->decoder_traffic_response,
                    s->decoder_traffic_frame, sizeof(s->decoder_traffic_frame));
            }
            s->decoder_traffic_response_seen = true;
        }
        if (s->decoder_paging_started) {
            s->decoder_paging_started = false;
            msm5xxx_poc_access_response_reset(s);
        }
        if (!(s->decoder_radio_tick % 3)) {
            uint8_t descriptor[8];
            bool decoded = false;
            cpu_physical_memory_read(s->decoder_traffic_route[5] + 8, descriptor, 8);
            if (s->decoder_traffic_response_enabled &&
                !s->decoder_traffic_response.pending) {
                decoded = msm5xxx_traffic_no_message_frame(descriptor,
                    s->decoder_traffic_words, &s->decoder_traffic_count);
                if (!decoded) {
                    s->decoder_traffic_frame_rejections++;
                } else {
                    s->decoder_traffic_crc_passes++;
                }
            } else if (s->decoder_traffic_frame_enabled) {
                decoded = msm5xxx_traffic_decoded_frame(
                    descriptor, s->decoder_traffic_frame,
                    sizeof(s->decoder_traffic_frame), s->decoder_traffic_words,
                    &s->decoder_traffic_count);
                if (!decoded) {
                    s->decoder_traffic_frame_rejections++;
                } else if (s->decoder_traffic_words[12] & 0x0100) {
                    s->decoder_traffic_crc_passes++;
                    if (s->decoder_traffic_response_enabled) {
                        s->decoder_traffic_response.delivered = true;
                        s->decoder_traffic_response_frames++;
                    }
                } else {
                    s->decoder_traffic_crc_failures++;
                }
            }
            if (!decoded && !msm5xxx_traffic_erasure_frame(
                    descriptor, s->decoder_traffic_words,
                    &s->decoder_traffic_count)) {
                s->decoder_traffic_count = 0;
                s->decoder_sync_have_frame = false;
                s->rex_irq_pending[0] &= ~decoder_mask;
                s->decoder_traffic_reject_reason = 4;
            } else {
                if (s->rex_irq_pending[0] & decoder_mask) {
                    s->decoder_sync_overruns++;
                }
                s->decoder_traffic_frames++;
                s->decoder_sync_have_frame = true;
                s->decoder_init_fires++;
                s->rex_irq_pending[0] |= decoder_mask;
            }
        }
    } else if (paging_callback && !s->decoder_paging_started && sync_boundary &&
        msm5xxx_poc_backing_read(msm, 0xa08, 2) == 0x40) {
        /* The first ISR must program its own rate/count; there is no valid frame yet. */
        s->decoder_sync_have_frame = false;
        s->decoder_paging_bootstraps++;
        s->decoder_init_fires++;
        s->rex_irq_pending[0] |= decoder_mask;
    } else if (paging_callback && s->decoder_paging_started &&
               !(s->decoder_radio_tick % 3) &&
               msm5xxx_poc_backing_read(msm, 0xa08, 2) == 0x20 &&
               msm5xxx_poc_backing_read(msm, 0xa38, 2) == 0 &&
               msm5xxx_poc_backing_read(msm, 0xa40, 2) == 96 &&
               msm5xxx_poc_backing_read(msm, 0xa44, 2) == 0 &&
               (paging_words == 12 || paging_words == 6)) {
        if (!msm5xxx_poc_paging_frame(s, paging_words == 6)) {
            s->decoder_init_active = s->decoder_sync_have_frame = false;
            s->decoder_init_rejections++;
            s->decoder_init_reject_reason = 8;
            msm5xxx_poc_tx_init_cancel(s);
            return;
        }
        if (s->rex_irq_pending[0] & decoder_mask) {
            s->decoder_sync_overruns++;
        }
        s->decoder_paging_frames++;
        s->decoder_sync_have_frame = true;
        s->decoder_init_fires++;
        s->rex_irq_pending[0] |= decoder_mask;
    } else if (sync_boundary &&
        msm5xxx_poc_backing_read(msm, 0xa08, 2) == 0x40 &&
        sync_callback) {
        if (s->decoder_init_done) {
            if (s->rex_irq_pending[0] & s->decoder_init_mask) {
                s->decoder_sync_overruns++;
            }
            if (!msm5xxx_sync_decoder_frame(s->decoder_sync_message,
                                    s->decoder_sync_message_length,
                                    s->decoder_sync_frames, s->decoder_sync_words)) {
                s->decoder_init_active = s->decoder_sync_have_frame = false;
                s->decoder_init_rejections++;
                s->decoder_init_reject_reason = 5;
                msm5xxx_poc_rex_irq_update(s);
                msm5xxx_poc_tx_init_cancel(s);
                return;
            }
            s->decoder_sync_frames++;
            s->decoder_sync_have_frame = true;
        }
        s->decoder_init_done = true;
        s->decoder_init_fires++;
        s->rex_irq_pending[0] |= s->decoder_init_mask;
    }
    msm5xxx_poc_rex_irq_update(s);
    deadline = s->decoder_paging_enabled ? msm5xxx_radio_deadline(s->decoder_radio_tick + 1) :
               msm5xxx_combiner_deadline(s->decoder_sync_roll + 1);
    if (deadline > INT64_MAX - s->decoder_sync_epoch) {
        s->decoder_init_active = false;
        s->decoder_init_rejections++;
        s->decoder_init_reject_reason = 7;
        msm5xxx_poc_tx_init_cancel(s);
        return;
    }
    timer_mod(s->decoder_init_timer, s->decoder_sync_epoch + deadline);
}

static uint64_t msm5xxx_poc_combiner_position_read(void *opaque, hwaddr offset,
                                                 unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint32_t mask;

    if (size == 1 && (offset == 4 || offset == 8) &&
        s->combiner_position_latched && msm5xxx_poc_decoder_sync_gate(s, &mask)) {
        return (s->combiner_position_snapshot >> (offset == 8 ? 8 : 0)) & 255;
    }
    return msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm),
                                   0xf4 + offset, size);
}

static void msm5xxx_poc_combiner_position_write(void *opaque, hwaddr offset,
                                               uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint32_t mask;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s->msm),
                              0xf4 + offset, value, size);
    if (!offset) {
        s->combiner_position_latched = false;
        if (size == 1 && value == 0 && s->decoder_init_active &&
            now >= s->decoder_sync_epoch && msm5xxx_poc_decoder_sync_gate(s, &mask)) {
            /* shortcut: shared ideal epoch, calibrate when TT/SLAM timing is measured. */
            s->combiner_position_snapshot = msm5xxx_combiner_position(now - s->decoder_sync_epoch);
            s->combiner_position_latched = true;
            s->combiner_position_latches++;
        }
    }
}

static unsigned msm5xxx_poc_decoder_output_words(MSM5xxxPOCMachineState *s)
{
    uint32_t mask;
    uint16_t mode = msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm), 0xa08, 2);

    if (mode == 0x40 && msm5xxx_poc_decoder_init_gate(s, &mask) && mask == s->decoder_init_mask) {
        return 8;
    }
    if (mode == 0x20 && s->decoder_paging_started && msm5xxx_poc_decoder_paging_gate(s, &mask)) {
        unsigned words = msm5xxx_poc_decoder_paging_words(s);
        return words == 6 || words == 12 ? words + 2 : 0;
    }
    if (mode == 0x20 && msm5xxx_poc_decoder_traffic_gate(s, &mask)) {
        return s->decoder_traffic_count;
    }
    return 0;
}

static uint64_t msm5xxx_poc_decoder_output_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint32_t mask;
    unsigned words = msm5xxx_poc_decoder_output_words(s);

    if (s->decoder_sync_have_frame && size == 2 &&
        msm5xxx_poc_decoder_sync_gate(s, &mask) &&
        words) {
        if (!offset) {
            return s->decoder_sync_cursor;
        }
        if (offset == 0x18 && s->decoder_sync_cursor < words) {
            if (msm5xxx_poc_decoder_traffic_gate(s, &mask)) {
                s->decoder_traffic_reads++;
                return s->decoder_traffic_words[s->decoder_sync_cursor++];
            }
            s->decoder_sync_reads++;
            return s->decoder_sync_words[s->decoder_sync_cursor++];
        }
    }
    return msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm),
                                   0xa58 + offset, size);
}

static void msm5xxx_poc_decoder_output_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint32_t mask;
    unsigned words = msm5xxx_poc_decoder_output_words(s);

    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s->msm),
                              0xa58 + offset, value, size);
    if (!offset) {
        s->decoder_sync_cursor = words;
        if (size == 2 && value < words && msm5xxx_poc_decoder_sync_gate(s, &mask)) {
            s->decoder_sync_cursor = value;
        }
    }
}

static const MemoryRegionOps msm5xxx_poc_combiner_position_ops = {
    .read = msm5xxx_poc_combiner_position_read,
    .write = msm5xxx_poc_combiner_position_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
    .impl.min_access_size = 1, .impl.max_access_size = 4,
};

static const MemoryRegionOps msm5xxx_poc_decoder_output_ops = {
    .read = msm5xxx_poc_decoder_output_read,
    .write = msm5xxx_poc_decoder_output_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
    .impl.min_access_size = 1, .impl.max_access_size = 4,
};

static void msm5xxx_poc_decoder_init_complete(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint32_t mask;

    if (s->decoder_sync_enabled) {
        msm5xxx_poc_decoder_sync_tick(s);
        return;
    }
    if (!s->decoder_init_active) {
        return;
    }
    s->decoder_init_active = false;
    if (msm5xxx_poc_backing_read(msm, 0xa08, 2) != 0x40 ||
        !msm5xxx_poc_decoder_init_gate(s, &mask) || mask != s->decoder_init_mask) {
        s->decoder_init_rejections++;
        s->decoder_init_reject_reason = 3;
        return;
    }
    s->decoder_init_done = true;
    s->decoder_init_fires++;
    s->rex_irq_pending[0] |= mask;
    msm5xxx_poc_rex_irq_update(s);
}

static uint64_t msm5xxx_poc_decoder_init_read(void *opaque, hwaddr offset,
                                            unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    return msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm),
                                   0xa08 + offset, size);
}

static void msm5xxx_poc_decoder_init_write(void *opaque, hwaddr offset,
                                          uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint32_t pc, mask;
    bool clock_was_active = s->decoder_sync_enabled && s->decoder_init_active;

    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s->msm),
                              0xa08 + offset, value, size);
    if (clock_was_active && !offset && size == 2 && value == 0x20 &&
        msm5xxx_poc_mmio_access_pc(s, &pc) && pc == s->decoder_paging_initializer + 0x36 &&
        msm5xxx_poc_decoder_paging_gate(s, &mask)) {
        /* Receiver reconfiguration must preserve the transmitted frame carry. */
        if (!s->decoder_paging_started) {
            s->decoder_paging_frames = 0;
            msm5xxx_poc_access_response_reset(s);
        }
        s->decoder_paging_started = true;
        s->decoder_sync_have_frame = false;
        s->decoder_sync_cursor = 14;
        s->rex_irq_pending[0] &= ~mask;
        msm5xxx_poc_rex_irq_update(s);
        return;
    }
    if (s->decoder_sync_enabled && s->decoder_init_active &&
        (offset || size != 2 || value != 0x40 ||
         !msm5xxx_poc_mmio_access_pc(s, &pc) || pc != s->decoder_init_write_pc)) {
        if (msm5xxx_poc_backing_read(memory_region_get_ram_ptr(&s->msm), 0xa08, 2) != 0x40) {
            s->decoder_sync_have_frame = false;
        }
        return;
    }
    if (s->decoder_init_active) {
        timer_del(s->decoder_init_timer);
        s->decoder_init_active = false;
        if (!clock_was_active) {
            s->decoder_init_rejections++;
            s->decoder_init_reject_reason = 2;
        }
    }
    if ((s->decoder_init_done && !s->decoder_sync_enabled) || offset || size != 2 || value != 0x40 ||
        !msm5xxx_poc_mmio_access_pc(s, &pc) || pc != s->decoder_init_write_pc) {
        return;
    }
    if (!msm5xxx_poc_decoder_init_gate(s, &mask)) {
        s->decoder_init_rejections++;
        s->decoder_init_reject_reason = 1;
        return;
    }
    s->decoder_init_mask = mask;
    s->decoder_init_active = true;
    if (s->decoder_sync_enabled) {
        s->decoder_init_done = s->decoder_sync_have_frame = false;
        if (!clock_was_active) {
            s->combiner_position_latched = false;
            s->decoder_sync_epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
            s->decoder_sync_roll = 0;
            s->decoder_radio_tick = 0;
        }
        s->decoder_sync_frames = 0;
        s->decoder_paging_started = false;
        s->decoder_paging_frames = 0;
        msm5xxx_poc_access_response_reset(s);
        s->decoder_sync_cursor = 8;
        s->rex_irq_pending[0] &= ~s->decoder_init_mask;
        msm5xxx_poc_rex_irq_update(s);
        timer_mod(s->decoder_init_timer,
                  s->decoder_sync_epoch + (s->decoder_paging_enabled ?
                  msm5xxx_radio_deadline(s->decoder_radio_tick + 1) :
                  msm5xxx_combiner_deadline(s->decoder_sync_roll + 1)));
    } else {
        /* Explicit one-shot diagnostic, separate from the repeated stream. */
        timer_mod(s->decoder_init_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->decoder_init_delay_ns);
    }
}

static const MemoryRegionOps msm5xxx_poc_decoder_init_ops = {
    .read = msm5xxx_poc_decoder_init_read,
    .write = msm5xxx_poc_decoder_init_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1, .valid.max_access_size = 4,
    .impl.min_access_size = 1, .impl.max_access_size = 4,
};

static bool msm5xxx_poc_sbi_raw_input_valid(MSM5xxxPOCMachineState *s)
{
    return s->sbi_enabled && !s->sbi_bootstrap_only &&
           s->board_adc_value <= UINT8_MAX && s->primary_nor_size >= 2 &&
           s->sbi_raw_input_pc <= s->primary_nor_size - 2;
}

static void msm5xxx_poc_sbi_raw_input_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;

    s->sbi_raw_input_last_pc = 0;
    s->sbi_raw_input_reject_reason = NULL;
    if (!s->sbi_raw_input_enabled) {
        return;
    }
    memset(s->sbi_backing, 0, sizeof(s->sbi_backing));
    s->sbi_status = MSM5XXX_POC_SBI_OBSERVING;
    s->sbi_bootstrap_phase = s->sbi_validation_phase = 0;
    s->sbi_control = 0;
    s->sbi_started = s->sbi_read_pending = s->sbi_read_full = false;
    s->sbi_board_adc_phase = 0;
    s->sbi_board_adc_selector = 0;
    s->sbi_board_adc_responses = s->sbi_reads = s->sbi_writes = 0;
}

static bool msm5xxx_poc_sbi_raw_input_guest(MSM5xxxPOCMachineState *s)
{
    CPUState *cpu = CPU(s->cpu);

    return qemu_in_vcpu_thread() && current_cpu == cpu && cpu->running &&
           cpu->neg.can_do_io;
}

static bool msm5xxx_poc_sbi_raw_input_selected(MSM5xxxPOCMachineState *s)
{
    return s->sbi_control == 0x086a &&
           (s->sbi_board_adc_selector & s->sbi_raw_input_mask) ==
               s->sbi_raw_input_value && s->board_adc_value <= UINT8_MAX;
}

static bool msm5xxx_poc_sbi_raw_input_read_allowed(
    MSM5xxxPOCMachineState *s, hwaddr offset, unsigned size)
{
    CPUState *cpu;

    if (s->sbi_status != MSM5XXX_POC_SBI_ACCEPTED) {
        return true;
    }
    if (offset == 0 && size == 2) {
        return true;
    }
    if (offset != 0x0c || size != 2) {
        s->sbi_raw_input_reject_reason = "unsupported-read-register-or-width";
        return false;
    }
    cpu = CPU(s->cpu);
    s->sbi_raw_input_last_pc = CPU_GET_CLASS(cpu)->get_pc(cpu) & ~1U;
    if (!msm5xxx_poc_sbi_raw_input_guest(s) ||
        s->sbi_raw_input_last_pc != s->sbi_raw_input_pc) {
        s->sbi_raw_input_reject_reason = "unowned-data-read";
        return false;
    }
    if (s->sbi_board_adc_phase != 9 || !s->sbi_read_full ||
        !msm5xxx_poc_sbi_raw_input_selected(s)) {
        s->sbi_raw_input_reject_reason = "unvalidated-data-read";
        return false;
    }
    return true;
}

static bool msm5xxx_poc_sbi_raw_input_write_allowed(
    MSM5xxxPOCMachineState *s, hwaddr offset, uint64_t value, unsigned size)
{
    if (s->sbi_status != MSM5XXX_POC_SBI_ACCEPTED) {
        return true;
    }
    if ((offset == 0 && size == 1 &&
         (value == 0x45 || value == 0xc5 || value == 0x4a || value == 0xca)) ||
        (offset == 4 && size == 2 &&
         (value == 0x0800 || value == 0x085f || value == 0x086a)) ||
        (offset == 0x10 && size == 1 && value <= 1)) {
        return true;
    }
    if (offset == 0x0c && size == 2 && value <= UINT16_MAX) {
        if (!(value & 0x8000)) {
            return true; /* Transmit words do not fabricate a slave response. */
        }
        if (value == 0x8b00 &&
            (s->sbi_board_adc_phase == 7 || s->sbi_board_adc_phase == 11) &&
            msm5xxx_poc_sbi_raw_input_selected(s)) {
            return true;
        }
        s->sbi_raw_input_reject_reason = "unvalidated-read-request";
        return false;
    }
    s->sbi_raw_input_reject_reason = "unsupported-write-register-width-or-mode";
    return false;
}

static uint16_t msm5xxx_poc_sbi_status_value(MSM5xxxPOCMachineState *s)
{
    return ((s->sbi_control & 0x00c0) << 8) |
           ((s->sbi_control & 0x003f) << 8) |
           ((s->sbi_control & 0x0600) >> 3) |
           ((s->sbi_control & 0x0800) >> 6) |
           (s->sbi_read_full ? 0x02 : 0);
}

static bool msm5xxx_poc_sbi_raw_input_peek(MSM5xxxPOCMachineState *s,
                                          hwaddr offset, unsigned size,
                                          uint64_t *value)
{
    if (msm5xxx_poc_sbi_raw_input_guest(s)) {
        return false;
    }
    *value = msm5xxx_poc_backing_read(s->sbi_backing, offset, size);
    if (offset == 0 && size == 2 &&
        (s->sbi_status == MSM5XXX_POC_SBI_CANDIDATE ||
         s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED)) {
        *value = msm5xxx_poc_sbi_status_value(s);
    }
    return true;
}

static void msm5xxx_poc_sbi_reject(MSM5xxxPOCMachineState *s)
{
    if (s->sbi_raw_input_enabled && !s->sbi_raw_input_reject_reason) {
        s->sbi_raw_input_reject_reason = "controller-validation-rejected";
    }
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
    if (s->sbi_raw_input_enabled &&
        msm5xxx_poc_sbi_raw_input_peek(s, offset, size, &backing)) {
        return backing;
    }
    s->sbi_reads++;
    backing = msm5xxx_poc_backing_read(s->sbi_backing, offset, size);
    if (s->sbi_raw_input_enabled &&
        !msm5xxx_poc_sbi_raw_input_read_allowed(s, offset, size)) {
        msm5xxx_poc_sbi_reject(s);
        return backing;
    }

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
        s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED && !became_accepted &&
        (offset != 0 || size != 2)) {
        msm5xxx_poc_sbi_reject(s);
        return backing;
    }

    if (offset == 0 && size == 2 &&
        (s->sbi_status == MSM5XXX_POC_SBI_CANDIDATE ||
         s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED)) {
        if (s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED) {
            if (s->sbi_board_adc_phase == 4 ||
                s->sbi_board_adc_phase == 6 ||
                s->sbi_board_adc_phase == 8 ||
                s->sbi_board_adc_phase == 10) {
                s->sbi_board_adc_phase++;
            } else if (s->sbi_board_adc_phase != 5 &&
                       s->sbi_board_adc_phase != 7 &&
                       s->sbi_board_adc_phase != 9 &&
                       s->sbi_board_adc_phase != 11) {
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
    if (s->sbi_raw_input_enabled &&
        !msm5xxx_poc_sbi_raw_input_write_allowed(s, offset, value, size)) {
        msm5xxx_poc_backing_write(s->sbi_backing, offset, value, size);
        msm5xxx_poc_sbi_reject(s);
        return;
    }
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
        } else if (s->sbi_board_adc_phase == 7 && value == 0x0c80) {
            /* Optional setup write must complete its own status poll. */
            s->sbi_board_adc_phase = 10;
        } else if (s->sbi_board_adc_phase == 11 && value == 0x8b00) {
            s->sbi_board_adc_phase = 8;
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

/* An explicit experimental protocol class, independently relocated in firmware.
 * It shares the LCD aperture: no overlay, and foreign accesses retain backing.
 * Check the currently mapped NOR, after loader/state import, on each owned I/O. */
static bool msm5xxx_poc_audio_packet_nor(MSM5xxxPOCMachineState *s,
                                        hwaddr address, uint8_t *data,
                                        unsigned size)
{
    MemoryRegionSection section;
    bool valid;

    if (size > s->primary_nor_size || address > s->primary_nor_size - size) {
        return false;
    }
    section = memory_region_find(get_system_memory(), address, size);
    valid = section.mr == &s->nor &&
            int128_ge(section.size, int128_make64(size));
    if (section.mr) {
        memory_region_unref(section.mr);
    }
    return valid && address_space_read(&address_space_memory, address,
        MEMTXATTRS_UNSPECIFIED, data, size) == MEMTX_OK;
}

static bool msm5xxx_poc_audio_packet_gate(MSM5xxxPOCMachineState *s,
                                         hwaddr address, unsigned size,
                                         bool write)
{
    static const uint8_t shape[72] = {
        0x41,0x21,0xc9,0x04,0x00,0xb5,0x08,0x70,0,0,0,0,0x08,0xbc,0x18,0x47,
        0x41,0x20,0xc0,0x04,0x80,0xb5,0x07,0x78,0,0,0,0,0x38,0x1c,0x80,0xbc,
        0x08,0xbc,0x18,0x47,0x41,0x21,0xc9,0x04,0x00,0xb5,0x88,0x70,0,0,0,0,
        0x08,0xbc,0x18,0x47,0x41,0x20,0xc0,0x04,0x80,0xb5,0x87,0x78,0,0,0,0,
        0x38,0x1c,0x80,0xbc,0x08,0xbc,0x18,0x47,
    };
    static const unsigned calls[4] = {8, 24, 44, 60};
    CPUState *cpu = current_cpu;
    uint8_t code[sizeof(shape)], delay[2];
    uint32_t entry, pc, expected, target = 0;
    unsigned i;

    if (!s->audio_packet_begin ||
        (!s->audio_packet_sequence &&
         (s->audio_packet_begin < 6 || s->primary_nor_size < sizeof(shape) ||
          s->audio_packet_begin - 6 > s->primary_nor_size - sizeof(shape) ||
          (s->audio_packet_begin & 1))) || size != 1 ||
        (address != 0x02080000 && address != 0x02080002) ||
        !qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running ||
        !cpu->neg.can_do_io || !s->cpu->env.thumb) {
        return false;
    }
    expected = s->audio_packet_begin + (address & 2 ? 0x24 : 0) +
               (write ? 0 : 0x10);
    pc = CPU_GET_CLASS(cpu)->get_pc(cpu);
    if ((pc & ~1U) != expected) {
        return false;
    }
    if (s->audio_packet_begin < 6 || s->primary_nor_size < sizeof(shape) ||
        s->audio_packet_begin - 6 > s->primary_nor_size - sizeof(shape) ||
        (s->audio_packet_begin & 1)) {
        goto reject;
    }
    entry = s->audio_packet_begin - 6;
    if (!msm5xxx_poc_audio_packet_nor(s, entry, code, sizeof(code))) {
        goto reject;
    }
    for (i = 0; i < ARRAY_SIZE(calls); i++) {
        unsigned offset = calls[i];
        uint16_t first = lduw_le_p(code + offset);
        uint16_t second = lduw_le_p(code + offset + 2);
        int32_t delta = ((first & 0x7ff) << 12) | ((second & 0x7ff) << 1);
        int64_t destination;

        if ((first & 0xf800) != 0xf000 || (second & 0xf800) != 0xf800) {
            goto reject;
        }
        if (delta & 0x400000) {
            delta -= 0x800000;
        }
        destination = (int64_t)entry + offset + 4 + delta;
        if (destination < 0 || destination > (int64_t)s->primary_nor_size - 2 ||
            (i && destination != target)) {
            goto reject;
        }
        target = destination;
        memset(code + offset, 0, 4);
    }
    if (memcmp(code, shape, sizeof(code)) ||
        !msm5xxx_poc_audio_packet_nor(s, target, delay, sizeof(delay)) ||
        lduw_le_p(delay) != 0x4770) {
        goto reject;
    }
    return true;
reject:
    if (s->audio_packet_sequence) {
        s->audio_packet_fault = true;
        s->audio_packet_ready = s->audio_packet_reset_armed = false;
        s->audio_packet_clear_armed = false;
        s->audio_packet_fifo_empty_known = false;
    }
    if (!s->audio_packet_gate_reported) {
        warn_report("experimental audio packet gate rejected: mapped wrapper "
                    "or delay mismatch; LCD fallback retained");
        s->audio_packet_gate_reported = true;
    }
    return false;
}

static void msm5xxx_poc_audio_packet_reject(MSM5xxxPOCMachineState *s,
                                           uint8_t value)
{
    s->audio_packet_fault = true;
    s->audio_packet_ready = s->audio_packet_reset_armed = false;
    s->audio_packet_clear_armed = false;
    s->audio_packet_fifo_empty_known = false;
    if (!s->audio_packet_reported) {
        warn_report("experimental audio packet rejected: index=%02x value=%02x "
                    "reason=%u address=%x registers=%u memory=%u; "
                    "renderer unavailable",
                    s->audio_packet_index, value, s->audio_packet_sink.reject,
                    s->audio_packet_sink.rejected_address,
                    s->audio_packet_sink.register_writes,
                    s->audio_packet_sink.memory_writes);
        s->audio_packet_reported = true;
    }
}

static bool msm5xxx_poc_audio_packet_read(MSM5xxxPOCMachineState *s,
                                         hwaddr address, unsigned size,
                                         uint64_t *value)
{
    if (!msm5xxx_poc_audio_packet_gate(s, address, size, false)) {
        return false;
    }
    if (address & 2) {
        /* No query/result model: preserve backing and withdraw capacity. */
        msm5xxx_poc_audio_packet_reject(s, 0);
        return false;
    }
    /* Synchronous sink capacity, not FIFO timing or a completed query/result. */
    *value = !s->audio_packet_fault && !s->audio_packet_sink.reject &&
             (!s->audio_packet_sequence || s->audio_packet_ready) &&
             !(s->audio_packet_control & 0x80) ?
             1 | (s->audio_packet_fifo_empty_known ? 2 : 0) : 0;
    return true;
}

static bool msm5xxx_poc_audio_packet_write(MSM5xxxPOCMachineState *s,
                                          hwaddr address, uint64_t value,
                                          unsigned size)
{
    uint8_t byte = value;
    uint8_t rising;
    unsigned writes;

    if (!msm5xxx_poc_audio_packet_gate(s, address, size, true)) {
        return false;
    }
    if (!(address & 2)) {
        if (s->audio_packet_clear_armed && (byte & 0x3f) != 4) {
            msm5xxx_poc_audio_packet_reject(s, byte);
            return true;
        }
        s->audio_packet_index = byte & 0x3f;
        return true; /* Selecting/restoring a command never resets framing. */
    }
    if (s->audio_packet_index == 4) {
        rising = byte & ~s->audio_packet_control;
        if (byte == 0x28 && s->audio_packet_clear_pulse) {
            if (!s->audio_packet_sequence || !s->audio_packet_ready ||
                s->audio_packet_clear_armed || s->audio_packet_reset_armed ||
                s->audio_packet_fault || s->audio_packet_sink.reject ||
                s->audio_packet_control || s->audio_packet_sink.packet.phase ||
                s->audio_packet_sink.sequence_pending_stage) {
                msm5xxx_poc_audio_packet_reject(s, byte);
                return true;
            }
            /* Closed aggregate pulse; no parser, timer or new empty knowledge. */
            s->audio_packet_clear_armed = true;
            s->audio_packet_ready = false;
            s->audio_packet_control = byte;
            return true;
        }
        if (byte & ~0xd3) {
            msm5xxx_poc_audio_packet_reject(s, byte);
            return true;
        }
        if (rising & 0x80) {
            s->audio_packet_clear_armed = false;
            msm5xxx_audio_packet_sink_reset(&s->audio_packet_sink);
            s->audio_packet_fault = false;
            /* Reset establishes empty; unsupported FIFO writes invalidate it. */
            s->audio_packet_fifo_empty_known = true;
            s->audio_packet_reported = false;
            s->audio_packet_mode = 0;
            s->audio_packet_init_valid = 0;
            memset(s->audio_packet_init, 0, sizeof(s->audio_packet_init));
            /* Reset defaults are unknown; invalid mirrors provide no readback. */
            s->audio_packet_control = byte;
            if (s->audio_packet_sequence) {
                s->audio_packet_reset_armed = true;
                s->audio_packet_ready = false;
            }
            return true; /* Full reset skips the new byte's low-bit mode. */
        }
        if (s->audio_packet_clear_armed) {
            if (byte || s->audio_packet_fault || s->audio_packet_sink.reject ||
                s->audio_packet_reset_armed || s->audio_packet_control != 0x28 ||
                s->audio_packet_sink.packet.phase ||
                s->audio_packet_sink.sequence_pending_stage) {
                msm5xxx_poc_audio_packet_reject(s, byte);
                return true;
            }
            s->audio_packet_clear_armed = false;
            s->audio_packet_control = 0;
            s->audio_packet_ready = true;
            return true;
        }
        if (s->audio_packet_sequence && (byte & 0x80)) {
            /* A repeated assertion is not a release edge. */
            s->audio_packet_control = byte;
            s->audio_packet_ready = false;
            return true;
        }
        if (s->audio_packet_sequence && s->audio_packet_reset_armed) {
            if (byte != 0) {
                msm5xxx_poc_audio_packet_reject(s, byte);
                return true;
            }
            s->audio_packet_reset_armed = false;
            s->audio_packet_ready = true;
        }
        if (rising & 0x50) {
            msm5xxx_audio_packet_reset(&s->audio_packet_sink.packet);
            if (s->audio_packet_sequence) {
                s->audio_packet_sink.sequence_pending_stage = 0;
                s->audio_packet_sink.sequence_pending_parameter = 0;
            }
        }
        s->audio_packet_mode = byte & 3;
        /* Repeated high control bits clear in the retained control mirror. */
        s->audio_packet_control = byte & ~(byte & s->audio_packet_control & 0xfc);
        return true;
    }
    if (s->audio_packet_fault || (s->audio_packet_control & 0x80)) {
        msm5xxx_poc_audio_packet_reject(s, byte);
        return true;
    }
    if (s->audio_packet_index == 5 || s->audio_packet_index == 6) {
        unsigned slot = s->audio_packet_index - 5;

        /* Raw banked initialization latches; no voice/query/render effect. */
        s->audio_packet_init[s->audio_packet_mode][slot] = byte;
        s->audio_packet_init_valid |= 1u << (2 * s->audio_packet_mode + slot);
        return true;
    }
    if (s->audio_packet_index != 2) {
        msm5xxx_poc_audio_packet_reject(s, byte);
        return true;
    }
    if (s->audio_packet_sequence && !s->audio_packet_ready) {
        msm5xxx_poc_audio_packet_reject(s, byte);
        return true;
    }
    writes = s->audio_packet_sink.register_writes;
    if (!(s->audio_packet_sequence ?
          msm5xxx_audio_packet_sink_feed_sequence(&s->audio_packet_sink, byte) :
          msm5xxx_audio_packet_sink_feed(&s->audio_packet_sink, byte))) {
        msm5xxx_poc_audio_packet_reject(s, byte);
    } else if (writes != s->audio_packet_sink.register_writes &&
               s->audio_packet_trace_count < 16) {
        /* Bounded diagnostic evidence of actual sink mutation, not PCM. */
        warn_report("experimental audio packet consumed: registers=%u "
                    "memory=%u; renderer unavailable",
                    s->audio_packet_sink.register_writes,
                    s->audio_packet_sink.memory_writes);
        s->audio_packet_trace_count++;
    }
    return true;
}

static uint64_t msm5xxx_poc_lcd_aperture_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    hwaddr address = MSM5XXX_POC_LCD_APERTURE_BASE + offset;
    uint64_t value;

    if (offset + size > MSM5XXX_POC_LCD_APERTURE_SIZE) {
        return 0;
    }
    if (msm5xxx_poc_audio_packet_read(s, address, size, &value)) {
        return value;
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
    if (msm5xxx_poc_audio_packet_write(s, address, value, size)) {
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

/* Return a unique fully containing LCD port for the explicit MA5 experiment. */
static int msm5xxx_poc_ma5_shared_lcd_port(const MSM5xxxPOCMachineState *s)
{
    uint64_t first = s->audio_base;
    uint64_t end = first + (uint64_t)s->audio_data_offset + 1;
    int selected = -1;
    unsigned index;

    if (!s->audio_enabled || !s->audio_ma5 || !s->ma5_byte_ns ||
        end <= first) {
        return -1;
    }
    for (index = 0; index < MSM5XXX_POC_LCD_PORTS; index++) {
        uint64_t base = msm5xxx_poc_lcd_bases[index];

        if (first < base + MSM5XXX_POC_LCD_SIZE && end > base) {
            if (first < base || end > base + MSM5XXX_POC_LCD_SIZE ||
                selected != -1) {
                return -1;
            }
            selected = index;
        }
    }
    return selected;
}

/* 0: unchanged LCD fallback; 1: declared MA5 PC; -1: unattributable port I/O. */
static int msm5xxx_poc_ma5_shared_lcd_route(MSM5xxxPOCLCDPort *port,
                                           hwaddr offset, unsigned size)
{
    MSM5xxxPOCMachineState *s = port->machine;
    CPUState *cpu = current_cpu;
    uint64_t address = msm5xxx_poc_lcd_bases[port->index] + offset;
    uint64_t end = address + size;
    uint32_t pc = 0;
    unsigned index;

    if (!s->audio_shared_lcd ||
        !qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running) {
        return 0;
    }
    if (!msm5xxx_poc_mmio_access_pc(s, &pc)) {
        return end > address && address < (uint64_t)s->audio_base +
               s->audio_data_offset + 1 && end > s->audio_base ? -1 : 0;
    }
    pc &= ~1U;
    for (index = 0; index < s->audio_site_count; index++) {
        if (s->audio_site_pc[index] == pc) {
            return 1;
        }
    }
    return 0;
}

static MemTxResult msm5xxx_poc_ma5_shared_lcd_read(
    void *opaque, hwaddr offset, uint64_t *value, unsigned size,
    MemTxAttrs attrs)
{
    MSM5xxxPOCLCDPort *port = opaque;
    MSM5xxxPOCMachineState *s = port->machine;
    int route = msm5xxx_poc_ma5_shared_lcd_route(port, offset, size);

    if (route < 0) {
        return MEMTX_ERROR;
    }
    if (route > 0) {
        return msm5xxx_poc_audio_opaque_read(s,
            msm5xxx_poc_lcd_bases[port->index] + offset - s->audio_base,
            value, size, attrs);
    }
    *value = msm5xxx_poc_lcd_read(opaque, offset, size);
    return MEMTX_OK;
}

static MemTxResult msm5xxx_poc_ma5_shared_lcd_write(
    void *opaque, hwaddr offset, uint64_t value, unsigned size,
    MemTxAttrs attrs)
{
    MSM5xxxPOCLCDPort *port = opaque;
    MSM5xxxPOCMachineState *s = port->machine;
    int route = msm5xxx_poc_ma5_shared_lcd_route(port, offset, size);

    if (route < 0) {
        return MEMTX_ERROR;
    }
    if (route > 0) {
        return msm5xxx_poc_audio_opaque_write(s,
            msm5xxx_poc_lcd_bases[port->index] + offset - s->audio_base,
            value, size, attrs);
    }
    msm5xxx_poc_lcd_write(opaque, offset, value, size);
    return MEMTX_OK;
}

static const MemoryRegionOps msm5xxx_poc_ma5_shared_lcd_ops = {
    .read_with_attrs = msm5xxx_poc_ma5_shared_lcd_read,
    .write_with_attrs = msm5xxx_poc_ma5_shared_lcd_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .impl.min_access_size = 1,
    .impl.max_access_size = 4,
};

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
    case 0xc4:
        return s->audio_irq_gate_status;
    case 0xc8:
        return s->audio_irq_assertions;
    case 0xcc:
    case 0xd0:
    case 0xd4:
    case 0xd8: {
        unsigned stream = (offset - 0xcc) / 4;
        uint32_t result;
        if (!s->audio_core_lock_initialized) {
            return 0;
        }
        qemu_mutex_lock(&s->audio_core_lock);
        result = s->ma2_audio.fifo_count[stream] |
                 ((uint32_t)s->audio_command_pending_count[stream] << 16);
        qemu_mutex_unlock(&s->audio_core_lock);
        return result;
    }
    case 0xdc:
    case 0xe0:
    case 0xe4:
    case 0xe8: {
        unsigned stream = (offset - 0xdc) / 4;
        uint32_t result;
        MSM5xxxMA2SequenceState *sequence = &s->ma2_audio.sequence[stream];
        if (!s->audio_core_lock_initialized) {
            return 0;
        }
        qemu_mutex_lock(&s->audio_core_lock);
        result = sequence->started | (sequence->running << 1) |
                 (sequence->pending << 2) | (sequence->end_pending << 3) |
                 (sequence->ended << 4) | ((uint32_t)sequence->parser.length << 16);
        qemu_mutex_unlock(&s->audio_core_lock);
        return result;
    }
    case 0xec: {
        uint32_t result;
        if (!s->audio_core_lock_initialized) {
            return 0;
        }
        qemu_mutex_lock(&s->audio_core_lock);
        result = s->ma2_audio.control | ((uint32_t)s->ma2_audio.fm_irq_ctrl << 8) |
                 ((uint32_t)s->ma2_audio.fifo_control << 16) |
                 ((uint32_t)msm5xxx_poc_ma2_fifo_flags(s) << 24);
        qemu_mutex_unlock(&s->audio_core_lock);
        return result;
    }
    case 0xf0:
        return s->search2_submits;
    case 0xf4:
        return s->search2_completions;
    case 0xf8:
        return s->search2_result_reads;
    case 0xfc:
        return s->search2_rejections;
    case 0x100:
        return s->search2.epoch;
    case 0x104:
        return s->search2.status | (s->search2.dump_enable << 8) |
               (s->search2.active << 16) | (s->search2_probe_done << 17) |
               (s->search2_probe_rejected << 18);
    case 0x108:
        return s->search2_reject_reason;
    case 0x10c:
        return s->search2_reject_pc;
    case 0x110:
        return s->search2_reject_value;
    case 0x114:
        return s->search2_reject_expected_pc;
    case 0x118:
        return s->search2.queued_records | (s->search2.result_records << 8) |
               (s->search2.queue_sub << 16);
    case 0x11c:
        return s->search2_position;
    case 0x120:
        return s->search1_submits;
    case 0x124:
        return s->search1_completions;
    case 0x128:
        return s->search1_result_reads;
    case 0x12c:
        return s->search1_rejections;
    case 0x130:
        return s->search1_sub | (s->search1_active << 8) |
               (s->search1_have_results << 9) | (s->search1_rejected << 10);
    case 0x134:
        return s->search1_position;
    case 0x150:
        return s->finger_latches;
    case 0x154:
        return s->finger_reads;
    case 0x158:
        return s->finger_fallback_writes;
    case 0x15c:
        return s->fingers.selected | (s->fingers.filter_gain << 8);
    case 0x160:
        return s->fingers.bank[0].position;
    case 0x164:
        return s->fingers.bank[0].rssi;
    case 0x168:
        return s->fingers.bank[0].seen |
               (s->fingers.bank[0].supported << 16) |
               (s->fingers.bank[0].latched << 17);
    case 0x16c:
        return s->fingers.bank[0].unsupported_offset |
               (s->fingers.bank[0].unsupported_value << 8);
    case 0x174:
        return s->decoder_init_active | (s->decoder_init_done << 1);
    case 0x178:
        return s->decoder_init_fires;
    case 0x17c:
        return s->decoder_init_rejections;
    case 0x180:
        return s->decoder_init_mask;
    case 0x184:
        return s->decoder_init_reject_reason;
    case 0x188:
        return s->decoder_sync_roll;
    case 0x18c:
        return s->decoder_sync_frames;
    case 0x190:
        return s->decoder_sync_reads;
    case 0x194:
        return s->decoder_sync_overruns;
    case 0x198:
        return s->combiner_position_snapshot | (s->combiner_position_latched << 16);
    case 0x19c:
        return s->combiner_position_latches;
    case 0x1a0:
        return s->decoder_paging_bootstraps;
    case 0x1a4:
        return s->decoder_paging_frames;
    case 0x1a8:
        return s->decoder_radio_tick;
    case 0x1ac:
        return s->decoder_paging_started;
    case 0x1b0:
        return s->search1_reject_reason;
    case 0x1b4:
        return s->search1_reject_pc;
    case 0x1b8:
        return s->search1_reject_access;
    case 0x1bc:
        return s->search1_reject_value;
    case 0x1c0:
        return s->search1_aborts;
    case 0x1c4:
        return s->tx_init_active;
    case 0x1c8:
        return s->tx_init_fires;
    case 0x1cc:
        return s->tx_init_cancels;
    case 0x1d0:
        return s->tx_init_seen;
    case 0x1d4:
        return s->tx_frame_fires;
    case 0x1d8:
        return s->tx_frame_overruns;
    case 0x1dc:
        return s->tx_frame_running;
    case 0x1e0:
        return s->tx_access.pieces;
    case 0x1e4:
        return s->tx_access.packets;
    case 0x1e8:
        return s->tx_access.gaps;
    case 0x1ec:
        return s->tx_access.crc_rejections;
    case 0x1f0:
        return s->tx_access.header_rejections;
    case 0x1f4:
        return s->tx_fifo_rejections;
    case 0x1f8:
        return s->tx_access.last.length | ((uint32_t)s->tx_access.last.type << 8) |
               ((uint32_t)s->tx_access.last.format << 16) |
               ((uint32_t)s->tx_access.last.sequence << 24);
    case 0x1fc:
        return s->tx_access.last.address_mode |
               ((uint32_t)s->tx_access.last.address_length << 8) |
               ((uint32_t)s->tx_access.last.address_valid << 16);
    case 0x200:
        return s->tx_fifo_reject_reason;
    case 0x204:
        return s->tx_fifo_reject_pc;
    case 0x208:
        return s->access_ack_queued;
    case 0x20c:
        return s->access_ack_encoded;
    case 0x210:
        return s->access_ack_rejections;
    case 0x214:
        return s->access_ack_reject_reason;
    case 0x218:
        return s->access_response_probe | (s->access_response_blocked << 1) |
               (s->access_paging.reply_pending << 2) |
               (s->access_paging.reply_active << 3) |
               ((uint32_t)s->access_station_sequence << 8);
    case 0x21c:
        return s->access_ack_resets;
    case 0x220:
        return s->decoder_traffic_frames;
    case 0x224:
        return s->decoder_traffic_reads;
    case 0x228:
        return s->decoder_traffic_reject_reason;
    case 0x22c:
        return s->decoder_traffic_count | (s->decoder_traffic_enabled << 16) |
               (s->decoder_traffic_frame_enabled << 17);
    case 0x230:
        return s->decoder_traffic_crc_passes;
    case 0x234:
        return s->decoder_traffic_crc_failures;
    case 0x238:
        return s->decoder_traffic_frame_rejections;
    case 0x23c:
        return s->decoder_traffic_acks;
    case 0x240:
        return s->decoder_traffic_response.pending |
               (s->decoder_traffic_response.delivered << 1) |
               (s->decoder_traffic_response_enabled << 2) |
               (s->traffic_service_tx_seen << 3);
    case 0x244:
        return s->decoder_traffic_ack_rejections;
    case 0x248:
        return s->decoder_traffic_response_frames;
    case 0x24c:
        return s->traffic_service_requests;
    case 0x250:
        return s->traffic_service_rejections;
    case 0x254:
        return s->traffic_service_duplicates;
    case 0x258:
        return s->traffic_service_reject_reason;
    case 0x25c:
        return s->traffic_service_revision;
    case 0x260:
        return s->traffic_service_option;
    case 0x170:
        return s->fingers.bank[0].registers[0] |
               (s->fingers.bank[0].registers[1] << 8) |
               (s->fingers.bank[0].registers[11] << 16);
    case 0x138:
    case 0x13c:
    case 0x140:
    case 0x144:
    case 0x148: {
        unsigned at = offset - 0x138;
        unsigned bytes = MIN(4U, MSM5XXX_SEARCH1_PARAMETERS - at);
        return msm5xxx_poc_backing_read(s->search1_packet, at, bytes);
    }
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
    if (s->ma5_audio_timer) {
        timer_del(s->ma5_audio_timer);
    }
    if (s->audio_voice) {
        AUD_set_active_out(s->audio_voice, false);
    }
    msm5xxx_poc_audio_pcm_cancel_watch(s);
    s->audio_pcm_length = 0u;
    s->audio_pcm_offset = 0u;
    s->audio_pcm_failed = false;
    s->audio_backend_pcm_length = 0u;
    s->audio_backend_pcm_offset = 0u;
    s->ma5_pcm_output_reported = false;
    s->ma5_pcm_resync_pending = false;
    s->ma5_pcm_timeline_gaps = 0;
    if (s->audio_synth_lock_initialized) {
        qemu_mutex_lock(&s->audio_synth_lock);
        msm5xxx_audio_synth_reset(&s->audio_synth);
        if (s->ma5_pcm_initialized &&
            msm5xxx_ma5_pcm_output_reset(&s->ma5_pcm_output) !=
                MSM5XXX_MA5_PCM_OK) {
            s->ma5_pcm_output_failed = true;
        } else if (s->ma5_pcm_initialized) {
            s->ma5_pcm_output_failed = false;
        }
        s->audio_output_started = false;
        s->audio_stream_reset_epoch = s->ma5_pcm_initialized ?
            s->ma5_pcm_output.queue.epoch : s->audio_synth.epoch;
        qemu_mutex_unlock(&s->audio_synth_lock);
    } else {
        s->audio_output_started = false;
    }
    s->audio_index = 0;
    memset(s->audio_backing, 0, sizeof(s->audio_backing));
    memset(&s->audio_readback, 0, sizeof(s->audio_readback));
    if (s->ma5_byte_ns) {
        msm5xxx_ma5_device_init(&s->ma5_device, s->ma5_byte_ns);
        if (s->ma5_clki_hz) {
            msm5xxx_ma5_device_set_clock(&s->ma5_device, s->ma5_clki_hz);
        } else if (s->ma5_target_rate_hz) {
            msm5xxx_ma5_device_set_target_rate(&s->ma5_device,
                                               s->ma5_target_rate_hz);
        }
        if (s->ma5_wt_engine) {
            ma5_wt_engine_reset(s->ma5_wt_engine,
                                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        }
        s->ma5_commit_traces = 0;
        s->ma5_device.commit_sink = msm5xxx_poc_ma5_commit_consume;
        s->ma5_device.commit_opaque = s;
        qemu_log_mask(LOG_GUEST_ERROR, "MA5 commit reset\n");
    }
    memset(s->ma5_gpio_pending, 0, sizeof(s->ma5_gpio_pending));
    s->ma5_parent_pending = 0;
    s->ma5_irq_qualified = s->ma5_irq_level = false;
    s->ma5_irq_gate_status = 0;
    if (s->ma5_irq_configured) {
        msm5xxx_poc_rex_irq_update(s);
    }
    msm5xxx_audio_packet_sink_reset(&s->audio_packet_sink);
    s->audio_packet_index = s->audio_packet_control = 0;
    s->audio_packet_mode = s->audio_packet_init_valid = 0;
    memset(s->audio_packet_init, 0, sizeof(s->audio_packet_init));
    s->audio_packet_fault = s->audio_packet_reported = false;
    s->audio_packet_fifo_empty_known = false;
    s->audio_packet_ready = s->audio_packet_reset_armed = false;
    s->audio_packet_clear_armed = false;
    s->audio_packet_gate_reported = false;
    s->audio_packet_trace_count = 0;
    s->audio_readback_rejection_reported = false;
    s->audio_stream_order = 0;
    s->audio_stream_dropped = 0;
    s->audio_stream_reject_code = 0;
    s->audio_stream_started = false;
    s->audio_stream_rejected = false;
    s->audio_stream_status_pending = s->ma5_pcm_output_failed ?
        MSM5XXX_POC_AUDIO_STATUS_REJECTED : warm_reset ?
        MSM5XXX_POC_AUDIO_STATUS_RESET :
        (s->audio_voice || s->audio_stream_chardev ?
         MSM5XXX_POC_AUDIO_STATUS_NATIVE : 0);
    s->audio_irq_asserted = false;
    s->audio_irq_gate_status = 0;
    s->audio_irq_assertions = 0;
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

#define MSM5XXX_SMALL_NAND_WINDOW UINT32_C(0x200000)

/* Trace only actual requests/completions, never READY poll transactions. */
static void msm5xxx_poc_small_nand_trace(MSM5xxxPOCMachineState *s,
                                         const char *operation, uint64_t now,
                                         hwaddr address, uint64_t value,
                                         unsigned width, bool ok)
{
    const MSM5xxxSmallPageNand *dev = &s->small_nand;
    CPUState *cpu = s->cpu ? CPU(s->cpu) : NULL;
    bool guest = cpu && qemu_in_vcpu_thread() && current_cpu == cpu &&
                 cpu->running && cpu->neg.can_do_io;
    uint32_t pc = guest ? CPU_GET_CLASS(cpu)->get_pc(cpu) & ~1U : 0;
    uint32_t lr = guest ? s->cpu->env.regs[14] : 0;
    unsigned thumb = guest ? s->cpu->env.thumb : 0;

    if (s->small_nand_trace_count >= 16384) {
        if (s->small_nand_trace_count == 16384) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "small-page NAND trace limit reached: cap=16384\n");
            s->small_nand_trace_count++;
        }
        return;
    }
    s->small_nand_trace_count++;
    qemu_log_mask(LOG_GUEST_ERROR,
                  "small-page NAND op=%s n=%" PRIu64 " t=%" PRIu64
                  " address=%" PRIx64 " value=%" PRIx64
                  " width=%u ok=%u reason=%u row=%u cursor=%u"
                  " pending=%u deadline=%" PRIu64 " generation=%" PRIu64
                  " persisted=%" PRIu64 " dirty_offset=%zu dirty_length=%zu"
                  " guest=%u pc=%08x lr=%08x thumb=%u\n",
                  operation, s->small_nand_trace_count, now, (uint64_t)address,
                  value, width, ok ? 1u : 0u, dev->reason, dev->row,
                  (unsigned)dev->cursor, dev->pending, dev->deadline_ns,
                  dev->mutation_generation, s->small_nand_persisted,
                  dev->last_mutation_offset, dev->last_mutation_length,
                  guest ? 1u : 0u, pc, lr, thumb);
}

static void msm5xxx_poc_small_nand_log(MSM5xxxPOCMachineState *s,
                                       const char *operation)
{
    if (s->small_nand_errors++ < 16) {
        warn_report("experimental small-page NAND %s: reason=%u generation=%" PRIu64,
                    operation, s->small_nand.reason,
                    s->small_nand.mutation_generation);
    }
}

static void msm5xxx_poc_small_nand_poison(MSM5xxxPOCMachineState *s,
                                          const char *operation)
{
    msm5xxx_poc_small_nand_log(s, operation);
    msm5xxx_nand_invalidate(&s->small_nand);
    if (s->small_nand_timer) {
        timer_del(s->small_nand_timer);
    }
}

static bool msm5xxx_poc_small_nand_sync(MSM5xxxPOCMachineState *s,
                                       uint64_t now)
{
    MSM5xxxSmallPageNand *dev = &s->small_nand;
    uint64_t generation;
    int ret;

    if (!msm5xxx_nand_advance(dev, now)) {
        msm5xxx_poc_small_nand_log(s, "advance rejected");
        return false;
    }
    generation = dev->mutation_generation;
    if (generation == s->small_nand_persisted) {
        return true;
    }
    if (generation < s->small_nand_persisted ||
        generation - s->small_nand_persisted != 1 ||
        !dev->last_mutation_length ||
        dev->last_mutation_offset > MSM5XXX_NAND_RAW_BYTES ||
        dev->last_mutation_length >
            MSM5XXX_NAND_RAW_BYTES - dev->last_mutation_offset) {
        msm5xxx_poc_small_nand_poison(s, "persistence generation/range mismatch");
        return false;
    }
    ret = blk_pwrite(s->small_nand_blk, dev->last_mutation_offset,
                     dev->last_mutation_length,
                     s->small_nand_raw + dev->last_mutation_offset,
                     BDRV_REQ_FUA);
    if (ret < 0) {
        if (s->small_nand_errors < 16) {
            warn_report("experimental small-page NAND backend FUA write failed: %s",
                        strerror(-ret));
        }
        msm5xxx_poc_small_nand_poison(s, "backend FUA write failed");
        return false;
    }
    s->small_nand_persisted = generation;
    s->small_nand_persists++;
    msm5xxx_poc_small_nand_trace(s, "complete-persist", now,
                                 s->small_nand_data, 0, 0, true);
    return true;
}

static void msm5xxx_poc_small_nand_arm(MSM5xxxPOCMachineState *s)
{
    if (!msm5xxx_nand_trusted(&s->small_nand) ||
        s->small_nand.pending == MSM5XXX_NAND_PENDING_NONE) {
        timer_del(s->small_nand_timer);
        return;
    }
    if (s->small_nand.deadline_ns > INT64_MAX) {
        msm5xxx_poc_small_nand_poison(s, "unrepresentable virtual deadline");
        return;
    }
    timer_mod(s->small_nand_timer, s->small_nand.deadline_ns);
}

static void msm5xxx_poc_small_nand_tick(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    msm5xxx_poc_small_nand_sync(s, now);
    msm5xxx_poc_small_nand_arm(s);
}

static MemTxResult msm5xxx_poc_small_nand_read(
    void *opaque, hwaddr offset, uint64_t *value, unsigned size,
    MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint16_t result = 0;
    bool ok;

    (void)attrs;
    if (!msm5xxx_poc_small_nand_sync(s, now)) {
        msm5xxx_poc_small_nand_trace(s, "data-read", now,
                                     (uint64_t)s->small_nand_data + offset,
                                     0, size, false);
        msm5xxx_poc_small_nand_arm(s);
        return MEMTX_ERROR;
    }
    if (offset != 0) {
        msm5xxx_poc_small_nand_trace(s, "unmapped-read", now,
                                     (uint64_t)s->small_nand_data + offset,
                                     0, size, false);
        msm5xxx_poc_small_nand_log(s, "unmapped read offset");
        msm5xxx_poc_small_nand_arm(s);
        return MEMTX_ERROR;
    }
    ok = msm5xxx_nand_read(&s->small_nand, size, now, &result);
    msm5xxx_poc_small_nand_trace(s, "data-read", now,
                                 s->small_nand_data, result, size, ok);
    if (!ok) {
        msm5xxx_poc_small_nand_log(s, "read rejected");
    }
    /* No second advance: it would clear the just-rejected request's reason. */
    msm5xxx_poc_small_nand_arm(s);
    if (ok) {
        *value = result;
    }
    return ok ? MEMTX_OK : MEMTX_ERROR;
}

static MemTxResult msm5xxx_poc_small_nand_write(
    void *opaque, hwaddr offset, uint64_t value, unsigned size,
    MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    const char *operation = offset == 0 ? "data-write" :
        offset == 0x80000 ? "address" :
        offset == 0x100000 ? "command" : "unmapped-write";
    bool ok;

    (void)attrs;
    if (!msm5xxx_poc_small_nand_sync(s, now)) {
        msm5xxx_poc_small_nand_trace(s, operation, now,
                                     (uint64_t)s->small_nand_data + offset,
                                     value, size, false);
        msm5xxx_poc_small_nand_arm(s);
        return MEMTX_ERROR;
    }
    if (offset == 0) {
        ok = msm5xxx_nand_write(&s->small_nand, value, size, now);
    } else if (offset == 0x80000) {
        ok = msm5xxx_nand_address(&s->small_nand, value, size, now);
    } else if (offset == 0x100000) {
        ok = msm5xxx_nand_command(&s->small_nand, value, size, now);
    } else {
        msm5xxx_poc_small_nand_trace(s, operation, now,
                                     (uint64_t)s->small_nand_data + offset,
                                     value, size, false);
        msm5xxx_poc_small_nand_log(s, "unmapped write offset");
        msm5xxx_poc_small_nand_arm(s);
        return MEMTX_ERROR;
    }
    msm5xxx_poc_small_nand_trace(s, operation, now,
                                 (uint64_t)s->small_nand_data + offset,
                                 value, size, ok);
    if (!ok) {
        msm5xxx_poc_small_nand_log(s, "write rejected");
    }
    msm5xxx_poc_small_nand_arm(s);
    return ok ? MEMTX_OK : MEMTX_ERROR;
}

static const MemoryRegionOps msm5xxx_poc_small_nand_ops = {
    .read_with_attrs = msm5xxx_poc_small_nand_read,
    .write_with_attrs = msm5xxx_poc_small_nand_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
};

static MemTxResult msm5xxx_poc_small_nand_ready_read(
    void *opaque, hwaddr offset, uint64_t *value, unsigned size,
    MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *backing = memory_region_get_ram_ptr(&s->msm);
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint16_t word;

    (void)attrs;
    if (!size || size > 2 || offset > 2 - size) {
        return MEMTX_ERROR;
    }
    msm5xxx_poc_small_nand_sync(s, now);
    msm5xxx_poc_small_nand_arm(s);
    word = msm5xxx_poc_backing_read(backing,
        s->small_nand_ready_address - MSM5XXX_POC_MSM_BASE, 2);
    word = (word & ~s->small_nand_ready_mask) |
           (msm5xxx_nand_ready(&s->small_nand) ? s->small_nand_ready_mask : 0);
    *value = (word >> (offset * 8)) & (size == 1 ? 0xff : 0xffff);
    if (s->small_nand_ready_trace_count < 64) {
        s->small_nand_ready_trace_count++;
        msm5xxx_poc_small_nand_trace(s, "ready-read", now,
            s->small_nand_ready_address + offset, *value, size, true);
    }
    return MEMTX_OK;
}

static MemTxResult msm5xxx_poc_small_nand_ready_write(
    void *opaque, hwaddr offset, uint64_t value, unsigned size,
    MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *backing = memory_region_get_ram_ptr(&s->msm);
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint16_t word, writable;
    hwaddr address = s->small_nand_ready_address - MSM5XXX_POC_MSM_BASE;

    (void)attrs;
    if (!size || size > 2 || offset > 2 - size) {
        return MEMTX_ERROR;
    }
    msm5xxx_poc_small_nand_sync(s, now);
    msm5xxx_poc_small_nand_arm(s);
    word = msm5xxx_poc_backing_read(backing, address, 2);
    writable = ((size == 1 ? 0xffu : 0xffffu) << (offset * 8)) &
               ~s->small_nand_ready_mask;
    word = (word & ~writable) | ((value << (offset * 8)) & writable);
    msm5xxx_poc_backing_write(backing, address, word, 2);
    return MEMTX_OK;
}

static const MemoryRegionOps msm5xxx_poc_small_nand_ready_ops = {
    .read_with_attrs = msm5xxx_poc_small_nand_ready_read,
    .write_with_attrs = msm5xxx_poc_small_nand_ready_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
};

static bool msm5xxx_poc_small_nand_conflict(MSM5xxxPOCMachineState *s)
{
    MemoryRegionSection data = memory_region_find(
        get_system_memory(), s->small_nand_data, MSM5XXX_SMALL_NAND_WINDOW);
    MemoryRegionSection ready = memory_region_find(
        get_system_memory(), s->small_nand_ready_address, 2);
    bool conflict = s->raw_nand_main_enabled || !s->ram_reserved_size ||
        s->small_nand_data < s->ram_reserved_base ||
        (uint64_t)s->small_nand_data + MSM5XXX_SMALL_NAND_WINDOW >
            (uint64_t)s->ram_reserved_base + s->ram_reserved_size ||
        data.mr || ready.mr != &s->msm ||
        !int128_eq(ready.size, int128_make64(2));

    /* Require an actual hole and the whole unclaimed GPIO word, not a hidden alias. */
    memory_region_unref(data.mr);
    memory_region_unref(ready.mr);
    return conflict;
}

static void msm5xxx_poc_small_nand_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    bool ok;

    if (!s->small_nand.initialized) {
        return;
    }
    ok = msm5xxx_poc_small_nand_sync(s, now) &&
         msm5xxx_nand_command(&s->small_nand, 0xff, 1, now);
    msm5xxx_poc_small_nand_trace(s, "reset-hook", now,
                                 s->small_nand_cle, 0xff, 1, ok);
    if (!ok) {
        msm5xxx_poc_small_nand_poison(s, "reset rejected; state not reinitialized");
    }
    msm5xxx_poc_small_nand_arm(s);
}

static void msm5xxx_poc_small_nand_init(MachineState *machine,
                                       MSM5xxxPOCMachineState *s, Error **errp)
{
    const MSM5xxxNandTimings timings = {
        .read_ns = 10000,
        .program_ns = 200000,
        .erase_ns = 2000000,
        .reset_ns = 5000,
        .idle_reset_ns = s->small_nand_idle_reset_ns,
    };
    int ret;

    if (!s->small_nand_enabled) {
        return;
    }
    if (msm5xxx_poc_small_nand_conflict(s)) {
        error_setg(errp, "experimental small-page NAND overlaps an existing route");
        return;
    }
    s->small_nand_blk = blk_by_name("msm5xxx-small-page-nand");
    if (!s->small_nand_blk) {
        error_setg(errp, "experimental small-page NAND requires a named raw backend");
        return;
    }
    blk_ref(s->small_nand_blk);
    ret = blk_set_perm(s->small_nand_blk,
                       BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE, 0, errp);
    if (ret < 0) {
        return;
    }
    if (blk_getlength(s->small_nand_blk) != (int64_t)MSM5XXX_NAND_RAW_BYTES) {
        error_setg(errp, "experimental small-page NAND backend must be 34603008 bytes");
        return;
    }
    s->small_nand_raw = g_malloc(MSM5XXX_NAND_RAW_BYTES);
    ret = blk_pread(s->small_nand_blk, 0, MSM5XXX_NAND_RAW_BYTES,
                    s->small_nand_raw, 0);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "experimental small-page NAND initial read failed");
        return;
    }
    if (!msm5xxx_nand_init(&s->small_nand, s->small_nand_raw,
                          MSM5XXX_NAND_RAW_BYTES, &timings, true,
                          qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL))) {
        error_setg(errp, "experimental small-page NAND core initialization rejected");
        return;
    }
    s->small_nand_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                      msm5xxx_poc_small_nand_tick, s);
    memory_region_init_io(&s->small_nand_io, OBJECT(machine),
                          &msm5xxx_poc_small_nand_ops, s,
                          "msm5xxx-poc.experimental-small-page-nand",
                          MSM5XXX_SMALL_NAND_WINDOW);
    memory_region_add_subregion_overlap(get_system_memory(), s->small_nand_data,
                                        &s->small_nand_io, 2);
    memory_region_init_io(&s->small_nand_ready_io, OBJECT(machine),
                          &msm5xxx_poc_small_nand_ready_ops, s,
                          "msm5xxx-poc.experimental-small-page-nand-ready", 2);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        s->small_nand_ready_address,
                                        &s->small_nand_ready_io, 2);
    /* Initial VM reset owns the first FF; avoid a second FF while reset is busy. */
    qemu_register_reset(msm5xxx_poc_small_nand_reset, s);
    warn_report("experimental small-page NAND: virtual x16 512+16-byte pages, "
                "32 pages/block, 65536 rows; unknown ID is unsupported; "
                "use a disposable full main/OOB backing, not original phone data");
    if (s->small_nand_idle_reset_ns) {
        warn_report("experimental small-page NAND idle-reset override=%u ns: "
                    "inferred virtual timing hypothesis, not silicon calibration; "
                    "read-abort reset remains 5000 ns",
                    s->small_nand_idle_reset_ns);
    }
}

/* Observation only: never advances a clock or completes a transaction. */
static char *msm5xxx_poc_get_small_nand_state(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    MSM5xxxSmallPageNand *dev = &s->small_nand;

    return g_strdup_printf(
        "{\"enabled\":%d,\"initialized\":%d,\"trusted\":%d,\"ready\":%d,"
        "\"safe_to_save\":%d,\"pending\":%u,\"mode\":%u,\"reason\":%u,\"row\":%u,\"cursor\":%u,"
        "\"now_ns\":%" PRIu64 ",\"deadline_ns\":%" PRIu64
        ",\"generation\":%" PRIu64 ",\"persisted\":%" PRIu64 "}",
        s->small_nand_enabled, dev->initialized, msm5xxx_nand_trusted(dev),
        msm5xxx_nand_ready(dev),
        msm5xxx_nand_trusted(dev) &&
            dev->mutation_generation == s->small_nand_persisted &&
            dev->pending != MSM5XXX_NAND_PENDING_PROGRAM &&
            dev->pending != MSM5XXX_NAND_PENDING_ERASE,
        dev->pending, dev->mode, dev->reason,
        dev->row, (unsigned)dev->cursor, dev->now_ns, dev->deadline_ns,
        dev->mutation_generation, s->small_nand_persisted);
}

static char *msm5xxx_poc_get_small_nand(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->small_nand_enabled) {
        return g_strdup("");
    }
    if (s->small_nand_idle_reset_ns) {
        return g_strdup_printf("%x:%x:%x:%x:%x:%x", s->small_nand_data,
                               s->small_nand_ale, s->small_nand_cle,
                               s->small_nand_ready_address, s->small_nand_ready_mask,
                               s->small_nand_idle_reset_ns);
    }
    return g_strdup_printf("%x:%x:%x:%x:%x", s->small_nand_data,
                           s->small_nand_ale, s->small_nand_cle,
                           s->small_nand_ready_address, s->small_nand_ready_mask);
}

static void msm5xxx_poc_set_small_nand(Object *obj, const char *value,
                                       Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t fields[5];
    uint32_t idle_reset_ns = 0;
    const char *cursor = value, *end;
    uint64_t parsed;
    unsigned i;

    if (s->cpu) {
        error_setg(errp, "experimental small-page NAND is immutable after initialization");
        return;
    }
    if (!cursor || !*cursor) {
        s->small_nand_enabled = false;
        return;
    }
    for (i = 0; i < 5; i++) {
        if (!g_ascii_isxdigit(*cursor) ||
            qemu_strtou64(cursor, &end, 16, &parsed) < 0 ||
            parsed > UINT32_MAX ||
            (i < 4 ? *end != ':' : (*end != '\0' && *end != ':'))) {
            error_setg(errp, "experimental-small-page-nand requires five or six hex32 fields");
            return;
        }
        fields[i] = parsed;
        cursor = end + (i != 4);
    }
    if (*cursor == ':') {
        cursor++;
        if (!g_ascii_isxdigit(*cursor) ||
            qemu_strtou64(cursor, &end, 16, &parsed) < 0 || *end ||
            !parsed || parsed > 5000) {
            error_setg(errp, "experimental NAND idle-reset override must be 1..1388 hex ns");
            return;
        }
        idle_reset_ns = parsed;
    }
    if (fields[0] < 0x01000000 || fields[0] > 0x01e00000 ||
        (fields[0] & (MSM5XXX_SMALL_NAND_WINDOW - 1)) ||
        (uint64_t)fields[0] + 0x80000 != fields[1] ||
        (uint64_t)fields[0] + 0x100000 != fields[2] ||
        (fields[3] & 1) || fields[3] < 0x03000700 || fields[3] > 0x0300077e ||
        !fields[4] || fields[4] > UINT16_MAX ||
        (fields[4] & (fields[4] - 1))) {
        error_setg(errp, "experimental small-page NAND has an invalid declared aperture");
        return;
    }
    s->small_nand_data = fields[0];
    s->small_nand_ale = fields[1];
    s->small_nand_cle = fields[2];
    s->small_nand_ready_address = fields[3];
    s->small_nand_ready_mask = fields[4];
    s->small_nand_idle_reset_ns = idle_reset_ns;
    s->small_nand_enabled = true;
}

/* shortcut: source-compatible virtual 16KiB/page32 class; physical part/timing
 * remain uncalibrated until independently measured. */
#define MSM5XXX_SPI_NV_BASE 0x03000660u
#define MSM5XXX_SPI_NV_WINDOW 0x20u
#define MSM5XXX_SPI_NV_CAPACITY 0x4000u

/* These overlays observe only source-bound guest reads, never debugger peeks. */
static bool msm5xxx_poc_boot_storage_guest(MSM5xxxPOCMachineState *s)
{
    CPUState *cpu = current_cpu;

    return cpu && qemu_in_vcpu_thread() && cpu == CPU(s->cpu) &&
           cpu->running && cpu->neg.can_do_io;
}

static bool msm5xxx_poc_boot_storage_hex(const char *value, uint32_t *out,
                                         unsigned count)
{
    const char *cursor = value;
    unsigned i;

    if (!cursor) {
        return false;
    }
    for (i = 0; i < count; i++) {
        const char *end;
        uint64_t parsed;

        if (!g_ascii_isxdigit(*cursor) ||
            qemu_strtou64(cursor, &end, 16, &parsed) || parsed > UINT32_MAX ||
            (i + 1 < count ? *end != ':' : *end != '\0')) {
            return false;
        }
        out[i] = parsed;
        cursor = end + (i + 1 < count);
    }
    return true;
}

static uint64_t msm5xxx_poc_boot_keysense_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    uint64_t value = msm5xxx_poc_backing_read(msm, 0x694 + offset, size);
    uint32_t pc;
    unsigned i;

    if (offset || size != 1 || s->boot_keysense_rejected ||
        s->boot_keysense_phase == 3 || !msm5xxx_poc_boot_storage_guest(s) ||
        !s->cpu->env.thumb) {
        return value;
    }
    pc = CPU_GET_CLASS(current_cpu)->get_pc(current_cpu) & ~1u;
    for (i = 0; i < 3; i++) {
        if (pc == s->boot_keysense_pc[i]) {
            s->boot_keysense_reads++;
            if (i != s->boot_keysense_phase) {
                s->boot_keysense_rejected = true;
                s->boot_keysense_reason = 1;
                s->boot_keysense_rejections++;
                return value;
            }
            s->boot_keysense_phase++;
            s->boot_keysense_releases++;
            return value | 0x0f;
        }
    }
    return value;
}

static void msm5xxx_poc_boot_keysense_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    msm5xxx_poc_backing_write(memory_region_get_ram_ptr(&s->msm),
                             0x694 + offset, value, size);
}

static const MemoryRegionOps msm5xxx_poc_boot_keysense_ops = {
    .read = msm5xxx_poc_boot_keysense_read,
    .write = msm5xxx_poc_boot_keysense_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 1 },
    .impl = { .min_access_size = 1, .max_access_size = 1 },
};

static void msm5xxx_poc_boot_keysense_reset(MSM5xxxPOCMachineState *s)
{
    s->boot_keysense_phase = s->boot_keysense_reason = 0;
    s->boot_keysense_rejected = false;
}

static void msm5xxx_poc_boot_keysense_init(MachineState *machine,
                                          MSM5xxxPOCMachineState *s,
                                          Error **errp)
{
    MemoryRegionSection section;
    unsigned i;
    bool conflict;

    s->boot_keysense_realized = true;
    if (!s->boot_keysense_enabled) {
        return;
    }
    if (!s->memory_profile_enabled || s->primary_nor_size < 2) {
        error_setg(errp, "boot-keysense-release requires a memory profile");
        return;
    }
    for (i = 0; i < 3; i++) {
        if (s->boot_keysense_pc[i] > s->primary_nor_size - 2) {
            error_setg(errp, "boot-keysense-release read PC outside primary NOR");
            return;
        }
    }
    section = memory_region_find(get_system_memory(), MSM5XXX_POC_MSM_BASE + 0x694, 1);
    conflict = section.mr != &s->msm || !int128_eq(section.size, int128_make64(1));
    memory_region_unref(section.mr);
    if (conflict) {
        error_setg(errp, "boot-keysense-release requires the whole unclaimed sense byte");
        return;
    }
    memory_region_init_io(&s->boot_keysense_region, OBJECT(machine),
                          &msm5xxx_poc_boot_keysense_ops, s,
                          "msm5xxx-poc.boot-keysense", 1);
    memory_region_add_subregion_overlap(get_system_memory(),
        MSM5XXX_POC_MSM_BASE + 0x694, &s->boot_keysense_region, 1);
}

static bool msm5xxx_poc_spi_nv_geometry_bounds(MSM5xxxPOCMachineState *s)
{
    uint64_t address = s->spi_nv_source_geometry;
    uint64_t end = address + 6;
    uint64_t ram_end = (uint64_t)s->ram_base + MACHINE(s)->ram_size;
    uint64_t reserved_end = (uint64_t)s->ram_reserved_base + s->ram_reserved_size;

    return !(address & 3) && address >= s->ram_base && end <= ram_end &&
           end <= UINT64_C(0x100000000) &&
           (!s->ram_reserved_size || end <= s->ram_reserved_base ||
            address >= reserved_end);
}

static bool msm5xxx_poc_spi_nv_geometry_valid(MSM5xxxPOCMachineState *s)
{
    const uint8_t *descriptor = memory_region_get_ram_ptr(MACHINE(s)->ram) +
                                (s->spi_nv_source_geometry - s->ram_base);

    return descriptor[2] == 0 && descriptor[3] == 0x40 && descriptor[4] == 1;
}

static char *msm5xxx_poc_get_boot_keysense_release(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->boot_keysense_enabled ?
        g_strdup_printf("%x:%x:%x", s->boot_keysense_pc[0],
                        s->boot_keysense_pc[1], s->boot_keysense_pc[2]) : g_strdup("");
}

static void msm5xxx_poc_set_boot_keysense_release(Object *obj, const char *value,
                                                 Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t pc[3];

    if (s->boot_keysense_realized || s->boot_keysense_enabled ||
        !msm5xxx_poc_boot_storage_hex(value, pc, 3) ||
        ((pc[0] | pc[1] | pc[2]) & 1) || pc[0] == pc[1] ||
        pc[0] == pc[2] || pc[1] == pc[2]) {
        error_setg(errp, "boot-keysense-release requires three distinct even hex PCs before realization");
        return;
    }
    memcpy(s->boot_keysense_pc, pc, sizeof(pc));
    s->boot_keysense_enabled = true;
}

static char *msm5xxx_poc_get_boot_keysense_state(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return g_strdup_printf("configured=%u phase=%u rejected=%u reason=%u"
        " reads=%" PRIu64 " releases=%" PRIu64 " rejections=%" PRIu64,
        s->boot_keysense_enabled, s->boot_keysense_phase,
        s->boot_keysense_rejected, s->boot_keysense_reason,
        s->boot_keysense_reads, s->boot_keysense_releases, s->boot_keysense_rejections);
}

static char *msm5xxx_poc_get_spi_nv_source_geometry(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->spi_nv_source_geometry ? g_strdup_printf("%x", s->spi_nv_source_geometry) : g_strdup("");
}

static void msm5xxx_poc_set_spi_nv_source_geometry(Object *obj, const char *value,
                                                  Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t descriptor;

    if (s->spi_nv_realized || s->spi_nv_source_geometry ||
        !msm5xxx_poc_boot_storage_hex(value, &descriptor, 1) ||
        !descriptor || (descriptor & 3)) {
        error_setg(errp, "spi-nv-source-geometry requires an aligned hex descriptor before realization");
        return;
    }
    s->spi_nv_source_geometry = descriptor;
}

static void msm5xxx_poc_spi_nv_persist(MSM5xxxPOCMachineState *s, bool committed)
{
    int ret;

    if (!committed) {
        return;
    }
    ret = blk_pwrite(s->spi_nv_blk, s->spi_nv.last_commit_page,
                     MSM5XXX_SPI_NV_PAGE_SIZE,
                     s->spi_nv.image + s->spi_nv.last_commit_page, BDRV_REQ_FUA);
    if (ret < 0) {
        error_report("SPI NVM state update failed: %s", strerror(-ret));
        exit(EXIT_FAILURE); /* Never return ready after a lost persistent write. */
    }
}

static void msm5xxx_poc_spi_nv_sync(MSM5xxxPOCMachineState *s)
{
    msm5xxx_poc_spi_nv_persist(s, msm5xxx_spi_nv_advance(
        &s->spi_nv, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)));
    if (s->spi_nv.wip) {
        if (s->spi_nv.deadline_ns > INT64_MAX) {
            error_report("SPI NVM virtual deadline is unrepresentable");
            exit(EXIT_FAILURE);
        }
        timer_mod(s->spi_nv_timer, s->spi_nv.deadline_ns);
    } else {
        timer_del(s->spi_nv_timer);
    }
}

static void msm5xxx_poc_spi_nv_tick(void *opaque)
{
    msm5xxx_poc_spi_nv_sync(opaque);
}

static void msm5xxx_poc_spi_nv_step(MSM5xxxPOCMachineState *s, bool cs,
                                    bool clk, bool data)
{
    msm5xxx_poc_spi_nv_persist(s, msm5xxx_spi_nv_step(
        &s->spi_nv, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), cs, clk, data));
    msm5xxx_poc_spi_nv_sync(s);
}

static bool msm5xxx_poc_spi_nv_geometry_gate(MSM5xxxPOCMachineState *s)
{
    const uint8_t *gpio = memory_region_get_ram_ptr(&s->msm) + 0x660;

    if (!s->spi_nv_source_geometry) {
        return true;
    }
    if (!msm5xxx_poc_spi_nv_geometry_valid(s)) {
        if (s->spi_nv_geometry_ready) {
            s->spi_nv_geometry_mismatches++;
            s->spi_nv_geometry_reason = 1;
            msm5xxx_spi_nv_abort_frame(&s->spi_nv);
            msm5xxx_poc_spi_nv_step(s, true, false, false);
        }
        s->spi_nv_geometry_ready = s->spi_nv_qualified = false;
        return false;
    }
    if (!s->spi_nv_geometry_ready) {
        if (!(gpio[4] & 0x40)) {
            return false;
        }
        s->spi_nv_geometry_ready = true;
    }
    return true;
}

static uint64_t msm5xxx_poc_spi_nv_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    const uint8_t *gpio = memory_region_get_ram_ptr(&s->msm) + 0x660;
    uint64_t value = msm5xxx_poc_backing_read(gpio, offset, size);
    bool level;

    if (s->spi_nv_source_geometry && !msm5xxx_poc_boot_storage_guest(s)) {
        return value;
    }
    msm5xxx_poc_spi_nv_sync(s);
    if (!msm5xxx_poc_spi_nv_geometry_gate(s)) {
        return value;
    }
    if (!s->spi_nv_revoked && s->spi_nv_qualified && offset <= 4 &&
        offset + size > 4 && msm5xxx_spi_nv_miso(&s->spi_nv, &level)) {
        unsigned shift = (4 - offset) * 8;

        value = (value & ~((uint64_t)0x80 << shift)) |
                ((uint64_t)(level ? 0x80 : 0) << shift);
    }
    return value;
}

static void msm5xxx_poc_spi_nv_revoke(MSM5xxxPOCMachineState *s,
                                      unsigned reason, hwaddr offset,
                                      uint64_t value, unsigned size)
{
    s->spi_nv_route_reason = reason;
    s->spi_nv_reject_pc = qemu_in_vcpu_thread() && current_cpu == CPU(s->cpu) ?
        CPU_GET_CLASS(current_cpu)->get_pc(current_cpu) : 0;
    s->spi_nv_reject_address = MSM5XXX_SPI_NV_BASE + offset;
    s->spi_nv_reject_width = size;
    s->spi_nv_reject_value = value;
    s->spi_nv_revoked = true;
    msm5xxx_spi_nv_abort_frame(&s->spi_nv);
    msm5xxx_poc_spi_nv_step(s, true, false, false);
}

static void msm5xxx_poc_spi_nv_write(void *opaque, hwaddr offset,
                                    uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    uint8_t *gpio = memory_region_get_ram_ptr(&s->msm) + 0x660;
    bool touches_pins = (offset <= 4 && offset + size > 4) ||
                        (offset <= 8 && offset + size > 8) ||
                        (offset <= 0x18 && offset + size > 0x18) ||
                        (offset <= 0x1c && offset + size > 0x1c);
    bool outputs;

    msm5xxx_poc_spi_nv_sync(s);
    msm5xxx_poc_backing_write(gpio, offset, value, size);
    if (s->spi_nv_revoked || !touches_pins ||
        (s->spi_nv_source_geometry && !msm5xxx_poc_boot_storage_guest(s))) {
        return;
    }
    if (!msm5xxx_poc_spi_nv_geometry_gate(s)) {
        return;
    }
    if (size != 1) {
        msm5xxx_poc_spi_nv_revoke(s, 1, offset, value, size);
        return;
    }
    if (gpio[0x18] & 0x80) {
        msm5xxx_poc_spi_nv_revoke(s, 2, offset, value, size);
        return;
    }
    outputs = (gpio[0x18] & 0x40) && (gpio[0x1c] & 3) == 3;
    if (!outputs) {
        s->spi_nv_qualified = false;
        msm5xxx_poc_spi_nv_step(s, true, false, false);
        return;
    }
    if (!s->spi_nv_qualified) {
        if (!(gpio[4] & 0x40)) {
            return; /* Require an inactive CS before admitting the first frame. */
        }
        s->spi_nv_qualified = true;
    }
    msm5xxx_poc_spi_nv_step(s, gpio[4] & 0x40, gpio[8] & 2, gpio[8] & 1);
}

static const MemoryRegionOps msm5xxx_poc_spi_nv_ops = {
    .read = msm5xxx_poc_spi_nv_read,
    .write = msm5xxx_poc_spi_nv_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
};

static void msm5xxx_poc_spi_nv_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;

    /* SoC reset is not an EEPROM power cycle; pending writes/WEL survive. */
    msm5xxx_poc_spi_nv_step(s, true, false, false);
    s->spi_nv_qualified = s->spi_nv_revoked = s->spi_nv_geometry_ready = false;
    s->spi_nv_geometry_reason = 0;
    s->spi_nv_route_reason = s->spi_nv_reject_pc = s->spi_nv_reject_address = 0;
    s->spi_nv_reject_width = 0;
    s->spi_nv_reject_value = 0;
}

static void msm5xxx_poc_spi_nv_init(MachineState *machine,
                                   MSM5xxxPOCMachineState *s, Error **errp)
{
    MemoryRegionSection section;
    bool conflict;
    int ret;

    s->spi_nv_realized = true;
    if (s->spi_nv_source_geometry) {
        if (!s->spi_nv_write_ns || !s->memory_profile_enabled ||
            !msm5xxx_poc_spi_nv_geometry_bounds(s)) {
            error_setg(errp, "SPI NVM geometry requires enabled SPI and a full nonreserved RAM descriptor");
            return;
        }
        section = memory_region_find(get_system_memory(), s->spi_nv_source_geometry, 6);
        conflict = section.mr != machine->ram ||
                   !int128_eq(section.size, int128_make64(6));
        memory_region_unref(section.mr);
        if (conflict) {
            error_setg(errp, "SPI NVM geometry descriptor must occupy actual unclaimed RAM");
            return;
        }
    }
    if (!s->spi_nv_write_ns) {
        return;
    }
    section = memory_region_find(get_system_memory(), MSM5XXX_SPI_NV_BASE,
                                  MSM5XXX_SPI_NV_WINDOW);
    conflict = section.mr != &s->msm ||
               !int128_eq(section.size, int128_make64(MSM5XXX_SPI_NV_WINDOW));
    memory_region_unref(section.mr);
    if (conflict || !s->memory_profile_enabled) {
        error_setg(errp, "SPI NVM requires the whole unclaimed GPIO aperture and memory profile");
        return;
    }
    s->spi_nv_blk = blk_by_name("msm5xxx-spi-nv-state");
    if (!s->spi_nv_blk) {
        error_setg(errp, "SPI NVM requires named raw backend msm5xxx-spi-nv-state");
        return;
    }
    blk_ref(s->spi_nv_blk);
    if (blk_set_perm(s->spi_nv_blk,
                     BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE, 0, errp) < 0) {
        return;
    }
    if (blk_getlength(s->spi_nv_blk) != MSM5XXX_SPI_NV_CAPACITY) {
        error_setg(errp, "SPI NVM virtual backend must be 16384 bytes");
        return;
    }
    s->spi_nv.image = g_malloc(MSM5XXX_SPI_NV_CAPACITY);
    ret = blk_pread(s->spi_nv_blk, 0, MSM5XXX_SPI_NV_CAPACITY, s->spi_nv.image, 0);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "SPI NVM initial state read failed");
        return;
    }
    msm5xxx_spi_nv_init(&s->spi_nv, s->spi_nv.image, MSM5XXX_SPI_NV_CAPACITY,
                         s->spi_nv_write_ns);
    s->spi_nv_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, msm5xxx_poc_spi_nv_tick, s);
    memory_region_init_io(&s->spi_nv_gpio, OBJECT(machine), &msm5xxx_poc_spi_nv_ops,
                          s, "msm5xxx-poc.spi-nv-gpio", MSM5XXX_SPI_NV_WINDOW);
    memory_region_add_subregion_overlap(get_system_memory(), MSM5XXX_SPI_NV_BASE,
                                        &s->spi_nv_gpio, 1);
}

static char *msm5xxx_poc_get_spi_nv_write_ns(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return g_strdup_printf("%" PRIu64, s->spi_nv_write_ns);
}

static void msm5xxx_poc_set_spi_nv_write_ns(Object *obj, const char *value,
                                          Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint64_t ns;
    const char *end;

    if (s->spi_nv_realized) {
        error_setg(errp, "SPI NVM write period is immutable after realization");
        return;
    }
    if (!*value || !g_ascii_isdigit(*value) ||
        qemu_strtou64(value, &end, 10, &ns) || *end || !ns || ns > INT64_MAX) {
        error_setg(errp, "experimental-spi-nv-write-ns requires positive decimal nanoseconds");
        return;
    }
    s->spi_nv_write_ns = ns;
}

static char *msm5xxx_poc_get_spi_nv_state(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return g_strdup_printf("qualified=%u revoked=%u status=%u commits=%" PRIu64
                           " rejections=%" PRIu64 " reason=%u route_reason=%u"
                           " pc=%u address=%u width=%u value=%" PRIu64
                           " geometry=%u geometry_ready=%u geometry_mismatches=%" PRIu64
                           " geometry_reason=%u",
                           s->spi_nv_qualified, s->spi_nv_revoked,
                           msm5xxx_spi_nv_status(&s->spi_nv), s->spi_nv.commits,
                           s->spi_nv.rejections, s->spi_nv.last_reject,
                           s->spi_nv_route_reason, s->spi_nv_reject_pc,
                           s->spi_nv_reject_address, s->spi_nv_reject_width,
                           s->spi_nv_reject_value, s->spi_nv_source_geometry,
                           s->spi_nv_geometry_ready, s->spi_nv_geometry_mismatches,
                           s->spi_nv_geometry_reason);
}

/* Source guards read only full-span RAM/immutable-ROM owners, never MMIO. */
static bool msm5xxx_poc_protected_owned_read(MSM5xxxPOCMachineState *s,
        uint32_t address, void *data, unsigned length, bool rom)
{
    MemoryRegionSection section = memory_region_find(get_system_memory(), address, length);
    bool valid = section.mr && memory_region_is_ram(section.mr) &&
        (rom ? section.mr == &s->nor && memory_region_is_rom(section.mr) :
               !memory_region_is_rom(section.mr)) &&
        int128_eq(section.size, int128_make64(length));
    if (valid) {
        memcpy(data, (uint8_t *)memory_region_get_ram_ptr(section.mr) +
               section.offset_within_region, length);
    }
    if (section.mr) {
        memory_region_unref(section.mr);
    }
    return valid;
}

static bool msm5xxx_poc_protected_source_bounds(MSM5xxxPOCMachineState *s)
{
    const uint32_t *v = s->protected_nor_source;
    const unsigned fields[] = {0, 2, 3, 4}, spans[] = {4, 4, 12, 20};
    uint64_t ram_end = (uint64_t)s->ram_base + MACHINE(s)->ram_size;
    uint64_t nv_end = (uint64_t)s->protected_nor_base + s->protected_nor_length;
    unsigned i;
    if (!s->protected_nor_enabled || !s->memory_profile_enabled) {
        return false;
    }
    for (i = 0; i < ARRAY_SIZE(fields); i++) {
        if (v[fields[i]] < s->ram_base ||
            (uint64_t)v[fields[i]] + spans[i] > ram_end) {
            return false;
        }
    }
    for (i = 1; i < 6; i += 4) {
        unsigned length = i == 1 ? 0xd0 : 20;
        if ((uint64_t)v[i] + length > s->primary_nor_size ||
            ((uint64_t)v[i] < nv_end &&
             s->protected_nor_base < (uint64_t)v[i] + length)) {
            return false;
        }
    }
    return true;
}

static bool msm5xxx_poc_protected_source_check(MSM5xxxPOCMachineState *s)
{
    const uint32_t *v = s->protected_nor_source;
    MSM5xxxProtectedNOR *p = &s->protected_nor;
    uint8_t object[0xd0], state[12], ram_probe[20], rom_probe[20], bytes[4];
    uint32_t count;
    unsigned i, reason = 0;
    if (!s->protected_nor_source_enabled) {
        return true;
    }
    s->protected_nor_source_checks++;
    if (!msm5xxx_poc_protected_owned_read(s, v[0], bytes, 4, false) ||
        ldl_le_p(bytes) != v[1] ||
        !msm5xxx_poc_protected_owned_read(s, v[2], bytes, 4, false) ||
        ldl_le_p(bytes) != v[1]) {
        reason = 1;
    } else if (!msm5xxx_poc_protected_owned_read(s, v[3], state, 12, false) ||
               ldl_le_p(state) != 0 || state[4] > 2) {
        reason = 2;
    } else if (!msm5xxx_poc_protected_owned_read(s, v[4], ram_probe, 20, false) ||
               !msm5xxx_poc_protected_owned_read(s, v[5], rom_probe, 20, true) ||
               memcmp(ram_probe, rom_probe, 20)) {
        reason = 3;
    } else if (!msm5xxx_poc_protected_owned_read(s, v[1], object, sizeof(object), true)) {
        reason = 4;
    } else {
        count = ldl_le_p(object + 4);
        if (count != p->sector_count || count > (0xb0 - 8) / 4 ||
            (uint64_t)ldl_le_p(object + 0xb0) * 2 != p->base ||
            (uint64_t)ldl_le_p(object + 0xb4) * 2 != p->length) {
            reason = 4;
        }
        for (i = 0; !reason && i < count; i++) {
            if (ldl_le_p(object + 8 + 4 * i) != p->starts[i + 1] - p->starts[i]) {
                reason = 4;
            }
        }
    }
    s->protected_nor_source_reason = reason;
    if (reason) {
        s->protected_nor_source_rejections++;
        return false;
    }
    return true;
}

/* Private, explicit virtual provider. No physical ID or automatic admission. */
static void msm5xxx_poc_protected_persist(MSM5xxxPOCMachineState *s,
                                          uint64_t programs, uint64_t erases)
{
    MSM5xxxProtectedNOR *p = &s->protected_nor;
    uint32_t start, length;
    uint8_t previous[256];
    int sector, ret;
    if (p->programs != programs) {
        start = p->target - p->base;
        length = p->staged_length;
    } else if (p->erases != erases) {
        sector = msm5xxx_protected_nor_sector(p, p->erase_target);
        assert(sector >= 0);
        start = p->starts[sector];
        length = p->starts[sector + 1] - start;
    } else {
        return;
    }
    /* Identical backend bytes need no new durable mutation. */
    if (length <= sizeof(previous)) {
        ret = blk_pread(s->protected_nor_blk, start, length, previous, 0);
        if (ret < 0) {
            error_report("protected NOR persistence read failed: %s", strerror(-ret));
            exit(EXIT_FAILURE);
        }
        if (!memcmp(previous, p->image + start, length)) {
            s->protected_nor_persist_skips++;
            return;
        }
    }
    ret = blk_pwrite(s->protected_nor_blk, start, length, p->image + start,
                     BDRV_REQ_FUA);
    if (ret < 0) {
        error_report("protected NOR state update failed: %s", strerror(-ret));
        exit(EXIT_FAILURE);
    }
    s->protected_nor_persist_writes++;
}

static void msm5xxx_poc_protected_sync(MSM5xxxPOCMachineState *s)
{
    MSM5xxxProtectedNOR *p = &s->protected_nor;
    uint64_t programs = p->programs, erases = p->erases;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    assert(now >= s->protected_nor_clock);
    msm5xxx_protected_nor_advance(p, now - s->protected_nor_clock);
    s->protected_nor_clock = now;
    msm5xxx_poc_protected_persist(s, programs, erases);
}

static MemTxResult msm5xxx_poc_protected_read(void *opaque, hwaddr offset,
        uint64_t *value, unsigned size, MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    MSM5xxxProtectedNOR *p = &s->protected_nor;
    uint16_t half;
    unsigned i;
    (void)attrs;
    if (size > 8 || offset > p->length || size > p->length - offset) {
        return MEMTX_ERROR;
    }
    /* QTest exemption is private test routing, never automatic admission. */
    if (!qtest_enabled() && !msm5xxx_poc_boot_storage_guest(s)) {
        *value = 0;
        for (i = 0; i < size; i++) {
            *value |= (uint64_t)p->image[offset + i] << (8 * i);
        }
        return MEMTX_OK;
    }
    msm5xxx_poc_protected_sync(s);
    if (p->phase == MSM5XXX_PROTECTED_NOR_ARRAY ||
        (p->phase == MSM5XXX_PROTECTED_NOR_STATUS && p->suspended && p->array_selected)) {
        /* Array bus reads are not command/status width violations. */
        *value = 0;
        for (i = 0; i < size; i++) {
            *value |= (uint64_t)p->image[offset + i] << (8 * i);
        }
        return MEMTX_OK;
    }
    if (msm5xxx_protected_nor_read(p, p->base + offset, size, &half)) {
        *value = half;
    } else {
        /* Unowned reads retain actual array data; no synthetic ready/ID. */
        *value = 0;
        for (i = 0; i < size; i++) {
            *value |= (uint64_t)p->image[offset + i] << (8 * i);
        }
    }
    return MEMTX_OK;
}

static MemTxResult msm5xxx_poc_protected_write(void *opaque, hwaddr offset,
        uint64_t value, unsigned size, MemTxAttrs attrs)
{
    MSM5xxxPOCMachineState *s = opaque;
    MSM5xxxProtectedNOR *p = &s->protected_nor;
    uint64_t programs, erases;
    (void)attrs;
    if (!qtest_enabled() && !msm5xxx_poc_boot_storage_guest(s)) {
        return MEMTX_OK;
    }
    msm5xxx_poc_protected_sync(s);
    if (size > 8 || offset > p->length || size > p->length - offset) {
        return MEMTX_ERROR;
    }
    programs = p->programs;
    erases = p->erases;
    /* One-operation admission lease: accepted erase/status work is not
     * retroactively revoked when firmware updates its software globals. */
    if (size == 2 && !(offset & 1) &&
        ((p->phase == MSM5XXX_PROTECTED_NOR_ARRAY && value == 0x60) ||
         (p->phase == MSM5XXX_PROTECTED_NOR_PROGRAM_BARRIER && value == 0x70) ||
         (p->phase == MSM5XXX_PROTECTED_NOR_GRANT && (value == 0x20 || value == 0x77)) ||
         ((p->phase == MSM5XXX_PROTECTED_NOR_ERASE_CONFIRM ||
           p->phase == MSM5XXX_PROTECTED_NOR_VERIFY_CONFIRM) && value == 0xd0)) &&
        !msm5xxx_poc_protected_source_check(s)) {
        msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL);
        return MEMTX_OK;
    }
    if (value > UINT32_MAX) {
        msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_WIDTH);
    } else {
        /* Unsupported writes preserve the native immutable-ROM behavior. */
        msm5xxx_protected_nor_write(p, p->base + offset, size, value);
    }
    msm5xxx_poc_protected_persist(s, programs, erases);
    return MEMTX_OK;
}

static const MemoryRegionOps msm5xxx_poc_protected_ops = {
    .read_with_attrs = msm5xxx_poc_protected_read,
    .write_with_attrs = msm5xxx_poc_protected_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
};

static void msm5xxx_poc_protected_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    /* Explicit virtual power reset: uncommitted operation is aborted. */
    msm5xxx_protected_nor_reset(&s->protected_nor);
    s->protected_nor_source_checks = s->protected_nor_source_rejections = 0;
    s->protected_nor_source_reason = 0;
    s->protected_nor_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static char *msm5xxx_poc_get_protected(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    return s->protected_nor_enabled ?
        g_strdup_printf("%x:%x:%x:%x", s->protected_nor_base,
            s->protected_nor_length, s->msm5xxx_protected_nor_sector,
            s->protected_nor_ticks) : g_strdup("");
}

static char *msm5xxx_poc_get_protected_stats(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    MSM5xxxProtectedNOR *p = &s->protected_nor;
    (void)errp;
    return g_strdup_printf("enabled=%u,phase=%u,programs=%" PRIu64
        ",erases=%" PRIu64 ",verifies=%" PRIu64 ",rejections=%" PRIu64
        ",reason=%u,persist_writes=%" PRIu64 ",persist_noops=%" PRIu64
        ",source_enabled=%u,source_checks=%" PRIu64 ",source_rejections=%" PRIu64
        ",source_reason=%u",
        s->protected_nor_enabled, p->phase, p->programs,
        p->erases, p->verifies, p->rejections, p->reason,
        s->protected_nor_persist_writes, s->protected_nor_persist_skips,
        s->protected_nor_source_enabled, s->protected_nor_source_checks,
        s->protected_nor_source_rejections, s->protected_nor_source_reason);
}

static void msm5xxx_poc_set_protected(Object *obj, const char *value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t v[4];
    if (s->protected_nor_realized || s->protected_nor_enabled ||
        !msm5xxx_poc_boot_storage_hex(value, v, 4) || !v[1] ||
        (v[0] & 255) || (v[1] & 255) || !v[2] || (v[2] & 255) ||
        v[1] % v[2] || v[1] / v[2] > MSM5XXX_PROTECTED_NOR_MAX_SECTORS || !v[3] ||
        (uint64_t)v[0] + v[1] > UINT32_MAX) {
        error_setg(errp, "protected NOR requires BASE:LENGTH:SECTOR:ERASE_NS before realization");
        return;
    }
    s->protected_nor_base = v[0];
    s->protected_nor_length = v[1];
    s->msm5xxx_protected_nor_sector = v[2];
    s->protected_nor_ticks = v[3];
    s->protected_nor_enabled = true;
}

static char *msm5xxx_poc_get_protected_source(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    const uint32_t *v = s->protected_nor_source;
    (void)errp;
    return s->protected_nor_source_enabled ?
        g_strdup_printf("%x:%x:%x:%x:%x:%x", v[0], v[1], v[2], v[3], v[4], v[5]) :
        g_strdup("");
}

static void msm5xxx_poc_set_protected_source(Object *obj, const char *value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    const unsigned spans[] = {4, 0xd0, 4, 12, 20, 20};
    uint32_t v[6];
    unsigned i;
    if (s->protected_nor_realized || s->protected_nor_source_enabled ||
        !msm5xxx_poc_boot_storage_hex(value, v, ARRAY_SIZE(v)) ||
        ((v[0] | v[1] | v[2] | v[3]) & 3) || ((v[4] | v[5]) & 1)) {
        goto invalid;
    }
    for (i = 0; i < ARRAY_SIZE(v); i++) {
        if ((uint64_t)v[i] + spans[i] > UINT64_C(0x100000000)) {
            goto invalid;
        }
    }
    memcpy(s->protected_nor_source, v, sizeof(v));
    s->protected_nor_source_enabled = true;
    return;
invalid:
    error_setg(errp, "protected-nor-source requires six aligned, nonoverflowing hex fields before realization");
}

static void msm5xxx_poc_protected_realize(MSM5xxxPOCMachineState *s)
{
    uint32_t sectors[MSM5XXX_PROTECTED_NOR_MAX_SECTORS], count, i;
    g_autofree uint8_t *seed = NULL;
    int ret;
    s->protected_nor_realized = true;
    if (s->protected_nor_source_enabled && !msm5xxx_poc_protected_source_bounds(s)) {
        error_report("protected NOR source requires bounded RAM/immutable primary ROM and an enabled model");
        exit(EXIT_FAILURE);
    }
    if (!s->protected_nor_enabled) {
        return;
    }
    if (!s->memory_profile_enabled ||
        s->protected_nor_base + (uint64_t)s->protected_nor_length >
            MIN(s->primary_nor_size, s->ram_base) ||
        s->primary_x16_nor_enabled || s->whole_primary_x16_enabled ||
        s->record_x16_nor_enabled || s->mapped_primary_x16_nor_enabled ||
        s->intel_x16_nor_enabled || s->amd_x16_nor_enabled ||
        s->fujitsu_x16_nor_enabled || s->upper_x8_nor_enabled ||
        s->upper_x16_nor_enabled) {
        error_report("protected NOR requires an exclusive seeded primary-ROM window");
        exit(EXIT_FAILURE);
    }
    s->protected_nor_blk = blk_by_name("msm5xxx-protected-nor-state");
    if (!s->protected_nor_blk) {
        error_report("protected NOR requires named private raw backend");
        exit(EXIT_FAILURE);
    }
    blk_ref(s->protected_nor_blk);
    if (blk_set_perm(s->protected_nor_blk,
        BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE, 0, &error_fatal) < 0 ||
        blk_getlength(s->protected_nor_blk) != s->protected_nor_length) {
        error_report("protected NOR backend length/permission mismatch");
        exit(EXIT_FAILURE);
    }
    seed = g_malloc(s->protected_nor_length);
    ret = blk_pread(s->protected_nor_blk, 0, s->protected_nor_length, seed, 0);
    if (ret < 0) {
        error_report("protected NOR seed read failed: %s", strerror(-ret));
        exit(EXIT_FAILURE);
    }
    /* Establish the initial backend baseline before eliding identical programs. */
    ret = blk_flush(s->protected_nor_blk);
    if (ret < 0) {
        error_report("protected NOR initial state flush failed: %s", strerror(-ret));
        exit(EXIT_FAILURE);
    }
    count = s->protected_nor_length / s->msm5xxx_protected_nor_sector;
    for (i = 0; i < count; i++) {
        sectors[i] = s->msm5xxx_protected_nor_sector;
    }
    s->protected_nor.image = g_malloc(s->protected_nor_length);
    if (!msm5xxx_protected_nor_init(&s->protected_nor, seed, s->protected_nor.image,
            s->protected_nor_length, s->protected_nor_base, sectors, count,
            s->protected_nor_ticks)) {
        error_report("protected NOR initialization failed");
        exit(EXIT_FAILURE);
    }
    s->protected_nor_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    memory_region_init_io(&s->protected_nor_region, OBJECT(s),
        &msm5xxx_poc_protected_ops, s, "msm5xxx-poc.protected-nor",
        s->protected_nor_length);
    memory_region_add_subregion_overlap(get_system_memory(),
        s->protected_nor_base, &s->protected_nor_region, 2);
    qemu_register_reset(msm5xxx_poc_protected_reset, s);
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
    if (s->search2_timer) {
        timer_del(s->search2_timer);
    }
    if (s->search1_timer) {
        timer_del(s->search1_timer);
    }
    if (s->decoder_init_timer) {
        timer_del(s->decoder_init_timer);
    }
    msm5xxx_poc_tx_init_cancel(s);
    s->tx_init_deadline = s->tx_init_fires = s->tx_init_cancels = 0;
    s->tx_frame_fires = s->tx_frame_overruns = 0;
    msm5xxx_access_init(&s->tx_access);
    s->tx_fifo_rejections = 0;
    s->tx_fifo_reject_reason = s->tx_fifo_reject_pc = 0;
    msm5xxx_paging_stream_init(&s->access_paging);
    s->access_ack_queued = s->access_ack_encoded = s->access_ack_rejections = 0;
    s->access_ack_resets = s->access_ack_reject_reason = 0;
    s->access_station_sequence = 0;
    s->access_response_blocked = false;
    s->decoder_init_active = s->decoder_init_done = false;
    s->decoder_init_mask = s->decoder_init_reject_reason = 0;
    s->decoder_sync_have_frame = s->combiner_position_latched = false;
    s->decoder_sync_epoch = s->decoder_sync_roll = s->decoder_sync_frames = 0;
    s->decoder_radio_tick = s->decoder_paging_frames = s->decoder_paging_bootstraps = 0;
    s->decoder_paging_started = false;
    s->decoder_sync_reads = s->decoder_sync_overruns = s->combiner_position_latches = 0;
    s->combiner_position_snapshot = 0;
    s->decoder_sync_cursor = 8;
    memset(s->decoder_sync_words, 0, sizeof(s->decoder_sync_words));
    s->decoder_traffic_count = s->decoder_traffic_reject_reason = 0;
    s->decoder_traffic_frames = s->decoder_traffic_reads = 0;
    s->decoder_traffic_crc_passes = s->decoder_traffic_crc_failures = 0;
    s->decoder_traffic_frame_rejections = 0;
    s->decoder_traffic_response_seen = false;
    memset(&s->decoder_traffic_response, 0, sizeof(s->decoder_traffic_response));
    s->decoder_traffic_acks = s->decoder_traffic_ack_rejections = 0;
    s->decoder_traffic_response_frames = 0;
    msm5xxx_poc_traffic_service_clear(s);
    s->traffic_service_requests = s->traffic_service_rejections = s->traffic_service_duplicates = 0;
    s->traffic_service_next_sequence = s->traffic_service_revision = 0;
    s->traffic_service_reject_reason = 0;
    memset(s->decoder_traffic_words, 0, sizeof(s->decoder_traffic_words));
    s->decoder_init_fires = s->decoder_init_rejections = 0;
    s->search1_active = s->search1_have_results = s->search1_rejected = false;
    s->search1_conditional = s->search1_config_valid = false;
    s->search1_config_known = false;
    memset(s->search1_verified_config,0,sizeof(s->search1_verified_config));
    s->search1_position = s->search1_pending_position = 0;
    s->search1_sub = s->search1_selector = 0;
    s->search1_submits = s->search1_completions = 0;
    s->search1_result_reads = s->search1_rejections = 0;
    s->search1_reject_reason = s->search1_reject_pc = 0;
    s->search1_reject_access = s->search1_reject_value = 0;
    s->search1_aborts = 0;
    memset(s->search1_packet, 0, sizeof(s->search1_packet));
    memset(s->search1_results, 0, sizeof(s->search1_results));
    memset(s->search1_pending_results, 0, sizeof(s->search1_pending_results));
    msm5xxx_fingers_reset(&s->fingers);
    s->finger_latches = s->finger_reads = s->finger_fallback_writes = 0;
    msm5xxx_search2_reset(&s->search2);
    s->search2_probe_done = s->search2_probe_rejected = false;
    s->search2_submits = s->search2_completions = s->search2_result_reads = 0;
    s->search2_rejections = 0;
    s->search2_reject_reason = s->search2_reject_pc = 0;
    s->search2_reject_value = s->search2_reject_expected_pc = 0;
    s->search2_position = s->search2_pending_position = 0;
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
        s->board_status_input_level & s->board_status_input_mask;
    msm5xxx_poc_matrix_row734_reset(s);
    s->matrix_input_backing = s->matrix_input_reset;
    /* Host contacts and chardev frames survive guest reset. */
    s->matrix_input_host_events = 0;
    s->matrix_input_active_reads = 0;
    s->matrix_input_rejections = 0;
    msm5xxx_poc_audio_reset(s);
    memset(s->rex_irq_backing, 0, sizeof(s->rex_irq_backing));
    s->rex_irq_arm_backing = 0;
    memset(s->rex_irq_pending, 0, sizeof(s->rex_irq_pending));
    s->rex_irq_armed = (s->rex_irq_enabled && s->rex_irq_c80 &&
                        !s->rex_irq_read_consume && !s->rex_irq_arm_address);
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
    if (s->spi_nv_timer) {
        msm5xxx_poc_spi_nv_reset(s);
    }
    msm5xxx_poc_boot_keysense_reset(s);
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

static bool msm5xxx_poc_ram_reserved_valid(MSM5xxxPOCMachineState *s)
{
    uint64_t end = (uint64_t)s->ram_reserved_base + s->ram_reserved_size;
    uint64_t ram_end = (uint64_t)s->ram_base + MACHINE(s)->ram_size;

    /* Keep the current stack word and first descending push outside the hole. */
    return !s->ram_reserved_size ||
           (s->memory_profile_enabled && s->ram_reserved_base &&
            !(s->ram_reserved_base & 0xfff) &&
            !(s->ram_reserved_size & 0xfff) &&
            MACHINE(s)->ram_size <= (uint64_t)UINT32_MAX + 1 - s->ram_base &&
            s->ram_reserved_base > s->ram_base && end < ram_end &&
            s->initial_sp >= (uint64_t)s->ram_base + 4 &&
            !((uint64_t)s->initial_sp <= end &&
              (uint64_t)s->initial_sp + 4 > s->ram_reserved_base));
}

/* Explicit virtual geometry; no automatic part identity or backend policy. */
static bool msm5xxx_poc_whole_primary_geometry(uint32_t size, uint32_t sector,
                                               unsigned regions,
                                               const uint32_t *counts,
                                               const uint32_t *lengths)
{
    uint64_t bytes = 0;
    unsigned i;

    if (!size || size > MSM5XXX_POC_NOR_MAX_SIZE || sector < 0x1000 ||
        (sector & (sector - 1)) || regions > MSM5XXX_POC_NOR_MAX_REGIONS) {
        return false;
    }
    for (i = 0; i < regions; i++) {
        if (!counts[i] || lengths[i] < 0x1000 ||
            (lengths[i] & (lengths[i] - 1)) || bytes % lengths[i] ||
            counts[i] > (UINT64_MAX - bytes) / lengths[i]) {
            return false;
        }
        bytes += (uint64_t)counts[i] * lengths[i];
    }
    return regions ? sector == lengths[0] && bytes == size : size % sector == 0;
}

static char *msm5xxx_poc_get_whole_primary_x16(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    GString *value;
    unsigned i;

    if (!s->whole_primary_x16_enabled) {
        return g_strdup("");
    }
    value = g_string_new(NULL);
    g_string_printf(value, "%x:%x:%x:%x", s->whole_primary_x16_size,
                    s->whole_primary_x16_sector, s->whole_primary_x16_id0,
                    s->whole_primary_x16_id1);
    for (i = 0; i < s->whole_primary_x16_region_count; i++) {
        g_string_append_printf(value, ":%x:%x", s->whole_primary_x16_block_count[i],
                               s->whole_primary_x16_region_size[i]);
    }
    return g_string_free(value, false);
}

static void msm5xxx_poc_set_whole_primary_x16(Object *obj, const char *value,
                                             Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value ? value : "", ":", -1);
    uint32_t parsed[4 + MSM5XXX_POC_NOR_MAX_REGIONS * 2];
    uint32_t counts[MSM5XXX_POC_NOR_MAX_REGIONS] = { 0 };
    uint32_t lengths[MSM5XXX_POC_NOR_MAX_REGIONS] = { 0 };
    unsigned n = g_strv_length(fields), regions, i;

    if (s->whole_primary_x16_realized || s->whole_primary_x16_enabled ||
        n < 4 || n > ARRAY_SIZE(parsed) || (n - 4) % 2) {
        error_setg(errp, "experimental-whole-primary-x16-nor requires SIZE:SECTOR:ID0:ID1[:COUNT:LENGTH...] before realization");
        return;
    }
    for (i = 0; i < n; i++) {
        const char *cursor = fields[i], *end;
        uint64_t number;

        if (!*cursor) {
            error_setg(errp, "invalid whole-primary x16 unsigned hexadecimal number");
            return;
        }
        for (; *cursor; cursor++) {
            if (!g_ascii_isxdigit(*cursor)) {
                error_setg(errp, "invalid whole-primary x16 unsigned hexadecimal number");
                return;
            }
        }
        if (qemu_strtou64(fields[i], &end, 16, &number) || *end ||
            number > UINT32_MAX) {
            error_setg(errp, "whole-primary x16 number exceeds 32 bits");
            return;
        }
        parsed[i] = number;
    }
    regions = (n - 4) / 2;
    for (i = 0; i < regions; i++) {
        counts[i] = parsed[4 + i * 2];
        lengths[i] = parsed[5 + i * 2];
    }
    if (parsed[2] > UINT16_MAX || parsed[3] > UINT16_MAX ||
        !msm5xxx_poc_whole_primary_geometry(parsed[0], parsed[1], regions,
                                           counts, lengths)) {
        error_setg(errp, "invalid whole-primary x16 virtual geometry or IDs");
        return;
    }
    s->whole_primary_x16_size = parsed[0];
    s->whole_primary_x16_sector = parsed[1];
    s->whole_primary_x16_id0 = parsed[2];
    s->whole_primary_x16_id1 = parsed[3];
    s->whole_primary_x16_region_count = regions;
    memcpy(s->whole_primary_x16_block_count, counts, sizeof(counts));
    memcpy(s->whole_primary_x16_region_size, lengths, sizeof(lengths));
    s->whole_primary_x16_enabled = true;
}

static bool msm5xxx_poc_configure_whole_primary(MSM5xxxPOCMachineState *s,
                                               Error **errp)
{
    s->whole_primary_x16_realized = true;
    if (!s->whole_primary_x16_enabled) {
        return true;
    }
    if (!s->memory_profile_enabled ||
        s->whole_primary_x16_size != s->primary_nor_size ||
        s->primary_nor_size > s->ram_base ||
        !msm5xxx_poc_whole_primary_geometry(s->whole_primary_x16_size,
            s->whole_primary_x16_sector, s->whole_primary_x16_region_count,
            s->whole_primary_x16_block_count, s->whole_primary_x16_region_size)) {
        error_setg(errp, "whole-primary x16 requires matching final primary memory-profile geometry");
        return false;
    }
    if (s->primary_x16_nor_enabled || s->record_x16_nor_enabled ||
        s->mapped_primary_x16_nor_enabled || s->intel_x16_nor_enabled ||
        s->amd_x16_nor_enabled || s->fujitsu_x16_nor_enabled ||
        s->upper_x8_nor_enabled || s->upper_x16_nor_enabled) {
        error_setg(errp, "whole-primary x16 conflicts with another NOR selector");
        return false;
    }
    s->primary_x16_nor_base = 0;
    s->primary_x16_nor_size = s->whole_primary_x16_size;
    s->primary_x16_nor_sector_size = s->whole_primary_x16_sector;
    s->primary_x16_nor_id0 = s->whole_primary_x16_id0;
    s->primary_x16_nor_id1 = s->whole_primary_x16_id1;
    s->primary_x16_nor_region_count = s->whole_primary_x16_region_count;
    memcpy(s->primary_x16_nor_block_count, s->whole_primary_x16_block_count,
           sizeof(s->primary_x16_nor_block_count));
    memcpy(s->primary_x16_nor_region_size, s->whole_primary_x16_region_size,
           sizeof(s->primary_x16_nor_region_size));
    s->primary_x16_nor_enabled = true;
    return true;
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

    if (!msm5xxx_poc_configure_whole_primary(s, &error_fatal)) {
        return;
    }
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
            (machine->ram_size < 4 ||
             machine->ram_size >
                (s->ram_base == MSM5XXX_POC_HIGH_RAM_BASE ?
                 MSM5XXX_POC_HIGH_RAM_END : 0x02000000) - s->ram_base ||
             s->initial_sp < s->ram_base ||
             s->initial_sp > s->ram_base + machine->ram_size - 4)) {
        error_report("memory-profile RAM range does not contain INITIAL_SP");
        exit(EXIT_FAILURE);
    }
    if (!msm5xxx_poc_ram_reserved_valid(s)) {
        error_report("ram-reserved requires an aligned interior memory-profile RAM range outside INITIAL_SP");
        exit(EXIT_FAILURE);
    }
    if (s->record_x16_nor_enabled) {
        uint64_t base = s->record_x16_nor_base;
        uint64_t end = base + s->record_x16_nor_size;

        if (end > s->primary_nor_size ||
                (s->record_x16_nor_explicit_ids && s->primary_x16_nor_enabled) ||
                (!s->record_x16_nor_explicit_ids &&
                 (!s->primary_x16_nor_enabled ||
                end != s->primary_x16_nor_base ||
                (uint64_t)s->primary_x16_nor_base +
                    s->primary_x16_nor_size != s->primary_nor_size)) ||
                (s->fujitsu_x16_nor_enabled &&
                 s->secondary_nor_base < s->primary_nor_size &&
                 base < (uint64_t)s->secondary_nor_base +
                        s->secondary_nor_size &&
                 end > s->secondary_nor_base)) {
            error_report(
                "record-x16-nor requires an in-range exclusive bank or "
                "disjoint adjacent primary tail"
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
    /* Reject an EEPROM boundary through either mapped halfword register. */
    if ((s->matrix_input_row_mask || s->matrix_input_loop) && s->eeprom_gpio_enabled) {
        uint64_t start = s->eeprom_gpio_base;
        uint64_t end = start + MSM5XXX_POC_EEPROM_GPIO_SIZE;

        const unsigned loop_offsets[] = { 0x720, 0x728, 0x72c };
        for (unsigned port_index = 0; port_index < (s->matrix_input_loop ? 3 : 2); port_index++) {
            unsigned offset = s->matrix_input_loop ? loop_offsets[port_index] : 0x724 + 8 * port_index;
            uint64_t address = MSM5XXX_POC_MSM_BASE + offset;

            if (start < address + 2 && end > address &&
                !(start <= address && end >= address + 2)) {
                error_report("mapped halfword register partially overlaps "
                             "EEPROM GPIO aperture");
                exit(EXIT_FAILURE);
            }
        }
    }
    /* Loop selector and sense apertures cannot bypass unrelated owners. */
    if (s->matrix_input_loop) {
        const unsigned offsets[] = { 0x720, 0x728, 0x72c };
        for (unsigned port_index = 0; port_index < sizeof(offsets) / sizeof(offsets[0]); port_index++) {
            uint64_t address = MSM5XXX_POC_MSM_BASE + offsets[port_index];
            bool ready = s->ready_poll_enabled && !s->ready_poll_lcd_enabled;
            if ((s->board_revision_enabled &&
                 (uint64_t)s->board_revision_address < address + 2 &&
                 (uint64_t)s->board_revision_address + 4 > address) ||
                (s->board_status_input_enabled &&
                 !msm5xxx_poc_loop_status_matches(s) &&
                 (uint64_t)s->board_status_input_address < address + 2 &&
                 (uint64_t)s->board_status_input_address +
                    (s->board_status_input_descriptor ? 2 : 1) > address) ||
                (ready &&
                 ((s->ready_status_address >= address &&
                   s->ready_status_address < address + 2) ||
                  (s->ready_pulse_address >= address &&
                   s->ready_pulse_address < address + 2) ||
                  (s->ready_poll_control_enabled &&
                   s->ready_control_address >= address &&
                   s->ready_control_address < address + 2)))) {
                error_report("matrix-halfword-loop conflicts with an MMIO owner");
                exit(EXIT_FAILURE);
            }
        }
    }
    /* Diagnostic contact cannot replace an EEPROM protocol pin or another class. */
    if (s->experimental_matrix_contact_enabled) {
        uint64_t address = MSM5XXX_POC_MSM_BASE + 0x72c;
        uint32_t site = s->experimental_matrix_contact_site;
        bool pin_collision = s->eeprom_gpio_enabled &&
            (((uint64_t)s->eeprom_gpio_base + s->eeprom_data_offset == address &&
              (s->eeprom_data_mask & 0x10)) ||
             ((uint64_t)s->eeprom_gpio_base + s->eeprom_clock_offset == address &&
              (s->eeprom_clock_mask & 0x10)) ||
             ((uint64_t)s->eeprom_gpio_base + s->eeprom_direction_offset == address &&
              (s->eeprom_data_mask & 0x10)));

        if (!s->matrix_input_halfword || !s->matrix_input_row_mask ||
            s->matrix_input_loop || s->matrix_input_low5 || s->matrix_input_gpio ||
            s->primary_nor_size < 2 || (site & 1) ||
            site > s->primary_nor_size - 2 ||
            site == s->matrix_input_presence_site ||
            site == s->matrix_input_sense_site || pin_collision) {
            error_report("experimental-matrix-contact requires an exclusive "
                         "mapped halfword read site and unowned bit 0x10");
            exit(EXIT_FAILURE);
        }
    }
    /* Status diagnostic requires this EEPROM owner and an unowned input bit. */
    if (s->experimental_matrix_status_enabled) {
        uint64_t address = MSM5XXX_POC_MSM_BASE + 0x728;
        uint64_t base = s->eeprom_gpio_base;
        uint32_t site = s->experimental_matrix_status_site;
        bool ready = s->ready_poll_enabled && !s->ready_poll_lcd_enabled;
        bool owner_conflict =
            (s->board_revision_enabled &&
             (uint64_t)s->board_revision_address < address + 2 &&
             (uint64_t)s->board_revision_address + 4 > address) ||
            (s->board_status_input_enabled &&
             (uint64_t)s->board_status_input_address < address + 2 &&
             (uint64_t)s->board_status_input_address +
                 (s->board_status_input_descriptor ? 2 : 1) > address) ||
            (ready && ((s->ready_status_address >= address &&
                        s->ready_status_address < address + 2) ||
                       (s->ready_pulse_address >= address &&
                        s->ready_pulse_address < address + 2) ||
                       (s->ready_poll_control_enabled &&
                        s->ready_control_address >= address &&
                        s->ready_control_address < address + 2)));
        bool pin_collision =
            (base + s->eeprom_data_offset == address && (s->eeprom_data_mask & 2)) ||
            (base + s->eeprom_clock_offset == address && (s->eeprom_clock_mask & 2)) ||
            (base + s->eeprom_direction_offset == address && (s->eeprom_data_mask & 2));

        if (!s->matrix_input_halfword || !s->matrix_input_row_mask ||
            s->matrix_input_loop || s->matrix_input_low5 || s->matrix_input_gpio ||
            !s->eeprom_gpio_enabled || base > address ||
            base + MSM5XXX_POC_EEPROM_GPIO_SIZE < address + 2 ||
            s->primary_nor_size < 2 || (site & 1) ||
            site > s->primary_nor_size - 2 ||
            site == s->matrix_input_presence_site || site == s->matrix_input_sense_site ||
            (s->experimental_matrix_contact_enabled &&
             site == s->experimental_matrix_contact_site) || owner_conflict || pin_collision) {
            error_report("experimental-matrix-status requires exclusive mapped "
                         "halfword EEPROM read ownership and unowned bit 0x02");
            exit(EXIT_FAILURE);
        }
    }
    if (s->matrix_input_row734) {
        uint32_t sites[] = {s->matrix_input_presence_site, s->matrix_input_sense_site,
            s->matrix_row734_presence2, s->matrix_row734_sense2,
            s->matrix_row734_boot_site};
        uint32_t ports[] = {0x03000720, 0x03000728, 0x0300072c, 0x03000734};
        for (unsigned i = 0; i < ARRAY_SIZE(sites); i++) {
            if (s->primary_nor_size < 4 || sites[i] > s->primary_nor_size - 4) {
                error_report("matrix-row734 source site exceeds primary NOR");
                exit(EXIT_FAILURE);
            }
        }
        for (unsigned i = 0; i < 2; i++) {
            uint64_t address = s->matrix_row734_row_tables[i];
            if (address < s->ram_base || address + 12 >
                (uint64_t)s->ram_base + machine->ram_size) {
                error_report("matrix-row734 row table exceeds RAM");
                exit(EXIT_FAILURE);
            }
        }
        for (unsigned i = 0; i < ARRAY_SIZE(ports); i++) {
            if (s->eeprom_gpio_enabled && s->eeprom_gpio_base < ports[i] + 2 &&
                (uint64_t)s->eeprom_gpio_base + MSM5XXX_POC_EEPROM_GPIO_SIZE > ports[i]) {
                error_report("matrix-row734 conflicts with an EEPROM GPIO owner");
                exit(EXIT_FAILURE);
            }
        }
    }
    /* Final property ordering must preserve GPIO owners and code bounds. */
    if (s->matrix_input_gpio && msm5xxx_poc_matrix_gpio_conflict(s)) {
        error_report("matrix-gpio conflicts with the final memory map");
        exit(EXIT_FAILURE);
    }
    if (s->matrix_input_halfword &&
        (s->matrix_input_descriptor < s->ram_base ||
         (uint64_t)s->matrix_input_descriptor + 0x38 >
             (uint64_t)s->ram_base + machine->ram_size ||
         s->matrix_input_presence_site >= s->primary_nor_size - 2 ||
         s->matrix_input_sense_site >= s->primary_nor_size - 2 ||
         (s->matrix_input_loop &&
          s->matrix_input_contact_site >= s->primary_nor_size - 2) ||
         (s->board_status_input_enabled &&
          s->board_status_input_address >= MSM5XXX_POC_MSM_BASE + 0x72c &&
          s->board_status_input_address < MSM5XXX_POC_MSM_BASE + 0x72e))) {
        error_report("matrix-halfword conflicts with the final memory map");
        exit(EXIT_FAILURE);
    }
    if (s->board_status_input_descriptor &&
        (!s->board_status_input_enabled || !s->matrix_input_halfword ||
         s->matrix_input_low5 || s->matrix_input_row_mask ||
         s->board_status_input_descriptor != s->matrix_input_descriptor ||
         s->board_status_input_address != MSM5XXX_POC_MSM_BASE + 0x720 ||
         s->board_status_input_mask != (s->matrix_input_loop ? 0x10 : 4))) {
        error_report("board-status-descriptor requires matching halfword "
                     "matrix and status GPIO class");
        exit(EXIT_FAILURE);
    }
    /* Status reads use native RAM backing; do not bypass EEPROM GPIO ownership. */
    if (msm5xxx_poc_loop_status_matches(s) && s->eeprom_gpio_enabled &&
        (uint64_t)s->eeprom_gpio_base < MSM5XXX_POC_MSM_BASE + 0x722 &&
        (uint64_t)s->eeprom_gpio_base + MSM5XXX_POC_EEPROM_GPIO_SIZE >
            MSM5XXX_POC_MSM_BASE + 0x720) {
        error_report("loop status conflicts with EEPROM GPIO ownership");
        exit(EXIT_FAILURE);
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
    msm5xxx_poc_protected_realize(s);
    if (s->primary_x16_nor_enabled) {
        DeviceState *dev = qdev_new(TYPE_PFLASH_CFI02);
        unsigned region;

        if (s->whole_primary_x16_enabled) {
            qdev_prop_set_bit(dev, "suspended-ready-dq7", true);
        }

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
        qdev_prop_set_uint16(dev, "id0", s->record_x16_nor_id0);
        qdev_prop_set_uint16(dev, "id1", s->record_x16_nor_id1);
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
    if (s->ram_reserved_size) {
        uint64_t low_size = s->ram_reserved_base - s->ram_base;
        uint64_t high_offset = low_size + s->ram_reserved_size;

        memory_region_init_alias(&s->ram_low_alias, OBJECT(machine),
                                 "msm5xxx-poc.ram-low", machine->ram, 0,
                                 low_size);
        memory_region_init_alias(&s->ram_high_alias, OBJECT(machine),
                                 "msm5xxx-poc.ram-high", machine->ram,
                                 high_offset, machine->ram_size - high_offset);
        memory_region_add_subregion(get_system_memory(), s->ram_base,
                                    &s->ram_low_alias);
        memory_region_add_subregion(get_system_memory(),
                                    (uint64_t)s->ram_base + high_offset,
                                    &s->ram_high_alias);
    } else {
        memory_region_add_subregion(get_system_memory(), s->ram_base,
                                    machine->ram);
    }
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
    if (s->ma5_irq_configured) {
        /* Target-rate clocks qualify only after guest PLL writes infer CLKI. */
        if (!s->ma5_byte_ns || (!s->ma5_clki_hz && !s->ma5_target_rate_hz) ||
            !s->rex_irq_enabled ||
            !s->rex_irq_c80 || s->rex_irq_read_consume ||
            s->rex_irq_status_address != 0x03000c80 ||
            s->rex_irq_enable_address != 0x03000c94 ||
            s->rex_irq_handler_address != (s->ma5_irq_route[MA5R_SOC_DISPATCH] & ~1u) ||
            s->rex_irq_handler_slot != s->ma5_irq_route[MA5R_EXCEPTION_SLOT] ||
            (s->eeprom_gpio_enabled && s->eeprom_gpio_base < 0x03000758 &&
             (uint64_t)s->eeprom_gpio_base + MSM5XXX_POC_EEPROM_GPIO_SIZE > 0x0300074c)) {
            error_report("experimental-ma5-irq-route requires matching MA5/c80 route and exclusive triggers");
            exit(EXIT_FAILURE);
        }
        /* Three GPIO banks share this aperture with two SoC IRQ banks. */
        s->rex_irq_controller_size = MAX(s->rex_irq_controller_size, 0x3a);
        memory_region_init_io(&s->ma5_trigger_region, OBJECT(machine),
                              &msm5xxx_poc_ma5_trigger_ops, s,
                              "msm5xxx-poc.ma5-gpio-trigger", 12);
        memory_region_add_subregion_overlap(get_system_memory(), 0x0300074c,
                                            &s->ma5_trigger_region, 1);
        warn_report("experimental MA5 GPIO/parent IRQ: live callback gates; auxiliary paths unverified");
    }
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
        if (s->rex_irq_c80 && !s->rex_irq_read_consume &&
            !s->rex_irq_arm_address) {
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
    s->sbi_raw_input_realized = true;
    if (s->sbi_raw_input_enabled) {
        if (!msm5xxx_poc_sbi_raw_input_valid(s)) {
            error_report("sbi-raw-input-profile requires full SBI, a byte input "
                         "and a read PC inside primary NOR");
            exit(EXIT_FAILURE);
        }
        qemu_register_reset(msm5xxx_poc_sbi_raw_input_reset, s);
        s->sbi_raw_input_registered = true;
        msm5xxx_poc_sbi_raw_input_reset(s);
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
                              msm5xxx_poc_ma5_shared_lcd_port(s) == (int)i ?
                              &msm5xxx_poc_ma5_shared_lcd_ops :
                              &msm5xxx_poc_lcd_ops, &s->lcd_port[i],
                              "msm5xxx-poc.lcd", MSM5XXX_POC_LCD_SIZE);
        memory_region_add_subregion(get_system_memory(),
                                    msm5xxx_poc_lcd_bases[i],
                                    &s->lcd[i]);
        if (msm5xxx_poc_ma5_shared_lcd_port(s) == (int)i) {
            s->audio_shared_lcd = true;
        }
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
        if (s->board_status_input_enabled) {
            /* Positive capability/readback; old transports ignore kind 10. */
            msm5xxx_poc_board_status_stream_write(s);
        }
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
    s->uart_console_realized = true;
    if (s->uart_console_enabled) {
        memory_region_init_io(&s->uart_console_region, OBJECT(machine),
                              &msm5xxx_poc_uart_console_ops, s,
                              "msm5xxx-poc.uart-console", 0x24);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            s->uart_console_base,
                                            &s->uart_console_region, 2);
        s->uart_console_mapped = true;
        qemu_register_reset(msm5xxx_poc_uart_console_reset, s);
        msm5xxx_poc_uart_console_reset(s);
    }
    if (s->board_status_input_enabled) {
        s->board_status_input_backing =
            s->board_status_input_level & s->board_status_input_mask;
        memory_region_init_io(&s->board_status_input, OBJECT(machine),
                              s->board_status_input_descriptor ?
                                  &msm5xxx_poc_board_status_halfword_ops :
                                  &msm5xxx_poc_board_status_input_ops, s,
                              "msm5xxx-poc.board-status-input",
                              s->board_status_input_descriptor ? 2 : 1);
        memory_region_add_subregion_overlap(
            get_system_memory(), s->board_status_input_address,
            &s->board_status_input, 2
        );
    }
    if (s->matrix_input_enabled) {
        memory_region_init_io(&s->matrix_input, OBJECT(machine),
                              s->matrix_input_halfword ?
                                  &msm5xxx_poc_matrix_halfword_ops :
                                  &msm5xxx_poc_matrix_input_ops, s,
                              "msm5xxx-poc.matrix-input",
                              s->matrix_input_halfword ? 2 : 1);
        memory_region_add_subregion_overlap(
            get_system_memory(), s->matrix_input_address,
            &s->matrix_input, 1
        );
    }
    if (s->audio_packet_clear_pulse && !s->audio_packet_sequence) {
        error_report("audio-packet-clear-pulse requires audio-packet-sequence");
        exit(EXIT_FAILURE);
    }
    if (s->audio_packet_sequence && !s->audio_packet_begin) {
        error_report("audio-packet-sequence requires experimental-audio-packet-bus");
        exit(EXIT_FAILURE);
    }
    if (s->audio_packet_begin) {
        if (!s->memory_profile_enabled || s->audio_enabled ||
            s->audio_packet_begin < 6 || (s->audio_packet_begin & 1) ||
            s->primary_nor_size < 72 ||
            s->audio_packet_begin - 6 > s->primary_nor_size - 72) {
            error_report("experimental-audio-packet-bus requires a primary "
                         "NOR wrapper, memory-profile and no other audio profile");
            exit(EXIT_FAILURE);
        }
        warn_report("experimental audio packet interface: synchronous partial "
                    "register/RAM consumer; timing, queries and renderer unavailable");
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
    if (s->ma5_clki_hz && !s->ma5_byte_ns) {
        error_report("experimental-ma5-clki-hz requires experimental-ma5-byte-ns");
        exit(EXIT_FAILURE);
    }
    if (s->ma5_target_rate_hz &&
        (!s->ma5_byte_ns || s->ma5_clki_hz || s->ma5_target_rate_hz < 8000u ||
         s->ma5_target_rate_hz > 96000u)) {
        error_report("experimental-ma5-target-rate-hz requires byte timing, "
                     "no explicit CLKI, and an 8..96 kHz target");
        exit(EXIT_FAILURE);
    }
    if (s->ma5_pcm_output_enabled &&
        (!s->audio_enabled || !s->audio_ma5 || !s->ma5_byte_ns ||
         !s->audio_sites_enabled || !s->audio_pcm_enabled)) {
        error_report("experimental-ma5-pcm-output requires MA5 byte transport, "
                     "owned audio sites and host PCM enabled");
        exit(EXIT_FAILURE);
    }
    if (s->ma5_clki_hz) {
        warn_report("experimental MA5 counter: supplied CLKI=%" PRIu64
                    " Hz; START-driven empty-FIFO clock is unverified; "
                    "cumulative delayed deadlines and late-packet catchup are "
                    "experimental; no calibrated physical clock", s->ma5_clki_hz);
    }
    if (s->ma5_target_rate_hz) {
        warn_report("temporary MA5 clock inference: runtime PLL bytes derive CLKI "
                    "for target=%" PRIu64 " Hz; not a physical oscillator measurement",
                    s->ma5_target_rate_hz);
    }
    if (s->ma5_byte_ns) {
        bool status_read = false, data_read = false;

        for (unsigned site = 0; site < s->audio_site_count; site++) {
            status_read |= !s->audio_site_write[site] && !s->audio_site_port[site];
            data_read |= !s->audio_site_write[site] &&
                         s->audio_site_port[site] == s->audio_data_offset;
        }
        if (!s->audio_enabled || !s->audio_ma5 || !s->audio_sites_enabled ||
            !status_read || !data_read || s->experimental_audio_readback) {
            error_report("experimental-ma5-byte-ns requires MA5 byte "
                         "index/data read/write sites and exclusive readback");
            exit(EXIT_FAILURE);
        }
        if (s->ma5_target_rate_hz) {
            warn_report("temporary MA5 class: byte service period=%" PRIu64
                        " ns; PLL-derived CLKI targets %" PRIu64
                        " Hz, both uncalibrated; unsupported PLL/readback falls back",
                        s->ma5_byte_ns, s->ma5_target_rate_hz);
        } else {
            warn_report("experimental MA5: service period=%" PRIu64 " ns; "
                        "uncalibrated byte scheduling, cold reset only, "
                        "B1 requires supplied or inferred CLKI; GPIO IRQ needs separate route; "
                        "WT PCM only under separate opt-in", s->ma5_byte_ns);
        }
        s->ma5_audio_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                         msm5xxx_poc_ma5_audio_tick, s);
    } else if (s->audio_ma5 && s->audio_base != 0x02840000) {
        error_report("unqualified MA5 aperture requires experimental-ma5-byte-ns");
        exit(EXIT_FAILURE);
    }
    if (s->experimental_audio_readback) {
        bool status_read = false, data_read = false;
        unsigned index;
        for (index = 0; index < s->audio_site_count; index++) {
            status_read |= !s->audio_site_write[index] &&
                           s->audio_site_port[index] == 0;
            data_read |= !s->audio_site_write[index] &&
                         s->audio_site_port[index] == s->audio_data_offset;
        }
        if (!s->audio_enabled || s->audio_ma2 || !s->audio_sites_enabled ||
            !status_read || !data_read) {
            error_report("experimental-audio-readback requires an opaque "
                         "audio aperture and index/data read/write sites");
            exit(EXIT_FAILURE);
        }
        warn_report("experimental audio readback: inferred reset values and "
                    "synchronous capacity; unknown results remain rejected");
    }
    if (s->audio_enabled && !s->audio_ma2 && !s->audio_sites_enabled) {
        error_report("opaque audio-aperture requires audio-sites");
        exit(EXIT_FAILURE);
    }
    if (s->audio_enabled) {
        bool ma5_pcm_output = s->audio_ma5 && s->ma5_pcm_output_enabled &&
                              s->audio_sites_enabled;

        if ((s->audio_ma2 && s->audio_sites_enabled) || ma5_pcm_output) {
            struct audsettings settings = {
                MSM5XXX_AUDIO_SAMPLE_RATE, 2, AUDIO_FORMAT_S16, 0
            };

            qemu_mutex_init(&s->audio_synth_lock);
            qemu_mutex_init(&s->audio_core_lock);
            s->audio_synth_lock_initialized = true;
            s->audio_core_lock_initialized = true;
            if (ma5_pcm_output) {
                if (msm5xxx_ma5_pcm_output_init(
                        &s->ma5_pcm_output, &s->ma5_pcm_storage[0][0],
                        MSM5XXX_AUDIO_MAX_FRAMES) != MSM5XXX_MA5_PCM_OK) {
                    warn_report("experimental MA5 PCM queue initialization failed; "
                                "MA5 device remains enabled");
                    s->ma5_pcm_output_enabled = false;
                } else {
                    s->ma5_pcm_initialized = true;
                    s->ma5_wt_engine = ma5_wt_engine_new(
                        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                        msm5xxx_poc_ma5_pcm_emit, s);
                    if (!s->ma5_wt_engine) {
                        warn_report("experimental MA5 WT renderer allocation failed; "
                                    "MA5 device remains enabled");
                        s->ma5_pcm_output_enabled = false;
                        s->ma5_pcm_initialized = false;
                    }
                }
            }
            if (s->audio_pcm_enabled && !s->audio_stream_chardev &&
                (!ma5_pcm_output || s->ma5_pcm_initialized)) {
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
            if (s->audio_ma2) {
                s->ma2_audio_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                                  msm5xxx_poc_ma2_audio_tick, s);
            }
        }
        if (!s->audio_ma2 && !s->audio_shared_lcd) {
            if (upper_nor_enabled &&
                s->audio_base < MSM5XXX_POC_UPPER_NOR_BASE +
                                MSM5XXX_POC_UPPER_NOR_SIZE &&
                (uint64_t)s->audio_base + s->audio_data_offset + 1 >
                    MSM5XXX_POC_UPPER_NOR_BASE) {
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
    if (s->search2_probe_description || s->search2_virtual_description) {
        const unsigned code_fields[] = {0, 1, 3, 4, 6, 7};
        const unsigned code_sizes[] = {36, 22, 0x32, 0x80, 0x174, 0x260};

        if (!s->memory_profile_enabled || !s->rex_irq_enabled ||
            s->rex_irq_c80 || s->rex_irq_read_consume ||
            s->rex_irq_status_address != 0x03000620 ||
            s->rex_irq_enable_address != 0x03000628) {
            error_report("search2-probe requires the legacy native W1C controller");
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < G_N_ELEMENTS(code_fields); i++) {
            uint32_t pc = s->search2_route[code_fields[i]];

            if (pc & 1 || pc >= s->primary_nor_size ||
                code_sizes[i] > s->primary_nor_size - pc) {
                error_report("search2-probe code outside primary NOR");
                exit(EXIT_FAILURE);
            }
        }
        for (i = 2; i <= 5; i += 3) {
            uint32_t slot = s->search2_route[i];

            if (slot & 3 || slot < s->ram_base || machine->ram_size < 4 ||
                slot - s->ram_base > machine->ram_size - 4) {
                error_report("search2-probe slot outside RAM");
                exit(EXIT_FAILURE);
            }
        }
        s->search2_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       msm5xxx_poc_search2_complete, s);
        memory_region_init_io(&s->search2_region, OBJECT(machine),
                              &msm5xxx_poc_search2_ops, s,
                              "msm5xxx-poc.search2-probe", 0x1c);
        memory_region_add_subregion_overlap(get_system_memory(), 0x03000800,
                                            &s->search2_region, 1);
    }
    if (s->search1_enabled) {
        if (!s->search2_virtual || !s->search2_timer ||
            s->search1_first_store < 4 || (s->search1_first_store & 1) ||
            s->search1_first_store >= s->primary_nor_size ||
            s->primary_nor_size - s->search1_first_store < 176 ||
            (s->search1_result_loop & 1) ||
            s->search1_result_loop >= s->primary_nor_size ||
            s->primary_nor_size - s->search1_result_loop < 24 ||
            (s->search1_abort_pc && (s->search1_abort_pc < 0x3e ||
             (s->search1_abort_pc & 1) || s->search1_result_loop < 0x26 ||
             s->search1_abort_pc >= s->primary_nor_size ||
             s->primary_nor_size - s->search1_abort_pc < 0x3e))) {
            error_report("search1-virtual requires search2-virtual and bounded primary-NOR code");
            exit(EXIT_FAILURE);
        }
        s->search1_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       msm5xxx_poc_search1_complete, s);
        memory_region_init_io(&s->search1_region, OBJECT(machine),
                              &msm5xxx_poc_search1_ops, s,
                              "msm5xxx-poc.search1-virtual", 0x50);
        memory_region_add_subregion_overlap(get_system_memory(), 0x03000000,
                                            &s->search1_region, 1);
    }
    if (s->finger_enabled) {
        if (!s->memory_profile_enabled || !s->search2_virtual ||
            s->finger_read_pc < 56 || (s->finger_read_pc & 1) ||
            s->finger_read_pc >= s->primary_nor_size ||
            s->primary_nor_size - s->finger_read_pc < 68 ||
            (s->finger_masks_i & 1) || (s->finger_masks_q & 1) ||
            s->finger_masks_i >= s->primary_nor_size ||
            s->finger_masks_q >= s->primary_nor_size ||
            s->primary_nor_size - s->finger_masks_i < 1024 ||
            s->primary_nor_size - s->finger_masks_q < 1024) {
            error_report("finger-virtual requires search2-virtual and bounded getter/mask tables");
            exit(EXIT_FAILURE);
        }
        memory_region_init_io(&s->finger_region, OBJECT(machine),
                              &msm5xxx_poc_fingers_ops, s,
                              "msm5xxx-poc.finger-virtual", 0x60);
        memory_region_add_subregion_overlap(get_system_memory(), 0x03000060,
                                            &s->finger_region, 1);
    }
    if (s->decoder_init_enabled) {
        uint32_t pcs[] = {s->decoder_init_reader, s->decoder_init_write_pc,
                          s->decoder_init_isr};
        unsigned spans[] = {20, 2, 0x5a};

        if (!s->memory_profile_enabled || !s->search2_virtual ||
            !s->search2_timer || s->decoder_init_write_pc < 0x24) {
            error_report("decoder-init-probe requires search2-virtual and bounded NOR code");
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < G_N_ELEMENTS(pcs); i++) {
            if (pcs[i] & 1 || pcs[i] >= s->primary_nor_size ||
                s->primary_nor_size - pcs[i] < spans[i]) {
                error_report("decoder-init-probe code outside primary NOR");
                exit(EXIT_FAILURE);
            }
        }
        s->decoder_init_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                             msm5xxx_poc_decoder_init_complete, s);
        memory_region_init_io(&s->decoder_init_region, OBJECT(machine),
                              &msm5xxx_poc_decoder_init_ops, s,
                              "msm5xxx-poc.decoder-init-probe", 4);
        memory_region_add_subregion_overlap(get_system_memory(), 0x03000a08,
                                            &s->decoder_init_region, 1);
    }
    if (s->decoder_sync_enabled) {
        if (!s->decoder_init_timer || s->decoder_init_delay_ns != 80000000 ||
            (s->combiner_position_reader & 1) ||
            s->combiner_position_reader >= s->primary_nor_size ||
            s->primary_nor_size - s->combiner_position_reader < 40 ||
            (s->combiner_roll_isr & 1) || s->combiner_roll_isr >= s->primary_nor_size ||
            s->primary_nor_size - s->combiner_roll_isr < 0x2a8 ||
            (s->decoder_sync_consumer & 1) || s->decoder_sync_consumer >= s->primary_nor_size ||
            s->primary_nor_size - s->decoder_sync_consumer < 0x70) {
            error_report("decoder-sync-source requires bounded getter/ISR and 80ms decoder-init-probe");
            exit(EXIT_FAILURE);
        }
        memory_region_init_io(&s->combiner_position_region, OBJECT(machine),
                              &msm5xxx_poc_combiner_position_ops, s,
                              "msm5xxx-poc.combiner-position", 12);
        memory_region_add_subregion_overlap(get_system_memory(), 0x030000f4,
                                            &s->combiner_position_region, 1);
        memory_region_init_io(&s->decoder_output_region, OBJECT(machine),
                              &msm5xxx_poc_decoder_output_ops, s,
                              "msm5xxx-poc.decoder-output", 0x1c);
        memory_region_add_subregion_overlap(get_system_memory(), 0x03000a58,
                                            &s->decoder_output_region, 1);
    }
    if (s->decoder_paging_enabled) {
        uint32_t pcs[] = {s->decoder_paging_isr, s->decoder_paging_reader,
                          s->decoder_paging_status, s->decoder_paging_initializer,
                          s->decoder_paging_consumer, s->decoder_paging_layout};
        unsigned spans[] = {0x1ec, 22, 24, 0x52, 0xca, 32};

        if (!s->decoder_sync_enabled || s->decoder_paging_count & 1 ||
            s->decoder_paging_count < s->ram_base ||
            s->decoder_paging_count - s->ram_base > machine->ram_size ||
            machine->ram_size - (s->decoder_paging_count - s->ram_base) < 2 ||
            s->decoder_paging_layout < 6 || s->decoder_paging_cache < s->ram_base ||
            s->decoder_paging_cache - s->ram_base > machine->ram_size ||
            machine->ram_size - (s->decoder_paging_cache - s->ram_base) < 0x60) {
            error_report("decoder-paging-source requires sync source and bounded RAM word count");
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < G_N_ELEMENTS(pcs); i++) {
            if (pcs[i] & 1 || pcs[i] >= s->primary_nor_size ||
                s->primary_nor_size - pcs[i] < spans[i]) {
                error_report("decoder-paging-source code outside primary NOR");
                exit(EXIT_FAILURE);
            }
        }
    }
    if (s->decoder_traffic_enabled) {
        const unsigned code_fields[] = {0, 1, 2, 3, 6, 7};
        const unsigned spans[] = {0x5f6, 146, 120, 166, 48, 20};
        const unsigned ram_fields[] = {4, 5}, ram_spans[] = {4, 48};
        uint32_t *r = s->decoder_traffic_route;
        if (!s->decoder_paging_enabled || !s->decoder_sync_enabled ||
            !s->access_assignment_code) {
            error_report("decoder-traffic-source requires paging, sync and access assignment");
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < G_N_ELEMENTS(code_fields); i++) {
            uint32_t pc = r[code_fields[i]];
            if ((pc & 1) || pc > s->primary_nor_size ||
                s->primary_nor_size - pc < spans[i]) {
                error_report("decoder-traffic-source outside primary NOR");
                exit(EXIT_FAILURE);
            }
        }
        for (i = 0; i < G_N_ELEMENTS(ram_fields); i++) {
            uint32_t address = r[ram_fields[i]];
            if (address < s->ram_base || address - s->ram_base > machine->ram_size ||
                machine->ram_size - (address - s->ram_base) < ram_spans[i]) {
                error_report("decoder-traffic-source outside RAM");
                exit(EXIT_FAILURE);
            }
        }
    }
    if (s->decoder_traffic_frame_enabled && !s->decoder_traffic_enabled) {
        error_report("decoder-traffic-frame requires decoder-traffic-source");
        exit(EXIT_FAILURE);
    }
    if (s->decoder_traffic_response_enabled && (!s->tx_fifo_enabled || !s->tx_frame_period_ns)) {
        error_report("decoder-traffic-response requires the bounded TX FIFO class");
        exit(EXIT_FAILURE);
    }
    if (s->traffic_service_enabled && (!s->access_response_probe || !s->access_assignment_code ||
        !s->decoder_traffic_enabled || !msm5xxx_poc_traffic_service_addresses(s))) {
        error_report("traffic-service-source requires a matched packet/decoder/encoder class");
        exit(EXIT_FAILURE);
    }
    if (s->access_assignment_code && !s->access_response_probe) {
        error_report("access-assignment-code requires access-response-probe");
        exit(EXIT_FAILURE);
    }
    if (s->access_response_probe && (!s->tx_fifo_enabled || !s->tx_frame_period_ns)) {
        error_report("access-response-probe requires the bounded TX FIFO class");
        exit(EXIT_FAILURE);
    }
    if (s->access_response_probe && !msm5xxx_poc_access_response_layout(s)) {
        error_report("access-response-probe requires the legacy paging layout");
        exit(EXIT_FAILURE);
    }
    if (s->tx_init_enabled) {
        const unsigned code_fields[] = {0, 4, 5, 6};
        const unsigned spans[] = {0x24, 4, 4, 4};
        const unsigned ram_fields[] = {1, 2, 3};
        const unsigned ram_spans[] = {4, 16, 4};

        if (!s->decoder_paging_enabled || !s->search2_virtual ||
            s->tx_init_route[4] < 8 || s->tx_init_route[6] < 4 ||
            s->tx_init_route[1] < s->ram_base ||
            s->tx_init_route[1] - s->ram_base < 20) {
            error_report("tx-init-probe requires paging source and bounded callback context");
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < G_N_ELEMENTS(code_fields); i++) {
            uint32_t pc = s->tx_init_route[code_fields[i]];
            if ((pc & 1) || pc >= s->primary_nor_size ||
                s->primary_nor_size - pc < spans[i]) {
                error_report("tx-init-probe code outside primary NOR");
                exit(EXIT_FAILURE);
            }
        }
        for (i = 0; i < G_N_ELEMENTS(ram_fields); i++) {
            uint32_t address = s->tx_init_route[ram_fields[i]];
            if (address < s->ram_base || address - s->ram_base > machine->ram_size ||
                machine->ram_size - (address - s->ram_base) < ram_spans[i] ||
                (ram_fields[i] != 2 && (address & 3))) {
                error_report("tx-init-probe state outside mapped RAM");
                exit(EXIT_FAILURE);
            }
        }
        if (s->tx_fifo_enabled) {
            if ((s->tx_fifo_mode_base & 3) || s->tx_fifo_mode_base > UINT32_MAX - 15 ||
                s->tx_fifo_mode_base < s->ram_base ||
                machine->ram_size < 16 ||
                s->tx_fifo_mode_base - s->ram_base > machine->ram_size - 16 ||
                (s->tx_fifo_writer & 1) || s->tx_fifo_writer >= s->primary_nor_size ||
                s->primary_nor_size - s->tx_fifo_writer < 38) {
                error_report("tx-init-probe FIFO class outside mapped code/state");
                exit(EXIT_FAILURE);
            }
            msm5xxx_access_init(&s->tx_access);
            memory_region_init_io(&s->tx_fifo_region, OBJECT(machine),
                                  &msm5xxx_poc_tx_fifo_ops, s,
                                  "msm5xxx-poc.encoder-fifo", 2);
            memory_region_add_subregion_overlap(get_system_memory(), 0x03000298,
                                                &s->tx_fifo_region, 1);
        }
        s->tx_init_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       msm5xxx_poc_tx_init_fire, s);
    }
    memory_region_init_io(&s->mmio, OBJECT(machine), &msm5xxx_poc_ops, s,
                          "msm5xxx-poc.mmio", MSM5XXX_POC_MMIO_SIZE);
    memory_region_add_subregion(get_system_memory(), MSM5XXX_POC_MMIO_BASE,
                                &s->mmio);
    msm5xxx_poc_small_nand_init(machine, s, &error_fatal);
    msm5xxx_poc_spi_nv_init(machine, s, &error_fatal);
    msm5xxx_poc_boot_keysense_init(machine, s, &error_fatal);
    if (s->uart_console_rearm_enabled) {
        if (!msm5xxx_poc_uart_rearm_valid(s)) {
            error_report("uart-console-rearm requires FF/DD and an exclusive passive MSM RAM CR underlay");
            exit(EXIT_FAILURE);
        }
        memory_region_init_io(&s->uart_console_rearm_region, OBJECT(machine),
            &msm5xxx_poc_uart_rearm_ops, s, "msm5xxx-poc.uart-console-rearm", 4);
        memory_region_set_enabled(&s->uart_console_rearm_region, false);
        memory_region_add_subregion_overlap(get_system_memory(),
            s->uart_console_base + 0x10, &s->uart_console_rearm_region, 3);
        s->uart_console_rearm_mapped = true;
    }
    if (s->dmd5100_enabled) {
        if (!msm5xxx_poc_dmd5100_topology(s)) {
            error_report("dmd5100-program requires readonly source metadata and exclusive passive MSM RAM ports");
            exit(EXIT_FAILURE);
        }
        s->dmd5100_ram_verified = true;
        s->dmd5100_even = g_new0(uint16_t, s->dmd5100_count);
        s->dmd5100_odd = g_new0(uint16_t, s->dmd5100_count);
        for (unsigned index = 0; index < 5; index++) {
            s->dmd5100_port[index] = (MSM5xxxPOCDMD5100Port){s, index};
            memory_region_init_io(&s->dmd5100_region[index], OBJECT(machine),
                &msm5xxx_poc_dmd5100_ops, &s->dmd5100_port[index], "msm5xxx-poc.dmd5100", 4);
            memory_region_set_enabled(&s->dmd5100_region[index], false);
            memory_region_add_subregion_overlap(get_system_memory(), dmd5100_ports[index],
                &s->dmd5100_region[index], 3);
        }
        s->dmd5100_mapped = true;
        qemu_register_reset(msm5xxx_poc_dmd5100_reset, s);
        msm5xxx_poc_dmd5100_reset(s);
    }
    if (s->watchdog_register || s->watchdog_mask) {
        if (!msm5xxx_poc_watchdog_valid(s)) {
            error_report("watchdog requires memory-profile, MSM pulse port, single byte mask and timeout 1..3600000 ms");
            exit(EXIT_FAILURE);
        }
        s->watchdog_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                         msm5xxx_poc_watchdog_expire, s);
        memory_region_init_io(&s->watchdog_region, OBJECT(machine),
            &msm5xxx_poc_watchdog_ops, s, "msm5xxx-poc.watchdog", 1);
        memory_region_add_subregion_overlap(get_system_memory(),
            s->watchdog_register, &s->watchdog_region, 4);
        qemu_register_reset(msm5xxx_poc_watchdog_reset, s);
        msm5xxx_poc_watchdog_reset(s);
    }
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

static bool msm5xxx_poc_get_ma5_pcm_output(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->ma5_pcm_output_enabled;
}

static void msm5xxx_poc_set_ma5_pcm_output(Object *obj, bool value, Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->ma5_pcm_output_enabled = value;
}

static bool msm5xxx_poc_get_audio_readback(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->experimental_audio_readback;
}

static void msm5xxx_poc_set_audio_readback(Object *obj, bool value, Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->experimental_audio_readback = value;
}

static char *msm5xxx_poc_get_ma5_byte_ns(Object *obj, Error **errp)
{
    return g_strdup_printf("%" PRIu64,
                           MSM5XXX_POC_MACHINE(obj)->ma5_byte_ns);
}

static void msm5xxx_poc_set_ma5_byte_ns(Object *obj, const char *value,
                                       Error **errp)
{
    const char *end;
    uint64_t period;

    if (!value || !g_ascii_isdigit(value[0]) ||
        qemu_strtou64(value, &end, 10, &period) < 0 || *end ||
        !period || period > 1000000000u) {
        error_setg(errp, "experimental-ma5-byte-ns requires 1..1000000000 ns");
        return;
    }
    MSM5XXX_POC_MACHINE(obj)->ma5_byte_ns = period;
}

static char *msm5xxx_poc_get_ma5_clki_hz(Object *obj, Error **errp)
{
    return g_strdup_printf("%" PRIu64,
                           MSM5XXX_POC_MACHINE(obj)->ma5_clki_hz);
}

static void msm5xxx_poc_set_ma5_clki_hz(Object *obj, const char *value,
                                      Error **errp)
{
    const char *end;
    uint64_t hz;

    if (!value || !g_ascii_isdigit(value[0]) ||
        qemu_strtou64(value, &end, 10, &hz) < 0 || *end ||
        !hz || hz > 1000000000u) {
        error_setg(errp, "experimental-ma5-clki-hz requires 1..1000000000 Hz");
        return;
    }
    MSM5XXX_POC_MACHINE(obj)->ma5_clki_hz = hz;
}

static char *msm5xxx_poc_get_ma5_target_rate_hz(Object *obj, Error **errp)
{
    return g_strdup_printf("%" PRIu64,
                           MSM5XXX_POC_MACHINE(obj)->ma5_target_rate_hz);
}

static void msm5xxx_poc_set_ma5_target_rate_hz(Object *obj, const char *value,
                                               Error **errp)
{
    const char *end;
    uint64_t hz;

    if (!value || !g_ascii_isdigit(value[0]) ||
        qemu_strtou64(value, &end, 10, &hz) < 0 || *end ||
        hz < 8000u || hz > 96000u) {
        error_setg(errp, "experimental-ma5-target-rate-hz requires 8000..96000 Hz");
        return;
    }
    MSM5XXX_POC_MACHINE(obj)->ma5_target_rate_hz = hz;
}

static char *msm5xxx_poc_get_ma5_irq_route(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    GString *text = g_string_new("");

    if (s->ma5_irq_configured) {
        for (unsigned i = 0; i < MA5R_COUNT; i++) {
            g_string_append_printf(text, "%s%x", i ? ":" : "", s->ma5_irq_route[i]);
        }
    }
    return g_string_free(text, false);
}

static void msm5xxx_poc_set_ma5_irq_route(Object *obj, const char *value,
                                         Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) parts = g_strsplit(value ? value : "", ":", -1);
    uint32_t r[MA5R_COUNT];

    if (g_strv_length(parts) != MA5R_COUNT) {
        error_setg(errp, "experimental-ma5-irq-route requires 18 hex fields");
        return;
    }
    for (unsigned i = 0; i < MA5R_COUNT; i++) {
        const char *end;
        uint64_t number;
        if (!g_ascii_isxdigit(parts[i][0]) ||
            qemu_strtou64(parts[i], &end, 16, &number) < 0 || *end ||
            number > UINT32_MAX) {
            error_setg(errp, "invalid experimental-ma5-irq-route field");
            return;
        }
        r[i] = number;
    }
    if (r[MA5R_PIN] >= 48 || r[MA5R_STATUS] != 0x03000c84 ||
        r[MA5R_ENABLE] != 0x03000c98 || !r[MA5R_MASK] ||
        r[MA5R_MASK] > 0x8000 || (r[MA5R_MASK] & (r[MA5R_MASK] - 1)) ||
        ((r[MA5R_TABLE] | r[MA5R_CALLBACKS] | r[MA5R_DESCRIPTOR] |
          r[MA5R_EXCEPTION_SLOT] | r[MA5R_CONTEXT]) & 3) ||
        ((r[MA5R_SHADOW] | r[MA5R_PRIORITY]) & 1) ||
        (!!r[MA5R_DEFERRED] != !!(r[MA5R_SELECT] && r[MA5R_OVERRIDE])) ||
        (!r[MA5R_DEFERRED] && (r[MA5R_SELECT] || r[MA5R_OVERRIDE])) ||
        (!r[MA5R_INSTALLED] && r[MA5R_DEFERRED])) {
        error_setg(errp, "MA5 IRQ route outside three-bank GPIO/parent class");
        return;
    }
    for (unsigned i = MA5R_GPIO_DISPATCH; i <= MA5R_DEFERRED; i++) {
        if (i == MA5R_EXCEPTION_SLOT || (i == MA5R_DEFERRED && !r[i])) {
            continue;
        }
        if (!(r[i] & 1) || r[i] >= 0x02000000) {
            error_setg(errp, "MA5 IRQ route requires bounded Thumb callbacks");
            return;
        }
    }
    memcpy(s->ma5_irq_route, r, sizeof(r));
    s->ma5_irq_configured = true;
}

static char *msm5xxx_poc_get_audio_packet_bus(Object *obj, Error **errp)
{
    return g_strdup_printf("%x", MSM5XXX_POC_MACHINE(obj)->audio_packet_begin);
}

static void msm5xxx_poc_set_audio_packet_bus(Object *obj, const char *value,
                                           Error **errp)
{
    const char *end;
    uint64_t begin;

    if (!value || !g_ascii_isxdigit(value[0]) ||
        qemu_strtou64(value, &end, 16, &begin) < 0 || *end ||
        begin > UINT32_MAX || (begin & 1) || (begin && begin < 6)) {
        error_setg(errp, "experimental-audio-packet-bus requires an even hex "
                   "wrapper access address, or 0 to disable");
        return;
    }
    MSM5XXX_POC_MACHINE(obj)->audio_packet_begin = begin;
}

static bool msm5xxx_poc_get_audio_packet_sequence(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->audio_packet_sequence;
}

static void msm5xxx_poc_set_audio_packet_sequence(Object *obj, bool value,
                                                Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    s->audio_packet_sequence = value;
    s->audio_packet_ready = s->audio_packet_reset_armed = false;
    s->audio_packet_clear_armed = false;
}

static bool msm5xxx_poc_get_audio_packet_clear_pulse(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->audio_packet_clear_pulse;
}

static void msm5xxx_poc_set_audio_packet_clear_pulse(Object *obj, bool value,
                                                   Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    s->audio_packet_clear_pulse = value;
    s->audio_packet_clear_armed = false;
}

static void msm5xxx_poc_set_sbi(Object *obj, bool value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (s->sbi_raw_input_enabled && !value) {
        error_setg(errp, "sbi-raw-input-profile requires sbi=on");
        return;
    }
    s->sbi_enabled = value;
}

static char *msm5xxx_poc_get_sbi_raw_input_profile(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->sbi_raw_input_enabled ?
        g_strdup_printf("%x:%x:%x", s->sbi_raw_input_pc,
                        s->sbi_raw_input_mask, s->sbi_raw_input_value) :
        g_strdup("");
}

static void msm5xxx_poc_set_sbi_raw_input_profile(Object *obj, const char *value,
                                                 Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned long fields[3];
    const char *part = value, *end;
    unsigned i;

    if (s->sbi_raw_input_realized || s->sbi_raw_input_enabled) {
        error_setg(errp, "sbi-raw-input-profile is immutable after configuration or initialization");
        return;
    }
    if (!*value) {
        return;
    }
    for (i = 0; i < 3; i++) {
        if (!g_ascii_isxdigit(*part) ||
            qemu_strtoul(part, &end, 16, &fields[i]) ||
            (i < 2 ? *end != ':' : *end != '\0')) {
            goto malformed;
        }
        part = end + (i < 2);
    }
    if (fields[0] > UINT32_MAX || fields[0] & 1 ||
        fields[1] < 1 || fields[1] > 0x7f || fields[2] & ~fields[1]) {
        goto malformed;
    }
    s->sbi_raw_input_pc = fields[0];
    s->sbi_raw_input_mask = fields[1];
    s->sbi_raw_input_value = fields[2];
    s->sbi_raw_input_enabled = true;
    return;

malformed:
    error_setg(errp, "sbi-raw-input-profile requires READ_PC:MASK:VALUE, "
                     "an even 32-bit PC and mask 1..7f/value within mask");
}

static char *msm5xxx_poc_get_sbi_raw_input_status(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return g_strdup_printf(
        "{\"configured\":%s,\"policy\":\"configured-virtual-raw-byte-uncalibrated\","
        "\"pc\":%u,\"mask\":%u,\"value\":%u,\"lastreadpc\":%u,"
        "\"rejectreason\":\"%s\",\"responsecount\":%" G_GUINT64_FORMAT "}",
        s->sbi_raw_input_enabled ? "true" : "false", s->sbi_raw_input_pc,
        s->sbi_raw_input_mask, s->sbi_raw_input_value, s->sbi_raw_input_last_pc,
        s->sbi_raw_input_reject_reason ? s->sbi_raw_input_reject_reason : "",
        s->sbi_board_adc_responses);
}

static bool msm5xxx_poc_get_sbi_bootstrap_only(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->sbi_bootstrap_only;
}

static void msm5xxx_poc_set_sbi_bootstrap_only(Object *obj, bool value,
                                                Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (s->sbi_raw_input_enabled && value) {
        error_setg(errp, "sbi-raw-input-profile excludes bootstrap-only mode");
        return;
    }
    s->sbi_bootstrap_only = value;
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
        const MSM5xxxPOCReadyPollSite *site = &s->ready_poll_sites[index];

        g_string_append_printf(value, "%s%x", index ? ";" : "",
                               site->entry);
        if (s->ready_poll_sites_explicit) {
            g_string_append_printf(value, ",%x,%x,%x", site->read_offset,
                                   site->set_offset, site->clear_offset);
            if (site->rx_empty_offset) {
                g_string_append_printf(value, ",%x", site->rx_empty_offset);
                if (site->rx_frame_offset) {
                    g_string_append_printf(value, ",%x", site->rx_frame_offset);
                }
            }
        }
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
    MSM5xxxPOCReadyPollSite sites[MSM5XXX_POC_READY_POLL_MAX_SITES] = { 0 };
    size_t count;
    size_t index;
    bool explicit;
    bool uart = false;

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
    explicit = strchr(entries[0], ',') != NULL;
    for (index = 0; index < count; index++) {
        g_auto(GStrv) tuple = g_strsplit(entries[index], ",", -1);
        size_t length = g_strv_length(tuple);
        uint32_t values[6] = { 0, 2, 12, 16, 0, 0 };
        uint32_t max_offset;
        size_t field;
        size_t prior;

        if ((!explicit && length != 1) ||
            (explicit && (length < 4 || length > 6))) {
            goto invalid;
        }
        for (field = 0; field < length; field++) {
            const char *end;
            unsigned long number;

            if (!*tuple[field] ||
                qemu_strtoul(tuple[field], &end, 16, &number) < 0 ||
                *end || number > UINT32_MAX || (number & 1)) {
                goto invalid;
            }
            values[field] = (uint32_t)number;
        }
        max_offset = MAX(values[1], MAX(values[2], values[3]));
        max_offset = MAX(max_offset, MAX(values[4], values[5]));
        if (values[0] > s->primary_nor_size - 22 ||
            values[2] >= values[3] || values[1] == values[2] ||
            values[1] == values[3] || max_offset > 0x1000 ||
            max_offset + 2 > s->primary_nor_size ||
            values[0] > s->primary_nor_size - max_offset - 2 ||
            (length >= 5 && (parsed[1] != 8 || values[4] <= values[3] ||
                             values[4] == values[1])) ||
            (length == 6 && (values[5] <= values[4] ||
                            values[5] == values[1]))) {
            goto invalid;
        }
        sites[index] = (MSM5xxxPOCReadyPollSite) {
            .entry = values[0], .read_offset = values[1],
            .set_offset = values[2], .clear_offset = values[3],
            .rx_empty_offset = values[4], .rx_frame_offset = values[5],
        };
        uart |= length >= 5;
        for (prior = 0; prior < index; prior++) {
            if (sites[prior].entry == sites[index].entry) {
                goto invalid;
            }
            if (explicit) {
                const uint32_t prior_offsets[] = {
                    sites[prior].read_offset, sites[prior].set_offset,
                    sites[prior].clear_offset, sites[prior].rx_empty_offset,
                    sites[prior].rx_frame_offset,
                };
                size_t left;
                size_t right;

                for (left = 1; left < length; left++) {
                    for (right = 0; right < G_N_ELEMENTS(prior_offsets); right++) {
                        if ((right < 3 || prior_offsets[right]) &&
                            sites[index].entry + values[left] ==
                            sites[prior].entry + prior_offsets[right]) {
                            goto invalid;
                        }
                    }
                }
            }
        }
    }
    s->ready_status_address = parsed[0];
    s->ready_status_mask = parsed[1];
    s->ready_pulse_address = parsed[2];
    memcpy(s->ready_poll_sites, sites, count * sizeof(sites[0]));
    s->ready_poll_site_count = (unsigned)count;
    s->ready_poll_sites_explicit = explicit;
    s->ready_poll_entry = sites[0].entry;
    s->ready_poll_active_entry = sites[0].entry;
    s->ready_status_pc_offset = sites[0].read_offset;
    s->ready_pulse_set_pc_offset = sites[0].set_offset;
    s->ready_pulse_clear_pc_offset = sites[0].clear_offset;
    s->ready_poll_active_set_offset = sites[0].set_offset;
    s->ready_poll_active_clear_offset = sites[0].clear_offset;
    s->ready_uart_rx_empty_read_pc_offset = sites[0].rx_empty_offset;
    s->ready_uart_rx_empty_frame_read_pc_offset = sites[0].rx_frame_offset;
    s->ready_uart_rx_empty_enabled = uart;
    s->ready_poll_enabled = true;
    return;

invalid:
    error_setg(errp,
               "ready-poll-sites must be STATUS:ONE_BIT_MASK:PULSE:"
               "SITE;SITE[;SITE...] for 2..%u unique even sites; SITE is ENTRY"
               " or ENTRY,READ_OFF,SET_OFF,CLEAR_OFF[,RX_OFF[,RX_FRAME_OFF]]",
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

    if (!s->primary_x16_nor_enabled || s->whole_primary_x16_enabled) {
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
    if (s->record_x16_nor_explicit_ids) {
        return g_strdup_printf("%x:%x:%x:%x:%x", s->record_x16_nor_base,
                               s->record_x16_nor_size,
                               s->record_x16_nor_sector_size,
                               s->record_x16_nor_id0,
                               s->record_x16_nor_id1);
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

static char *msm5xxx_poc_get_matrix_row734(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    (void)errp;
    return s->matrix_input_row734 ?
        g_strdup_printf("%x:%x:%x:%x:%x:%x:%x:%x", s->matrix_input_descriptor,
            s->matrix_input_presence_site, s->matrix_input_sense_site,
            s->matrix_row734_presence2, s->matrix_row734_sense2,
            s->matrix_row734_boot_site, s->matrix_row734_row_tables[0],
            s->matrix_row734_row_tables[1]) : g_strdup("");
}

static char *msm5xxx_poc_get_matrix_row734_state(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    (void)errp;
    return g_strdup_printf("{\"configured\":%s,\"boot_seen\":%s,"
        "\"boot_reads\":%" PRIu64 ",\"normal_reads\":%" PRIu64
        ",\"active_reads\":%" PRIu64 ",\"rejections\":%" PRIu64
        ",\"reason\":%u}", s->matrix_input_row734 ? "true" : "false",
        s->matrix_row734_boot_seen ? "true" : "false",
        s->matrix_row734_boot_reads, s->matrix_row734_normal_reads,
        s->matrix_input_active_reads, s->matrix_input_rejections,
        s->matrix_row734_reason);
}

static void msm5xxx_poc_set_matrix_row734(Object *obj, const char *value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint32_t v[8];
    unsigned i, j;
    if (s->cpu || s->matrix_input_enabled || s->board_status_input_enabled ||
        s->board_status_input_descriptor ||
        !msm5xxx_poc_boot_storage_hex(value, v, 8) || !v[0] || (v[0] & 3) ||
        v[0] > UINT32_MAX - 0x38) {
        goto invalid;
    }
    for (i = 1; i < 6; i++) {
        if (v[i] < 2 || (v[i] & 1) || v[i] > UINT32_MAX - 4) {
            goto invalid;
        }
        for (j = 1; j < i; j++) {
            if (v[i] == v[j]) {
                goto invalid;
            }
        }
    }
    for (i = 6; i < 8; i++) {
        if (!v[i] || (v[i] & 1) || v[i] > UINT32_MAX - 12) {
            goto invalid;
        }
    }
    s->matrix_row734_row_tables[0] = v[6];
    s->matrix_row734_row_tables[1] = v[7];
    s->matrix_input_row734 = s->matrix_input_halfword = true;
    s->matrix_input_descriptor = v[0];
    s->matrix_input_presence_site = v[1];
    s->matrix_input_sense_site = v[2];
    s->matrix_row734_presence2 = v[3];
    s->matrix_row734_sense2 = v[4];
    s->matrix_row734_boot_site = v[5];
    s->matrix_input_address = MSM5XXX_POC_MSM_BASE + 0x72c;
    s->matrix_input_no_key = 0x1f;
    s->matrix_input_rows = 6;
    s->matrix_input_sideband_mask = 0;
    s->matrix_input_sense_bitmap = (1U << 30) | (1U << 29) |
        (1U << 27) | (1U << 23) | (1U << 15);
    s->board_status_input_enabled = true;
    s->board_status_input_address = MSM5XXX_POC_MSM_BASE + 0x720;
    s->board_status_input_descriptor = v[0];
    /* Provisional released auxiliary contact; physical identity is unverified. */
    s->board_status_input_mask = s->board_status_input_default =
        s->board_status_input_level = 4;
    s->matrix_input_host_enabled = s->matrix_input_enabled = true;
    return;
invalid:
    error_setg(errp, "matrix-row734 requires exclusive aligned D:P0:R0:P1:R1:BOOT:T0:T1");
}

static char *msm5xxx_poc_get_matrix_input(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->matrix_input_enabled || s->matrix_input_gpio) {
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
    if (s->matrix_input_gpio) {
        for (unsigned i = 0; i < 4; i++) {
            if (address == (i == 3 ? s->matrix_input_address :
                            s->matrix_input_gpio_port[i])) {
                error_setg(errp, "board-status-input conflicts with matrix-gpio");
                return;
            }
        }
    }
    s->board_status_input_address = address;
    s->board_status_input_mask = mask;
    s->board_status_input_default = default_value;
    s->board_status_input_level = default_value;
    s->board_status_input_enabled = true;
}

static char *msm5xxx_poc_get_board_status_descriptor(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return g_strdup_printf("%x", s->board_status_input_descriptor);
}

static void msm5xxx_poc_set_board_status_descriptor(Object *obj,
                                                      const char *value,
                                                      Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint64_t descriptor;

    if (s->matrix_input_gpio || s->matrix_input_low5 ||
        s->matrix_input_row_mask ||
        qemu_strtou64(value, NULL, 16, &descriptor) || !descriptor ||
        descriptor > UINT32_MAX - 0x38 || descriptor & 3) {
        error_setg(errp, "board-status-descriptor requires aligned descriptor");
        return;
    }
    s->board_status_input_descriptor = descriptor;
}

static char *msm5xxx_poc_get_audio_aperture(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->audio_enabled ?
        g_strdup_printf("%x:%x:%s", s->audio_base, s->audio_data_offset,
                        s->audio_ma2 ? "ma2" :
                        s->audio_ma5 ? "ma5" : "opaque") :
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
    /* New apertures require the explicit experimental device at realize. */
    ma5_valid = ma5 && base >= 0x02001000 && base <= 0x02ffff00 &&
                (data_offset == 2 || data_offset == 4 || data_offset == 128);
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
    s->audio_ma5 = ma5;
    s->audio_enabled = true;
}

static char *msm5xxx_poc_get_audio_irq_route(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    GString *text = g_string_new("");
    unsigned i;

    if (s->audio_irq_configured) {
        for (i = 0; i < 10; i++) {
            g_string_append_printf(text, "%s%x", i ? ":" : "", s->audio_irq_route[i]);
        }
    }
    return g_string_free(text, false);
}

static void msm5xxx_poc_set_audio_irq_route(Object *obj, const char *value,
                                            Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) parts = g_strsplit(value ? value : "", ":", -1);
    uint32_t r[10];
    unsigned i;

    if (g_strv_length(parts) != 10) {
        error_setg(errp, "audio-irq-route requires ten hex fields");
        return;
    }
    for (i = 0; i < 10; i++) {
        const char *end;
        uint64_t number;

        if (!g_ascii_isxdigit(parts[i][0]) ||
            qemu_strtou64(parts[i], &end, 16, &number) < 0 || *end || number > UINT32_MAX) {
            error_setg(errp, "invalid audio-irq-route field");
            return;
        }
        r[i] = number;
    }
    if (r[1] != 0x03000624 || r[2] != 0x0300062c ||
        !r[3] || r[3] > 0x8000 || (r[3] & (r[3] - 1)) ||
        (r[0] & 3) || (r[4] & 1) || (r[5] & 1) ||
        (r[6] & 1) || (r[7] & 3) || (r[8] & 3) || (r[9] & 1) ||
        r[6] >= 0x02000000 || r[9] >= 0x02000000) {
        error_setg(errp, "audio-irq-route outside supported descriptor class");
        return;
    }
    memcpy(s->audio_irq_route, r, sizeof(r));
    s->audio_irq_configured = true;
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

    if (s->matrix_input_gpio) {
        error_setg(errp, "matrix-input conflicts with matrix-gpio");
        return;
    }
    if (s->matrix_input_halfword) {
        error_setg(errp, "matrix-input conflicts with matrix-halfword");
        return;
    }
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

static char *msm5xxx_poc_get_matrix_halfword(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    (void)errp;

    if (!s->matrix_input_halfword || s->matrix_input_low5 ||
        s->matrix_input_loop || s->matrix_input_row734) {
        return g_strdup("");
    }
    if (s->matrix_input_row_mask) {
        return g_strdup_printf("%x:%x:%x:%x", s->matrix_input_descriptor,
                               s->matrix_input_presence_site,
                               s->matrix_input_sense_site,
                               s->matrix_input_row_mask);
    }
    return g_strdup_printf("%x:%x:%x", s->matrix_input_descriptor,
                           s->matrix_input_presence_site,
                           s->matrix_input_sense_site);
}

static void msm5xxx_poc_set_matrix_halfword(Object *obj, const char *value,
                                             Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint64_t fields[4] = {0};
    const char *field = value;
    unsigned count, rows = 0;

    if (s->matrix_input_enabled) {
        goto invalid;
    }
    for (count = 0; count < 4; count++) {
        const char *end;

        if (!field || !g_ascii_isxdigit(*field) ||
            qemu_strtou64(field, &end, 16, &fields[count]) < 0 ||
            fields[count] > UINT32_MAX) {
            goto invalid;
        }
        if (!*end) {
            count++;
            break;
        }
        if (*end != ':' || count == 3) {
            goto invalid;
        }
        field = end + 1;
    }
    if (count < 3 || fields[0] & 3 || fields[1] & 1 || fields[2] & 1 ||
        fields[1] == fields[2] || fields[1] > UINT32_MAX - 2 ||
        fields[2] > UINT32_MAX - 2 ||
        (count == 4 && (!fields[3] || fields[3] > UINT16_MAX ||
                        s->board_status_input_descriptor))) {
        goto invalid;
    }
    for (unsigned bits = fields[3]; bits; bits &= bits - 1) {
        rows++;
    }
    s->matrix_input_halfword = true;
    s->matrix_input_row_mask = fields[3];
    s->matrix_input_descriptor = fields[0];
    s->matrix_input_presence_site = fields[1];
    s->matrix_input_sense_site = fields[2];
    s->matrix_input_address = MSM5XXX_POC_MSM_BASE + 0x72c;
    s->matrix_input_no_key = 0xf;
    s->matrix_input_rows = rows ? rows : 6;
    s->matrix_input_sense_bitmap = (1U << 14) | (1U << 13) |
                                   (1U << 11) | (1U << 7);
    s->matrix_input_host_enabled = true;
    s->matrix_input_enabled = true;
    return;

invalid:
    error_setg(errp, "matrix-halfword requires exclusive "
               "DESCRIPTOR:PRESENCE_SITE:SENSE_SITE[:ROW_MASK]");
}

static char *msm5xxx_poc_get_experimental_matrix_contact(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    (void)errp;
    return s->experimental_matrix_contact_enabled ?
        g_strdup_printf("%x:%x", s->experimental_matrix_contact_site,
                        s->experimental_matrix_contact_level) : g_strdup("");
}

static void msm5xxx_poc_set_experimental_matrix_contact(Object *obj,
                                                       const char *value,
                                                       Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint64_t fields[2];
    const char *field = value;

    if (s->experimental_matrix_contact_enabled) {
        goto invalid;
    }
    for (unsigned i = 0; i < 2; i++) {
        const char *end;

        if (!field || !g_ascii_isxdigit(*field) ||
            qemu_strtou64(field, &end, 16, &fields[i]) < 0 ||
            fields[i] > UINT32_MAX || (i == 0 ? *end != ':' : *end != '\0')) {
            goto invalid;
        }
        field = end + 1;
    }
    if ((fields[0] & 1) || fields[0] > UINT32_MAX - 2 ||
        (fields[1] != 0 && fields[1] != 0x10)) {
        goto invalid;
    }
    s->experimental_matrix_contact_site = fields[0];
    s->experimental_matrix_contact_level = fields[1];
    s->experimental_matrix_contact_enabled = true;
    return;

invalid:
    error_setg(errp, "experimental-matrix-contact requires exclusive "
               "CONTACT_PC:LEVEL (hex 0 or 10)");
}

static char *msm5xxx_poc_get_experimental_matrix_status(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    (void)errp;
    return s->experimental_matrix_status_enabled ?
        g_strdup_printf("%x:%x", s->experimental_matrix_status_site,
                        s->experimental_matrix_status_level) : g_strdup("");
}

static void msm5xxx_poc_set_experimental_matrix_status(Object *obj,
                                                       const char *value,
                                                       Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint64_t fields[2];
    const char *field = value;

    if (s->experimental_matrix_status_enabled) {
        goto invalid;
    }
    for (unsigned i = 0; i < 2; i++) {
        const char *end;

        if (!field || !g_ascii_isxdigit(*field) ||
            qemu_strtou64(field, &end, 16, &fields[i]) < 0 ||
            fields[i] > UINT32_MAX || (i == 0 ? *end != ':' : *end != '\0')) {
            goto invalid;
        }
        field = end + 1;
    }
    if ((fields[0] & 1) || fields[0] > UINT32_MAX - 2 ||
        (fields[1] != 0 && fields[1] != 0x02)) {
        goto invalid;
    }
    s->experimental_matrix_status_site = fields[0];
    s->experimental_matrix_status_level = fields[1];
    s->experimental_matrix_status_enabled = true;
    return;

invalid:
    error_setg(errp, "experimental-matrix-status requires exclusive "
               "STATUS_PC:LEVEL (hex 0 or 2)");
}

static char *msm5xxx_poc_get_matrix_low5(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->matrix_input_low5 ?
        g_strdup_printf("%x:%x:%x", s->matrix_input_descriptor,
                        s->matrix_input_presence_site,
                        s->matrix_input_sense_site) : g_strdup("");
}

static void msm5xxx_poc_set_matrix_low5(Object *obj, const char *value,
                                         Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned descriptor, presence, sense;
    char trailing;

    if (s->matrix_input_enabled || s->board_status_input_descriptor ||
        sscanf(value, "%x:%x:%x%c", &descriptor, &presence, &sense,
               &trailing) != 3 || !descriptor || descriptor & 3 ||
        descriptor > UINT32_MAX - 0x38 || presence & 1 || sense & 1 ||
        presence == sense || presence > UINT32_MAX - 2 ||
        sense > UINT32_MAX - 2) {
        error_setg(errp, "matrix-low5 requires exclusive aligned "
                   "DESCRIPTOR:PRESENCE_SITE:SENSE_SITE");
        return;
    }
    s->matrix_input_low5 = true;
    s->matrix_input_halfword = true;
    s->matrix_input_descriptor = descriptor;
    s->matrix_input_presence_site = presence;
    s->matrix_input_sense_site = sense;
    s->matrix_input_address = MSM5XXX_POC_MSM_BASE + 0x72c;
    s->matrix_input_no_key = 0x1f;
    s->matrix_input_rows = 6;
    s->matrix_input_sideband_mask = 0;
    s->matrix_input_sense_bitmap = (1U << 30) | (1U << 29) |
        (1U << 27) | (1U << 23) | (1U << 15);
    s->matrix_input_host_enabled = true;
    s->matrix_input_enabled = true;
}

static char *msm5xxx_poc_get_matrix_loop(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    (void)errp;
    return s->matrix_input_loop ?
        g_strdup_printf("%x:%x:%x:%x", s->matrix_input_descriptor,
            s->matrix_input_contact_site, s->matrix_input_presence_site,
            s->matrix_input_sense_site) : g_strdup("");
}

static void msm5xxx_poc_set_matrix_loop(Object *obj, const char *value,
                                       Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned descriptor, contact, presence, row;
    uint64_t fields[4];
    const char *field = value;

    for (unsigned i = 0; i < 4; i++) {
        const char *end;

        if (!g_ascii_isxdigit(*field) ||
            qemu_strtou64(field, &end, 16, &fields[i]) < 0 ||
            fields[i] > UINT32_MAX || (i == 3 ? *end != 0 : *end != ':')) {
            error_setg(errp, "matrix-halfword-loop requires four bounded hex fields");
            return;
        }
        field = end + 1;
    }
    descriptor = fields[0]; contact = fields[1];
    presence = fields[2]; row = fields[3];

    if (s->matrix_input_enabled ||
        (s->board_status_input_descriptor &&
         s->board_status_input_descriptor != descriptor) ||
        !descriptor || descriptor & 3 ||
        descriptor > UINT32_MAX - 0x38 || contact & 1 || presence & 1 ||
        row & 1 || contact == presence || contact == row || presence == row ||
        contact > UINT32_MAX - 2 || presence > UINT32_MAX - 2 ||
        row > UINT32_MAX - 2) {
        error_setg(errp, "matrix-halfword-loop requires exclusive aligned "
                   "DESCRIPTOR:CONTACT:PRESENCE:ROW");
        return;
    }
    s->matrix_input_loop = s->matrix_input_halfword = true;
    s->matrix_input_descriptor = descriptor;
    s->matrix_input_contact_site = contact;
    s->matrix_input_presence_site = presence;
    s->matrix_input_sense_site = row;
    s->matrix_input_address = MSM5XXX_POC_MSM_BASE + 0x72c;
    s->matrix_input_no_key = 31;
    s->matrix_input_rows = 6;
    s->matrix_input_sideband_mask = 0;
    s->matrix_input_sense_bitmap = (1U << 30) | (1U << 29) |
                                  (1U << 27) | (1U << 23);
    s->matrix_input_host_enabled = s->matrix_input_enabled = true;
}

static char *msm5xxx_poc_get_matrix_gpio(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    (void)errp;
    if (s->matrix_input_gpio && s->matrix_input_sideband_mask) {
        return g_strdup_printf("%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
            s->matrix_input_address, s->matrix_input_presence_site,
            s->matrix_input_sense_site, s->matrix_input_gpio_port[0],
            s->matrix_input_gpio_mask[0], s->matrix_input_gpio_port[1],
            s->matrix_input_gpio_mask[1], s->matrix_input_gpio_port[2],
            s->matrix_input_gpio_mask[2], s->matrix_input_sideband_mask);
    }
    return s->matrix_input_gpio ? g_strdup_printf("%x:%x:%x:%x:%x:%x:%x:%x:%x",
        s->matrix_input_address, s->matrix_input_presence_site,
        s->matrix_input_sense_site, s->matrix_input_gpio_port[0],
        s->matrix_input_gpio_mask[0], s->matrix_input_gpio_port[1],
        s->matrix_input_gpio_mask[1], s->matrix_input_gpio_port[2],
        s->matrix_input_gpio_mask[2]) : g_strdup("");
}

static void msm5xxx_poc_set_matrix_gpio(Object *obj, const char *value,
                                       Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint64_t fields[10] = { 0 };
    const char *field = value;
    unsigned rows = 0;

    if (s->matrix_input_enabled || s->board_status_input_descriptor) {
        goto invalid;
    }
    for (unsigned i = 0; i < 9; i++) {
        const char *end;

        if (!field || !g_ascii_isxdigit(*field) ||
            qemu_strtou64(field, &end, 16, &fields[i]) < 0 ||
            fields[i] > UINT32_MAX ||
            (i == 8 ? (*end != 0 && *end != ':') : *end != ':')) {
            goto invalid;
        }
        field = end + (i != 8);
    }
    if (*field == ':') {
        const char *end;

        field++;
        if (!g_ascii_isxdigit(*field) ||
            qemu_strtou64(field, &end, 16, &fields[9]) < 0 || *end ||
            fields[9] > UINT8_MAX || (fields[9] & 0xf) ||
            (fields[9] && (fields[9] & (fields[9] - 1)))) {
            goto invalid;
        }
    }
    if (fields[0] < MSM5XXX_POC_MSM_BASE ||
        fields[0] >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
        fields[1] & 1 || fields[2] & 1 || fields[1] == fields[2] ||
        s->primary_nor_size < 2 || fields[1] > s->primary_nor_size - 2 ||
        fields[2] > s->primary_nor_size - 2) {
        goto invalid;
    }
    for (unsigned i = 0; i < 3; i++) {
        uint64_t address = fields[3 + 2 * i], mask = fields[4 + 2 * i];

        if (address < MSM5XXX_POC_MSM_BASE ||
            address >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE ||
            address == fields[0] || !mask || mask > UINT8_MAX) {
            goto invalid;
        }
        for (unsigned j = 0; j < i; j++) {
            if (address == fields[3 + 2 * j]) {
                goto invalid;
            }
        }
        for (unsigned bits = mask; bits; bits &= bits - 1) {
            rows++;
        }
        if (s->board_status_input_enabled &&
            s->board_status_input_address == address) {
            goto invalid;
        }
    }
    if (rows != 6 || (s->board_status_input_enabled &&
        s->board_status_input_address == fields[0])) {
        goto invalid;
    }
    s->matrix_input_address = fields[0];
    s->matrix_input_presence_site = fields[1];
    s->matrix_input_sense_site = fields[2];
    for (unsigned i = 0; i < 3; i++) {
        s->matrix_input_gpio_port[i] = fields[3 + 2 * i];
        s->matrix_input_gpio_mask[i] = fields[4 + 2 * i];
    }
    s->matrix_input_gpio = true;
    s->matrix_input_rows = 6;
    s->matrix_input_no_key = 0xf;
    s->matrix_input_sideband_mask = fields[9];
    s->matrix_input_sense_bitmap = (1U << 14) | (1U << 13) |
        (1U << 11) | (1U << 7);
    s->matrix_input_host_enabled = true;
    s->matrix_input_enabled = true;
    return;

invalid:
    error_setg(errp, "matrix-gpio requires exclusive "
               "ADDRESS:PRESENCE_PC:ROW_PC:PORT0:MASK0:PORT1:MASK1:PORT2:MASK2"
               "[:SIDEBAND_MASK]");
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
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    size_t count = g_strv_length(fields);
    uint32_t parsed[5] = { 0, 0, 0, UINT16_MAX, UINT16_MAX };
    unsigned base, size, sector_size, id0, id1;

    if (count != 3 && count != 5) {
        error_setg(errp, "record-x16-nor must be BASE:SIZE:SECTOR[:ID0:ID1]");
        return;
    }
    for (size_t index = 0; index < count; index++) {
        unsigned long number;
        if (qemu_strtoul(fields[index], NULL, 16, &number) < 0 ||
                number > UINT32_MAX) {
            error_setg(errp, "invalid record-x16-nor number");
            return;
        }
        parsed[index] = number;
    }
    base = parsed[0];
    size = parsed[1];
    sector_size = parsed[2];
    id0 = parsed[3];
    id1 = parsed[4];
    if (!base || !size ||
            base >= s->primary_nor_size ||
            size > s->primary_nor_size - base ||
            sector_size < 0x1000 || sector_size & (sector_size - 1) ||
            base % sector_size || size % sector_size ||
            id0 > UINT16_MAX || id1 > UINT16_MAX) {
        error_setg(errp, "record-x16-nor must be BASE:SIZE:SECTOR[:ID0:ID1]");
        return;
    }
    s->record_x16_nor_base = base;
    s->record_x16_nor_size = size;
    s->record_x16_nor_sector_size = sector_size;
    s->record_x16_nor_explicit_ids = count == 5;
    s->record_x16_nor_id0 = id0;
    s->record_x16_nor_id1 = id1;
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
            (status != 0x03000c80 && status != 0x03000fb0) ||
            enable != status + 0x14 ||
            (bank_count != 2 && bank_count != 3) ||
            (status == 0x03000fb0 &&
             (bank_count != 2 || handler_size != 0x182)) ||
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
    /* The FB0 timer class requires the firmware's byte-2 arm write. */
    s->rex_irq_arm_address = status == 0x03000fb0 ? 0x030006e0 : 0;
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

static void msm5xxx_poc_get_watchdog_register(Object *obj, Visitor *v,
    const char *name, void *opaque, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    visit_type_uint32(v, name, &s->watchdog_register, errp);
}

static void msm5xxx_poc_set_watchdog_register(Object *obj, Visitor *v,
    const char *name, void *opaque, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    visit_type_uint32(v, name, &s->watchdog_register, errp);
}

static void msm5xxx_poc_get_watchdog_mask(Object *obj, Visitor *v,
    const char *name, void *opaque, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    visit_type_uint32(v, name, &s->watchdog_mask, errp);
}

static void msm5xxx_poc_set_watchdog_mask(Object *obj, Visitor *v,
    const char *name, void *opaque, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    visit_type_uint32(v, name, &s->watchdog_mask, errp);
}

static void msm5xxx_poc_get_watchdog_timeout_ms(Object *obj, Visitor *v,
    const char *name, void *opaque, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    visit_type_uint32(v, name, &s->watchdog_timeout_ms, errp);
}

static void msm5xxx_poc_set_watchdog_timeout_ms(Object *obj, Visitor *v,
    const char *name, void *opaque, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    visit_type_uint32(v, name, &s->watchdog_timeout_ms, errp);
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
            ((ram_base < MSM5XXX_POC_RAM_BASE || ram_base >= 0x02000000) &&
             ram_base != MSM5XXX_POC_HIGH_RAM_BASE) ||
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

static char *msm5xxx_poc_get_ram_reserved(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    return s->ram_reserved_size ?
        g_strdup_printf("%x:%x", s->ram_reserved_base, s->ram_reserved_size) :
        g_strdup("");
}

static void msm5xxx_poc_set_ram_reserved(Object *obj, const char *value,
                                         Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t values[2];
    unsigned i;

    if (g_strv_length(fields) != G_N_ELEMENTS(values)) {
        error_setg(errp, "ram-reserved must be BASE:SIZE in hexadecimal");
        return;
    }
    for (i = 0; i < G_N_ELEMENTS(values); i++) {
        const char *end;

        if (!g_ascii_isxdigit(fields[i][0]) ||
            qemu_strtou64(fields[i], &end, 16, &values[i]) || *end ||
            !values[i] || values[i] > UINT32_MAX || (values[i] & 0xfff)) {
            error_setg(errp, "ram-reserved requires nonzero 4KiB-aligned 32-bit BASE:SIZE");
            return;
        }
    }
    s->ram_reserved_base = values[0];
    s->ram_reserved_size = values[1];
}

static char *msm5xxx_poc_get_search2_probe(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->search2_probe_description);
}

static void msm5xxx_poc_set_search2_probe(Object *obj, const char *value,
                                        Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t values[18];
    unsigned i;

    if (s->search2_timer || s->search2_virtual_description ||
        g_strv_length(fields) != G_N_ELEMENTS(values)) {
        error_setg(errp, "search2-probe needs 9 route fields, delay-ns, 8 explicit words before init");
        return;
    }
    for (i = 0; i < G_N_ELEMENTS(values); i++) {
        const char *end;

        if (qemu_strtou64(fields[i], &end, 16, &values[i]) || *end ||
            values[i] > (i < 9 ? UINT32_MAX : (i > 9 ? UINT16_MAX : UINT64_MAX))) {
            error_setg(errp, "invalid search2-probe field");
            return;
        }
    }
    if (values[8] != 0x80 || !values[9] || values[9] > NANOSECONDS_PER_SECOND) {
        error_setg(errp, "search2-probe requires row6 mask and a bounded explicit virtual delay");
        return;
    }
    for (i = 0; i < 9; i++) {
        s->search2_route[i] = values[i];
    }
    s->search2_delay_ns = values[9];
    for (i = 0; i < 8; i++) {
        s->search2_samples[i] = values[i + 10];
    }
    g_free(s->search2_probe_description);
    s->search2_probe_description = g_strdup(value);
}

static char *msm5xxx_poc_get_search2_virtual(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->search2_virtual_description);
}

static void msm5xxx_poc_set_search2_virtual(Object *obj, const char *value,
                                          Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t values[12];
    unsigned i;

    if (s->search2_timer || s->search2_probe_description ||
        g_strv_length(fields) != G_N_ELEMENTS(values)) {
        error_setg(errp, "search2-virtual needs 9 route fields, delay-ns, pilot-phase, raw-energy before init; exclusive with search2-probe");
        return;
    }
    for (i = 0; i < G_N_ELEMENTS(values); i++) {
        const char *end;

        if (qemu_strtou64(fields[i], &end, 16, &values[i]) || *end ||
            (i < 9 && values[i] > UINT32_MAX)) {
            error_setg(errp, "invalid search2-virtual field");
            return;
        }
    }
    if (values[8] != 0x80 || !values[9] || values[9] > NANOSECONDS_PER_SECOND ||
        values[10] > 0x3ffff || values[11] > UINT16_MAX) {
        error_setg(errp, "search2-virtual requires row6 mask, bounded virtual delay, 18-bit phase and 16-bit energy");
        return;
    }
    for (i = 0; i < 9; i++) {
        s->search2_route[i] = values[i];
    }
    s->search2_delay_ns = values[9];
    s->search2_pilot_phase = values[10];
    s->search2_peak_energy = values[11];
    s->search2_virtual = true;
    g_free(s->search2_virtual_description);
    s->search2_virtual_description = g_strdup(value);
}

static char *msm5xxx_poc_get_search1_virtual(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->search1_description);
}

static void msm5xxx_poc_set_search1_virtual(Object *obj, const char *value,
                                           Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t first, loop, abort = 0;
    unsigned fields_count = g_strv_length(fields);
    const char *end;

    if (s->search1_timer || (fields_count != 2 && fields_count != 3) ||
        qemu_strtou64(fields[0], &end, 16, &first) || *end || first > UINT32_MAX ||
        qemu_strtou64(fields[1], &end, 16, &loop) || *end || loop > UINT32_MAX ||
        (fields_count == 3 && (qemu_strtou64(fields[2], &end, 16, &abort) ||
                              *end || !abort || abort > UINT32_MAX))) {
        error_setg(errp, "search1-virtual needs first-byte-store:result-loop[:abort-first-store] before init");
        return;
    }
    s->search1_first_store = first;
    s->search1_result_loop = loop;
    s->search1_abort_pc = abort;
    s->search1_enabled = true;
    g_free(s->search1_description);
    s->search1_description = g_strdup(value);
}

static char *msm5xxx_poc_get_finger_virtual(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->finger_description);
}

static void msm5xxx_poc_set_finger_virtual(Object *obj, const char *value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t values[3];
    unsigned i;

    if (s->finger_region.name || g_strv_length(fields) != 3) {
        error_setg(errp, "finger-virtual needs RSSI-read:mask-I-table:mask-Q-table before init");
        return;
    }
    for (i = 0; i < 3; i++) {
        const char *end;
        if (qemu_strtou64(fields[i], &end, 16, &values[i]) || *end || values[i] > UINT32_MAX) {
            error_setg(errp, "invalid finger-virtual field");
            return;
        }
    }
    s->finger_read_pc = values[0];
    s->finger_masks_i = values[1];
    s->finger_masks_q = values[2];
    s->finger_enabled = true;
    g_free(s->finger_description);
    s->finger_description = g_strdup(value);
}

static bool msm5xxx_poc_get_access_response_probe(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->access_response_probe;
}

static void msm5xxx_poc_set_access_response_probe(Object *obj, bool value,
                                                 Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (s->msm.name) {
        error_setg(errp, "access-response-probe must be set before init");
        return;
    }
    s->access_response_probe = value;
}

static char *msm5xxx_poc_get_access_assignment_code(Object *obj, Error **errp)
{
    return g_strdup_printf("%x", (unsigned)MSM5XXX_POC_MACHINE(obj)->access_assignment_code);
}

static void msm5xxx_poc_set_access_assignment_code(Object *obj, const char *value,
                                                  Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    char *end;
    uint64_t code;

    if (s->msm.name || !value || !*value) {
        error_setg(errp, "access-assignment-code needs a hexadecimal value before init");
        return;
    }
    code = g_ascii_strtoull(value, &end, 16);
    if (end == value || *end || !g_ascii_isxdigit(value[0]) || code > 128) {
        error_setg(errp, "access-assignment-code must be 0..80 hexadecimal");
        return;
    }
    s->access_assignment_code = (uint8_t)code;
}

static char *msm5xxx_poc_get_tx_init_probe(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->tx_init_description);
}

static void msm5xxx_poc_set_tx_init_probe(Object *obj, const char *value,
                                        Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t values[11] = {0};
    unsigned i, count = g_strv_length(fields);

    if (s->tx_init_timer || (count != 8 && count != 9 && count != 11)) {
        error_setg(errp, "tx-init-probe needs callback:slot:flag:tcb:signal:control:registration:delay-ns[:frame-period-ns[:mode-base:writer]] before init");
        return;
    }
    for (i = 0; i < count; i++) {
        const char *end;
        if (!fields[i][0] || fields[i][0] == '-' || fields[i][0] == '+' ||
            qemu_strtou64(fields[i], &end, 16, &values[i]) || *end || values[i] > UINT32_MAX) {
            error_setg(errp, "invalid tx-init-probe field");
            return;
        }
    }
    if (!values[7] || values[7] > 1000000000) {
        error_setg(errp, "tx-init-probe delay must be 1..1000000000 ns");
        return;
    }
    if (count >= 9 && (!values[8] || values[8] > 1000000000)) {
        error_setg(errp, "tx-init-probe frame period must be 1..1000000000 ns");
        return;
    }
    for (i = 0; i < G_N_ELEMENTS(s->tx_init_route); i++) {
        s->tx_init_route[i] = values[i];
    }
    s->tx_init_delay_ns = values[7];
    s->tx_frame_period_ns = values[8];
    s->tx_fifo_enabled = count == 11;
    s->tx_fifo_mode_base = values[9];
    s->tx_fifo_writer = values[10];
    s->tx_init_enabled = true;
    g_free(s->tx_init_description);
    s->tx_init_description = g_strdup(value);
}

static char *msm5xxx_poc_get_decoder_init_probe(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->decoder_init_description);
}

static void msm5xxx_poc_set_decoder_init_probe(Object *obj, const char *value,
                                              Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t values[4];
    unsigned i;

    if (s->decoder_init_timer || g_strv_length(fields) != 4) {
        error_setg(errp, "decoder-init-probe needs reader:init-write:isr:delay-ns before init");
        return;
    }
    for (i = 0; i < G_N_ELEMENTS(values); i++) {
        const char *end;
        if (!fields[i][0] || fields[i][0] == '-' || fields[i][0] == '+' ||
            qemu_strtou64(fields[i], &end, 16, &values[i]) || *end ||
            values[i] > UINT32_MAX || (i < 3 && (values[i] & 1))) {
            error_setg(errp, "invalid decoder-init-probe field");
            return;
        }
    }
    if (!values[3] || values[3] > 1000000000) {
        error_setg(errp, "decoder-init-probe delay must be 1..1000000000 ns");
        return;
    }
    s->decoder_init_reader = values[0];
    s->decoder_init_write_pc = values[1];
    s->decoder_init_isr = values[2];
    s->decoder_init_delay_ns = values[3];
    s->decoder_init_enabled = true;
    g_free(s->decoder_init_description);
    s->decoder_init_description = g_strdup(value);
}

static char *msm5xxx_poc_get_decoder_sync_source(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->decoder_sync_description);
}

static void msm5xxx_poc_set_decoder_sync_source(Object *obj, const char *value,
                                               Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t values[3];
    uint8_t message[MSM5XXX_SYNC_MAX_BYTES];
    uint16_t words[8];
    unsigned i, length;

    if (s->decoder_init_timer || g_strv_length(fields) != 4) {
        error_setg(errp, "decoder-sync-source needs position-getter:roll-isr:consumer:message-hex before init");
        return;
    }
    for (i = 0; i < 3; i++) {
        const char *end;
        if (!fields[i][0] || !g_ascii_isxdigit(fields[i][0]) ||
            qemu_strtou64(fields[i], &end, 16, &values[i]) || *end ||
            values[i] > UINT32_MAX || values[i] & 1) {
            error_setg(errp, "invalid decoder-sync-source code field");
            return;
        }
    }
    length = strlen(fields[3]);
    if (length < 10 || length > sizeof(message) * 2 || length & 1) {
        error_setg(errp, "invalid decoder-sync-source message length");
        return;
    }
    length /= 2;
    for (i = 0; i < length; i++) {
        int hi = g_ascii_xdigit_value(fields[3][2 * i]);
        int lo = g_ascii_xdigit_value(fields[3][2 * i + 1]);
        if (hi < 0 || lo < 0) {
            error_setg(errp, "invalid decoder-sync-source message hex");
            return;
        }
        message[i] = (hi << 4) | lo;
    }
    if (!msm5xxx_sync_frame(message, length, 0, words)) {
        error_setg(errp, "decoder-sync-source message length byte or CRC30 invalid");
        return;
    }
    s->combiner_position_reader = values[0];
    s->combiner_roll_isr = values[1];
    s->decoder_sync_consumer = values[2];
    memcpy(s->decoder_sync_message, message, length);
    s->decoder_sync_message_length = length;
    s->decoder_sync_enabled = true;
    g_free(s->decoder_sync_description);
    s->decoder_sync_description = g_strdup(value);
}

static char *msm5xxx_poc_get_decoder_paging_source(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->decoder_paging_description);
}

static void msm5xxx_poc_set_decoder_paging_source(Object *obj, const char *value,
                                                 Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint64_t values[8];
    uint8_t messages[MSM5XXX_PAGING_MESSAGES][MSM5XXX_PAGING_MAX_BYTES] = {{0}};
    uint8_t lengths[MSM5XXX_PAGING_MESSAGES];
    uint16_t words[14];
    unsigned i, j;

    if (s->decoder_init_timer || g_strv_length(fields) != 12) {
        error_setg(errp, "decoder-paging-source needs isr:reader:status:initializer:wordcount:consumer:cache:layout and four message-hex fields before init");
        return;
    }
    for (i = 0; i < 8; i++) {
        const char *end;
        if (!fields[i][0] || !g_ascii_isxdigit(fields[i][0]) ||
            qemu_strtou64(fields[i], &end, 16, &values[i]) || *end ||
            values[i] > UINT32_MAX || values[i] & 1) {
            error_setg(errp, "invalid decoder-paging-source address field");
            return;
        }
    }
    for (i = 0; i < MSM5XXX_PAGING_MESSAGES; i++) {
        unsigned length = strlen(fields[8 + i]);
        if (length < 10 || length > MSM5XXX_PAGING_MAX_BYTES * 2 || length & 1) {
            error_setg(errp, "invalid decoder-paging-source message length");
            return;
        }
        lengths[i] = length / 2;
        for (j = 0; j < lengths[i]; j++) {
            int hi = g_ascii_xdigit_value(fields[8 + i][2 * j]);
            int lo = g_ascii_xdigit_value(fields[8 + i][2 * j + 1]);
            if (hi < 0 || lo < 0) {
                error_setg(errp, "invalid decoder-paging-source message hex");
                return;
            }
            messages[i][j] = (hi << 4) | lo;
        }
    }
    if (!msm5xxx_paging_decoder_frame(messages, lengths, 0, 0, words)) {
        error_setg(errp, "decoder-paging-source message length byte or CRC30 invalid");
        return;
    }
    s->decoder_paging_isr = values[0];
    s->decoder_paging_reader = values[1];
    s->decoder_paging_status = values[2];
    s->decoder_paging_initializer = values[3];
    s->decoder_paging_count = values[4];
    s->decoder_paging_consumer = values[5];
    s->decoder_paging_cache = values[6];
    s->decoder_paging_layout = values[7];
    memcpy(s->decoder_paging_messages, messages, sizeof(messages));
    memcpy(s->decoder_paging_lengths, lengths, sizeof(lengths));
    s->decoder_paging_enabled = true;
    g_free(s->decoder_paging_description);
    s->decoder_paging_description = g_strdup(value);
}

static char *msm5xxx_poc_get_decoder_traffic_source(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->decoder_traffic_description);
}

static void msm5xxx_poc_set_decoder_traffic_source(Object *obj, const char *value,
                                                 Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value, ":", -1);
    uint32_t route[8];
    unsigned i;
    if (s->decoder_init_timer || g_strv_length(fields) != 8) {
        error_setg(errp, "decoder-traffic-source needs eight addresses before init");
        return;
    }
    for (i = 0; i < 8; i++) {
        uint64_t number;
        const char *end;
        if (!fields[i][0] || !g_ascii_isxdigit(fields[i][0]) ||
            qemu_strtou64(fields[i], &end, 16, &number) || *end ||
            number > UINT32_MAX || number & 1) {
            error_setg(errp, "invalid decoder-traffic-source address");
            return;
        }
        route[i] = number;
    }
    memcpy(s->decoder_traffic_route, route, sizeof(route));
    s->decoder_traffic_enabled = true;
    g_free(s->decoder_traffic_description);
    s->decoder_traffic_description = g_strdup(value);
}

static char *msm5xxx_poc_get_decoder_traffic_frame(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->decoder_traffic_frame_description);
}

static void msm5xxx_poc_set_decoder_traffic_data(Object *obj, const char *value,
                                                bool response, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    uint8_t frame[24];
    MSM5xxxTrafficResponse next;
    unsigned i;

    if (s->traffic_service_enabled || (response && s->decoder_traffic_frame_enabled) ||
        (!response && s->decoder_traffic_response_enabled)) {
        error_setg(errp, "traffic frame and response sources are mutually exclusive");
        return;
    }
    if (s->decoder_init_timer || !value || strlen(value) != 48) {
        error_setg(errp, "decoder-traffic-frame needs 24 hex bytes before init");
        return;
    }
    for (i = 0; i < sizeof(frame); i++) {
        int hi = g_ascii_xdigit_value(value[2 * i]);
        int lo = g_ascii_xdigit_value(value[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            error_setg(errp, "invalid decoder-traffic-frame hex");
            return;
        }
        frame[i] = (hi << 4) | lo;
    }
    if (frame[23] != 0) {
        error_setg(errp, "decoder-traffic-frame requires zero encoder tail bits");
        return;
    }
    if (response && !msm5xxx_traffic_response_init(&next, frame, sizeof(frame))) {
        error_setg(errp, "decoder-traffic-response requires a CRC-valid unencrypted ACK-requested service response");
        return;
    }
    memcpy(s->decoder_traffic_frame, frame, sizeof(frame));
    s->decoder_traffic_frame_enabled = true;
    s->decoder_traffic_response_enabled = response;
    if (response) {
        s->decoder_traffic_response = next;
    }
    g_free(s->decoder_traffic_frame_description);
    s->decoder_traffic_frame_description = g_strdup(value);
}

static void msm5xxx_poc_set_decoder_traffic_frame(Object *obj, const char *value,
                                                Error **errp)
{
    msm5xxx_poc_set_decoder_traffic_data(obj, value, false, errp);
}

static void msm5xxx_poc_set_decoder_traffic_response(Object *obj, const char *value,
                                                   Error **errp)
{
    msm5xxx_poc_set_decoder_traffic_data(obj, value, true, errp);
}

static char *msm5xxx_poc_get_traffic_service_source(Object *obj, Error **errp)
{
    return g_strdup(MSM5XXX_POC_MACHINE(obj)->traffic_service_description);
}

static void msm5xxx_poc_set_traffic_service_source(Object *obj, const char *value, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    g_auto(GStrv) fields = g_strsplit(value ? value : "", ":", -1);
    uint32_t route[4];
    unsigned i;
    if (s->msm.name || s->decoder_traffic_frame_enabled ||
        s->traffic_service_enabled || g_strv_length(fields) != 4) {
        error_setg(errp, "traffic-service-source needs an exclusive four-field profile before init");
        return;
    }
    for (i = 0; i < 4; i++) {
        const char *end;
        uint64_t number;
        if (!fields[i][0] || !g_ascii_isxdigit(fields[i][0]) ||
            qemu_strtou64(fields[i], &end, 16, &number) || *end ||
            number > UINT32_MAX || (i < 3 && (number & 1))) {
            error_setg(errp, "invalid traffic-service-source address");
            return;
        }
        route[i] = number;
    }
    memcpy(s->traffic_service_route, route, sizeof(route));
    s->traffic_service_enabled = s->decoder_traffic_response_enabled = true;
    s->traffic_service_description = g_strdup(value);
}

static void msm5xxx_poc_instance_init(Object *obj)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    s->watchdog_timeout_ms = 30000;

    s->sbi_enabled = false;
    s->tx_init_last_mode = UINT8_MAX;
    s->sbi_bootstrap_only = false;
    s->lcd_trace_enabled = false;
    s->audio_pcm_enabled = true;
    s->ram_base = MSM5XXX_POC_RAM_BASE;
    s->board_adc_value = UINT8_MAX + 1;
    s->dc0_board_adc_value = UINT8_MAX + 1;
    s->primary_nor_size = MSM5XXX_POC_NOR_SIZE;
    s->rex_irq_controller_size = MSM5XXX_POC_REX_CONTROLLER_SIZE;
    s->rex_irq_bank_count = 2;
    msm5xxx_search2_init(&s->search2);
    msm5xxx_fingers_reset(&s->fingers);
}

static void msm5xxx_poc_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    machine_add_audiodev_property(mc);
    object_class_property_add_str(oc, "search2-probe",
                                  msm5xxx_poc_get_search2_probe,
                                  msm5xxx_poc_set_search2_probe);
    object_class_property_set_description(oc, "search2-probe",
        "Diagnostic one-packet search transport with explicit samples and virtual delay");
    object_class_property_add_str(oc, "search2-virtual",
                                  msm5xxx_poc_get_search2_virtual,
                                  msm5xxx_poc_set_search2_virtual);
    object_class_property_set_description(oc, "search2-virtual",
        "Experimental ideal single-pilot search with explicit phase, raw energy and virtual delay");
    object_class_property_add_str(oc, "search1-virtual",
                                  msm5xxx_poc_get_search1_virtual,
                                  msm5xxx_poc_set_search1_virtual);
    object_class_property_set_description(oc, "search1-virtual",
        "Experimental byte-program/selected-result search using the shared virtual pilot");
    object_class_property_add_str(oc, "decoder-sync-source",
                                  msm5xxx_poc_get_decoder_sync_source,
                                  msm5xxx_poc_set_decoder_sync_source);
    object_class_property_set_description(oc, "decoder-sync-source",
        "Opt-in repeated decoded sync stream with shared ideal roll/frame clock; not RF calibration");
    object_class_property_add_str(oc, "decoder-paging-source",
                                  msm5xxx_poc_get_decoder_paging_source,
                                  msm5xxx_poc_set_decoder_paging_source);
    object_class_property_add_str(oc, "decoder-traffic-source",
                                  msm5xxx_poc_get_decoder_traffic_source,
                                  msm5xxx_poc_set_decoder_traffic_source);
    object_class_property_add_str(oc, "decoder-traffic-frame",
                                  msm5xxx_poc_get_decoder_traffic_frame,
                                  msm5xxx_poc_set_decoder_traffic_frame);
    object_class_property_add_str(oc, "traffic-service-source",
                                  msm5xxx_poc_get_traffic_service_source,
                                  msm5xxx_poc_set_traffic_service_source);
    object_class_property_set_description(oc, "traffic-service-source",
        "Opt-in detector-bound request/revision source for the verified virtual service class");
    object_class_property_add_str(oc, "decoder-traffic-response",
                                  msm5xxx_poc_get_decoder_traffic_frame,
                                  msm5xxx_poc_set_decoder_traffic_response);
    object_class_property_set_description(oc, "decoder-traffic-response",
        "Explicit service response repeated until a validated encoder FIFO ACK; no voice or RF backend");
    object_class_property_set_description(oc, "decoder-traffic-frame",
        "Explicit ideal decoded 192-bit traffic frame with CRC-derived status; not RF or SIP");
    object_class_property_set_description(oc, "decoder-paging-source",
        "Opt-in decoded paging packets and shared 20ms clock; ideal error metrics, not RF calibration");
    object_class_property_add_str(oc, "tx-init-probe",
                                  msm5xxx_poc_get_tx_init_probe,
                                  msm5xxx_poc_set_tx_init_probe);
    object_class_property_set_description(oc, "tx-init-probe",
        "Explicit one-shot encoder initialization event; no physical period or call completion claim");
    object_class_property_add_bool(oc, "access-response-probe",
                                  msm5xxx_poc_get_access_response_probe,
                                  msm5xxx_poc_set_access_response_probe);
    object_class_property_set_description(oc, "access-response-probe",
        "Opt-in legacy access ACK through the paging source; no traffic or connected-call claim");
    object_class_property_add_str(oc, "access-assignment-code",
                                  msm5xxx_poc_get_access_assignment_code,
                                  msm5xxx_poc_set_access_assignment_code);
    object_class_property_set_description(oc, "access-assignment-code",
        "Experimental legacy assignment code in hexadecimal; zero retains ACK-only responses");
    object_class_property_add_str(oc, "decoder-init-probe",
                                  msm5xxx_poc_get_decoder_init_probe,
                                  msm5xxx_poc_set_decoder_init_probe);
    object_class_property_set_description(oc, "decoder-init-probe",
        "Opt-in one-shot decoder initialization IRQ; no decoded frames or service");
    object_class_property_add_str(oc, "finger-virtual",
                                  msm5xxx_poc_get_finger_virtual,
                                  msm5xxx_poc_set_finger_virtual);
    object_class_property_set_description(oc, "finger-virtual",
        "Experimental selected-bank RSSI/position latched from the shared ideal virtual pilot");
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
    object_class_property_add_str(oc, "sbi-raw-input-profile",
                                  msm5xxx_poc_get_sbi_raw_input_profile,
                                  msm5xxx_poc_set_sbi_raw_input_profile);
    object_class_property_set_description(oc, "sbi-raw-input-profile",
        "Limited source-bound uncalibrated virtual raw input READ_PC:MASK:VALUE");
    object_class_property_add_str(oc, "sbi-raw-input-status",
                                  msm5xxx_poc_get_sbi_raw_input_status, NULL);
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
    object_class_property_add_bool(oc, "experimental-ma5-pcm-output",
                                   msm5xxx_poc_get_ma5_pcm_output,
                                   msm5xxx_poc_set_ma5_pcm_output);
    object_class_property_set_description(
        oc, "experimental-ma5-pcm-output",
        "Enable the bounded experimental MA5 WT PCM renderer and host output");
    object_class_property_add_str(oc, "memory-profile",
                                  msm5xxx_poc_get_memory_profile,
                                  msm5xxx_poc_set_memory_profile);
    object_class_property_set_description(
        oc, "memory-profile",
        "Detector-provided flash size, RAM base, and initial SP");
    object_class_property_add_str(oc, "ram-reserved",
                                  msm5xxx_poc_get_ram_reserved,
                                  msm5xxx_poc_set_ram_reserved);
    object_class_property_set_description(
        oc, "ram-reserved", "Unmapped interior RAM aperture BASE:SIZE in hexadecimal");
    object_class_property_add_str(oc, "uart-console", msm5xxx_poc_get_uart_console,
                                  msm5xxx_poc_set_uart_console);
    object_class_property_set_description(oc, "uart-console",
        "Provisional null TX BASE[:WIDTH:CSR], classes 2:99 or 1:ff (default off)");
    object_class_property_add_str(oc, "uart-console-probe",
                                  msm5xxx_poc_get_uart_console_probe,
                                  msm5xxx_poc_set_uart_console_probe);
    object_class_property_set_description(oc, "uart-console-probe",
        "Source-qualified finite mixed-width null console BASE:ff:dd or BASE:ff:cc:99");
    object_class_property_add_str(oc, "uart-console-rearm",
                                  msm5xxx_poc_get_uart_console_rearm,
                                  msm5xxx_poc_set_uart_console_rearm);
    object_class_property_add_str(oc, "uart-console-rearm-state",
                                  msm5xxx_poc_get_uart_console_rearm_state, NULL);
    object_class_property_add_str(oc, "uart-console-probe-state",
                                  msm5xxx_poc_get_uart_console_probe_state, NULL);
    object_class_property_add_str(oc, "uart-console-status",
                                  msm5xxx_poc_get_uart_console_status, NULL);
    object_class_property_add(oc, "watchdog-register", "uint32",
        msm5xxx_poc_get_watchdog_register, msm5xxx_poc_set_watchdog_register, NULL, NULL);
    object_class_property_add(oc, "watchdog-mask", "uint32",
        msm5xxx_poc_get_watchdog_mask, msm5xxx_poc_set_watchdog_mask, NULL, NULL);
    object_class_property_add(oc, "watchdog-timeout-ms", "uint32",
        msm5xxx_poc_get_watchdog_timeout_ms, msm5xxx_poc_set_watchdog_timeout_ms, NULL, NULL);
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
    object_class_property_add_str(oc, "dmd5100-program",
                                  msm5xxx_poc_get_dmd5100, msm5xxx_poc_set_dmd5100);
    object_class_property_add_str(oc, "dmd5100-stats",
                                  msm5xxx_poc_get_dmd5100_stats, NULL);
    object_class_property_add_str(oc, "dmd5100-rejection",
                                  msm5xxx_poc_get_dmd5100_rejection, NULL);
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
    object_class_property_add_str(oc, "board-status-descriptor",
                                  msm5xxx_poc_get_board_status_descriptor,
                                  msm5xxx_poc_set_board_status_descriptor);
    object_class_property_set_description(
        oc, "board-status-descriptor",
        "Experimental live descriptor guard for halfword status GPIO");
    object_class_property_add_str(oc, "matrix-input",
                                  msm5xxx_poc_get_matrix_input,
                                  msm5xxx_poc_set_matrix_input);
    object_class_property_set_description(
        oc, "matrix-input", "Detector-provided direct matrix input state");
    object_class_property_add_str(oc, "matrix-halfword",
                                  msm5xxx_poc_get_matrix_halfword,
                                  msm5xxx_poc_set_matrix_halfword);
    object_class_property_set_description(
        oc, "matrix-halfword", "Experimental descriptor-gated halfword matrix "
        "with optional active-low ROW_MASK");
    object_class_property_add_str(oc, "experimental-matrix-contact",
                                  msm5xxx_poc_get_experimental_matrix_contact,
                                  msm5xxx_poc_set_experimental_matrix_contact);
    object_class_property_set_description(oc, "experimental-matrix-contact",
        "Explicit mapped-matrix contact electrical approximation; no default level");
    object_class_property_add_str(oc, "experimental-matrix-status",
                                  msm5xxx_poc_get_experimental_matrix_status,
                                  msm5xxx_poc_set_experimental_matrix_status);
    object_class_property_set_description(oc, "experimental-matrix-status",
        "Explicit mapped-matrix status electrical approximation; no default level");
    object_class_property_add_str(oc, "matrix-row734",
        msm5xxx_poc_get_matrix_row734, msm5xxx_poc_set_matrix_row734);
    object_class_property_add_str(oc, "matrix-row734-state",
        msm5xxx_poc_get_matrix_row734_state, NULL);
    object_class_property_add_str(oc, "matrix-low5",
                                  msm5xxx_poc_get_matrix_low5,
                                  msm5xxx_poc_set_matrix_low5);
    object_class_property_set_description(
        oc, "matrix-low5", "Temporary descriptor-qualified low-five sense plane");
    object_class_property_add_str(oc, "matrix-halfword-loop",
                                  msm5xxx_poc_get_matrix_loop,
                                  msm5xxx_poc_set_matrix_loop);
    object_class_property_set_description(oc, "matrix-halfword-loop",
        "Temporary opt-in loop matrix sense plane; contact released approximation");
    object_class_property_add_str(oc, "matrix-gpio",
                                  msm5xxx_poc_get_matrix_gpio,
                                  msm5xxx_poc_set_matrix_gpio);
    object_class_property_set_description(
        oc, "matrix-gpio", "Temporary qualified distributed byte matrix");
    object_class_property_add_str(oc, "audio-aperture",
                                  msm5xxx_poc_get_audio_aperture,
                                  msm5xxx_poc_set_audio_aperture);
    object_class_property_set_description(
        oc, "audio-aperture", "Detector-provided audio transport aperture");
    object_class_property_add_str(oc, "audio-irq-route",
                                  msm5xxx_poc_get_audio_irq_route,
                                  msm5xxx_poc_set_audio_irq_route);
    object_class_property_add_str(oc, "audio-sites",
                                  msm5xxx_poc_get_audio_sites,
                                  msm5xxx_poc_set_audio_sites);
    object_class_property_set_description(
        oc, "audio-sites", "Detector-provided audio bus access PCs");
    object_class_property_add_str(oc, "experimental-ma5-byte-ns",
                                  msm5xxx_poc_get_ma5_byte_ns,
                                  msm5xxx_poc_set_ma5_byte_ns);
    object_class_property_set_description(
        oc, "experimental-ma5-byte-ns",
        "Opt-in uncalibrated MA5 cold-init byte service period; no renderer");
    object_class_property_add_str(oc, "experimental-ma5-clki-hz",
                                  msm5xxx_poc_get_ma5_clki_hz,
                                  msm5xxx_poc_set_ma5_clki_hz);
    object_class_property_set_description(
        oc, "experimental-ma5-clki-hz",
        "Explicit experimental START-driven counter clock; empty-FIFO timing unverified");
    object_class_property_add_str(oc, "experimental-ma5-target-rate-hz",
                                  msm5xxx_poc_get_ma5_target_rate_hz,
                                  msm5xxx_poc_set_ma5_target_rate_hz);
    object_class_property_set_description(
        oc, "experimental-ma5-target-rate-hz",
        "Temporary clock inference from runtime PLL bytes and PC target rate; uncalibrated");
    object_class_property_add_str(oc, "experimental-ma5-irq-route",
                                  msm5xxx_poc_get_ma5_irq_route,
                                  msm5xxx_poc_set_ma5_irq_route);
    object_class_property_set_description(
        oc, "experimental-ma5-irq-route",
        "Opt-in same-image GPIO/parent route with live callback/polarity/enable gates");
    object_class_property_add_bool(oc, "experimental-audio-readback",
                                  msm5xxx_poc_get_audio_readback,
                                  msm5xxx_poc_set_audio_readback);
    object_class_property_set_description(
        oc, "experimental-audio-readback",
        "Opt-in inferred reset readback; not validated silicon behavior");
    object_class_property_add_str(oc, "experimental-audio-packet-bus",
                                  msm5xxx_poc_get_audio_packet_bus,
                                  msm5xxx_poc_set_audio_packet_bus);
    object_class_property_set_description(
        oc, "experimental-audio-packet-bus",
        "Opt-in primary-NOR wrapper for partial command-2 state; no renderer");
    object_class_property_add_bool(oc, "audio-packet-sequence",
                                  msm5xxx_poc_get_audio_packet_sequence,
                                  msm5xxx_poc_set_audio_packet_sequence);
    object_class_property_set_description(
        oc, "audio-packet-sequence",
        "Opt-in raw sequence packet receiver after executed reset; no timing or renderer");
    object_class_property_add_bool(oc, "audio-packet-clear-pulse",
                                  msm5xxx_poc_get_audio_packet_clear_pulse,
                                  msm5xxx_poc_set_audio_packet_clear_pulse);
    object_class_property_set_description(
        oc, "audio-packet-clear-pulse",
        "Opt-in bounded aggregate control pulse; no FIFO timing or renderer");
    object_class_property_add_str(oc, "experimental-protected-nor",
        msm5xxx_poc_get_protected, msm5xxx_poc_set_protected);
    object_class_property_add_str(oc, "protected-nor-source",
        msm5xxx_poc_get_protected_source, msm5xxx_poc_set_protected_source);
    object_class_property_add_str(oc, "protected-nor-stats",
        msm5xxx_poc_get_protected_stats, NULL);
    object_class_property_add_str(oc, "experimental-whole-primary-x16-nor",
                                  msm5xxx_poc_get_whole_primary_x16,
                                  msm5xxx_poc_set_whole_primary_x16);
    object_class_property_set_description(
        oc, "experimental-whole-primary-x16-nor",
        "Explicit virtual whole-primary base0 x16 SIZE:SECTOR:ID0:ID1[:COUNT:LENGTH...]");
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
    object_class_property_add_str(oc, "experimental-small-page-nand-state",
                                  msm5xxx_poc_get_small_nand_state, NULL);
    object_class_property_add_str(oc, "experimental-small-page-nand",
                                  msm5xxx_poc_get_small_nand,
                                  msm5xxx_poc_set_small_nand);
    object_class_property_set_description(
        oc, "experimental-small-page-nand",
        "Explicit virtual NAND DATA:ALE:CLE:READY:MASK[:IDLE_RESET_NS] route");
    object_class_property_add_str(oc, "raw-nand-main",
                                  msm5xxx_poc_get_raw_nand_main,
                                  msm5xxx_poc_set_raw_nand_main);
    object_class_property_set_description(
        oc, "raw-nand-main",
        "Detector-provided main-area-only small-page x16 NAND route");
    object_class_property_add_str(oc, "boot-keysense-release",
                                   msm5xxx_poc_get_boot_keysense_release,
                                   msm5xxx_poc_set_boot_keysense_release);
    object_class_property_add_str(oc, "boot-keysense-state",
                                   msm5xxx_poc_get_boot_keysense_state, NULL);
    object_class_property_add_str(oc, "spi-nv-source-geometry",
                                   msm5xxx_poc_get_spi_nv_source_geometry,
                                   msm5xxx_poc_set_spi_nv_source_geometry);
    object_class_property_add_str(oc, "experimental-spi-nv-write-ns",
                                   msm5xxx_poc_get_spi_nv_write_ns,
                                   msm5xxx_poc_set_spi_nv_write_ns);
    object_class_property_set_description(
        oc, "experimental-spi-nv-write-ns",
        "Virtual 16KiB/page32 GPIO serial NVM write period in ns; uncalibrated");
    object_class_property_add_str(oc, "experimental-spi-nv-state",
                                   msm5xxx_poc_get_spi_nv_state, NULL);
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

static void msm5xxx_poc_instance_finalize(Object *obj)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (s->watchdog_timer) {
        qemu_unregister_reset(msm5xxx_poc_watchdog_reset, s);
        timer_free(s->watchdog_timer);
    }
    if (s->sbi_raw_input_registered) {
        qemu_unregister_reset(msm5xxx_poc_sbi_raw_input_reset, s);
    }
    if (s->uart_console_mapped) {
        qemu_unregister_reset(msm5xxx_poc_uart_console_reset, s);
    }
    if (s->dmd5100_enabled) {
        qemu_unregister_reset(msm5xxx_poc_dmd5100_reset, s);
    }
    g_free(s->dmd5100_even);
    g_free(s->dmd5100_odd);

    if (s->protected_nor.initialized) {
        qemu_unregister_reset(msm5xxx_poc_protected_reset, s);
        g_free(s->protected_nor.image);
        blk_unref(s->protected_nor_blk);
    }
    if (s->spi_nv_timer) {
        msm5xxx_poc_spi_nv_sync(s);
        timer_free(s->spi_nv_timer);
    }
    if (s->spi_nv_blk) {
        blk_unref(s->spi_nv_blk);
    }
    g_free(s->spi_nv.image);

    if (s->small_nand.initialized) {
        qemu_unregister_reset(msm5xxx_poc_small_nand_reset, s);
        msm5xxx_poc_small_nand_sync(s, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        if (s->small_nand.pending == MSM5XXX_NAND_PENDING_PROGRAM ||
            s->small_nand.pending == MSM5XXX_NAND_PENDING_ERASE) {
            msm5xxx_poc_small_nand_poison(s, "shutdown interrupted mutation");
        }
    }
    if (s->small_nand_timer) {
        timer_free(s->small_nand_timer);
    }
    if (s->small_nand_blk) {
        blk_unref(s->small_nand_blk);
    }
    g_free(s->small_nand_raw);

    msm5xxx_poc_audio_pcm_cancel_watch(s);
    if (s->ma5_audio_timer) {
        timer_free(s->ma5_audio_timer);
    }
    ma5_wt_engine_free(s->ma5_wt_engine);
    if (s->search2_timer) {
        timer_free(s->search2_timer);
    }
    g_free(s->search2_probe_description);
    g_free(s->search2_virtual_description);
    if (s->search1_timer) {
        timer_free(s->search1_timer);
    }
    g_free(s->search1_description);
    g_free(s->finger_description);
    if (s->decoder_init_timer) {
        timer_free(s->decoder_init_timer);
    }
    if (s->tx_init_timer) {
        timer_free(s->tx_init_timer);
    }
    g_free(s->tx_init_description);
    g_free(s->decoder_init_description);
    g_free(s->decoder_sync_description);
    g_free(s->decoder_paging_description);
    g_free(s->decoder_traffic_description);
    g_free(s->decoder_traffic_frame_description);
    g_free(s->traffic_service_description);
}

static const TypeInfo msm5xxx_poc_machine_typeinfo = {
    .name = TYPE_MSM5XXX_POC_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(MSM5xxxPOCMachineState),
    .instance_init = msm5xxx_poc_instance_init,
    .instance_finalize = msm5xxx_poc_instance_finalize,
    .class_init = msm5xxx_poc_machine_class_init,
    .interfaces = arm_machine_interfaces,
};

static void msm5xxx_poc_machine_register_types(void)
{
    type_register_static(&msm5xxx_24lcxx_typeinfo);
    type_register_static(&msm5xxx_poc_machine_typeinfo);
}

type_init(msm5xxx_poc_machine_register_types)
