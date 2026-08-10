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
#include "qemu/error-report.h"
#include "qemu/module.h"
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

#define TYPE_MSM5XXX_POC_MACHINE MACHINE_TYPE_NAME("msm5xxx-poc")
OBJECT_DECLARE_SIMPLE_TYPE(MSM5xxxPOCMachineState, MSM5XXX_POC_MACHINE)

#define TYPE_MSM5XXX_24LCXX "msm5xxx-24lcxx"
OBJECT_DECLARE_SIMPLE_TYPE(MSM5xxx24LCxxState, MSM5XXX_24LCXX)

#define MSM5XXX_POC_MMIO_BASE 0x10000000
#define MSM5XXX_POC_MMIO_SIZE 0x1000
#define MSM5XXX_POC_NOR_SIZE (16 * MiB)
#define MSM5XXX_POC_NOR_MAX_SIZE (32 * MiB)
#define MSM5XXX_POC_UPPER_NOR_BASE 0x02800000
#define MSM5XXX_POC_UPPER_NOR_SIZE (8 * MiB)
#define MSM5XXX_POC_UPPER_NOR_SECTOR_SIZE 0x10000
#define MSM5XXX_POC_RAM_BASE 0x01000000
#define MSM5XXX_POC_BOOTSTRAP_BASE 0x04800000
#define MSM5XXX_POC_BOOTSTRAP_SIZE 0x1000
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define MSM5XXX_POC_MSM_SIZE (16 * MiB)
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
#define MSM5XXX_POC_LCD_TRACE_BASE 0x10001000
#define MSM5XXX_POC_LCD_TRACE_RECORD_SIZE 12
#define MSM5XXX_POC_LCD_TRACE_CAPACITY 65536
#define MSM5XXX_POC_LCD_TRACE_SIZE \
    (MSM5XXX_POC_LCD_TRACE_RECORD_SIZE * MSM5XXX_POC_LCD_TRACE_CAPACITY)
#define MSM5XXX_POC_LCD_STREAM_RECORD_SIZE 16
#define MSM5XXX_POC_LCD_STREAM_WRITE 1
#define MSM5XXX_POC_LCD_STREAM_TELEMETRY 2
#define MSM5XXX_POC_DEVICE_STREAM_TELEMETRY 3
#define MSM5XXX_POC_INPUT_STREAM_TELEMETRY 4
#define MSM5XXX_POC_AUDIO_STREAM_WRITE 5
#define MSM5XXX_POC_AUDIO_STREAM_STATUS 6
#define MSM5XXX_POC_AUDIO_STATUS_OVERFLOW 1
#define MSM5XXX_POC_AUDIO_STATUS_RESET 2
#define MSM5XXX_POC_HOST_INPUT 0x80
#define MSM5XXX_POC_HOST_INPUT_SIZE 4
#define MSM5XXX_POC_HOST_INPUT_SIDEBAND_ROW UINT8_MAX
#define MSM5XXX_POC_READY_POLL_DELAY 200000
#define MSM5XXX_POC_PAUSE_TIMER_SIZE 4
#define MSM5XXX_POC_REX_CONTROLLER_SIZE 0x10
#define MSM5XXX_POC_REX_C80_CONTROLLER_SIZE 0x1a
#define MSM5XXX_POC_EEPROM_GPIO_SIZE 0x20
#define MSM5XXX_POC_24LC256_PAGE_SIZE 64

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

typedef struct MSM5xxxPOCLCDPort {
    MSM5xxxPOCMachineState *machine;
    unsigned index;
} MSM5xxxPOCLCDPort;

struct MSM5xxxPOCMachineState {
    MachineState parent_obj;

    ARMCPU *cpu;
    uint32_t ram_base;
    uint32_t initial_sp;
    bool memory_profile_enabled;
    MemoryRegion nor;
    uint32_t primary_nor_size;
    bool primary_x16_nor_enabled;
    uint32_t primary_x16_nor_base;
    uint32_t primary_x16_nor_size;
    uint32_t primary_x16_nor_sector_size;
    uint16_t primary_x16_nor_id0;
    uint16_t primary_x16_nor_id1;
    bool fujitsu_x16_nor_enabled;
    uint32_t secondary_nor_base;
    uint32_t secondary_nor_size;
    uint16_t secondary_nor_id0;
    uint16_t secondary_nor_id1;
    bool upper_x8_nor_enabled;
    MemoryRegion bootstrap;
    MemoryRegion msm;
    MemoryRegion sbi;
    MemoryRegion dc0;
    MemoryRegion lcd_aperture;
    MemoryRegion lcd[MSM5XXX_POC_LCD_PORTS];
    MemoryRegion lcd_trace;
    MemoryRegion ready_status;
    MemoryRegion ready_pulse;
    MemoryRegion pause_timer;
    MemoryRegion board_status_input;
    MemoryRegion matrix_input;
    MemoryRegion audio;
    MemoryRegion mmio;
    qemu_irq cpu_irq;
    uint32_t value;
    uint64_t reads;
    uint64_t writes;
    bool irq_level;
    bool sbi_enabled;
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
    uint32_t ready_status_address;
    uint8_t ready_status_mask;
    uint32_t ready_pulse_address;
    uint32_t ready_poll_entry;
    uint8_t ready_status_backing;
    uint8_t ready_pulse_backing;
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
    uint32_t audio_base;
    uint8_t audio_data_offset;
    uint8_t audio_index;
    uint8_t audio_backing[MSM5XXX_POC_AUDIO_MAX_PORTS];
    uint32_t audio_stream_order;
    uint32_t audio_stream_dropped;
    uint8_t audio_stream_status_pending;
    bool audio_stream_started;
    bool audio_stream_rejected;
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
    uint32_t rex_irq_vector_target;
    uint32_t rex_irq_wrapper_address;
    uint32_t rex_irq_handler_slot;
    uint32_t rex_irq_handler_address;
    uint32_t rex_irq_handler_size;
    uint32_t rex_irq_callback_slot;
    uint32_t rex_irq_callback_address;
    MemoryRegion rex_irq_controller;
    MemoryRegion rex_irq_arm;
    uint8_t rex_irq_backing[MSM5XXX_POC_REX_C80_CONTROLLER_SIZE];
    uint8_t rex_irq_arm_backing;
    uint16_t rex_irq_pending[2];
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
        MSM5XXX_POC_LCD_TRACE_SIZE) {
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
            status == MSM5XXX_POC_AUDIO_STATUS_OVERFLOW ?
                s->audio_stream_order : 0,
            status == MSM5XXX_POC_AUDIO_STATUS_OVERFLOW ?
                s->audio_stream_dropped : 0,
            0)) {
        s->audio_stream_status_pending = 0;
    }
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

static uint64_t msm5xxx_poc_ready_status_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUClass *cc = CPU_GET_CLASS(s->cpu);
    uint64_t now = icount_get_raw();

    if (offset || size != 1) {
        return 0;
    }
    if (cc->get_pc(CPU(s->cpu)) != s->ready_poll_entry + 2) {
        return s->ready_status_backing;
    }
    s->ready_poll_reads++;
    if (s->ready_poll_status == MSM5XXX_POC_READY_OBSERVING) {
        s->ready_poll_status = MSM5XXX_POC_READY_CANDIDATE;
        s->ready_poll_phase = 1;
        s->ready_poll_first_icount = now;
    } else if (s->ready_poll_status == MSM5XXX_POC_READY_CANDIDATE) {
        if (s->ready_poll_phase != 3) {
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
        if (pc == s->ready_poll_entry + 12) {
            if (value == 1) {
                s->ready_poll_phase = 2;
            } else {
                msm5xxx_poc_ready_reject(s);
            }
        } else if (pc == s->ready_poll_entry + 16) {
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
        s->board_status_input_backing = value |
            (s->board_status_input_default & s->board_status_input_mask);
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

static uint64_t msm5xxx_poc_audio_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (size != 1 || offset > s->audio_data_offset) {
        return 0;
    }
    return s->audio_backing[offset];
}

static void msm5xxx_poc_audio_write(void *opaque, hwaddr offset,
                                    uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUState *cpu = current_cpu;
    CPUClass *cc;
    uint32_t pc;

    if (size != 1 || offset > s->audio_data_offset) {
        return;
    }
    s->audio_backing[offset] = value;
    if (!offset) {
        s->audio_index = value;
    }
    if (!qemu_in_vcpu_thread() || cpu != CPU(s->cpu) || !cpu->running ||
        !cpu->neg.can_do_io) {
        return;
    }
    s->audio_stream_started = true;
    s->audio_stream_order++;
    if (s->audio_stream_rejected) {
        if (s->audio_stream_dropped != UINT32_MAX) {
            s->audio_stream_dropped++;
        }
        return;
    }
    cc = CPU_GET_CLASS(cpu);
    pc = cc->get_pc(cpu) & ~1U;
    if (!s->lcd_trace_buffer || !msm5xxx_poc_lcd_stream_append(
            s, MSM5XXX_POC_AUDIO_STREAM_WRITE, size, pc,
            offset | ((value & UINT8_MAX) << 8),
            s->audio_stream_order)) {
        s->audio_stream_rejected = true;
        s->audio_stream_dropped = 1;
        s->audio_stream_status_pending = MSM5XXX_POC_AUDIO_STATUS_OVERFLOW;
    }
}

static const MemoryRegionOps msm5xxx_poc_audio_ops = {
    .read = msm5xxx_poc_audio_read,
    .write = msm5xxx_poc_audio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 1,
};

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
        msm5xxx_poc_backing_write(s->rex_irq_backing, 0,
                                  s->rex_irq_pending[0], 2);
        msm5xxx_poc_backing_write(s->rex_irq_backing, 4,
                                  s->rex_irq_pending[1], 2);
        return msm5xxx_poc_backing_read(s->rex_irq_backing, offset, size);
    }
    for (i = 0; i < size; i++) {
        hwaddr byte = offset + i;
        uint8_t pending;

        if (byte < 2) {
            pending = s->rex_irq_pending[0] >> (byte * 8);
        } else if (byte >= 4 && byte < 6) {
            pending = s->rex_irq_pending[1] >> ((byte - 4) * 8);
        } else {
            continue;
        }
        value &= ~(UINT64_C(0xff) << (i * 8));
        value |= (uint64_t)pending << (i * 8);
    }
    for (i = 0; i < 2; i++) {
        hwaddr bank = i * 4;

        if (offset < bank + 2 && offset + size > bank) {
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

        if (byte < 2) {
            s->rex_irq_pending[0] &= ~((uint16_t)incoming << (byte * 8));
        } else if (byte >= 4 && byte < 6) {
            s->rex_irq_pending[1] &=
                ~((uint16_t)incoming << ((byte - 4) * 8));
        } else {
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
        } else {
            msm5xxx_poc_sbi_reject(s);
            return backing;
        }
    }

    if (offset == 0 && size == 2 &&
        (s->sbi_status == MSM5XXX_POC_SBI_CANDIDATE ||
         s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED)) {
        if (s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED) {
            if (s->sbi_board_adc_phase == 4 ||
                s->sbi_board_adc_phase == 6 ||
                s->sbi_board_adc_phase == 8) {
                s->sbi_board_adc_phase++;
            } else {
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
    if (offset == 4 && size == 2) {
        s->sbi_control = value & 0x0fff;
        s->sbi_board_adc_phase =
            s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED && value == 0x086a;
    } else if (offset == 0x0c && size == 2 &&
               s->sbi_status == MSM5XXX_POC_SBI_ACCEPTED) {
        if ((s->sbi_board_adc_phase == 1 && value == 0x0ada) ||
            (s->sbi_board_adc_phase == 5 && value == 0x0a5a) ||
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
    uint8_t record[MSM5XXX_POC_LCD_TRACE_RECORD_SIZE] = { 0 };

    if (!s->lcd_trace_enabled && !s->lcd_trace_buffer) {
        return;
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
        msm5xxx_poc_lcd_stream_append(
            s, MSM5XXX_POC_LCD_STREAM_WRITE, size, address, value, 0
        );
    }
    s->lcd_trace_count++;
}

static uint64_t msm5xxx_poc_lcd_aperture_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset + size > MSM5XXX_POC_LCD_APERTURE_SIZE) {
        return 0;
    }
    s->lcd_aperture_reads++;
    return msm5xxx_poc_backing_read(s->lcd_aperture_backing, offset, size);
}

static void msm5xxx_poc_lcd_aperture_write(void *opaque, hwaddr offset,
                                           uint64_t value, unsigned size)
{
    MSM5xxxPOCMachineState *s = opaque;

    if (offset + size > MSM5XXX_POC_LCD_APERTURE_SIZE) {
        return;
    }
    s->lcd_aperture_writes++;
    msm5xxx_poc_lcd_trace_write(
        s, MSM5XXX_POC_LCD_APERTURE_BASE + offset, value, size
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

    if (offset + size > MSM5XXX_POC_LCD_SIZE) {
        return 0;
    }
    s->lcd_reads[port->index]++;
    return msm5xxx_poc_backing_read(
        s->lcd_backing[port->index], offset, size
    );
}

static void msm5xxx_poc_lcd_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{
    MSM5xxxPOCLCDPort *port = opaque;
    MSM5xxxPOCMachineState *s = port->machine;

    if (offset + size > MSM5XXX_POC_LCD_SIZE) {
        return;
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

static void msm5xxx_poc_reset(void *opaque)
{
    MSM5xxxPOCMachineState *s = opaque;
    CPUARMState *env = &s->cpu->env;
    uint8_t *msm = memory_region_get_ram_ptr(&s->msm);
    bool audio_was_started = s->audio_stream_started;

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
    s->ready_poll_status = s->ready_poll_enabled ?
        MSM5XXX_POC_READY_OBSERVING : MSM5XXX_POC_READY_DISABLED;
    s->ready_poll_phase = 0;
    s->ready_poll_first_icount = 0;
    s->ready_poll_reads = 0;
    s->ready_poll_cycles = 0;
    s->ready_poll_responses = 0;
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
    s->audio_index = 0;
    memset(s->audio_backing, 0, sizeof(s->audio_backing));
    s->audio_stream_order = 0;
    s->audio_stream_dropped = 0;
    s->audio_stream_started = false;
    s->audio_stream_rejected = audio_was_started;
    s->audio_stream_status_pending = audio_was_started ?
        MSM5XXX_POC_AUDIO_STATUS_RESET : 0;
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
    unsigned i;

    s->cpu = ARM_CPU(cpu_create(machine->cpu_type));
    s->cpu_irq = qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_IRQ);

    if (s->pause_timer_enabled &&
        (icount_enabled() != ICOUNT_PRECISE ||
         s->pause_timer_helper_end > s->primary_nor_size)) {
        error_report("pause-timer requires fixed-shift icount and a NOR scope");
        exit(EXIT_FAILURE);
    }

    if (s->memory_profile_enabled &&
            (machine->ram_size > 0x02000000 - s->ram_base ||
             s->initial_sp < s->ram_base ||
             s->initial_sp > s->ram_base + machine->ram_size - 4)) {
        error_report("memory-profile RAM range does not contain INITIAL_SP");
        exit(EXIT_FAILURE);
    }

    if (s->rex_irq_c80) {
        uint64_t ram_end = s->ram_base + machine->ram_size;
        bool vector_invalid = s->rex_irq_read_consume ?
            s->rex_irq_vector_target < s->ram_base ||
            s->rex_irq_vector_target > ram_end - 4 :
            s->rex_irq_vector_target != s->ram_base;

        if (vector_invalid ||
                s->rex_irq_wrapper_address >= s->primary_nor_size ||
                s->rex_irq_handler_address >= s->primary_nor_size ||
                s->rex_irq_handler_size >
                    s->primary_nor_size - s->rex_irq_handler_address ||
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
        qdev_prop_set_uint32(
            dev, "num-blocks",
            s->primary_x16_nor_size / s->primary_x16_nor_sector_size
        );
        qdev_prop_set_uint32(dev, "sector-length",
                             s->primary_x16_nor_sector_size);
        qdev_prop_set_uint8(dev, "width", 2);
        qdev_prop_set_uint8(dev, "mappings", 1);
        qdev_prop_set_uint8(dev, "big-endian", 0);
        qdev_prop_set_uint16(dev, "id0", s->primary_x16_nor_id0);
        qdev_prop_set_uint16(dev, "id1", s->primary_x16_nor_id1);
        qdev_prop_set_uint16(dev, "id2", 0);
        qdev_prop_set_uint16(dev, "id3", 0);
        qdev_prop_set_uint16(dev, "unlock-addr0", 0x555);
        qdev_prop_set_uint16(dev, "unlock-addr1", 0x2aa);
        qdev_prop_set_string(dev, "name", "msm5xxx-poc.primary-nor");
        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        sysbus_mmio_map_overlap(SYS_BUS_DEVICE(dev), 0,
                                s->primary_x16_nor_base, 1);
    }
    if (s->fujitsu_x16_nor_enabled) {
        DeviceState *dev = qdev_new(TYPE_PFLASH_CFI02);
        uint32_t remaining;

        dinfo = drive_get(IF_PFLASH, 0,
                          s->primary_x16_nor_enabled ? 1 : 0);
        if (!dinfo) {
            error_report("fujitsu-x16-nor requires one pflash drive");
            exit(EXIT_FAILURE);
        }
        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo));
        if (s->secondary_nor_id0 == 0x0004 &&
            s->secondary_nor_id1 == 0x005f) {
            remaining = s->secondary_nor_size - 0x10000;
            qdev_prop_set_uint32(dev, "num-blocks0", 8);
            qdev_prop_set_uint32(dev, "sector-length0", 0x2000);
            qdev_prop_set_uint32(dev, "num-blocks1", remaining / 0x10000);
            qdev_prop_set_uint32(dev, "sector-length1", 0x10000);
        } else {
            qdev_prop_set_uint32(dev, "num-blocks",
                                 s->secondary_nor_size / 0x10000);
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
        if (s->secondary_nor_base < s->primary_nor_size) {
            sysbus_mmio_map_overlap(SYS_BUS_DEVICE(dev), 0,
                                    s->secondary_nor_base, 1);
        } else {
            sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, s->secondary_nor_base);
        }
    }
    if (s->upper_x8_nor_enabled) {
        DeviceState *dev = qdev_new(TYPE_PFLASH_CFI02);
        unsigned unit = s->primary_x16_nor_enabled +
                        s->fujitsu_x16_nor_enabled;

        dinfo = drive_get(IF_PFLASH, 0, unit);
        if (!dinfo) {
            error_report("upper-x8-nor requires one pflash drive");
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
        qdev_prop_set_uint8(dev, "width", 1);
        qdev_prop_set_uint8(dev, "mappings", 1);
        qdev_prop_set_uint8(dev, "big-endian", 0);
        qdev_prop_set_uint16(dev, "id0", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id1", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id2", UINT16_MAX);
        qdev_prop_set_uint16(dev, "id3", UINT16_MAX);
        qdev_prop_set_uint16(dev, "unlock-addr0", 0xaaa);
        qdev_prop_set_uint16(dev, "unlock-addr1", 0x554);
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
    memory_region_init_io(&s->lcd_aperture, OBJECT(machine),
                          &msm5xxx_poc_lcd_aperture_ops, s,
                          "msm5xxx-poc.lcd-aperture",
                          MSM5XXX_POC_LCD_APERTURE_SIZE);
    memory_region_add_subregion_overlap(
        get_system_memory(), MSM5XXX_POC_LCD_APERTURE_BASE,
        &s->lcd_aperture, -1
    );
    for (i = 0; i < MSM5XXX_POC_LCD_PORTS; i++) {
        if (s->upper_x8_nor_enabled &&
            msm5xxx_poc_lcd_bases[i] >= MSM5XXX_POC_UPPER_NOR_BASE) {
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
    s->ready_poll_status = s->ready_poll_enabled ?
        MSM5XXX_POC_READY_OBSERVING : MSM5XXX_POC_READY_DISABLED;
    if (s->ready_poll_enabled) {
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
    if (s->audio_enabled) {
        memory_region_init_io(&s->audio, OBJECT(machine),
                              &msm5xxx_poc_audio_ops, s,
                              "msm5xxx-poc.audio",
                              s->audio_data_offset + 1);
        memory_region_add_subregion(get_system_memory(), s->audio_base,
                                    &s->audio);
    }
    memory_region_init_io(&s->mmio, OBJECT(machine), &msm5xxx_poc_ops, s,
                          "msm5xxx-poc.mmio", MSM5XXX_POC_MMIO_SIZE);
    memory_region_add_subregion(get_system_memory(), MSM5XXX_POC_MMIO_BASE,
                                &s->mmio);
    if (s->memory_profile_enabled) {
        qemu_register_reset(msm5xxx_poc_reset, s);
        msm5xxx_poc_reset(s);
    }
}

static bool msm5xxx_poc_get_sbi(Object *obj, Error **errp)
{
    return MSM5XXX_POC_MACHINE(obj)->sbi_enabled;
}

static void msm5xxx_poc_set_sbi(Object *obj, bool value, Error **errp)
{
    MSM5XXX_POC_MACHINE(obj)->sbi_enabled = value;
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

static char *msm5xxx_poc_get_ready_poll(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->ready_poll_enabled) {
        return g_strdup("");
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
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x%c", &status, &mask, &pulse, &entry,
               &trailing) != 4
            || status < MSM5XXX_POC_MSM_BASE
            || status >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE
            || pulse < MSM5XXX_POC_MSM_BASE
            || pulse >= MSM5XXX_POC_MSM_BASE + MSM5XXX_POC_MSM_SIZE
            || status == pulse || !mask || mask > UINT8_MAX
            || (mask & (mask - 1)) || (entry & 1)
            || entry > s->primary_nor_size - 22) {
        error_setg(errp,
                   "ready-poll must be STATUS:ONE_BIT_MASK:PULSE:ENTRY");
        return;
    }
    s->ready_status_address = status;
    s->ready_status_mask = mask;
    s->ready_pulse_address = pulse;
    s->ready_poll_entry = entry;
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

    if (!s->primary_x16_nor_enabled) {
        return g_strdup("");
    }
    return g_strdup_printf("%x:%x:%x:%x:%x", s->primary_x16_nor_base,
                           s->primary_x16_nor_size,
                           s->primary_x16_nor_sector_size,
                           s->primary_x16_nor_id0,
                           s->primary_x16_nor_id1);
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
        g_strdup_printf("%x:%x", s->audio_base, s->audio_data_offset) :
        g_strdup("");
}

static void msm5xxx_poc_set_audio_aperture(Object *obj, const char *value,
                                            Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);
    unsigned base, data_offset;
    char trailing;

    if (sscanf(value, "%x:%x%c", &base, &data_offset, &trailing) != 2 ||
            base < 0x02001000 || base >= MSM5XXX_POC_MSM_BASE ||
            !data_offset || data_offset >= MSM5XXX_POC_AUDIO_MAX_PORTS) {
        error_setg(errp, "audio-aperture must be BASE:DATA_OFFSET");
        return;
    }
    s->audio_base = base;
    s->audio_data_offset = data_offset;
    s->audio_enabled = true;
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
               &id0, &id1, &trailing) != 5 || !primary || !size ||
            primary > s->primary_nor_size || base >= MSM5XXX_POC_RAM_BASE ||
            (base < primary ? size > primary - base :
             size > MSM5XXX_POC_RAM_BASE - base) || size < 0x10000 ||
            size % 0x10000 || id0 > UINT16_MAX || id1 > UINT16_MAX ||
            (base < primary &&
             (base % 0x200000 || size != 0x200000 ||
              id0 != 0x0004 || id1 != 0x005f))) {
        error_setg(errp,
                   "fujitsu-x16-nor must be PRIMARY:BASE:SIZE:ID0:ID1");
        return;
    }
    s->primary_nor_size = primary;
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
    unsigned base, size, sector_size, id0, id1;
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x:%x%c", &base, &size, &sector_size,
               &id0, &id1, &trailing) != 5 || !base || !size ||
            base >= s->primary_nor_size ||
            size > s->primary_nor_size - base ||
            sector_size < 0x1000 || size % sector_size ||
            base % sector_size || id0 > UINT16_MAX || id1 > UINT16_MAX) {
        error_setg(errp,
                   "primary-x16-nor must be BASE:SIZE:SECTOR:ID0:ID1");
        return;
    }
    s->primary_x16_nor_base = base;
    s->primary_x16_nor_size = size;
    s->primary_x16_nor_sector_size = sector_size;
    s->primary_x16_nor_id0 = id0;
    s->primary_x16_nor_id1 = id1;
    s->primary_x16_nor_enabled = true;
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
    s->rex_irq_enabled = true;
}

static char *msm5xxx_poc_get_rex_static_c80(Object *obj, Error **errp)
{
    MSM5xxxPOCMachineState *s = MSM5XXX_POC_MACHINE(obj);

    if (!s->rex_irq_c80) {
        return g_strdup("");
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
    char trailing;

    if (sscanf(value, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x%c",
               &status, &enable, &mask, &interval, &vector_target, &wrapper,
               &handler_slot, &handler, &handler_size, &callback_slot,
               &callback, &trailing) != 11 || s->rex_irq_enabled ||
            status != 0x03000c80 || enable != status + 0x14 ||
            status + MSM5XXX_POC_REX_C80_CONTROLLER_SIZE >
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
    s->rex_irq_controller_size = MSM5XXX_POC_REX_C80_CONTROLLER_SIZE;
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
    s->rex_irq_gate_status = MSM5XXX_POC_REX_GATE_VECTOR_WAIT;
    s->rex_irq_read_consume = true;
    s->rex_irq_c80 = true;
    s->rex_irq_enabled = true;
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
    s->lcd_trace_enabled = false;
    s->ram_base = MSM5XXX_POC_RAM_BASE;
    s->board_adc_value = UINT8_MAX + 1;
    s->dc0_board_adc_value = UINT8_MAX + 1;
    s->primary_nor_size = MSM5XXX_POC_NOR_SIZE;
    s->rex_irq_controller_size = MSM5XXX_POC_REX_CONTROLLER_SIZE;
}

static void msm5xxx_poc_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

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
    object_class_property_add_str(oc, "pause-timer",
                                  msm5xxx_poc_get_pause_timer,
                                  msm5xxx_poc_set_pause_timer);
    object_class_property_set_description(
        oc, "pause-timer",
        "Detector-scoped noninterruptible pause-timer writes");
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
    object_class_property_add_str(oc, "primary-x16-nor",
                                  msm5xxx_poc_get_primary_x16_nor,
                                  msm5xxx_poc_set_primary_x16_nor);
    object_class_property_set_description(
        oc, "primary-x16-nor",
        "Detector-provided writable primary x16 NOR tail");
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
