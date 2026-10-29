/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_SPI_NV_H
#define MSM5XXX_SPI_NV_H

#include <stdbool.h>
#include <stdint.h>

#define MSM5XXX_SPI_NV_PAGE_SIZE 32u

typedef enum MSM5xxxSPINVReject {
    MSM5XXX_SPI_NV_OK,
    MSM5XXX_SPI_NV_UNKNOWN_OPCODE,
    MSM5XXX_SPI_NV_BUSY_OPCODE,
    MSM5XXX_SPI_NV_WEL_REQUIRED,
    MSM5XXX_SPI_NV_TRUNCATED,
    MSM5XXX_SPI_NV_EXTRA_DATA,
    MSM5XXX_SPI_NV_STATUS_VALUE,
    MSM5XXX_SPI_NV_TIME_OVERFLOW,
    MSM5XXX_SPI_NV_INVALID_ACCESS,
} MSM5xxxSPINVReject;

typedef enum MSM5xxxSPINVPhase {
    MSM5XXX_SPI_NV_COMMAND,
    MSM5XXX_SPI_NV_ADDRESS_HIGH,
    MSM5XXX_SPI_NV_ADDRESS_LOW,
    MSM5XXX_SPI_NV_READ,
    MSM5XXX_SPI_NV_WRITE,
    MSM5XXX_SPI_NV_STATUS,
    MSM5XXX_SPI_NV_WREN,
    MSM5XXX_SPI_NV_WRDI,
    MSM5XXX_SPI_NV_WRSR,
    MSM5XXX_SPI_NV_WRSR_DONE,
    MSM5XXX_SPI_NV_REJECTED,
} MSM5xxxSPINVPhase;

typedef struct MSM5xxxSPINV {
    /* Caller retains the image; successful initialization never changes its bytes. */
    uint8_t *image;
    uint32_t capacity;
    uint64_t write_cycle_ns;
    /* Image-commit telemetry survives power reset. Counters saturate. */
    uint64_t commits, rejections;
    uint32_t last_commit_page;
    MSM5xxxSPINVReject last_reject;
    bool wel, wip, rejected;

    /* Protocol state: caller must not modify these fields. */
    MSM5xxxSPINVPhase phase;
    bool cs_n, sck, miso_driven, miso_level, has_payload, pending_status;
    uint8_t opcode, rx_shift, rx_bits, tx_shift, tx_bits, page_offset;
    uint32_t address, pending_page;
    uint64_t deadline_ns;
    uint8_t page[MSM5XXX_SPI_NV_PAGE_SIZE];
} MSM5xxxSPINV;

/* capacity: power of two, 32..65536; timing is a supplied virtual policy, not calibration.
 * Invalid initialization leaves the previous state and image unchanged. */
bool msm5xxx_spi_nv_init(MSM5xxxSPINV *s, uint8_t *image, uint32_t capacity,
                         uint64_t write_cycle_ns);
/* Reject the active frame without altering an already pending write. */
void msm5xxx_spi_nv_abort_frame(MSM5xxxSPINV *s);
/* Explicit virtual POWER reset: abort uncommitted work, preserve image/config/counters.
 * Caller advances elapsed time first if a completed cycle must precede the reset. */
void msm5xxx_spi_nv_power_reset(MSM5xxxSPINV *s);
/* Supply monotonic virtual nanoseconds. true means image committed: flush before reply.
 * WRSR00 completion changes WEL/WIP but returns false (no image commit). */
bool msm5xxx_spi_nv_advance(MSM5xxxSPINV *s, uint64_t now_ns);
/* cs_n is physical active-low CS. CS transitions take priority over clock transitions.
 * Input is latched on SCK rising; MISO changes on falling edges, MSB first. */
bool msm5xxx_spi_nv_step(MSM5xxxSPINV *s, uint64_t now_ns, bool cs_n,
                         bool sck, bool mosi);
/* false means high impedance, not a zero-valued input level. */
bool msm5xxx_spi_nv_miso(const MSM5xxxSPINV *s, bool *level);
/* Only supported WEL/WIP bits; getter does not advance time or consume serial data. */
uint8_t msm5xxx_spi_nv_status(const MSM5xxxSPINV *s);

#endif
