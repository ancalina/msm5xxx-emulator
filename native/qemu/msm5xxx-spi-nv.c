/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-spi-nv.h"
#include <string.h>

static void reject(MSM5xxxSPINV *s, MSM5xxxSPINVReject reason)
{
    if (!s->rejected && s->rejections != UINT64_MAX) {
        s->rejections++;
    }
    s->rejected = true;
    s->last_reject = reason;
    s->phase = MSM5XXX_SPI_NV_REJECTED;
    s->miso_driven = false;
    s->tx_bits = 0;
}

void msm5xxx_spi_nv_abort_frame(MSM5xxxSPINV *s)
{
    if (s && s->image) {
        reject(s, MSM5XXX_SPI_NV_INVALID_ACCESS);
    }
}

static void begin_frame(MSM5xxxSPINV *s)
{
    s->phase = MSM5XXX_SPI_NV_COMMAND;
    s->rejected = false;
    s->last_reject = MSM5XXX_SPI_NV_OK;
    s->opcode = s->rx_shift = s->rx_bits = 0;
    s->tx_shift = s->tx_bits = 0;
    s->address = 0;
    s->page_offset = 0;
    s->has_payload = false;
    s->miso_driven = false;
    /* A pending write owns page/pending_page until its deadline or power reset. */
}

bool msm5xxx_spi_nv_init(MSM5xxxSPINV *s, uint8_t *image, uint32_t capacity,
                         uint64_t write_cycle_ns)
{
    if (!s || !image || capacity < MSM5XXX_SPI_NV_PAGE_SIZE || capacity > 65536u ||
        (capacity & (capacity - 1u)) || !write_cycle_ns) {
        return false;
    }
    memset(s, 0, sizeof(*s));
    s->image = image;
    s->capacity = capacity;
    s->write_cycle_ns = write_cycle_ns;
    msm5xxx_spi_nv_power_reset(s);
    return true;
}

void msm5xxx_spi_nv_power_reset(MSM5xxxSPINV *s)
{
    if (!s) {
        return;
    }
    s->wel = s->wip = false;
    s->pending_status = false;
    s->pending_page = 0;
    s->deadline_ns = 0;
    memset(s->page, 0, sizeof(s->page));
    begin_frame(s);
    s->cs_n = true;
    s->sck = false;
    s->miso_level = false;
}

uint8_t msm5xxx_spi_nv_status(const MSM5xxxSPINV *s)
{
    return s ? (s->wel ? 2u : 0u) | (s->wip ? 1u : 0u) : 0;
}

bool msm5xxx_spi_nv_advance(MSM5xxxSPINV *s, uint64_t now_ns)
{
    bool committed;

    if (!s || !s->image || !s->wip || now_ns < s->deadline_ns) {
        return false;
    }
    committed = !s->pending_status;
    if (committed) {
        memcpy(s->image + s->pending_page, s->page, sizeof(s->page));
        s->last_commit_page = s->pending_page;
        if (s->commits != UINT64_MAX) {
            s->commits++;
        }
    }
    s->wel = s->wip = false;
    s->pending_status = false;
    s->deadline_ns = 0;
    return committed;
}

static void input_byte(MSM5xxxSPINV *s, uint8_t value)
{
    switch (s->phase) {
    case MSM5XXX_SPI_NV_COMMAND:
        s->opcode = value;
        if (s->wip && value != 0x05) {
            reject(s, MSM5XXX_SPI_NV_BUSY_OPCODE);
            return;
        }
        switch (value) {
        case 0x06:
            s->phase = MSM5XXX_SPI_NV_WREN;
            break;
        case 0x04:
            s->phase = MSM5XXX_SPI_NV_WRDI;
            break;
        case 0x02:
        case 0x01:
            if (!s->wel) {
                reject(s, MSM5XXX_SPI_NV_WEL_REQUIRED);
            } else {
                s->phase = value == 0x02 ? MSM5XXX_SPI_NV_ADDRESS_HIGH : MSM5XXX_SPI_NV_WRSR;
            }
            break;
        case 0x03:
            s->phase = MSM5XXX_SPI_NV_ADDRESS_HIGH;
            break;
        case 0x05:
            s->phase = MSM5XXX_SPI_NV_STATUS;
            break;
        default:
            reject(s, MSM5XXX_SPI_NV_UNKNOWN_OPCODE);
            break;
        }
        break;
    case MSM5XXX_SPI_NV_ADDRESS_HIGH:
        s->address = (uint32_t)value << 8;
        s->phase = MSM5XXX_SPI_NV_ADDRESS_LOW;
        break;
    case MSM5XXX_SPI_NV_ADDRESS_LOW:
        s->address = (s->address | value) & (s->capacity - 1u);
        if (s->opcode == 0x03) {
            s->phase = MSM5XXX_SPI_NV_READ;
        } else {
            s->pending_page = s->address & ~(MSM5XXX_SPI_NV_PAGE_SIZE - 1u);
            s->page_offset = s->address & (MSM5XXX_SPI_NV_PAGE_SIZE - 1u);
            memcpy(s->page, s->image + s->pending_page, sizeof(s->page));
            s->phase = MSM5XXX_SPI_NV_WRITE;
        }
        break;
    case MSM5XXX_SPI_NV_WRITE:
        s->page[s->page_offset] = value;
        s->page_offset = (s->page_offset + 1u) & (MSM5XXX_SPI_NV_PAGE_SIZE - 1u);
        s->has_payload = true;
        break;
    case MSM5XXX_SPI_NV_WRSR:
        if (value != 0) {
            reject(s, MSM5XXX_SPI_NV_STATUS_VALUE);
        } else {
            s->phase = MSM5XXX_SPI_NV_WRSR_DONE;
        }
        break;
    default:
        reject(s, MSM5XXX_SPI_NV_EXTRA_DATA);
        break;
    }
}

static void finish_frame(MSM5xxxSPINV *s, uint64_t now_ns)
{
    bool write = s->phase == MSM5XXX_SPI_NV_WRITE;
    bool status_write = s->phase == MSM5XXX_SPI_NV_WRSR_DONE;

    if (s->rejected || s->phase == MSM5XXX_SPI_NV_READ ||
        s->phase == MSM5XXX_SPI_NV_STATUS) {
        return; /* Output streams may be deselected at any bit. */
    }
    if (s->rx_bits || (write && !s->has_payload) ||
        (!write && !status_write && s->phase != MSM5XXX_SPI_NV_WREN &&
         s->phase != MSM5XXX_SPI_NV_WRDI)) {
        reject(s, MSM5XXX_SPI_NV_TRUNCATED);
    } else if (s->phase == MSM5XXX_SPI_NV_WREN) {
        s->wel = true;
    } else if (s->phase == MSM5XXX_SPI_NV_WRDI) {
        s->wel = false;
    } else if (now_ns > UINT64_MAX - s->write_cycle_ns) {
        reject(s, MSM5XXX_SPI_NV_TIME_OVERFLOW);
    } else {
        s->pending_status = status_write;
        s->deadline_ns = now_ns + s->write_cycle_ns;
        s->wip = true;
    }
}

static void falling_edge(MSM5xxxSPINV *s)
{
    if (s->phase != MSM5XXX_SPI_NV_READ && s->phase != MSM5XXX_SPI_NV_STATUS) {
        return;
    }
    if (!s->tx_bits) {
        if (s->phase == MSM5XXX_SPI_NV_READ) {
            s->tx_shift = s->image[s->address];
            s->address = (s->address + 1u) & (s->capacity - 1u);
        } else {
            s->tx_shift = msm5xxx_spi_nv_status(s);
        }
        s->tx_bits = 8;
    }
    s->miso_level = (s->tx_shift & 0x80) != 0;
    s->miso_driven = true;
    s->tx_shift <<= 1;
    s->tx_bits--;
}

bool msm5xxx_spi_nv_step(MSM5xxxSPINV *s, uint64_t now_ns, bool cs_n,
                         bool sck, bool mosi)
{
    bool committed;

    if (!s || !s->image) {
        return false;
    }
    committed = msm5xxx_spi_nv_advance(s, now_ns);
    if (cs_n != s->cs_n) {
        if (cs_n) {
            finish_frame(s, now_ns);
            s->miso_driven = false;
        } else {
            begin_frame(s);
        }
    } else if (!cs_n && !s->rejected) {
        if (!s->sck && sck && s->phase != MSM5XXX_SPI_NV_READ &&
            s->phase != MSM5XXX_SPI_NV_STATUS) {
            s->rx_shift = (uint8_t)((s->rx_shift << 1) | (mosi ? 1u : 0u));
            if (++s->rx_bits == 8) {
                uint8_t value = s->rx_shift;
                s->rx_shift = s->rx_bits = 0;
                input_byte(s, value);
            }
        } else if (s->sck && !sck) {
            falling_edge(s);
        }
    }
    s->cs_n = cs_n;
    s->sck = sck;
    return committed;
}

bool msm5xxx_spi_nv_miso(const MSM5xxxSPINV *s, bool *level)
{
    if (!s || !level || s->cs_n || !s->miso_driven) {
        return false;
    }
    *level = s->miso_level;
    return true;
}
