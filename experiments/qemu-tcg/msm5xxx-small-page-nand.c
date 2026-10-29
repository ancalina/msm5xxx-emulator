/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-small-page-nand.h"
#include <string.h>

static bool reject(MSM5xxxSmallPageNand *d, MSM5xxxNandReason why)
{
    if (d != NULL) { d->reason = why; }
    return false;
}

bool msm5xxx_nand_trusted(const MSM5xxxSmallPageNand *d)
{
    return d != NULL && d->initialized && d->trusted;
}

void msm5xxx_nand_invalidate(MSM5xxxSmallPageNand *d)
{
    if (d != NULL) {
        d->trusted = false;
        d->pending = MSM5XXX_NAND_PENDING_NONE;
        d->reason = MSM5XXX_NAND_UNTRUSTED;
    }
}

bool msm5xxx_nand_ready(const MSM5xxxSmallPageNand *d)
{
    return msm5xxx_nand_trusted(d) && d->pending == MSM5XXX_NAND_PENDING_NONE;
}

bool msm5xxx_nand_init(MSM5xxxSmallPageNand *d, uint8_t *raw, size_t size,
                       const MSM5xxxNandTimings *t, bool writable, uint64_t now)
{
    MSM5xxxSmallPageNand fresh;
    if (d == NULL || raw == NULL || size != MSM5XXX_NAND_RAW_BYTES ||
        t == NULL || t->read_ns == 0 || t->program_ns == 0 ||
        t->erase_ns == 0 || t->reset_ns == 0) {
        return false;
    }
    memset(&fresh, 0, sizeof(fresh));
    fresh.raw = raw;
    fresh.raw_size = size;
    fresh.timings = *t;
    fresh.now_ns = now;
    fresh.writable = writable;
    fresh.trusted = true;
    fresh.initialized = true;
    *d = fresh;
    return true;
}

bool msm5xxx_nand_advance(MSM5xxxSmallPageNand *d, uint64_t now)
{
    size_t base;
    unsigned i;
    if (d == NULL || !d->initialized) { return reject(d, MSM5XXX_NAND_ARGUMENT); }
    if (!d->trusted) { return reject(d, MSM5XXX_NAND_UNTRUSTED); }
    if (now < d->now_ns) { return reject(d, MSM5XXX_NAND_TIME); }
    d->now_ns = now;
    if (d->pending != MSM5XXX_NAND_PENDING_NONE && now >= d->deadline_ns) {
        base = (size_t)d->row * MSM5XXX_NAND_PAGE_BYTES;
        switch (d->pending) {
        case MSM5XXX_NAND_PENDING_PROGRAM:
            for (i = 0; i < d->program_count; i++) {
                d->raw[base + d->program_start + i] &= d->staged[d->program_start + i];
            }
            d->last_mutation_offset = base;
            d->last_mutation_length = MSM5XXX_NAND_PAGE_BYTES;
            d->mutation_generation++;
            break;
        case MSM5XXX_NAND_PENDING_ERASE:
            base = (size_t)(d->row & ~UINT32_C(31)) * MSM5XXX_NAND_PAGE_BYTES;
            memset(d->raw + base, 0xff, 32U * MSM5XXX_NAND_PAGE_BYTES);
            d->last_mutation_offset = base;
            d->last_mutation_length = 32U * MSM5XXX_NAND_PAGE_BYTES;
            d->mutation_generation++;
            break;
        case MSM5XXX_NAND_PENDING_READ:
        case MSM5XXX_NAND_PENDING_RESET:
        case MSM5XXX_NAND_PENDING_NONE:
            break;
        }
        d->pending = MSM5XXX_NAND_PENDING_NONE;
    }
    d->reason = MSM5XXX_NAND_OK;
    return true;
}

static bool can_schedule(MSM5xxxSmallPageNand *d, uint64_t period)
{
    return period <= UINT64_MAX - d->now_ns || reject(d, MSM5XXX_NAND_OVERFLOW);
}

static void schedule(MSM5xxxSmallPageNand *d, MSM5xxxNandPending p, uint64_t period)
{
    d->pending = p;
    d->deadline_ns = d->now_ns + period;
}

static void clear_parser(MSM5xxxSmallPageNand *d)
{
    d->address_count = 0;
    d->program_count = 0;
    d->cursor = 0;
    d->mode = MSM5XXX_NAND_IDLE;
}

bool msm5xxx_nand_command(MSM5xxxSmallPageNand *d, uint8_t command,
                          unsigned width, uint64_t now)
{
    uint64_t period;
    if (!msm5xxx_nand_advance(d, now)) { return false; }
    if (width != 1) { return reject(d, MSM5XXX_NAND_WIDTH); }
    if (d->pending != MSM5XXX_NAND_PENDING_NONE) {
        if (command == 0x70) { d->mode = MSM5XXX_NAND_STATUS; return true; }
        if (command != 0xff) { return reject(d, MSM5XXX_NAND_BUSY); }
        if (d->pending == MSM5XXX_NAND_PENDING_PROGRAM ||
            d->pending == MSM5XXX_NAND_PENDING_ERASE) {
            d->trusted = false;
            d->pending = MSM5XXX_NAND_PENDING_NONE;
            clear_parser(d);
            return reject(d, MSM5XXX_NAND_RESET_INTERRUPTED_MUTATION);
        }
        if (d->pending == MSM5XXX_NAND_PENDING_RESET) {
            return reject(d, MSM5XXX_NAND_BUSY);
        }
        /* A read may be aborted without modifying storage. */
    }
    switch (command) {
    case 0xff:
        period = d->timings.reset_ns;
        if (d->pending == MSM5XXX_NAND_PENDING_NONE && d->timings.idle_reset_ns != 0) {
            period = d->timings.idle_reset_ns;
        }
        if (!can_schedule(d, period)) { return false; }
        clear_parser(d);
        d->spare = false;
        d->pointer_selected = false;
        d->failed = false;
        schedule(d, MSM5XXX_NAND_PENDING_RESET, period);
        return true;
    case 0x70:
        d->mode = MSM5XXX_NAND_STATUS;
        return true;
    case 0x00:
    case 0x50:
        clear_parser(d);
        d->mode = MSM5XXX_NAND_READ_ADDRESS;
        d->spare = command == 0x50;
        d->pointer_selected = true;
        return true;
    case 0x80:
        if (!d->pointer_selected ||
            !((d->mode == MSM5XXX_NAND_READ_ADDRESS && d->address_count == 0) ||
              d->mode == MSM5XXX_NAND_READ_DATA || d->mode == MSM5XXX_NAND_STATUS)) {
            return reject(d, MSM5XXX_NAND_SEQUENCE);
        }
        clear_parser(d);
        d->mode = MSM5XXX_NAND_PROGRAM_ADDRESS;
        memset(d->staged, 0xff, sizeof(d->staged));
        return true;
    case 0x10:
        if (d->mode != MSM5XXX_NAND_PROGRAM_DATA || d->program_count == 0) {
            return reject(d, MSM5XXX_NAND_SEQUENCE);
        }
        if (!d->writable) {
            d->failed = true;
            d->mode = MSM5XXX_NAND_STATUS;
            return reject(d, MSM5XXX_NAND_WRITE_PROTECTED);
        }
        if (d->mutation_generation == UINT64_MAX) { return reject(d, MSM5XXX_NAND_OVERFLOW); }
        period = d->timings.program_ns;
        if (!can_schedule(d, period)) { return false; }
        d->failed = false;
        d->mode = MSM5XXX_NAND_STATUS;
        schedule(d, MSM5XXX_NAND_PENDING_PROGRAM, period);
        return true;
    case 0x60:
        clear_parser(d);
        d->mode = MSM5XXX_NAND_ERASE_ADDRESS;
        return true;
    case 0xd0:
        if (d->mode != MSM5XXX_NAND_ERASE_ADDRESS || d->address_count != 2) {
            return reject(d, MSM5XXX_NAND_SEQUENCE);
        }
        if (!d->writable) {
            d->failed = true;
            d->mode = MSM5XXX_NAND_STATUS;
            return reject(d, MSM5XXX_NAND_WRITE_PROTECTED);
        }
        if (d->mutation_generation == UINT64_MAX) { return reject(d, MSM5XXX_NAND_OVERFLOW); }
        period = d->timings.erase_ns;
        if (!can_schedule(d, period)) { return false; }
        d->failed = false;
        d->mode = MSM5XXX_NAND_STATUS;
        schedule(d, MSM5XXX_NAND_PENDING_ERASE, period);
        return true;
    case 0x90:
        return reject(d, MSM5XXX_NAND_UNSUPPORTED);
    default:
        return reject(d, MSM5XXX_NAND_UNSUPPORTED);
    }
}

bool msm5xxx_nand_address(MSM5xxxSmallPageNand *d, uint8_t value,
                          unsigned width, uint64_t now)
{
    uint8_t a[3];
    uint16_t column;
    uint32_t row;
    unsigned count;
    if (!msm5xxx_nand_advance(d, now)) { return false; }
    if (width != 1) { return reject(d, MSM5XXX_NAND_WIDTH); }
    if (!msm5xxx_nand_ready(d)) { return reject(d, MSM5XXX_NAND_BUSY); }
    if (d->mode != MSM5XXX_NAND_READ_ADDRESS &&
        d->mode != MSM5XXX_NAND_PROGRAM_ADDRESS &&
        d->mode != MSM5XXX_NAND_ERASE_ADDRESS) {
        return reject(d, MSM5XXX_NAND_SEQUENCE);
    }
    count = d->address_count;
    if (count >= (d->mode == MSM5XXX_NAND_ERASE_ADDRESS ? 2U : 3U)) {
        return reject(d, MSM5XXX_NAND_SEQUENCE);
    }
    memcpy(a, d->address, sizeof(a));
    a[count] = value;
    if (d->mode == MSM5XXX_NAND_ERASE_ADDRESS) {
        d->address[count] = value;
        d->address_count++;
        if (d->address_count == 2) { d->row = (uint32_t)a[0] | (uint32_t)a[1] << 8; }
        return true;
    }
    if (count == 0 && d->spare && value >= 8) { return reject(d, MSM5XXX_NAND_RANGE); }
    if (count == 2) {
        column = (uint16_t)((d->spare ? 512U : 0U) + (unsigned)a[0] * 2U);
        row = (uint32_t)a[1] | (uint32_t)a[2] << 8;
        if (column >= MSM5XXX_NAND_PAGE_BYTES || row >= MSM5XXX_NAND_PAGES) {
            return reject(d, MSM5XXX_NAND_RANGE);
        }
        if (d->mode == MSM5XXX_NAND_READ_ADDRESS &&
            !can_schedule(d, d->timings.read_ns)) { return false; }
        d->row = row;
        d->cursor = column;
        d->program_start = column;
        if (d->mode == MSM5XXX_NAND_READ_ADDRESS) {
            d->mode = MSM5XXX_NAND_READ_DATA;
            schedule(d, MSM5XXX_NAND_PENDING_READ, d->timings.read_ns);
        } else { d->mode = MSM5XXX_NAND_PROGRAM_DATA; }
    }
    d->address[count] = value;
    d->address_count++;
    return true;
}

bool msm5xxx_nand_write(MSM5xxxSmallPageNand *d, uint16_t value,
                        unsigned width, uint64_t now)
{
    if (!msm5xxx_nand_advance(d, now)) { return false; }
    if (width != 2) { return reject(d, MSM5XXX_NAND_WIDTH); }
    if (!msm5xxx_nand_ready(d)) { return reject(d, MSM5XXX_NAND_BUSY); }
    if (d->mode != MSM5XXX_NAND_PROGRAM_DATA) { return reject(d, MSM5XXX_NAND_SEQUENCE); }
    if (d->cursor > MSM5XXX_NAND_PAGE_BYTES - 2) { return reject(d, MSM5XXX_NAND_PAGE_END); }
    d->staged[d->cursor] = (uint8_t)value;
    d->staged[d->cursor + 1] = (uint8_t)(value >> 8);
    d->cursor += 2;
    d->program_count += 2;
    return true;
}

bool msm5xxx_nand_read(MSM5xxxSmallPageNand *d, unsigned width,
                       uint64_t now, uint16_t *out)
{
    size_t base;
    uint16_t value;
    if (out == NULL) { return reject(d, MSM5XXX_NAND_ARGUMENT); }
    if (!msm5xxx_nand_advance(d, now)) { return false; }
    if (d->mode == MSM5XXX_NAND_STATUS) {
        if (width != 1 && width != 2) { return reject(d, MSM5XXX_NAND_WIDTH); }
        value = (uint16_t)((d->writable ? 0x80U : 0U) |
                (msm5xxx_nand_ready(d) ? 0x40U : 0U) | (d->failed ? 1U : 0U));
        *out = (uint16_t)(value | (width == 2 ? 0xff00U : 0U));
        return true;
    }
    if (width != 2) { return reject(d, MSM5XXX_NAND_WIDTH); }
    if (!msm5xxx_nand_ready(d)) { return reject(d, MSM5XXX_NAND_BUSY); }
    if (d->mode != MSM5XXX_NAND_READ_DATA) { return reject(d, MSM5XXX_NAND_SEQUENCE); }
    if (d->cursor > MSM5XXX_NAND_PAGE_BYTES - 2) { return reject(d, MSM5XXX_NAND_PAGE_END); }
    base = (size_t)d->row * MSM5XXX_NAND_PAGE_BYTES + d->cursor;
    value = (uint16_t)((unsigned)d->raw[base] | (unsigned)d->raw[base + 1] << 8);
    d->cursor += 2;
    *out = value;
    return true;
}
