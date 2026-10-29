/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Private source-compatible x16 aperture, not a physical part implementation.
 * The caller supplies an immutable seed and a separate, private working image.
 * Virtual policy: program commits at the following same-target 70 barrier;
 * exactly 128 ordered HALF stores alone do not commit. This conservative delay
 * makes truncated/overfull streams atomic; it is not physical program timing.
 * Erase commits after caller-supplied virtual ticks. Suspend freezes those ticks.
 * 0-to-1 requests are rejected atomically, not assigned physical error bits.
 * Reset or invalid owned protocol aborts pending work, preserving prior commits.
 * Foreign aperture accesses are unhandled and do not consume protocol state.
 * No allocation, I/O, persistence, physical ID or durability acknowledgment.
 */
#include "msm5xxx-protected-nor.h"

#include <string.h>

/* All addresses are physical byte addresses; width must be exactly two. */
static bool msm5xxx_protected_nor_bounds(const MSM5xxxProtectedNOR *p, uint32_t address)
{
    return p && p->initialized && !(address & 1) && address >= p->base &&
           (uint64_t)address + 2 <= (uint64_t)p->base + p->length;
}

void msm5xxx_protected_nor_reset(MSM5xxxProtectedNOR *p)
{
    p->phase = MSM5XXX_PROTECTED_NOR_ARRAY;
    p->operation = MSM5XXX_PROTECTED_NOR_NONE;
    p->remaining = 0;
    p->count = p->staged_length = 0;
    p->suspended = p->complete = p->last_erase_valid = false;
    p->array_selected = true;
    p->error = 0;
    p->reason = MSM5XXX_PROTECTED_NOR_REJECT_NONE;
}

bool msm5xxx_protected_nor_init(MSM5xxxProtectedNOR *p, const uint8_t *seed, uint8_t *working,
                        size_t length, uint32_t base, const uint32_t *sectors,
                        unsigned count, uint64_t erase_ticks)
{
    uint64_t total = 0;
    uintptr_t a = (uintptr_t)seed, b = (uintptr_t)working;
    uintptr_t c = (uintptr_t)p, d = (uintptr_t)sectors;
    size_t geometry_bytes;
    unsigned i;

    if (!p || !seed || !working || !sectors || !length || length > UINT32_MAX ||
        (base & 255) || (length & 255) || !count ||
        count > MSM5XXX_PROTECTED_NOR_MAX_SECTORS || !erase_ticks ||
        (uint64_t)base + length > UINT64_C(0x100000000) ||
        length > UINTPTR_MAX - a || length > UINTPTR_MAX - b ||
        (a < b + length && b < a + length)) {
        return false;
    }
    geometry_bytes = count * sizeof(*sectors);
    if (sizeof(*p) > UINTPTR_MAX - c || geometry_bytes > UINTPTR_MAX - d ||
        (c < a + length && a < c + sizeof(*p)) ||
        (c < b + length && b < c + sizeof(*p)) ||
        (c < d + geometry_bytes && d < c + sizeof(*p)) ||
        (b < d + geometry_bytes && d < b + length)) {
        return false;
    }
    for (i = 0; i < count; i++) {
        if (!sectors[i] || (sectors[i] & 255)) {
            return false;
        }
        total += sectors[i];
        if (total > length) {
            return false;
        }
    }
    if (total != length) {
        return false;
    }
    memset(p, 0, sizeof(*p));
    p->image = working;
    p->base = base;
    p->length = (uint32_t)length;
    p->sector_count = count;
    p->erase_ticks = erase_ticks;
    for (i = 0; i < count; i++) {
        p->starts[i + 1] = p->starts[i] + sectors[i];
    }
    memcpy(working, seed, length);
    p->initialized = true;
    msm5xxx_protected_nor_reset(p);
    return true;
}

bool msm5xxx_protected_nor_reject(MSM5xxxProtectedNOR *p, enum MSM5xxxProtectedNORReject reason)
{
    msm5xxx_protected_nor_reset(p);
    p->reason = reason;
    p->rejections++;
    return false;
}

int msm5xxx_protected_nor_sector(const MSM5xxxProtectedNOR *p, uint32_t address)
{
    unsigned i;

    for (i = 0; i < p->sector_count; i++) {
        if (address - p->base == p->starts[i]) {
            return (int)i;
        }
    }
    return -1;
}

static bool msm5xxx_protected_nor_blank(const MSM5xxxProtectedNOR *p, uint32_t target)
{
    int sector = msm5xxx_protected_nor_sector(p, target);
    uint32_t i;

    if (sector < 0) {
        return false;
    }
    for (i = p->starts[sector]; i < p->starts[sector + 1]; i++) {
        if (p->image[i] != 0xff) {
            return false;
        }
    }
    return true;
}

/* Explicit virtual time, no wall clock or implicit progress from status reads. */
void msm5xxx_protected_nor_advance(MSM5xxxProtectedNOR *p, uint64_t ticks)
{
    int sector;

    if (!p || !p->initialized || p->operation != MSM5XXX_PROTECTED_NOR_ERASE || p->complete ||
        p->suspended || !ticks) {
        return;
    }
    if (ticks < p->remaining) {
        p->remaining -= ticks;
        return;
    }
    sector = msm5xxx_protected_nor_sector(p, p->erase_target);
    if (sector < 0) {
        msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL);
        return;
    }
    memset(p->image + p->starts[sector], 0xff,
           p->starts[sector + 1] - p->starts[sector]);
    p->remaining = 0;
    p->complete = true;
    p->last_erase_valid = msm5xxx_protected_nor_blank(p, p->erase_target);
    p->error = p->last_erase_valid ? 0 : 0x20;
    p->erases++;
}

bool msm5xxx_protected_nor_read(MSM5xxxProtectedNOR *p, uint32_t address, unsigned width,
                        uint16_t *value)
{
    uint32_t at;

    if (!p || !p->initialized || address < p->base ||
        (uint64_t)address >= (uint64_t)p->base + p->length) {
        return false;
    }
    if (!value || width != 2 || !msm5xxx_protected_nor_bounds(p, address)) {
        return msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_WIDTH);
    }
    if (p->phase == MSM5XXX_PROTECTED_NOR_ARRAY ||
        (p->phase == MSM5XXX_PROTECTED_NOR_STATUS && p->array_selected && p->suspended)) {
        at = address - p->base;
        *value = p->image[at] | ((uint16_t)p->image[at + 1] << 8);
        return true;
    }
    if (p->phase != MSM5XXX_PROTECTED_NOR_STATUS || p->array_selected || address != p->target) {
        return msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL);
    }
    *value = (p->complete ? 0x80 : p->suspended ? 0xc0 : 0) | p->error;
    return true;
}

bool msm5xxx_protected_nor_write(MSM5xxxProtectedNOR *p, uint32_t address, unsigned width,
                         uint32_t value)
{
    uint32_t at, expected;
    unsigned mask;

    if (!p || !p->initialized || address < p->base ||
        (uint64_t)address >= (uint64_t)p->base + p->length) {
        return false;
    }
    if (width != 2 || value > 0xffff || !msm5xxx_protected_nor_bounds(p, address)) {
        return msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_WIDTH);
    }
    if (p->phase == MSM5XXX_PROTECTED_NOR_SINGLE || p->phase == MSM5XXX_PROTECTED_NOR_STREAM) {
        expected = p->target + (p->phase == MSM5XXX_PROTECTED_NOR_STREAM ? p->count * 2 : 0);
        if (address != expected || p->count >= 128) {
            return msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL);
        }
        p->staged[p->count * 2] = value;
        p->staged[p->count * 2 + 1] = value >> 8;
        p->count++;
        if (p->phase == MSM5XXX_PROTECTED_NOR_SINGLE || p->count == 128) {
            p->staged_length = p->count * 2;
            p->phase = MSM5XXX_PROTECTED_NOR_PROGRAM_BARRIER;
        }
        return true;
    }
    if (p->phase == MSM5XXX_PROTECTED_NOR_ARRAY) {
        if (value != 0x60) {
            return msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL);
        }
        p->target = address;
        p->phase = MSM5XXX_PROTECTED_NOR_INDEX;
        return true;
    }
    if (address != p->target) {
        return msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL);
    }
    mask = address >= 0x800000 ? 0x3f : 0x7f;
    switch (p->phase) {
    case MSM5XXX_PROTECTED_NOR_INDEX:
        if (value != ((address >> 16) & mask)) { break; }
        p->phase = MSM5XXX_PROTECTED_NOR_AC;
        return true;
    case MSM5XXX_PROTECTED_NOR_AC:
        if (value != 0xac) { break; }
        p->phase = MSM5XXX_PROTECTED_NOR_COMPLEMENT;
        return true;
    case MSM5XXX_PROTECTED_NOR_COMPLEMENT:
        if (value != (mask & ~(address >> 16))) { break; }
        p->phase = MSM5XXX_PROTECTED_NOR_7B;
        return true;
    case MSM5XXX_PROTECTED_NOR_7B:
        if (value != 0x7b) { break; }
        p->phase = MSM5XXX_PROTECTED_NOR_GRANT;
        return true;
    case MSM5XXX_PROTECTED_NOR_GRANT:
        if (value == 0x40 || value == 0x41) {
            if (value == 0x41 && ((address & 255) ||
                (uint64_t)address + 256 > (uint64_t)p->base + p->length)) {
                break;
            }
            p->last_erase_valid = false;
            p->count = 0;
            p->phase = value == 0x40 ? MSM5XXX_PROTECTED_NOR_SINGLE : MSM5XXX_PROTECTED_NOR_STREAM;
            return true;
        }
        if (msm5xxx_protected_nor_sector(p, address) < 0) { break; }
        if (value == 0x20) {
            p->last_erase_valid = false;
            p->phase = MSM5XXX_PROTECTED_NOR_ERASE_CONFIRM;
            return true;
        }
        if (value == 0x77 && p->last_erase_valid && address == p->erase_target) {
            p->phase = MSM5XXX_PROTECTED_NOR_VERIFY_CONFIRM;
            return true;
        }
        break;
    case MSM5XXX_PROTECTED_NOR_PROGRAM_BARRIER:
        if (value != 0x70) { break; }
        at = address - p->base;
        for (expected = 0; expected < p->staged_length; expected++) {
            if (p->staged[expected] & (uint8_t)~p->image[at + expected]) {
                return msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL);
            }
        }
        for (expected = 0; expected < p->staged_length; expected++) {
            p->image[at + expected] &= p->staged[expected];
        }
        p->operation = MSM5XXX_PROTECTED_NOR_PROGRAM;
        p->complete = true;
        p->array_selected = false;
        p->error = 0;
        p->phase = MSM5XXX_PROTECTED_NOR_STATUS;
        p->programs++;
        return true;
    case MSM5XXX_PROTECTED_NOR_ERASE_CONFIRM:
        if (value != 0xd0) { break; }
        p->operation = MSM5XXX_PROTECTED_NOR_ERASE;
        p->erase_target = address;
        p->remaining = p->erase_ticks;
        p->complete = p->suspended = false;
        p->array_selected = false;
        p->error = 0;
        p->phase = MSM5XXX_PROTECTED_NOR_STATUS;
        return true;
    case MSM5XXX_PROTECTED_NOR_VERIFY_CONFIRM:
        if (value != 0xd0) { break; }
        p->operation = MSM5XXX_PROTECTED_NOR_VERIFY;
        p->complete = true;
        p->array_selected = false;
        /* Virtual verification failure uses a source-observed error mask. */
        p->error = msm5xxx_protected_nor_blank(p, address) ? 0 : 0x20;
        p->phase = MSM5XXX_PROTECTED_NOR_STATUS;
        p->verifies++;
        return true;
    case MSM5XXX_PROTECTED_NOR_STATUS:
        if (value == 0x70) {
            p->array_selected = false;
            return true;
        }
        if (p->operation == MSM5XXX_PROTECTED_NOR_ERASE && !p->complete) {
            if (value == 0xb0 && !p->suspended) {
                p->suspended = true;
                p->array_selected = false;
                return true;
            }
            if (value == 0xd0 && p->suspended) {
                p->suspended = false;
                p->array_selected = false;
                return true;
            }
            if (value == 0xff && p->suspended) {
                p->array_selected = true;
                return true;
            }
            break;
        }
        if (value == 0x50 && p->complete) {
            p->error = 0;
            p->phase = MSM5XXX_PROTECTED_NOR_CLEARED;
            return true;
        }
        break;
    case MSM5XXX_PROTECTED_NOR_CLEARED:
        if (value != 0xff) { break; }
        p->operation = MSM5XXX_PROTECTED_NOR_NONE;
        p->array_selected = true;
        p->phase = MSM5XXX_PROTECTED_NOR_ARRAY;
        return true;
    default:
        break;
    }
    return msm5xxx_protected_nor_reject(p, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL);
}
