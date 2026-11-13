/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-boot-nand.h"

#include <string.h>

static bool access_valid(unsigned size)
{
    return size == 1 || size == 2 || size == 4;
}

static uint32_t read_le(const uint8_t *bytes, unsigned size)
{
    uint32_t value = 0;
    unsigned i;

    for (i = 0; i < size; i++) {
        value |= (uint32_t)bytes[i] << (i * 8);
    }
    return value;
}

static void write_le(uint8_t *bytes, unsigned size, uint32_t value)
{
    unsigned i;

    for (i = 0; i < size; i++) {
        bytes[i] = (uint8_t)(value >> (i * 8));
    }
}

static void clear_page_buffers(MSM5xxxBootNand *nand)
{
    memset(nand->data, 0xff, sizeof(nand->data));
    memset(nand->spare, 0xff, sizeof(nand->spare));
    nand->spare_column = 0;
}

void msm5xxx_boot_nand_reset(MSM5xxxBootNand *nand)
{
    uint8_t *media;
    size_t main_size, media_size;
    uint32_t completion_mask, read_complete_mask, identity_status;
    bool raw_spare_window;

    if (nand == NULL) {
        return;
    }
    media = nand->media;
    main_size = nand->main_size;
    media_size = nand->media_size;
    completion_mask = nand->completion_mask;
    read_complete_mask = nand->read_complete_mask;
    identity_status = nand->identity_status;
    raw_spare_window = nand->raw_spare_window;
    memset(nand, 0, sizeof(*nand));
    nand->media = media;
    nand->main_size = main_size;
    nand->media_size = media_size;
    nand->completion_mask = completion_mask;
    nand->read_complete_mask = read_complete_mask;
    nand->identity_status = identity_status;
    nand->raw_spare_window = raw_spare_window;
    clear_page_buffers(nand);
}

bool msm5xxx_boot_nand_init(MSM5xxxBootNand *nand, uint8_t *media,
                            size_t main_size, size_t media_size,
                            uint32_t completion_mask,
                            uint32_t read_complete_mask)
{
    MSM5xxxBootNand fresh;

    if (nand == NULL || media == NULL || main_size == 0 ||
        main_size % MSM5XXX_BOOT_NAND_BLOCK_SIZE != 0 ||
        main_size > SIZE_MAX - main_size / 32 ||
        media_size != main_size + main_size / 32 ||
        completion_mask == 0 || read_complete_mask == 0 ||
        (completion_mask & read_complete_mask) != read_complete_mask) {
        return false;
    }

    memset(&fresh, 0, sizeof(fresh));
    fresh.media = media;
    fresh.main_size = main_size;
    fresh.media_size = media_size;
    fresh.completion_mask = completion_mask;
    fresh.read_complete_mask = read_complete_mask;
    clear_page_buffers(&fresh);
    *nand = fresh;
    return true;
}

static bool page_offsets(const MSM5xxxBootNand *nand, uint32_t address,
                         size_t *main_offset, size_t *spare_offset)
{
    size_t page = address / MSM5XXX_BOOT_NAND_PAGE_SIZE;
    size_t offset;

    if (nand->media == NULL || address % MSM5XXX_BOOT_NAND_PAGE_SIZE != 0 ||
        page > SIZE_MAX / MSM5XXX_BOOT_NAND_PAGE_SIZE) {
        return false;
    }
    offset = page * MSM5XXX_BOOT_NAND_PAGE_SIZE;
    if (offset > nand->main_size ||
        MSM5XXX_BOOT_NAND_PAGE_SIZE > nand->main_size - offset ||
        page > (SIZE_MAX - nand->main_size) / MSM5XXX_BOOT_NAND_SPARE_SIZE) {
        return false;
    }
    *main_offset = offset;
    *spare_offset = nand->main_size + page * MSM5XXX_BOOT_NAND_SPARE_SIZE;
    return *spare_offset <= nand->media_size &&
           MSM5XXX_BOOT_NAND_SPARE_SIZE <= nand->media_size - *spare_offset;
}

static void run_command(MSM5xxxBootNand *nand, uint32_t command)
{
    size_t main_offset, spare_offset;
    unsigned i;

    nand->command = command;
    if (command == 6) {
        /* Completion polling preserves the preceding operation's state. */
        if (nand->identity_status != 0) {
            nand->status |= nand->identity_status;
        }
        nand->pending |= nand->read_complete_mask;
        return;
    }
    nand->pending &= ~(nand->completion_mask | nand->read_complete_mask);
    switch (command) {
    case 0:
        nand->address = 0;
        nand->status = 0;
        clear_page_buffers(nand);
        return;
    case 1:
        if (!page_offsets(nand, nand->address, &main_offset,
                          &spare_offset)) {
            nand->status = 0x80;
            nand->pending |= nand->read_complete_mask;
            return;
        }
        memcpy(nand->data, nand->media + main_offset, sizeof(nand->data));
        memcpy(nand->spare, nand->media + spare_offset,
               sizeof(nand->spare));
        nand->spare_column = 0;
        nand->status = 0;
        nand->pending |= nand->read_complete_mask;
        return;
    case 2: {
        size_t page;

        page = nand->address / MSM5XXX_BOOT_NAND_PAGE_SIZE;
        if (nand->address % MSM5XXX_BOOT_NAND_PAGE_SIZE >=
            MSM5XXX_BOOT_NAND_SPARE_SIZE) {
            nand->status = 0x80;
            nand->pending |= nand->read_complete_mask;
            return;
        }
        nand->spare_column = (uint8_t)(nand->address %
                                      MSM5XXX_BOOT_NAND_PAGE_SIZE);
        if (nand->media == NULL ||
            page > (SIZE_MAX - nand->main_size) /
                       MSM5XXX_BOOT_NAND_SPARE_SIZE) {
            nand->status = 0x80;
            nand->pending |= nand->read_complete_mask;
            return;
        }
        spare_offset = nand->main_size + page * MSM5XXX_BOOT_NAND_SPARE_SIZE;
        if (spare_offset > nand->media_size ||
            MSM5XXX_BOOT_NAND_SPARE_SIZE > nand->media_size - spare_offset) {
            nand->status = 0x80;
            nand->pending |= nand->read_complete_mask;
            return;
        }
        memcpy(nand->spare, nand->media + spare_offset,
               sizeof(nand->spare));
        nand->status = 0;
        nand->pending |= nand->read_complete_mask;
        return;
    }
    case 3:
        if (!page_offsets(nand, nand->address, &main_offset,
                          &spare_offset)) {
            nand->status = 0x80;
            nand->pending |= nand->completion_mask;
            return;
        }
        /* NAND programming only clears bits; already-cleared bits are kept. */
        for (i = 0; i < sizeof(nand->data); i++) {
            nand->media[main_offset + i] &= nand->data[i];
        }
        for (i = 0; i < sizeof(nand->spare); i++) {
            nand->media[spare_offset + i] &= nand->spare[i];
        }
        nand->status = 0;
        nand->pending |= nand->completion_mask;
        return;
    case 4: {
        size_t block, spare_begin, spare_length;

        if (nand->media == NULL ||
            nand->address % MSM5XXX_BOOT_NAND_BLOCK_SIZE != 0 ||
            (size_t)nand->address > nand->main_size ||
            MSM5XXX_BOOT_NAND_BLOCK_SIZE >
                nand->main_size - (size_t)nand->address) {
            nand->status = 0x80;
            nand->pending |= nand->completion_mask;
            return;
        }
        block = (size_t)nand->address;
        spare_begin = nand->main_size +
            (block / MSM5XXX_BOOT_NAND_PAGE_SIZE) *
                MSM5XXX_BOOT_NAND_SPARE_SIZE;
        spare_length = MSM5XXX_BOOT_NAND_PAGES_PER_BLOCK *
                       MSM5XXX_BOOT_NAND_SPARE_SIZE;
        if (spare_begin > nand->media_size ||
            spare_length > nand->media_size - spare_begin) {
            nand->status = 0x80;
            nand->pending |= nand->completion_mask;
            return;
        }
        memset(nand->media + block, 0xff,
               MSM5XXX_BOOT_NAND_BLOCK_SIZE);
        memset(nand->media + spare_begin, 0xff, spare_length);
        nand->status = 0;
        nand->pending |= nand->completion_mask;
        return;
    }
    case 5:
    case 7:
        nand->status = 0;
        clear_page_buffers(nand);
        nand->pending |= command == 7 && nand->raw_spare_window ?
                         nand->completion_mask : nand->read_complete_mask;
        return;
    default:
        nand->status = 0x80;
        nand->pending |= nand->read_complete_mask;
        return;
    }
}

static bool read_spare(const MSM5xxxBootNand *nand, uint32_t offset,
                       unsigned size, uint64_t *value)
{
    unsigned start = (unsigned)(offset - 0x320) + nand->spare_column;
    unsigned i;
    uint32_t result = 0;

    for (i = 0; i < size; i++) {
        uint8_t byte = start + i < sizeof(nand->spare) ?
                       nand->spare[start + i] : 0xff;
        result |= (uint32_t)byte << (i * 8);
    }
    *value = result;
    return true;
}

bool msm5xxx_boot_nand_read(const MSM5xxxBootNand *nand, uint32_t offset,
                            unsigned size, uint64_t *value)
{
    if (nand == NULL || value == NULL || !access_valid(size)) {
        return false;
    }
    if (offset <= sizeof(nand->data) && size <= sizeof(nand->data) - offset) {
        *value = read_le(nand->data + offset, size);
        return true;
    }
    if (nand->raw_spare_window && offset >= 0x200 && offset < 0x210 &&
        size <= 0x210 - offset) {
        *value = read_le(nand->spare + offset - 0x200, size);
        return true;
    }
    if (offset >= 0x320 && offset < 0x330 && size <= 0x330 - offset) {
        return read_spare(nand, offset, size, value);
    }
    if (offset >= 0x300 && offset < 0x330 && size <= 0x330 - offset) {
        uint32_t reg = offset - 0x300;
        uint32_t reg_value;

        if (reg < 4 && 4 - reg >= size) {
            reg_value = nand->command;
        } else if (reg >= 4 && reg < 8 && 8 - reg >= size) {
            reg_value = nand->address;
        } else if (reg >= 8 && reg < 12 && 12 - reg >= size) {
            reg_value = nand->status;
        } else if (reg >= 0x1c && reg + size <= sizeof(nand->registers)) {
            reg_value = read_le(nand->registers + reg, size);
            *value = reg_value;
            return true;
        } else {
            return false;
        }
        *value = (reg_value >> ((reg & 3) * 8)) &
                 (size == 4 ? UINT32_MAX : (UINT32_C(1) << (size * 8)) - 1);
        return true;
    }
    return false;
}

bool msm5xxx_boot_nand_write(MSM5xxxBootNand *nand, uint32_t offset,
                             unsigned size, uint64_t value)
{
    if (nand == NULL || !access_valid(size) || value > UINT32_MAX) {
        return false;
    }
    if (offset < sizeof(nand->data) && size <= sizeof(nand->data) - offset) {
        write_le(nand->data + offset, size, (uint32_t)value);
        return true;
    }
    if (nand->raw_spare_window && offset >= 0x200 && offset < 0x210 &&
        size <= 0x210 - offset) {
        write_le(nand->spare + offset - 0x200, size, (uint32_t)value);
        return true;
    }
    if (offset >= 0x320 && offset < 0x330 && size <= 0x330 - offset) {
        write_le(nand->spare + offset - 0x320, size, (uint32_t)value);
        return true;
    }
    if (offset >= 0x300 && offset < 0x330 && size <= 0x330 - offset) {
        uint32_t reg = offset - 0x300;

        if (reg == 0 && (size == 1 || size == 4)) {
            nand->command = (uint32_t)value & 0xff;
            run_command(nand, nand->command);
            return true;
        }
        if (reg >= 4 && reg < 8 && 8 - reg >= size) {
            uint32_t shift = (reg & 3) * 8;
            uint32_t mask = size == 4 ? UINT32_MAX :
                            ((UINT32_C(1) << (size * 8)) - 1) << shift;
            nand->address = (nand->address & ~mask) |
                            (((uint32_t)value << shift) & mask);
            write_le(nand->registers + reg, size, (uint32_t)value);
            return true;
        }
        if (reg >= 8 && reg < 12 && 12 - reg >= size) {
            return true;
        }
        if (reg >= 0x1c && reg + size <= sizeof(nand->registers)) {
            write_le(nand->registers + reg, size, (uint32_t)value);
            return true;
        }
    }
    return false;
}

void msm5xxx_boot_nand_irq_ack(MSM5xxxBootNand *nand, uint32_t value)
{
    if (nand != NULL) {
        nand->pending &= ~value;
    }
}
