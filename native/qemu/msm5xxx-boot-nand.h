/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_BOOT_NAND_H
#define MSM5XXX_BOOT_NAND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSM5XXX_BOOT_NAND_PAGE_SIZE UINT32_C(512)
#define MSM5XXX_BOOT_NAND_SPARE_SIZE UINT32_C(16)
#define MSM5XXX_BOOT_NAND_PAGES_PER_BLOCK UINT32_C(32)
#define MSM5XXX_BOOT_NAND_BLOCK_SIZE \
    (MSM5XXX_BOOT_NAND_PAGE_SIZE * MSM5XXX_BOOT_NAND_PAGES_PER_BLOCK)

/* The caller owns media for the life of the controller. Main data is followed
 * by one 16-byte spare area for each 512-byte page. */
typedef struct {
    uint8_t *media;
    size_t main_size;
    size_t media_size;
    uint32_t identity_status;
    bool raw_spare_window;
    uint8_t data[MSM5XXX_BOOT_NAND_PAGE_SIZE];
    uint8_t spare[MSM5XXX_BOOT_NAND_SPARE_SIZE];
    uint8_t registers[0x30];
    uint32_t address;
    uint32_t status;
    uint32_t command;
    uint32_t pending;
    uint32_t completion_mask;
    uint32_t read_complete_mask;
    uint8_t spare_column;
} MSM5xxxBootNand;

bool msm5xxx_boot_nand_init(MSM5xxxBootNand *nand, uint8_t *media,
                            size_t main_size, size_t media_size,
                            uint32_t completion_mask,
                            uint32_t read_complete_mask);
void msm5xxx_boot_nand_reset(MSM5xxxBootNand *nand);
bool msm5xxx_boot_nand_read(const MSM5xxxBootNand *nand, uint32_t offset,
                            unsigned size, uint64_t *value);
bool msm5xxx_boot_nand_write(MSM5xxxBootNand *nand, uint32_t offset,
                             unsigned size, uint64_t value);
void msm5xxx_boot_nand_irq_ack(MSM5xxxBootNand *nand, uint32_t value);

#endif
