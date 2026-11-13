/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-boot-nand.h"

#include <stdio.h>
#include <string.h>

#define MAIN_SIZE 32768u
#define SPARE_SIZE (MAIN_SIZE / 32u)
#define MEDIA_SIZE (MAIN_SIZE + SPARE_SIZE)
#define PAGE2_MAIN (MSM5XXX_BOOT_NAND_BLOCK_SIZE + 2u * MSM5XXX_BOOT_NAND_PAGE_SIZE)
#define PAGE2_SPARE (MAIN_SIZE + (MSM5XXX_BOOT_NAND_PAGES_PER_BLOCK + 2u) * MSM5XXX_BOOT_NAND_SPARE_SIZE)
#define IRQ_COMPLETE UINT32_C(0x6000)
#define IRQ_READ UINT32_C(0x2000)

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL:%d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static bool write_reg(MSM5xxxBootNand *nand, uint32_t offset,
                      unsigned size, uint32_t value)
{
    return msm5xxx_boot_nand_write(nand, offset, size, value);
}

static bool write_address_bytes(MSM5xxxBootNand *nand, uint32_t address)
{
    unsigned i;

    for (i = 0; i < 4; i++) {
        if (!write_reg(nand, 0x304 + i, 1, (address >> (8 * i)) & 0xff)) {
            return false;
        }
    }
    return true;
}

static bool issue(MSM5xxxBootNand *nand, uint8_t command)
{
    return write_reg(nand, 0x300, 1, command);
}

static int check_pending(const MSM5xxxBootNand *nand, uint32_t expected)
{
    return nand->pending == expected;
}

int main(void)
{
    uint8_t media[MEDIA_SIZE];
    uint8_t before[MEDIA_SIZE];
    MSM5xxxBootNand nand;
    uint64_t value;
    unsigned i;

    memset(media, 0xff, sizeof(media));
    for (i = 0; i < MSM5XXX_BOOT_NAND_PAGE_SIZE; i++) {
        media[PAGE2_MAIN + i] = (uint8_t)(i ^ 0x5a);
    }
    media[PAGE2_SPARE + 5] = 0x3c;
    media[0] = 0;
    media[MAIN_SIZE] = 0;

    CHECK(msm5xxx_boot_nand_init(&nand, media, MAIN_SIZE, MEDIA_SIZE,
                                 IRQ_COMPLETE, IRQ_READ));
    CHECK(nand.data[0] == 0xff && nand.spare[0] == 0xff);
    CHECK(!msm5xxx_boot_nand_read(&nand, 0x200, 4, &value));
    nand.raw_spare_window = true;
    /* Erased-page scans include the 16 contiguous spare bytes. */
    for (i = 0; i < 528; i += 4) {
        CHECK(msm5xxx_boot_nand_read(&nand, i, 4, &value));
        CHECK(value == UINT32_MAX);
    }
    CHECK(msm5xxx_boot_nand_write(&nand, 0x208, 4, UINT32_C(0x12345678)));
    CHECK(msm5xxx_boot_nand_read(&nand, 0x328, 4, &value));
    CHECK(value == UINT32_C(0x12345678));
    CHECK(!msm5xxx_boot_nand_read(&nand, 0x20f, 2, &value));
    CHECK(!msm5xxx_boot_nand_write(&nand, 0x20e, 4, 0));
    msm5xxx_boot_nand_reset(&nand);
    CHECK(nand.raw_spare_window);

    /* Compose page address from byte writes, then read main and spare data. */
    CHECK(write_address_bytes(&nand, PAGE2_MAIN));
    CHECK(issue(&nand, 1));
    CHECK(check_pending(&nand, IRQ_READ));
    CHECK(nand.status == 0);
    CHECK(msm5xxx_boot_nand_read(&nand, 0, 2, &value));
    CHECK(value == ((uint64_t)media[PAGE2_MAIN] |
                    ((uint16_t)media[PAGE2_MAIN + 1] << 8)));
    CHECK(msm5xxx_boot_nand_read(&nand, 4, 4, &value));
    CHECK(value == ((uint32_t)media[PAGE2_MAIN + 4] |
                    ((uint32_t)media[PAGE2_MAIN + 5] << 8) |
                    ((uint32_t)media[PAGE2_MAIN + 6] << 16) |
                    ((uint32_t)media[PAGE2_MAIN + 7] << 24)));
    nand.pending |= UINT32_C(0x80000000);
    msm5xxx_boot_nand_irq_ack(&nand, IRQ_READ);
    CHECK(check_pending(&nand, UINT32_C(0x80000000)));
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);
    CHECK(check_pending(&nand, 0));

    CHECK(write_address_bytes(&nand, PAGE2_MAIN + 5));
    CHECK(issue(&nand, 2));
    CHECK(check_pending(&nand, IRQ_READ));
    CHECK(msm5xxx_boot_nand_read(&nand, 0x320, 1, &value));
    CHECK(value == 0x3c);
    CHECK(msm5xxx_boot_nand_read(&nand, 0x32b, 4, &value));
    CHECK(value == UINT32_MAX);
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);

    /* Prepare buffers twice, then program by NAND AND; FF bytes are no-ops. */
    CHECK(issue(&nand, 5));
    CHECK(check_pending(&nand, IRQ_READ));
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);
    CHECK(issue(&nand, 7));
    CHECK(check_pending(&nand, IRQ_COMPLETE));
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);
    nand.raw_spare_window = false;
    CHECK(issue(&nand, 7));
    CHECK(check_pending(&nand, IRQ_READ));
    nand.raw_spare_window = true;
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);
    CHECK(msm5xxx_boot_nand_write(&nand, 0, 4, UINT32_C(0x0f0ff00f)));
    CHECK(msm5xxx_boot_nand_write(&nand, 0x325, 1, 0x0f));
    CHECK(write_address_bytes(&nand, PAGE2_MAIN));
    CHECK(issue(&nand, 3));
    CHECK(check_pending(&nand, IRQ_COMPLETE));
    CHECK(nand.status == 0);
    CHECK(media[PAGE2_MAIN] == ((uint8_t)0x5a & 0x0f));
    CHECK(media[PAGE2_MAIN + 1] == ((uint8_t)0x5b & 0xf0));
    CHECK(media[PAGE2_MAIN + 2] == ((uint8_t)0x58 & 0x0f));
    CHECK(media[PAGE2_MAIN + 3] == ((uint8_t)0x59 & 0x0f));
    CHECK(media[PAGE2_MAIN + 4] == (uint8_t)(4 ^ 0x5a));
    CHECK(media[PAGE2_SPARE + 5] == 0x0c);
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);

    /* Erase block zero's main and spare regions, leaving block one intact. */
    CHECK(write_address_bytes(&nand, 0));
    CHECK(issue(&nand, 4));
    CHECK(check_pending(&nand, IRQ_COMPLETE));
    CHECK(media[0] == 0xff && media[MAIN_SIZE] == 0xff);
    CHECK(media[PAGE2_MAIN] == 0x0a);
    CHECK(media[PAGE2_SPARE + 5] == 0x0c);
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);

    /* Errors do not alter media; CMD6 preserves status and unrelated IRQs. */
    memcpy(before, media, sizeof(media));
    CHECK(write_address_bytes(&nand, 1));
    CHECK(issue(&nand, 3));
    CHECK(nand.status == 0x80);
    CHECK(check_pending(&nand, IRQ_COMPLETE));
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);
    nand.pending |= UINT32_C(0x80000000);
    CHECK(issue(&nand, 6));
    CHECK(nand.status == 0x80);
    CHECK(check_pending(&nand, UINT32_C(0x80000000) | IRQ_READ));
    CHECK(memcmp(before, media, sizeof(media)) == 0);
    msm5xxx_boot_nand_irq_ack(&nand, UINT32_MAX);

    CHECK(issue(&nand, 0x99));
    CHECK(nand.status == 0x80 && check_pending(&nand, IRQ_READ));
    CHECK(memcmp(before, media, sizeof(media)) == 0);
    CHECK(write_address_bytes(&nand, MAIN_SIZE));
    CHECK(issue(&nand, 1));
    CHECK(nand.status == 0x80);
    CHECK(memcmp(before, media, sizeof(media)) == 0);
    CHECK(!msm5xxx_boot_nand_read(&nand, 511, 2, &value));
    CHECK(!msm5xxx_boot_nand_write(&nand, 511, 4, 0));
    CHECK(!msm5xxx_boot_nand_read(&nand, 0, 3, &value));
    CHECK(!msm5xxx_boot_nand_write(&nand, 0, 3, 0));
    CHECK(memcmp(before, media, sizeof(media)) == 0);

    /* Identity shares the status register without discarding operation errors. */
    nand.identity_status = UINT32_C(0xa5400000);
    CHECK(write_reg(&nand, 0x300, 4, 6));
    CHECK(msm5xxx_boot_nand_read(&nand, 0x308, 4, &value));
    CHECK(value == UINT32_C(0xa5400080));
    CHECK(memcmp(before, media, sizeof(media)) == 0);
    msm5xxx_boot_nand_reset(&nand);
    CHECK(nand.media == media && nand.main_size == MAIN_SIZE);
    CHECK(nand.address == 0 && nand.status == 0 && nand.command == 0);
    CHECK(nand.pending == 0 && nand.data[0] == 0xff && nand.spare[0] == 0xff);
    CHECK(nand.identity_status == UINT32_C(0xa5400000));
    CHECK(write_reg(&nand, 0x300, 4, 6));
    CHECK(nand.status == UINT32_C(0xa5400000));
    CHECK(memcmp(before, media, sizeof(media)) == 0);
    CHECK(!msm5xxx_boot_nand_init(&nand, media, MAIN_SIZE, MEDIA_SIZE - 1,
                                  IRQ_COMPLETE, IRQ_READ));
    CHECK(!msm5xxx_boot_nand_init(&nand, media, MAIN_SIZE, MEDIA_SIZE,
                                  IRQ_READ, IRQ_COMPLETE));

    puts("PASS: boot NAND page, spare, program, erase, IRQ, and error protocol");
    return 0;
}
