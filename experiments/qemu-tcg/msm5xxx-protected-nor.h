/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_PROTECTED_NOR_H
#define MSM5XXX_PROTECTED_NOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSM5XXX_PROTECTED_NOR_MAX_SECTORS 64

enum MSM5xxxProtectedNORPhase {
    MSM5XXX_PROTECTED_NOR_ARRAY, MSM5XXX_PROTECTED_NOR_INDEX, MSM5XXX_PROTECTED_NOR_AC, MSM5XXX_PROTECTED_NOR_COMPLEMENT, MSM5XXX_PROTECTED_NOR_7B, MSM5XXX_PROTECTED_NOR_GRANT,
    MSM5XXX_PROTECTED_NOR_SINGLE, MSM5XXX_PROTECTED_NOR_STREAM, MSM5XXX_PROTECTED_NOR_PROGRAM_BARRIER, MSM5XXX_PROTECTED_NOR_ERASE_CONFIRM,
    MSM5XXX_PROTECTED_NOR_VERIFY_CONFIRM, MSM5XXX_PROTECTED_NOR_STATUS, MSM5XXX_PROTECTED_NOR_CLEARED
};
enum MSM5xxxProtectedNOROperation { MSM5XXX_PROTECTED_NOR_NONE, MSM5XXX_PROTECTED_NOR_PROGRAM, MSM5XXX_PROTECTED_NOR_ERASE, MSM5XXX_PROTECTED_NOR_VERIFY };
enum MSM5xxxProtectedNORReject { MSM5XXX_PROTECTED_NOR_REJECT_NONE, MSM5XXX_PROTECTED_NOR_REJECT_WIDTH, MSM5XXX_PROTECTED_NOR_REJECT_PROTOCOL };

typedef struct MSM5xxxProtectedNOR {
    uint8_t *image;
    uint32_t base, length, starts[MSM5XXX_PROTECTED_NOR_MAX_SECTORS + 1];
    unsigned sector_count;
    uint64_t erase_ticks, remaining;
    enum MSM5xxxProtectedNORPhase phase;
    enum MSM5xxxProtectedNOROperation operation;
    uint32_t target, erase_target, staged_length;
    uint8_t staged[256];
    unsigned count;
    bool initialized, suspended, complete, array_selected, last_erase_valid;
    uint16_t error;
    uint64_t programs, erases, verifies, rejections;
    enum MSM5xxxProtectedNORReject reason;
} MSM5xxxProtectedNOR;

bool msm5xxx_protected_nor_init(MSM5xxxProtectedNOR *p, const uint8_t *seed, uint8_t *working,
                        size_t length, uint32_t base, const uint32_t *sectors,
                        unsigned count, uint64_t erase_ticks);

void msm5xxx_protected_nor_reset(MSM5xxxProtectedNOR *p);

bool msm5xxx_protected_nor_read(MSM5xxxProtectedNOR *p, uint32_t address, unsigned width,
                        uint16_t *value);

bool msm5xxx_protected_nor_write(MSM5xxxProtectedNOR *p, uint32_t address, unsigned width,
                         uint32_t value);

void msm5xxx_protected_nor_advance(MSM5xxxProtectedNOR *p, uint64_t ticks);

int msm5xxx_protected_nor_sector(const MSM5xxxProtectedNOR *p, uint32_t address);

bool msm5xxx_protected_nor_reject(MSM5xxxProtectedNOR *p, enum MSM5xxxProtectedNORReject reason);

#endif /* MSM5XXX_PROTECTED_NOR_H */
