/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_SMALL_PAGE_NAND_H
#define MSM5XXX_SMALL_PAGE_NAND_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* shortcut: Fixed virtual 65536 rows*(512+16), 32 pages/block; revisit with
 * independent geometry evidence, not detected physical identity/capacity. */
#define MSM5XXX_NAND_PAGES UINT32_C(65536)
#define MSM5XXX_NAND_PAGE_BYTES UINT32_C(528)
#define MSM5XXX_NAND_RAW_BYTES ((size_t)MSM5XXX_NAND_PAGES * MSM5XXX_NAND_PAGE_BYTES)

/* Declared virtual x16 small-page subset; no physical-device identification.
 * The caller exclusively owns a full interleaved main/OOB buffer. No wear,
 * disturb, ECC, partial-program-count or disk-persistence model is provided.
 * Init assumes stable power and qualified backing, not a Vcc ramp. Protected
 * mutation confirms reject and set a conservative virtual failure bit; the
 * precise protected-operation failure-bit behavior is not a silicon claim.
 * Status-to-data recovery requires a new addressed read in this subset; extra
 * address cycles, copy-back and row-sequential reads explicitly reject.
 * READ ID is unsupported. Status high lanes use an FF pull-up. No row auto-increment.
 * All timestamps are monotonic ns; completion is applied before a new request.
 * A rejected request never starts a storage mutation. Earlier due operations
 * may complete first. Query failure reason separately from NAND status.
 * Reset during mutation poisons the device: raw bytes are UNTRUSTED, and must
 * not be persisted as valid. Re-init is allowed only with qualified backing.
 */
typedef enum {
    MSM5XXX_NAND_OK, MSM5XXX_NAND_ARGUMENT, MSM5XXX_NAND_TIME,
    MSM5XXX_NAND_OVERFLOW, MSM5XXX_NAND_WIDTH, MSM5XXX_NAND_SEQUENCE,
    MSM5XXX_NAND_UNSUPPORTED, MSM5XXX_NAND_RANGE, MSM5XXX_NAND_BUSY,
    MSM5XXX_NAND_WRITE_PROTECTED, MSM5XXX_NAND_PAGE_END,
    MSM5XXX_NAND_RESET_INTERRUPTED_MUTATION, MSM5XXX_NAND_UNTRUSTED
} MSM5xxxNandReason;
typedef enum {
    MSM5XXX_NAND_IDLE, MSM5XXX_NAND_READ_ADDRESS, MSM5XXX_NAND_READ_DATA,
    MSM5XXX_NAND_PROGRAM_ADDRESS, MSM5XXX_NAND_PROGRAM_DATA,
    MSM5XXX_NAND_ERASE_ADDRESS,
    MSM5XXX_NAND_STATUS = 8 /* Preserve the existing status telemetry value. */
} MSM5xxxNandMode;
typedef enum {
    MSM5XXX_NAND_PENDING_NONE, MSM5XXX_NAND_PENDING_READ,
    MSM5XXX_NAND_PENDING_PROGRAM, MSM5XXX_NAND_PENDING_ERASE,
    MSM5XXX_NAND_PENDING_RESET
} MSM5xxxNandPending;
typedef struct {
    uint64_t read_ns, program_ns, erase_ns, reset_ns;
    /* Optional unverified experimental nominal input for idle FF only.
     * Zero preserves reset_ns; read aborts always retain reset_ns. */
    uint64_t idle_reset_ns;
} MSM5xxxNandTimings;
typedef struct {
    uint8_t *raw;
    size_t raw_size;
    MSM5xxxNandTimings timings;
    uint64_t now_ns, deadline_ns;
    uint64_t mutation_generation;
    size_t last_mutation_offset, last_mutation_length;
    uint32_t row;
    uint16_t cursor, program_start, program_count;
    uint8_t address[3], address_count;
    uint8_t staged[MSM5XXX_NAND_PAGE_BYTES];
    MSM5xxxNandMode mode;
    MSM5xxxNandPending pending;
    MSM5xxxNandReason reason;
    bool initialized, trusted, writable, failed, spare, pointer_selected;
} MSM5xxxSmallPageNand;

bool msm5xxx_nand_init(MSM5xxxSmallPageNand *dev, uint8_t *raw, size_t size,
                       const MSM5xxxNandTimings *timings, bool writable,
                       uint64_t now_ns);
bool msm5xxx_nand_advance(MSM5xxxSmallPageNand *dev, uint64_t now_ns);
bool msm5xxx_nand_command(MSM5xxxSmallPageNand *dev, uint8_t command,
                          unsigned width, uint64_t now_ns);
bool msm5xxx_nand_address(MSM5xxxSmallPageNand *dev, uint8_t address,
                          unsigned width, uint64_t now_ns);
bool msm5xxx_nand_write(MSM5xxxSmallPageNand *dev, uint16_t value,
                        unsigned width, uint64_t now_ns);
bool msm5xxx_nand_read(MSM5xxxSmallPageNand *dev, unsigned width,
                       uint64_t now_ns, uint16_t *out);
/* On each completed program/erase, generation increments and the last dirty
 * range covers the whole raw page/block. The frontend must persist a new
 * generation before advancing another mutation. Backend failure must invalidate
 * the core and stop; this is not a rollback guarantee. */
void msm5xxx_nand_invalidate(MSM5xxxSmallPageNand *dev);
bool msm5xxx_nand_ready(const MSM5xxxSmallPageNand *dev);
bool msm5xxx_nand_trusted(const MSM5xxxSmallPageNand *dev);
#endif
