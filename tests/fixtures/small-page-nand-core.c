/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "msm5xxx-small-page-nand.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const MSM5xxxNandTimings timing = {10000, 200000, 2000000, 5000, 0};
static uint64_t ticks;
static uint8_t *raw, *copy;
static MSM5xxxSmallPageNand d;
static unsigned checks;
#define CHECK(x) do { assert(x); checks++; } while (0)
static void init(bool writable)
{
    memset(raw, 0xff, MSM5XXX_NAND_RAW_BYTES);
    ticks = 0;
    CHECK(msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES, &timing, writable, ticks));
}
static void command(uint8_t c) { CHECK(msm5xxx_nand_command(&d, c, 1, ticks)); }
static void address(uint8_t a) { CHECK(msm5xxx_nand_address(&d, a, 1, ticks)); }
static void advance(uint64_t n) { ticks += n; CHECK(msm5xxx_nand_advance(&d, ticks)); }
static uint16_t read_word(void)
{
    uint16_t value = 0;
    CHECK(msm5xxx_nand_read(&d, 2, ticks, &value));
    return value;
}
static uint16_t status(unsigned width)
{
    uint16_t value = 0;
    command(0x70);
    CHECK(msm5xxx_nand_read(&d, width, ticks, &value));
    return value;
}
static uint64_t digest(const uint8_t *p)
{
    size_t i;
    uint64_t h = 1469598103934665603ULL;
    for (i = 0; i < MSM5XXX_NAND_RAW_BYTES; i++) { h = (h ^ p[i]) * 1099511628211ULL; }
    return h;
}
static void coordinates(uint32_t row, uint8_t col)
{
    address(col); address((uint8_t)row); address((uint8_t)(row >> 8));
}
static void read_page(uint32_t row, bool spare, uint8_t column)
{
    command(spare ? 0x50 : 0x00);
    coordinates(row, column);
    CHECK(!msm5xxx_nand_ready(&d));
    advance(timing.read_ns);
    CHECK(msm5xxx_nand_ready(&d));
}
static void program(uint32_t row, bool spare, uint8_t column, unsigned words, uint16_t data)
{
    unsigned i;
    command(spare ? 0x50 : 0x00);
    command(0x80);
    coordinates(row, column);
    for (i = 0; i < words; i++) { CHECK(msm5xxx_nand_write(&d, data, 2, ticks)); }
    command(0x10);
}
static void erase(uint32_t row)
{
    command(0x60); address((uint8_t)row); address((uint8_t)(row >> 8)); command(0xd0);
}
static void basic_read_and_id(void)
{
    uint16_t value = 0x1234;
    uint64_t deadline, before;
    MSM5xxxSmallPageNand saved;
    init(true);
    CHECK(msm5xxx_nand_ready(&d));
    CHECK(msm5xxx_nand_trusted(&d));
    before = digest(raw); saved = d;
    CHECK(!msm5xxx_nand_command(&d, 0x90, 1, ticks));
    saved.reason = MSM5XXX_NAND_UNSUPPORTED;
    CHECK(memcmp(&saved, &d, sizeof(d)) == 0);
    CHECK(d.reason == MSM5XXX_NAND_UNSUPPORTED && digest(raw) == before);
    CHECK(d.mutation_generation == 0 && d.deadline_ns == 0);
    CHECK(!msm5xxx_nand_read(&d, 2, ticks, &value));
    CHECK(d.reason == MSM5XXX_NAND_SEQUENCE && value == 0x1234);
    command(0x00); coordinates(0, 0); deadline = d.deadline_ns;
    CHECK(deadline == 10000);
    CHECK(!msm5xxx_nand_read(&d, 2, ticks, &value));
    CHECK(d.reason == MSM5XXX_NAND_BUSY && value == 0x1234);
    CHECK(status(1) == 0x80);
    before = digest(raw); saved = d;
    CHECK(!msm5xxx_nand_command(&d, 0x90, 1, ticks));
    saved.reason = MSM5XXX_NAND_BUSY;
    CHECK(memcmp(&saved, &d, sizeof(d)) == 0 && digest(raw) == before);
    CHECK(d.reason == MSM5XXX_NAND_BUSY && d.deadline_ns == deadline);
    advance(9999); CHECK(!msm5xxx_nand_ready(&d)); CHECK(status(2) == 0xff80);
    advance(1); CHECK(msm5xxx_nand_ready(&d)); CHECK(status(1) == 0xc0);
    read_page(0, false, 255);
    CHECK(read_word() == 0xffff);
    /* Main column255 is byte510, and data continues into the same page's OOB. */
    CHECK(d.cursor == 512);
    CHECK(read_word() == 0xffff);
    CHECK(d.cursor == 514);
    read_page(0, true, 7); CHECK(read_word() == 0xffff);
    CHECK(!msm5xxx_nand_read(&d, 2, ticks, &value));
    CHECK(d.reason == MSM5XXX_NAND_PAGE_END);
    CHECK(d.row == 0 && d.cursor == 528);
    before = digest(raw); saved = d;
    CHECK(!msm5xxx_nand_command(&d, 0x90, 1, ticks));
    saved.reason = MSM5XXX_NAND_UNSUPPORTED;
    CHECK(memcmp(&saved, &d, sizeof(d)) == 0 && digest(raw) == before);
    /* Rejection still completes an earlier due mutation before returning. */
    init(true); program(3, false, 0, 1, 0x3412);
    ticks += timing.program_ns;
    CHECK(!msm5xxx_nand_command(&d, 0x90, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_UNSUPPORTED && d.pending == MSM5XXX_NAND_PENDING_NONE);
    CHECK(d.mutation_generation == 1 && d.now_ns == ticks && d.deadline_ns == ticks);
    CHECK(raw[3 * 528] == 0x12 && raw[3 * 528 + 1] == 0x34);
}
static void full_raw_program_reload_and_erase(void)
{
    unsigned i;
    uint64_t before;
    MSM5xxxSmallPageNand reload;
    uint16_t value;
    size_t base = MSM5XXX_NAND_PAGE_BYTES;
    init(true);
    command(0); command(0x80); coordinates(1, 0);
    for (i = 0; i < 264; i++) {
        CHECK(msm5xxx_nand_write(&d, (uint16_t)(0xa500U | i), 2, ticks));
    }
    CHECK(!msm5xxx_nand_write(&d, 0, 2, ticks));
    CHECK(d.reason == MSM5XXX_NAND_PAGE_END);
    before = digest(raw); command(0x10);
    CHECK(d.mutation_generation == 0 && digest(raw) == before);
    CHECK(status(1) == 0x80);
    advance(199999); CHECK(digest(raw) == before);
    advance(1);
    CHECK(d.mutation_generation == 1);
    CHECK(d.last_mutation_offset == base && d.last_mutation_length == 528);
    for (i = 0; i < 264; i++) {
        CHECK(raw[base + 2*i] == (uint8_t)i);
        CHECK(raw[base + 2*i + 1] == (uint8_t)((0xa500U | i) >> 8));
    }
    read_page(1, false, 0);
    for (i = 0; i < 264; i++) { CHECK(read_word() == (uint16_t)(0xa500U | i)); }
    /* Second ideal-cell program is AND, within documented partial count. */
    program(1, false, 0, 264, 0x0f0f); advance(200000);
    CHECK(d.mutation_generation == 2);
    read_page(1, true, 0);
    CHECK(read_word() == ((0xa500U | 256U) & 0x0f0fU));
    memcpy(copy, raw, MSM5XXX_NAND_RAW_BYTES);
    CHECK(msm5xxx_nand_init(&reload, copy, MSM5XXX_NAND_RAW_BYTES, &timing, true, ticks));
    CHECK(msm5xxx_nand_command(&reload, 0x50, 1, ticks));
    CHECK(msm5xxx_nand_address(&reload, 0, 1, ticks));
    CHECK(msm5xxx_nand_address(&reload, 1, 1, ticks));
    CHECK(msm5xxx_nand_address(&reload, 0, 1, ticks));
    CHECK(msm5xxx_nand_advance(&reload, ticks + 10000));
    CHECK(msm5xxx_nand_read(&reload, 2, ticks + 10000, &value));
    CHECK(value == ((0xa500U | 256U) & 0x0f0fU));
    before = digest(raw); erase(31); CHECK(digest(raw) == before);
    advance(1999999); CHECK(digest(raw) == before);
    advance(1); CHECK(d.mutation_generation == 3);
    CHECK(d.last_mutation_offset == 0 && d.last_mutation_length == 32*528);
    for (i = 0; i < 32*528; i++) { CHECK(raw[i] == 0xff); }
    CHECK(raw[32*528] == 0xff);
}
static void endpoint_and_protection(void)
{
    size_t last = MSM5XXX_NAND_RAW_BYTES - 2;
    uint64_t before;
    init(true);
    program(65535, true, 7, 1, 0x1234);
    CHECK(raw[last] == 0xff); advance(200000);
    CHECK(raw[last] == 0x34 && raw[last+1] == 0x12);
    read_page(65535, true, 7); CHECK(read_word() == 0x1234);
    raw[(size_t)65504*528-1] = 0xa5; /* Previous block sentinel in qualified backing. */
    erase(65535); advance(2000000);
    CHECK(raw[last] == 0xff && raw[last+1] == 0xff);
    CHECK(raw[(size_t)65504*528-1] == 0xa5);
    init(false); before = digest(raw);
    command(0); command(0x80); coordinates(0, 0);
    CHECK(msm5xxx_nand_write(&d, 0, 2, ticks));
    CHECK(!msm5xxx_nand_command(&d, 0x10, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_WRITE_PROTECTED && msm5xxx_nand_ready(&d));
    CHECK(status(1) == 0x41);
    command(0x60); address(0); address(0);
    CHECK(!msm5xxx_nand_command(&d, 0xd0, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_WRITE_PROTECTED);
    CHECK(d.mutation_generation == 0 && digest(raw) == before);
    command(0xff); advance(5000); CHECK(status(1) == 0x40);
}
static void reset_and_pending(void)
{
    uint64_t before, deadline;
    uint16_t value = 0;
    init(true); before = digest(raw);
    command(0); coordinates(0, 0); advance(1); command(0xff);
    deadline = d.deadline_ns;
    CHECK(deadline == 5001 && !msm5xxx_nand_ready(&d));
    CHECK(!msm5xxx_nand_command(&d, 0xff, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_BUSY && d.deadline_ns == deadline);
    CHECK(status(1) == 0x80); advance(5000); CHECK(status(1) == 0xc0);
    CHECK(digest(raw) == before && d.mutation_generation == 0);
    program(0, false, 0, 1, 0);
    advance(1);
    CHECK(!msm5xxx_nand_command(&d, 0xff, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_RESET_INTERRUPTED_MUTATION);
    CHECK(!msm5xxx_nand_trusted(&d) && !msm5xxx_nand_ready(&d));
    CHECK(digest(raw) == before && d.mutation_generation == 0);
    CHECK(!msm5xxx_nand_advance(&d, ticks+1000000));
    CHECK(!msm5xxx_nand_read(&d, 1, ticks, &value));
    CHECK(!msm5xxx_nand_command(&d, 0x70, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_UNTRUSTED);
    init(true); raw[0] = 0; before = digest(raw); erase(0); advance(1);
    CHECK(!msm5xxx_nand_command(&d, 0xff, 1, ticks));
    CHECK(!msm5xxx_nand_trusted(&d) && digest(raw) == before);
    init(true); msm5xxx_nand_invalidate(&d);
    CHECK(!msm5xxx_nand_trusted(&d)); CHECK(!msm5xxx_nand_advance(&d, 0));
}
static void markers_reset_boundary_and_widths(void)
{
    uint64_t before;
    uint16_t value = 0x5678;
    MSM5xxxSmallPageNand saved;
    init(true);
    program(0, true, 0, 1, 0xff00); advance(200000);
    program(1, true, 0, 1, 0x00ff); advance(200000);
    read_page(0, true, 0); CHECK(read_word() == 0xff00);
    read_page(1, true, 0); CHECK(read_word() == 0x00ff);
    read_page(2, true, 0); CHECK(read_word() == 0xffff);
    before = digest(raw); command(0xff); advance(5000);
    CHECK(digest(raw) == before && d.mutation_generation == 2);
    read_page(1, true, 0); CHECK(read_word() == 0x00ff);
    CHECK(!msm5xxx_nand_read(&d, 1, ticks, &value));
    CHECK(value == 0x5678 && d.reason == MSM5XXX_NAND_WIDTH);
    CHECK(!msm5xxx_nand_address(&d, 1, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_SEQUENCE); /* A fourth row/address cycle is never a capacity wrap. */
    command(0x70); CHECK(!msm5xxx_nand_read(&d, 4, ticks, &value));
    command(0); command(0x80); coordinates(3, 0);
    CHECK(!msm5xxx_nand_write(&d, 0, 1, ticks));
    CHECK(d.program_count == 0);
    CHECK(!msm5xxx_nand_command(&d, 0x80, 1, ticks));
    CHECK(!msm5xxx_nand_command(&d, 0x10, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_SEQUENCE);
    init(true); program(0, false, 0, 1, 0x1234);
    ticks += 200000; command(0xff); /* Already due commit precedes reset. */
    CHECK(d.mutation_generation == 1 && raw[0] == 0x34 && msm5xxx_nand_trusted(&d));
    advance(5000); read_page(0, false, 0); CHECK(read_word() == 0x1234);
    saved = d;
    CHECK(!msm5xxx_nand_advance(&d, ticks-1));
    saved.reason = MSM5XXX_NAND_TIME;
    CHECK(memcmp(&saved, &d, sizeof(d)) == 0);
    init(true); command(0); command(0x80); coordinates(0, 0);
    CHECK(msm5xxx_nand_write(&d, 0, 2, ticks));
    d.mutation_generation = UINT64_MAX;
    CHECK(!msm5xxx_nand_command(&d, 0x10, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_OVERFLOW && raw[0] == 0xff);
    init(true);
    CHECK(msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES, &timing, true, UINT64_MAX-5000));
    CHECK(msm5xxx_nand_command(&d, 0xff, 1, UINT64_MAX-5000));
    CHECK(d.deadline_ns == UINT64_MAX);
    CHECK(msm5xxx_nand_advance(&d, UINT64_MAX));
    CHECK(msm5xxx_nand_ready(&d));
}
static void experimental_idle_reset_override(void)
{
    const MSM5xxxNandTimings experimental = {10000, 200000, 2000000, 5000, 200};
    uint64_t deadline, before;
    init(true);
    CHECK(msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES, &experimental, true, 0));
    command(0xff); CHECK(d.deadline_ns == 200);
    advance(199); CHECK(!msm5xxx_nand_ready(&d));
    CHECK(!msm5xxx_nand_command(&d, 0, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_BUSY && d.deadline_ns == 200);
    advance(1); CHECK(msm5xxx_nand_ready(&d));
    command(0); coordinates(0, 0); advance(1);
    command(0xff); CHECK(d.deadline_ns == ticks + 5000);
    deadline = d.deadline_ns;
    CHECK(!msm5xxx_nand_command(&d, 0xff, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_BUSY && d.deadline_ns == deadline);
    advance(4999); CHECK(!msm5xxx_nand_ready(&d));
    advance(1); CHECK(msm5xxx_nand_ready(&d));
    before = digest(raw); program(0, false, 0, 1, 0x1234); advance(1);
    CHECK(!msm5xxx_nand_command(&d, 0xff, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_RESET_INTERRUPTED_MUTATION);
    CHECK(!msm5xxx_nand_trusted(&d) && digest(raw) == before);
    init(true); /* Explicit fresh erased test backing, not recovery of poisoned state. */
    CHECK(msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES, &experimental, true, UINT64_MAX-199));
    CHECK(!msm5xxx_nand_command(&d, 0xff, 1, UINT64_MAX-199));
    CHECK(d.reason == MSM5XXX_NAND_OVERFLOW && d.pending == MSM5XXX_NAND_PENDING_NONE);
    CHECK(msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES, &experimental, true, UINT64_MAX-200));
    CHECK(msm5xxx_nand_command(&d, 0xff, 1, UINT64_MAX-200));
    CHECK(d.deadline_ns == UINT64_MAX);
    CHECK(msm5xxx_nand_advance(&d, UINT64_MAX) && msm5xxx_nand_ready(&d));
    ticks = UINT64_MAX-10001;
    CHECK(msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES, &experimental, true, ticks));
    command(0); coordinates(0, 0); deadline = d.deadline_ns;
    ticks = UINT64_MAX-1000;
    CHECK(!msm5xxx_nand_command(&d, 0xff, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_OVERFLOW);
    CHECK(d.pending == MSM5XXX_NAND_PENDING_READ && d.deadline_ns == deadline);
    CHECK(msm5xxx_nand_trusted(&d));
}
static void negative_and_overflow(void)
{
    uint16_t value = 0xabcd;
    uint64_t before;
    MSM5xxxSmallPageNand saved;
    MSM5xxxNandTimings invalid = timing;
    init(true); saved = d;
    CHECK(!msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES-1, &timing, true, 0));
    CHECK(memcmp(&d, &saved, sizeof(d)) == 0);
    invalid.read_ns = 0;
    CHECK(!msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES, &invalid, true, 0));
    CHECK(!msm5xxx_nand_init(NULL, raw, MSM5XXX_NAND_RAW_BYTES, &timing, true, 0));
    CHECK(!msm5xxx_nand_command(NULL, 0, 1, 0));
    CHECK(!msm5xxx_nand_command(&d, 0x10, 1, ticks));
    CHECK(!msm5xxx_nand_command(&d, 0xd0, 1, ticks));
    CHECK(!msm5xxx_nand_command(&d, 0x80, 1, ticks));
    CHECK(!msm5xxx_nand_address(&d, 0, 1, ticks));
    CHECK(!msm5xxx_nand_write(&d, 0, 2, ticks));
    CHECK(!msm5xxx_nand_read(&d, 2, ticks, &value) && value == 0xabcd);
    CHECK(!msm5xxx_nand_command(&d, 0x01, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_UNSUPPORTED);
    CHECK(!msm5xxx_nand_command(&d, 0x8a, 1, ticks));
    CHECK(!msm5xxx_nand_command(&d, 0, 2, ticks));
    command(0x50);
    CHECK(!msm5xxx_nand_address(&d, 8, 1, ticks)); CHECK(d.address_count == 0);
    CHECK(!msm5xxx_nand_address(&d, 0, 2, ticks));
    CHECK(!msm5xxx_nand_command(&d, 0x90, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_UNSUPPORTED);
    command(0); CHECK(!msm5xxx_nand_read(&d, 1, ticks, &value));
    CHECK(!msm5xxx_nand_read(&d, 2, ticks, NULL));
    command(0x60); address(0);
    CHECK(!msm5xxx_nand_command(&d, 0xd0, 1, ticks));
    address(0); CHECK(!msm5xxx_nand_address(&d, 0, 1, ticks));
    advance(5); before = digest(raw);
    CHECK(!msm5xxx_nand_advance(&d, 4)); CHECK(d.reason == MSM5XXX_NAND_TIME);
    CHECK(d.now_ns == 5 && digest(raw) == before);
    CHECK(msm5xxx_nand_init(&d, raw, MSM5XXX_NAND_RAW_BYTES, &timing, true, UINT64_MAX-4));
    CHECK(!msm5xxx_nand_command(&d, 0xff, 1, UINT64_MAX-4));
    CHECK(d.reason == MSM5XXX_NAND_OVERFLOW && d.pending == MSM5XXX_NAND_PENDING_NONE);
    ticks = UINT64_MAX-4;
    command(0); address(0); address(0);
    CHECK(!msm5xxx_nand_address(&d, 0, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_OVERFLOW && d.address_count == 2);
    command(0); command(0x80); coordinates(0, 0);
    CHECK(msm5xxx_nand_write(&d, 0, 2, ticks));
    CHECK(!msm5xxx_nand_command(&d, 0x10, 1, ticks));
    CHECK(d.reason == MSM5XXX_NAND_OVERFLOW && digest(raw) == before);
    init(true); program(0, false, 0, 1, 0x3412);
    ticks += 200000;
    CHECK(!msm5xxx_nand_command(&d, 0x01, 1, ticks));
    CHECK(d.mutation_generation == 1 && raw[0] == 0x12 && raw[1] == 0x34);
    CHECK(d.reason == MSM5XXX_NAND_UNSUPPORTED);
}
int main(void)
{
    raw = malloc(MSM5XXX_NAND_RAW_BYTES); copy = malloc(MSM5XXX_NAND_RAW_BYTES);
    CHECK(raw != NULL && copy != NULL);
    basic_read_and_id(); full_raw_program_reload_and_erase();
    endpoint_and_protection(); reset_and_pending(); markers_reset_boundary_and_widths(); experimental_idle_reset_override(); negative_and_overflow();
    printf("PASS: %u C assertions; full raw/OOB buffer, deterministic deadlines, no guest/disk claim\n", checks);
    free(copy); free(raw); return 0;
}
