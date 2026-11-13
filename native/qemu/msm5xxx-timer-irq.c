/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "msm5xxx-timer-irq.h"

static uint8_t msm5xxx_timer_irq_pending_byte(const MSM5xxxTimerIRQ *p,
                                               uint32_t offset)
{
    if (offset < 4) {
        return (uint8_t)(p->pending[0] >> (offset * 8));
    }
    return (uint8_t)p->pending[1];
}

static uint32_t msm5xxx_timer_irq_enable_word(const MSM5xxxTimerIRQ *p,
                                               unsigned word)
{
    unsigned i = word ? 0x18 : 0x14;
    return (uint32_t)p->backing[i] |
           ((uint32_t)p->backing[i + 1] << 8) |
           ((uint32_t)p->backing[i + 2] << 16) |
           ((uint32_t)p->backing[i + 3] << 24);
}

void msm5xxx_timer_irq_init(MSM5xxxTimerIRQ *p, uint32_t mask,
                            uint64_t period_ns)
{
    unsigned i;

    if (!p) {
        return;
    }
    for (i = 0; i < MSM5XXX_TIMER_IRQ_REG_SIZE; i++) {
        p->backing[i] = 0;
    }
    p->pending[0] = 0;
    p->pending[1] = 0;
    p->timer_mask = mask;
    p->period_ns = period_ns;
    p->remaining_ns = 0;
    p->armed = false;
}

void msm5xxx_timer_irq_reset(MSM5xxxTimerIRQ *p)
{
    uint32_t mask;
    uint64_t period_ns;

    if (!p) {
        return;
    }
    mask = p->timer_mask;
    period_ns = p->period_ns;
    msm5xxx_timer_irq_init(p, mask, period_ns);
}

bool msm5xxx_timer_irq_read(const MSM5xxxTimerIRQ *p, uint32_t offset,
                            unsigned size, uint32_t *value)
{
    uint32_t result = 0;
    unsigned i;

    if (!p || !value || (size != 1 && size != 2 && size != 4) ||
        offset > MSM5XXX_TIMER_IRQ_REG_SIZE ||
        size > MSM5XXX_TIMER_IRQ_REG_SIZE - offset) {
        return false;
    }
    for (i = 0; i < size; i++) {
        uint32_t address = offset + i;
        uint8_t byte;

        if (address <= 4) {
            byte = msm5xxx_timer_irq_pending_byte(p, address);
        } else if ((address >= 5 && address <= 7) ||
                   (address >= 0x19 && address <= 0x1b)) {
            byte = 0;
        } else {
            byte = p->backing[address];
        }
        result |= (uint32_t)byte << (i * 8);
    }
    *value = result;
    return true;
}

bool msm5xxx_timer_irq_write(MSM5xxxTimerIRQ *p, uint32_t offset,
                             unsigned size, uint32_t value)
{
    unsigned i;

    if (!p || (size != 1 && size != 2 && size != 4) ||
        offset > MSM5XXX_TIMER_IRQ_REG_SIZE ||
        size > MSM5XXX_TIMER_IRQ_REG_SIZE - offset) {
        return false;
    }
    for (i = 0; i < size; i++) {
        uint32_t address = offset + i;
        uint8_t byte = (uint8_t)(value >> (i * 8));

        if (address < 4) {
            p->pending[0] &= ~((uint32_t)byte << (address * 8));
        } else if (address == 4) {
            p->pending[1] &= ~(uint32_t)byte;
        } else if ((address >= 5 && address <= 7) ||
                   (address >= 0x19 && address <= 0x1b)) {
            continue;
        } else if (address == 0x18) {
            p->backing[address] = byte & 0xff;
        } else {
            p->backing[address] = byte;
        }
    }
    return true;
}

void msm5xxx_timer_irq_set_armed(MSM5xxxTimerIRQ *p, bool armed)
{
    if (!p) {
        return;
    }
    if (!armed) {
        p->armed = false;
        p->remaining_ns = 0;
    } else if (!p->armed && p->period_ns) {
        p->armed = true;
        p->remaining_ns = p->period_ns;
    }
}

void msm5xxx_timer_irq_advance(MSM5xxxTimerIRQ *p, uint64_t elapsed_ns)
{
    uint64_t remainder;

    if (!p || !p->armed || !p->period_ns ||
        elapsed_ns < p->remaining_ns) {
        if (p && p->armed && p->period_ns &&
            elapsed_ns < p->remaining_ns) {
            p->remaining_ns -= elapsed_ns;
        }
        return;
    }

    elapsed_ns -= p->remaining_ns;
    p->pending[0] |= p->timer_mask;
    remainder = elapsed_ns % p->period_ns;
    p->remaining_ns = p->period_ns - remainder;
}

bool msm5xxx_timer_irq_level(const MSM5xxxTimerIRQ *p)
{
    if (!p) {
        return false;
    }
    return (p->pending[0] & msm5xxx_timer_irq_enable_word(p, 0)) != 0 ||
           (p->pending[1] & 0xff & msm5xxx_timer_irq_enable_word(p, 1)) != 0;
}
