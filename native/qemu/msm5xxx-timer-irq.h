/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MSM5XXX_TIMER_IRQ_H
#define MSM5XXX_TIMER_IRQ_H

#include <stdbool.h>
#include <stdint.h>

#define MSM5XXX_TIMER_IRQ_REG_SIZE 0x20

/* Source-backed 0x03000A80 controller and separately armed periodic source. */
typedef struct MSM5xxxTimerIRQ {
    uint32_t pending[2];
    uint8_t backing[MSM5XXX_TIMER_IRQ_REG_SIZE];
    uint32_t timer_mask;
    uint64_t period_ns;
    uint64_t remaining_ns;
    bool armed;
} MSM5xxxTimerIRQ;

void msm5xxx_timer_irq_init(MSM5xxxTimerIRQ *p, uint32_t mask, uint64_t period_ns);
void msm5xxx_timer_irq_reset(MSM5xxxTimerIRQ *p);
bool msm5xxx_timer_irq_read(const MSM5xxxTimerIRQ *p, uint32_t offset,
                            unsigned size, uint32_t *value);
bool msm5xxx_timer_irq_write(MSM5xxxTimerIRQ *p, uint32_t offset,
                             unsigned size, uint32_t value);
void msm5xxx_timer_irq_set_armed(MSM5xxxTimerIRQ *p, bool armed);
void msm5xxx_timer_irq_advance(MSM5xxxTimerIRQ *p, uint64_t elapsed_ns);
bool msm5xxx_timer_irq_level(const MSM5xxxTimerIRQ *p);

#endif /* MSM5XXX_TIMER_IRQ_H */
