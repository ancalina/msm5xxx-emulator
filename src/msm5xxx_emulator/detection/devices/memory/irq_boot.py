"""Firmware evidence for the high-stack IRQ boot hardware."""

_IRQ = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe10010e0e3010050e10400001a')
_STACKS = bytes.fromhex('00d27f1890e77f1800c97f1890db7f1890e87f1800da7f18')
_BOOT = bytes.fromhex('f8b5bf49002008608904c8600121c9020b22d2065160bb4a49041160d160b24a')


def has_high_stack_irq_boot(image: bytes) -> bool:
    irq = image.find(_IRQ)
    boot = image.find(_BOOT)
    return (irq >= 0 and irq % 4 == 0 and image.find(_IRQ, irq + 1) < 0
            and image[irq + 0xf0:irq + 0xf4] == bytes.fromhex('0020ffff')
            and image[irq + 0x120:irq + 0x138] == _STACKS
            and boot >= 0 and boot % 2 == 0 and image.find(_BOOT, boot + 1) < 0
            and image[boot + 0x302:boot + 0x306] == bytes.fromhex('00160080'))
