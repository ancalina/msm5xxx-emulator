"""SBI register and transaction parameters shared within this domain."""
from capstone import arm as a

BASE = 0x03000780
SBI_SIZE = 0x14
BOOTSTRAP_EVENTS = (('write', 0, 1, 0x45), ('write', 0, 1, 0xC5),
                    ('write', 4, 2, 0x085F), ('write', 0x0C, 2, 0x041F),
                    ('write', 0x10, 1, 0), ('write', 0x10, 1, 1))
VALIDATION_EVENTS = (('read', 0, 2, None), ('write', 0x0C, 2, 0x0900),
                     ('read', 0, 2, None))
EVENTS = BOOTSTRAP_EVENTS + VALIDATION_EVENTS
APERTURE = (BASE, BASE + 0x11)
_UNCONDITIONAL = (a.ARM_CC_AL, a.ARM_CC_INVALID)


def compatibility_events():
    """Return mutable legacy profile arrays without exposing canonical tuples."""
    return ([list(event[1:]) for event in BOOTSTRAP_EVENTS],
            [list(event[1:]) for event in VALIDATION_EVENTS])


def _native_status(control: int = 0x085F) -> int:
    return (((control & 0x00C0) << 8) | ((control & 0x003F) << 8)
            | ((control & 0x0600) >> 3) | ((control & 0x0800) >> 6))



SBI_BOOTSTRAP, SBI_BOOTSTRAP_VALIDATION = compatibility_events()
