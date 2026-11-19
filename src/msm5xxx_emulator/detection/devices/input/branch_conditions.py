"""Partial NZCV facts for source-only Thumb event-path proofs."""
from capstone import arm as a


def unknown_flags():
    return (None, None, None, None)


def compare_flags(left, right):
    if type(left) is not int or type(right) is not int:
        return unknown_flags()
    left, right = left & 0xffffffff, right & 0xffffffff
    result = (left - right) & 0xffffffff
    return (bool(result & 0x80000000), result == 0, left >= right,
            bool((left ^ right) & (left ^ result) & 0x80000000))


def add_flags(left, right):
    if type(left) is not int or type(right) is not int:
        return unknown_flags()
    left, right = left & 0xffffffff, right & 0xffffffff
    result = (left + right) & 0xffffffff
    return (bool(result & 0x80000000), result == 0,
            left + right > 0xffffffff,
            bool(~(left ^ right) & (left ^ result) & 0x80000000))


def move_flags(value, previous):
    if type(previous) is int:
        result = 0
        for state in range(16):
            if previous & (1 << state):
                result |= flag_mask(move_flags(value, _state_flags(state)))
        return result
    n, z = ((bool(value & 0x80000000), value & 0xffffffff == 0)
            if type(value) is int else (None, None))
    return (n, z, previous[2], previous[3])


def _not(value):
    return None if value is None else not value


def _and(left, right):
    if left is False or right is False:
        return False
    return True if left is True and right is True else None


def _or(left, right):
    if left is True or right is True:
        return True
    return False if left is False and right is False else None


def condition_holds(condition, flags):
    if type(flags) is int:
        values = {condition_holds(condition, _state_flags(state))
                  for state in range(16) if flags & (1 << state)}
        return next(iter(values)) if len(values) == 1 else None
    n, z, c, v = flags
    equal_sign = None if n is None or v is None else n == v
    return {
        a.ARM_CC_AL: True, a.ARM_CC_INVALID: True,
        a.ARM_CC_EQ: z, a.ARM_CC_NE: _not(z),
        a.ARM_CC_HS: c, a.ARM_CC_LO: _not(c),
        a.ARM_CC_MI: n, a.ARM_CC_PL: _not(n),
        a.ARM_CC_VS: v, a.ARM_CC_VC: _not(v),
        a.ARM_CC_HI: _and(c, _not(z)),
        a.ARM_CC_LS: _or(_not(c), z),
        a.ARM_CC_GE: equal_sign, a.ARM_CC_LT: _not(equal_sign),
        a.ARM_CC_GT: _and(_not(z), equal_sign),
        a.ARM_CC_LE: _or(z, _not(equal_sign)),
    }.get(condition)


def _state_flags(state):
    return tuple(bool(state & (1 << bit)) for bit in (3, 2, 1, 0))


def flag_mask(flags):
    """Encode possible NZCV states, retaining correlations across branches."""
    if type(flags) is int:
        return flags & 0xffff
    return sum(1 << state for state in range(16)
               if all(value is None or value == candidate
                      for value, candidate in zip(flags, _state_flags(state))))


def refine_flags(condition, flags, taken):
    mask = flag_mask(flags)
    return sum(1 << state for state in range(16)
               if mask & (1 << state)
               and condition_holds(condition, _state_flags(state)) in (taken, None))
