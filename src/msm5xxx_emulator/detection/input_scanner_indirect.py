"""Closed HIGH-open halfword input through a reset-initialized GPIO descriptor."""
from __future__ import annotations

import hashlib
import struct

from ..core.config import BoardStatusInput
from .arm import arm_b_target, thumb_bl_target, thumb_literal_value
from .input_scanner_indirect_profiles import _PRIMITIVES

# Complete scanner body, preserving mask, stores, debounce and paired events.
_SCANNER_SHA = 'cb46f6427fa61261da00bccac0ddb19fa88e4f11d367b845bffdb0ca1500e9d1'
_SCANNER_LITERALS = ((0, 0, 0x01000628), (0x10, 7, 0x01005c1d),
    (0x12, 5, 0x0100221c), (0x28, 0, 0x0111844a), (0x40, 0, 0x01005db3),
    (0x48, 0, 0x01118435), (0x4a, 1, 0x01118434), (0x4c, 2, 0x010c7dd4),
    (0x78, 1, 0x0100ba84), (0x7e, 0, 0x010e27cc))
_SCANNER_CALLS = ((0x2c, 'memset_veneer'), (0x36, 'scanner_aux_context_test'),
                  (0x82, 'timer_remove_wrapper'), (0x88, 'event'))
_IRAM_SOURCE, _IRAM_TARGET, _IRAM_SIZE = 0x006c02e8, 0x03800000, 0xb410


def _word(image: bytes, at: int) -> int:
    if not 0 <= at <= len(image) - 4:
        raise ValueError('input literal outside image')
    return struct.unpack_from('<I', image, at)[0]


def _mapped(image: bytes, at: int, size: int) -> int:
    if _IRAM_TARGET <= at and at + size <= _IRAM_TARGET + _IRAM_SIZE:
        at += _IRAM_SOURCE - _IRAM_TARGET
    if size <= 0 or not 0 <= at <= len(image) - size:
        raise ValueError('input primitive outside image/copy')
    return at


def _primitive(image: bytes, role: str) -> bool:
    entry, size, mode, digest, literals, branches, mixed = _PRIMITIVES[role]
    start = _mapped(image, entry, size)
    code = bytearray(image[start:start + size])
    for offset, register in literals:
        if mode == 'thumb':
            value = thumb_literal_value(image, start + offset, register)
        else:
            op = _word(image, start + offset)
            pool = entry + offset + 8 + ((op & 0xfff) if op & 0x800000 else -(op & 0xfff))
            value = _word(image, _mapped(image, pool, 4))
        if value is None:
            return False
        code.extend(struct.pack('<I', value))
    if hashlib.sha256(code).hexdigest() != digest:
        return False
    for offset, target in branches:
        if mode == 'thumb':
            actual = thumb_bl_target(image, start + offset)
        else:
            op = _word(image, start + offset)
            delta = op & 0xffffff
            if delta & 0x800000:
                delta -= 0x1000000
            actual = entry + offset + 8 + delta * 4
        if actual != target:
            return False
    return mixed is None or _word(image, start + size - 4) == mixed


def _copy_owned(image: bytes) -> bool:
    # Reset stub calls all three returning preinit primitives then the scatter
    # copier. Its literal-verified word loops consume these exact two tables.
    if arm_b_target(image, 0) != _PRIMITIVES['reset_stub'][0]:
        return False
    ram = tuple(_word(image, 0x10028 + offset) for offset in (0, 4, 8))
    iram = tuple(_word(image, 0xba08 + offset) for offset in (0, 4, 8))
    if (ram != (0x6abaf0, 0x01000000, 0x147f8)
            or iram != (_IRAM_SOURCE, _IRAM_TARGET, _IRAM_SIZE)):
        return False
    # The scanner reads descriptor+24; bind its GPIO word to the initialized
    # source, never to a stale RAM tail included in a full JTAG capture.
    if hashlib.sha256(image[0x31b1b6:0x31b1c0]).hexdigest() != (
            '01d448afd928065458cf670b60f5a594d735af0172c8d67f22a81680132681ca'):
        return False
    descriptor = ram[0] + 0x01000628 - ram[1]
    return (descriptor + 48 <= ram[0] + ram[2] <= len(image)
            and hashlib.sha256(image[descriptor:descriptor + 48]).hexdigest() ==
            '7e258745eb1a74605b0a1f34bad7ac1beb86edefd21212c3177a5df2c45c69ac'
            and _word(image, descriptor + 0x24) == 0x03000728)


def _registration(image: bytes, scanner: int) -> bool:
    # Complete Thumb init/registration argument block: one 37-byte clock object,
    # repeat-enable=1, initial=repeat=25, and the independently checked callback.
    start = 0xa1452
    if start + 0x18 > len(image):
        return False
    code = bytearray(image[start:start + 0x18])
    if (thumb_literal_value(image, start, 4) != 0x010c7f08
            or thumb_literal_value(image, start + 0x12, 1) !=
            _PRIMITIVES['callback_prefix'][0] | 1
            or thumb_bl_target(image, _PRIMITIVES['callback_prefix'][0] + 0x16) != scanner):
        return False
    for offset in (0, 0x12):
        op = struct.unpack_from('<H', code, offset)[0]
        struct.pack_into('<H', code, offset, op & 0xff00)
    for offset, role in ((4, 'timer_init'), (0x14, 'register_wrapper')):
        if thumb_bl_target(image, start + offset) != _PRIMITIVES[role][0]:
            return False
        code[offset:offset + 4] = struct.pack('<HH', 0xf000, 0xf800)
    return hashlib.sha256(code).hexdigest() == (
        '5388134a43fdbc5b725e0e195e4c75a2fc7254448e2867eb6f8066724692d6b5')


def indirect_scanner_at(image: bytes, start: int) -> tuple[BoardStatusInput | None, str]:
    """Admit only the complete one/two-scan descriptor/5F60/timer/refresh class."""
    if start < 0 or start & 1 or start + 0xc4 > len(image):
        return None, ''
    if image[start + 2:start + 12] != struct.pack('<5H', 0xb5f0, 0x6a40, 0x8800, 0x2302, 0x4018):
        return None, ''
    code = bytearray(image[start:start + 0xc4])
    for offset, register, expected in _SCANNER_LITERALS:
        if thumb_literal_value(image, start + offset, register) != expected:
            return None, ''
        op = struct.unpack_from('<H', code, offset)[0]
        struct.pack_into('<H', code, offset, op & 0xff00)
    for offset, role in _SCANNER_CALLS:
        if thumb_bl_target(image, start + offset) != _PRIMITIVES[role][0]:
            return None, ''
        code[offset:offset + 4] = struct.pack('<HH', 0xf000, 0xf800)
    if hashlib.sha256(code).hexdigest() != _SCANNER_SHA:
        return None, ''
    try:
        if (not _copy_owned(image) or not _registration(image, start)
                or not all(_primitive(image, role) for role in _PRIMITIVES)):
            return None, 'indirect-scanner-copy-or-callee-unclosed'
    except (ValueError, struct.error):
        return None, 'indirect-scanner-source-out-of-bounds'
    # Restrict only an already closed candidate: earlier rejection paths and
    # their telemetry stay identical. The whole copied IRAM and the preinit
    # register-table entries must exist before reset can reach the scanner.
    if _IRAM_SOURCE + _IRAM_SIZE > len(image):
        return None, 'indirect-scanner-copy-extent-truncated'
    if hashlib.sha256(image[0x1494:0x14b0]).hexdigest() != (
            'b83e268f1191016780088756cc778c5084e4325a7ae881d864cd5ca3613f500b'):
        return None, 'indirect-scanner-reset-register-table-unclosed'
    return BoardStatusInput(0x03000728, 2, 2), ''
