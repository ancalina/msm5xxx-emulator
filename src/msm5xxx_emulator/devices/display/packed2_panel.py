"""Statically gated interleaved two-plane vertical LCD observer."""
from __future__ import annotations

import struct

_HELPER = bytes.fromhex('002201235b0600b51a701870081298709970')
_CONSUMER = bytes.fromhex('315d601c0e4a4900441c305c515a0c4a4000105a01431220fff733ff0137')


def find_packed2_port(image: bytes) -> tuple[int | None, str]:
    """Require the byte writer, its actual LUT consumer and both full bitplanes."""
    matches = []
    offset = image.find(_CONSUMER)
    while offset >= 0:
        helper = offset - 0x17e
        if offset % 2 == 0 and helper >= 0 and image[helper:helper + len(_HELPER)] == _HELPER:
            # Literal loads are part of the consumer; unrelated LUT occurrences cannot qualify.
            pointers = [((offset + delta + 4) & ~3) + immediate * 4
                        for delta, immediate in ((4, 14), (14, 12))]
            if all(p + 4 <= len(image) for p in pointers):
                addresses = [struct.unpack_from('<I', image, p)[0] for p in pointers]
                valid = True
                for address, plane in zip(addresses, (1, 0)):
                    if address + 512 > len(image):
                        valid = False
                        break
                    words = struct.unpack_from('<256H', image, address)
                    if any(word != sum(((n >> b) & 1) << (2 * b + plane)
                                       for b in range(8)) for n, word in enumerate(words)):
                        valid = False
                        break
                if valid:
                    matches.append(offset)
        offset = image.find(_CONSUMER, offset + 1)
    if len(matches) == 1:
        return 0x02000000, 'interleaved-two-plane-byte-writer'
    return None, 'ambiguous-packed2-writer' if matches else 'packed2-writer-not-found'


class Packed2Panel:
    """Observe only a static-approved port; publish bounded complete page runs."""

    width, height = 128, 160

    def __init__(self, port: int):
        if port != 0x02000000:
            raise ValueError('unsupported packed2 port')
        self.port = port
        self.sequence = 0
        self.frame = bytes([255]) * (self.width * self.height * 3)
        self.reset()

    def reset(self) -> None:
        self.qualified = False
        self.rejection = ''
        self.observation = 'awaiting-initialization'
        self._packet = []
        self._init = set()
        self._preamble = 0
        self._next_page = 1
        self._page = self._x = None
        self._words = []
        self._committed = 0
        self._base = bytearray([255]) * (self.width * self.height * 3)

    def _reject(self, reason: str) -> None:
        self._packet.clear()
        self._words.clear()
        self._committed = 0
        self._page = self._x = None
        self._preamble = 0
        self.rejection = reason
        if not self.qualified:
            self._next_page = 1
            self._base[:] = bytes([255]) * len(self._base)

    def write(self, address: int, size: int, value: int) -> None:
        if address not in (self.port, self.port + 2):
            return
        if size != 1 or not 0 <= value <= 255:
            self._reject('unsupported-transfer')
            return
        expected = (self.port, self.port, self.port + 2, self.port + 2)
        index = len(self._packet)
        if address != expected[index] or (index == 0 and value != 0):
            self._reject('malformed-packet')
            return
        self._packet.append(value)
        if len(self._packet) == 4:
            _, command, high, low = self._packet
            self._packet.clear()
            self._command(command, high * 256 + low)

    def _command(self, command: int, word: int) -> None:
        if command == 3:
            self.reset()
            if word == 0x0504:
                self._init.add(3)
            else:
                self._reject('unsupported-initialization')
            return
        if command != 0x12:
            self._finish()
        if command in (0x0d, 0x0e):
            if word != (0x7f00 if command == 0x0d else 0) or 3 not in self._init:
                self.reset()
                self._reject('unsupported-initialization')
                return
            self._init.add(command)
        elif command == 5:
            self._preamble = 1 if word == 0x14 else 0
        elif command == 0x10:
            self._preamble = 2 if self._preamble == 1 and word == 0 else 0
        elif command == 0x11:
            page, x = word & 31, word >> 5
            if not (1 <= page <= 20 and x < 128):
                self._reject('invalid-packed-address')
                return
            if not self.qualified and (self._init != {3, 13, 14} or self._preamble != 2
                                       or page != self._next_page or x != 0):
                self._reject('unqualified-page-sequence')
                return
            self._page, self._x = page, x
            self._preamble = 0
        elif command == 0x12:
            if self._page is None:
                self._reject('data-without-address')
            elif self._x + len(self._words) >= 128:
                self._reject('packed-row-overflow')
            else:
                self._words.append(word)
        elif command not in (1, 2, 4, 6, 7, 8, 11, 12):
            self._reject('unsupported-command')

    def _finish(self) -> None:
        if self._words and not self.qualified and len(self._words) != 128:
            self._reject('incomplete-full-page')
            return
        self.flush()
        self._words.clear()
        self._committed = 0
        self._page = self._x = None

    def flush(self) -> None:
        # Telemetry can split either a packet or a page; only command boundaries end runs.
        if (self._packet or not self._words or self._committed == len(self._words)
                or (not self.qualified and len(self._words) != 128)):
            return
        page, x = self._page, self._x
        for offset in range(self._committed, len(self._words)):
            word = self._words[offset]
            for bit in range(8):
                shade = 255 - ((word >> (2 * bit)) & 3) * 85
                index = (((page - 1) * 8 + bit) * 128 + x + offset) * 3
                self._base[index:index + 3] = bytes([shade]) * 3
        self._committed = len(self._words)
        if not self.qualified:
            self._next_page += 1
            if self._next_page <= 20:
                self.observation = 'awaiting-ordered-full-pages'
                return
            self.qualified = True
        self.frame = bytes(self._base)
        self.sequence += 1
        self.rejection = ''
        self.observation = 'complete-packed2-update'

    def snapshot(self) -> dict:
        return dict(width=self.width, height=self.height, frame=self.frame,
                    qualified=self.qualified, enabled=None, port=self.port,
                    rejection=self.rejection, observation=self.observation,
                    sequence=self.sequence)
