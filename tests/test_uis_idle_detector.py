"""UI-idle observation requires its complete static call shape."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.rex import (
    UIS_IDLE_BODY_DELTA,
    UIS_IDLE_BODY_PREFIX,
    UIS_IDLE_COMPACT_BODY_DELTA,
    UIS_IDLE_COMPACT_BODY_PREFIX,
    UIS_IDLE_COMPACT_ENTRY_PREFIX,
    UIS_IDLE_ENTRY_PREFIX,
    UIS_IDLE_DRAW_MARKER,
    find_uis_idle_pair,
)


def _bl(source: int, target: int) -> bytes:
    displacement = target - source - 4
    return struct.pack("<2H", 0xF000 | (displacement >> 12 & 0x7FF),
                       0xF800 | (displacement >> 1 & 0x7FF))


def _pair(image: bytearray, entry: int, callsites: tuple[int, int, int]) -> None:
    body = entry + UIS_IDLE_BODY_DELTA
    image[entry:entry + len(UIS_IDLE_ENTRY_PREFIX)] = UIS_IDLE_ENTRY_PREFIX
    image[body:body + len(UIS_IDLE_BODY_PREFIX)] = UIS_IDLE_BODY_PREFIX
    for source in callsites[:2]:
        image[source:source + 4] = _bl(source, entry)
    image[callsites[2]:callsites[2] + 4] = _bl(callsites[2], body)


def _draw_pair(image: bytearray, entry: int, delta: int, push: int) -> int:
    body = entry + delta
    registration = entry - 0x40
    marker = body + 0x340
    helper = marker - 0x38
    struct.pack_into("<3H", image, registration, 0xB500, 0x4909, 0x2001)
    image[registration + 6:registration + 10] = _bl(registration + 6, 0x200)
    struct.pack_into("<I", image, registration + 0x28, entry | 1)
    image[0x100:0x104] = _bl(0x100, registration)
    struct.pack_into(
        "<16H", image, entry,
        push, 0x1C04, 0x4884, 0x1C0F, 0x4983, 0x6940, 0x1C15,
        0x6188, 0x4982, 0x4A83, 0x2000, 0x4E83, 0x1889, 0x73C8,
        0x7830, 0x2800,
    )
    event_call = entry + 0x100
    struct.pack_into("<2H", image, event_call - 4, 0x1C29, 0x1C38)
    image[event_call:event_call + 4] = _bl(event_call, body)
    struct.pack_into("<2H", image, event_call + 4, 0x27FF, 0x3701)
    struct.pack_into(
        "<13H", image, body,
        0xB5F0, 0x1C0D, 0x4954, 0x1C04, 0x2000, 0x6248, 0x203F,
        0x4953, 0x0100, 0x1808, 0x7800, 0x2800, 0xD000,
    )
    draw_call = body + 0xA0
    image[draw_call:draw_call + 4] = _bl(draw_call, helper)
    struct.pack_into("<2H", image, helper, 0x480B, 0xB500)
    struct.pack_into("<H", image, marker - 0x14, 0xA004)
    image[marker:marker + len(UIS_IDLE_DRAW_MARKER)] = UIS_IDLE_DRAW_MARKER
    return marker


class UisIdleDetectorTests(unittest.TestCase):
    def test_accepts_one_complete_pair(self) -> None:
        image = bytearray(b"\xff" * 0x2000)
        _pair(image, 0x400, (0x1000, 0x1100, 0x1200))

        self.assertEqual(find_uis_idle_pair(image), (0x400, 0x55E))

    def test_accepts_relocated_callers(self) -> None:
        image = bytearray(b"\xff" * 0x2000)
        entry, body = 0x400, 0x400 + UIS_IDLE_BODY_DELTA
        callsites = (0x1000, 0x1100, 0x1200)
        runtime = {
            entry: 0x00200000,
            body: 0x0020015E,
            0x1000: 0x00101000,
            0x1100: 0x00101100,
            0x1200: 0x00101200,
        }
        image[entry:entry + len(UIS_IDLE_ENTRY_PREFIX)] = UIS_IDLE_ENTRY_PREFIX
        image[body:body + len(UIS_IDLE_BODY_PREFIX)] = UIS_IDLE_BODY_PREFIX
        for source in callsites[:2]:
            image[source:source + 4] = _bl(runtime[source], runtime[entry])
        image[callsites[2]:callsites[2] + 4] = _bl(
            runtime[callsites[2]], runtime[body]
        )
        reverse = {address: position for position, address in runtime.items()}

        self.assertEqual(find_uis_idle_pair(
            image, runtime.get, reverse.get
        ), (entry, body))

    def test_accepts_compact_one_caller_pair(self) -> None:
        image = bytearray(b"\xff" * 0x2000)
        entry = 0x400
        body = entry + UIS_IDLE_COMPACT_BODY_DELTA
        image[entry:entry + len(UIS_IDLE_COMPACT_ENTRY_PREFIX)] = (
            UIS_IDLE_COMPACT_ENTRY_PREFIX
        )
        image[body:body + len(UIS_IDLE_COMPACT_BODY_PREFIX)] = (
            UIS_IDLE_COMPACT_BODY_PREFIX
        )
        image[0x1000:0x1004] = _bl(0x1000, entry)
        image[0x1200:0x1204] = _bl(0x1200, body)

        self.assertEqual(find_uis_idle_pair(image), (entry, body))
        image[0x1100:0x1104] = _bl(0x1100, entry)
        self.assertIsNone(find_uis_idle_pair(image))

    def test_accepts_registered_idle_draw_pair(self) -> None:
        for delta, push in ((0x8B8, 0xB5FC), (0x908, 0xB5F8)):
            with self.subTest(delta=delta):
                image = bytearray(b"\xff" * 0x3000)
                marker = _draw_pair(image, 0x400, delta, push)
                self.assertEqual(find_uis_idle_pair(image), (0x400, 0x400 + delta))
                image[marker] ^= 1
                self.assertIsNone(find_uis_idle_pair(image))

    def test_rejects_body_or_call_count_mutation(self) -> None:
        image = bytearray(b"\xff" * 0x2000)
        _pair(image, 0x400, (0x1000, 0x1100, 0x1200))
        image[0x55E] ^= 1
        self.assertIsNone(find_uis_idle_pair(image))

        image = bytearray(b"\xff" * 0x2000)
        _pair(image, 0x400, (0x1000, 0x1100, 0x1200))
        image[0x1300:0x1304] = _bl(0x1300, 0x400)
        self.assertIsNone(find_uis_idle_pair(image))

    def test_rejects_ambiguous_pairs(self) -> None:
        image = bytearray(b"\xff" * 0x2000)
        _pair(image, 0x400, (0x1000, 0x1100, 0x1200))
        _pair(image, 0x800, (0x1500, 0x1600, 0x1700))

        self.assertIsNone(find_uis_idle_pair(image))
