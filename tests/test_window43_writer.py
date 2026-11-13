"""Generated source checks for the 43/42 windowed halfword writer."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.display.window43_writer import find_window43
from msm5xxx_emulator.detection.devices.display.source_writers import machine_plan
from msm5xxx_emulator.devices.display.source_plan import apply_source_plan


class _ThumbCode:
    def __init__(self, image, address):
        self.image, self.pc = image, address
        self.labels, self.fixups = {}, []

    def emit(self, opcode):
        struct.pack_into('<H', self.image, self.pc, opcode)
        self.pc += 2

    def label(self, name):
        self.labels[name] = self.pc

    def branch(self, opcode, label):
        self.fixups.append((self.pc, opcode, label))
        self.emit(opcode)

    def call(self, target):
        delta = target - self.pc - 4
        self.emit(0xF000 | (delta >> 12 & 0x7ff))
        self.emit(0xF800 | (delta >> 1 & 0x7ff))

    def finish(self):
        for address, opcode, label in self.fixups:
            delta = (self.labels[label] - address - 4) // 2
            mask = 0xff if opcode & 0xf000 == 0xd000 else 0x7ff
            struct.pack_into('<H', self.image, address,
                             opcode | delta & mask)


def _add3(dst, left, right):
    return 0x1800 | (right << 6) | (left << 3) | dst


def _add_imm3(dst, source, value):
    return 0x1c00 | (value << 6) | (source << 3) | dst


def _sub_imm3(dst, source, value):
    return 0x1e00 | (value << 6) | (source << 3) | dst


def _strh(source, base, offset=0):
    return 0x8000 | ((offset // 2) << 6) | (base << 3) | source


def _thumb_ldr_literal(rd, pc, pool):
    base = (pc + 4) & ~3
    delta = pool - base
    if delta < 0 or delta % 4:
        raise ValueError('literal must be forward and word aligned')
    return 0x4800 | (rd << 8) | (delta // 4)


def _image(*, width=4, height=3, caller_width=None,
           clear_count_delta=0, blit_width=None, blit_height=None,
           row_stride_delta=0, wrong_pixel_register=False,
           data_offset=2, y_offset=10, wrong_setter_port=False,
           pixel_clobber=False, pointer_clobber=False):
    image = bytearray(0x1000)
    setter, clear, init, blitter, pool = 0x500, 0x300, 0x100, 0x700, 0x900
    caller_width = width if caller_width is None else caller_width
    blit_width = width if blit_width is None else blit_width
    blit_height = height if blit_height is None else blit_height

    # Coordinate setter: 43 selects X, 42 selects Y; Y coordinates are offset.
    code = _ThumbCode(image, setter)
    code.emit(0x2543)                         # MOVS R5,#43
    code.emit(0x2402 if wrong_setter_port else 0x2403)
    code.emit(0x06e4)                         # LSLS R4,R4,#27 -> 18000000
    code.emit(_strh(5, 4))
    code.emit(_strh(0, 4))
    code.emit(_strh(2, 4))
    code.emit(0x2542)                         # MOVS R5,#42
    code.emit(_strh(5, 4))
    code.emit(0x3100 | y_offset)              # ADDS R1,#y origin
    code.emit(_strh(1, 4))
    code.emit(0x3300 | y_offset)              # ADDS R3,#y origin
    code.emit(_strh(3, 4))
    code.emit(0x4770)                         # BX LR
    code.finish()

    # Uniform clear routine; rectangle size comes from the caller's R2/R3.
    code = _ThumbCode(image, clear)
    code.emit(0xB570)                         # PUSH {R4-R6,LR}
    code.emit(_add_imm3(5, 3, 0))            # R5 = height
    code.emit(_add_imm3(6, 2, 0))            # R6 = width
    code.emit(_add3(2, 0, 2))                # x end before -1
    code.emit(0x3A01)                         # SUBS R2,#1
    code.emit(_add3(3, 1, 3))                # y end before -1
    code.emit(0x3B01)                         # SUBS R3,#1
    code.call(setter)
    code.emit(_sub_imm3(0, 5, 1))            # outer count = height - 1
    code.emit(_sub_imm3(5, 6, 1 - clear_count_delta))
    code.emit(0x2203)                         # MOVS R2,#3
    code.emit(0x06d2)                         # LSLS R2,R2,#27
    code.emit(0x2400)                         # fixed color = 0
    code.label('outer')
    code.emit(_add_imm3(1, 5, 0))            # inner count
    code.label('inner')
    code.emit(_strh(4, 2, data_offset))       # FIFO halfword write
    code.emit(0x3901)                         # SUBS R1,#1
    code.branch(0xD200, 'inner')             # BHS inner
    code.emit(0x3801)                         # SUBS R0,#1
    code.branch(0xD200, 'outer')             # BHS outer
    code.emit(0xBC70)
    code.emit(0xBC08)
    code.emit(0x4718)
    code.finish()

    # Caller publishes a concrete clear rectangle.
    code = _ThumbCode(image, init)
    for opcode in (0xB510, 0x2000, 0x2100,
                   0x2200 | caller_width, 0x2300 | height):
        code.emit(opcode)
    code.call(clear)
    code.emit(0xBC10)
    code.emit(0xBC08)
    code.emit(0x4718)
    code.finish()

    # Linked source blitter: same rectangle, LDRH to FIFO, packed 16-bit rows.
    code = _ThumbCode(image, blitter)
    code.emit(0xB570)
    for opcode in (0x2000, 0x2100,
                   0x2200 | (blit_width - 1),
                   0x2300 | (blit_height - 1)):
        code.emit(opcode)
    code.call(setter)
    code.emit(_thumb_ldr_literal(2, code.pc, pool))
    code.emit(0x2400 | (blit_height - 1))       # outer count
    code.emit(0x2503)                          # MOVS R5,#3
    code.emit(0x06ed)                          # LSLS R5,R5,#27
    code.label('outer')
    code.emit(_add_imm3(0, 2, 0))             # reset row source pointer
    code.emit(0x2100 | (blit_width - 1))       # inner count
    code.label('inner')
    if pointer_clobber:
        code.emit(0x2000)                     # replace the row source pointer
    code.emit(0x8800 | (0 << 3) | 3)           # LDRH R3,[R0]
    if pixel_clobber:
        code.emit(0x2300)                     # replace the loaded pixel
    code.emit(_strh(3 if not wrong_pixel_register else 4, 5, data_offset))
    code.emit(0x3002)                          # source cursor += 2
    code.emit(0x3901)
    code.branch(0xD200, 'inner')
    code.emit(0x3200 | (blit_width * 2 + row_stride_delta))
    code.emit(0x3c01)                          # outer count -= 1
    code.branch(0xD200, 'outer')
    code.emit(0xBC70)
    code.emit(0xBC08)
    code.emit(0x4718)
    code.finish()
    struct.pack_into('<I', image, pool, 0x14000100)
    return bytes(image)


class Window43WriterTests(unittest.TestCase):
    def test_plan_selects_existing_window_model_and_checks_loaded_bytes(self):
        image = _image().ljust(0x10000, b'\0')
        cfg = SimpleNamespace(image_kind='firmware', load_address=0,
                              image_offset=0, entry=0, missing_overlays=[],
                              ram_bootstrap_profile=None,
                              display_geometry_source='auto-default',
                              width=176, height=220)
        plan = machine_plan(image, image, cfg)
        self.assertEqual(dict(plan.capabilities[0].parameters)['window51'],
                         (4, 3, 0, 10))
        decoder = SimpleNamespace()
        apply_source_plan(decoder, plan)
        panel = decoder._lcd_b0_source_page
        self.assertEqual((panel.width, panel.height, panel.x_origin,
                          panel.y_origin), (4, 3, 0, 10))
        changed = bytearray(image)
        changed[0x500] ^= 1
        self.assertFalse(machine_plan(image, bytes(changed), cfg).capabilities)
        cfg.display_geometry_source = 'external-config'
        self.assertFalse(machine_plan(image, image, cfg).capabilities)

    def test_geometry_is_linked_to_clear_setter_and_ram_blitter(self):
        profile = find_window43(_image())
        self.assertIsNotNone(profile)
        self.assertEqual((profile['width'], profile['height'],
                          profile['x_origin'], profile['y_origin'],
                          profile['data_port'], profile['protocol']),
                         (4, 3, 0, 10, 0x18000002, 'window43'))
        self.assertGreaterEqual(len(profile['evidence']), 5)

    def test_setter_translation_is_derived_from_source(self):
        profile = find_window43(_image(y_offset=11))
        self.assertIsNotNone(profile)
        self.assertEqual(profile['y_origin'], 11)

    def test_inconsistent_geometry_count_stride_dataflow_or_port_is_rejected(self):
        for kwargs in (
            {'caller_width': 5},
            {'clear_count_delta': -1},
            {'blit_width': 3},
            {'row_stride_delta': 2},
            {'wrong_pixel_register': True},
            {'pixel_clobber': True},
            {'pointer_clobber': True},
            {'data_offset': 4},
            {'wrong_setter_port': True},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertIsNone(find_window43(_image(**kwargs)))


if __name__ == '__main__':
    unittest.main()
