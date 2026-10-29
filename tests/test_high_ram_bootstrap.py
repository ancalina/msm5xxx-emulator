"""Closed high-RAM bootstrap acceptance and negative controls."""
from corpus import snippet
import argparse
from pathlib import Path
import struct
import tempfile
import unittest
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.memory_layout import (
    find_high_ram_readback_tests, high_ram_bootstrap_profile, find_linker_layout,
)


def _readback_body():
    return snippet("test_high_ram_bootstrap", "readback_body")

class HighRAMBootstrapTests(unittest.TestCase):
    def test_reset_readback_extent_and_rejections(self):
        image = bytearray(0x800)
        struct.pack_into('<I', image, 0, 0xEA00003E)  # reset 0x100
        struct.pack_into('<5I', image, 0x100,
                         0xE59F4078, 0xE3140001, 0x159FE074,
                         0x059FE074, 0xE12FFF14)
        struct.pack_into('<3I', image, 0x180, 0x300, 0x115, 0x118)
        struct.pack_into('<7I', image, 0x2E4, 0x14000000, 0x3FFFFF,
                         0x10, 0x55AA0F, 0xAA0F, 0x55, 0x030006D0)
        body = _readback_body()
        image[0x300:0x450] = body
        self.assertEqual(find_high_ram_readback_tests(bytes(image)), [0x300])
        self.assertEqual(find_high_ram_readback_tests(b'\x00\x00\x00\x14' * 128), [])
        self.assertEqual(find_high_ram_readback_tests(bytes(image[:0x440])), [])
        low_ram = image.copy()
        struct.pack_into('<I', low_ram, 0x2E4, 0x01100000)
        self.assertEqual(find_high_ram_readback_tests(bytes(low_ram)), [])
        for offset, field in ((0,0),(0x10,8),(0x40,24),(0x6C,4),
                              (0x80,4),(0xF4,12),(0x108,16),(0x11C,20)):
            instruction = struct.unpack_from('<I', image, 0x300+offset)[0]
            literal = 0x300+offset+8+(instruction & 0xFFF)
            struct.pack_into('<I', image, literal, 0x2E4+field)
        self.assertEqual(high_ram_bootstrap_profile(bytes(image)),
                         (0x14000000, 0x400000))
        reserved = image.copy()
        struct.pack_into('<I', reserved, 0x2E8, 0x3FFDFF)
        self.assertEqual(high_ram_bootstrap_profile(bytes(reserved)),
                         (0x14000000, 0x400000))
        larger = image.copy()
        struct.pack_into('<I', larger, 0x2E8, 0x7FFFFF)
        self.assertEqual(high_ram_bootstrap_profile(bytes(larger)),
                         (0x14000000, 0x800000))
        for offset, value in ((0,0),(0x180,0x304),(0x188,0x11C),
                              (0x2E4,0x01000000),(0x2E8,0x5FFFFF),
                              (0x2F0,0),(0x31C,0),(0x45C,0)):
            bad = image.copy()
            struct.pack_into('<I', bad, offset, value)
            with self.subTest(offset=offset):
                self.assertIsNone(high_ram_bootstrap_profile(bytes(bad)))
        for length in (0,3,0x100,0x310,0x450):
            self.assertIsNone(high_ram_bootstrap_profile(bytes(image[:length])))
        # A reset-called Thumb copy can corroborate an otherwise uncalled
        # readback descriptor. Only literal offsets vary within the loop shape.
        copied = larger.copy()
        struct.pack_into('<I', copied, 0x180, 0x501)
        struct.pack_into('<H', copied, 0x114, 0x4778)
        struct.pack_into('<12H', copied, 0x500,
                         0x481F, 0x6804, 0x481F, 0x6800, 0x1826, 0x481F,
                         0x6805, 0xE001, 0xCD01, 0xC401, 0x42B4, 0xD3FB)
        struct.pack_into('<3I', copied, 0x580, 0x604, 0x608, 0x600)
        struct.pack_into('<3I', copied, 0x600, 0x700, 0x147F0000, 0x100)
        self.assertEqual(high_ram_bootstrap_profile(bytes(copied)),
                         (0x14000000, 0x800000))
        alternate = copied.copy()
        struct.pack_into('<12H', alternate, 0x500,
                         0x4A1F, 0x6814, 0x4A1F, 0x6812, 0x18A6, 0x4A1F,
                         0x6815, 0xE001, 0xCD04, 0xC404, 0x42B4, 0xD3FB)
        self.assertEqual(high_ram_bootstrap_profile(bytes(alternate)),
                         (0x14000000, 0x800000))
        smaller_copy = copied.copy()
        struct.pack_into('<I', smaller_copy, 0x2E8, 0x3FFFFF)
        struct.pack_into('<I', smaller_copy, 0x604, 0x143F0000)
        self.assertEqual(high_ram_bootstrap_profile(bytes(smaller_copy)),
                         (0x14000000, 0x400000))
        for offset, value, width in (
                (0x184, 0x119, 4), (0x188, 0x11C, 4), (0x114, 0, 2),
                (0x514, 0x42B5, 2), (0x502, 0x6844, 2),
                (0x50E, 0xE000, 2), (0x510, 0xCD03, 2),
                (0x580, 0x602, 4), (0x584, 0x60C, 4),
                (0x600, 0x780, 4), (0x604, 0x14800000, 4),
                (0x604, 0x14001000, 4), (0x608, 0, 4),
                (0x608, 0x101, 4), (0x31C, 0, 4)):
            bad = copied.copy()
            struct.pack_into('<I' if width == 4 else '<H', bad, offset, value)
            with self.subTest(copy_offset=offset, value=value):
                self.assertIsNone(high_ram_bootstrap_profile(bytes(bad)))
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / 'anonymous.bin'
            firmware.write_bytes(image)
            automatic = detect(firmware)
            self.assertEqual((automatic.ram_base, automatic.ram_size),
                             (0x14000000, 0x400000))
            overridden = detect(firmware, argparse.Namespace(
                ram_base=0x01800000, ram_size=0x800000))
            self.assertEqual((overridden.ram_base, overridden.ram_size),
                             (0x01800000, 0x800000))
            rebased = detect(firmware, argparse.Namespace(load_address=0x10000000))
            self.assertFalse(any('high-RAM readback/extent profile detected' in note
                                 for note in rebased.detection_notes))
            firmware.write_bytes(copied)
            copied_config = detect(firmware)
            self.assertEqual((copied_config.ram_base, copied_config.ram_size),
                             (0x14000000, 0x800000))


def prefixed_fixture(shift=0, image=None):
    if image is None:
        image = bytearray(0x1000)
    reset, body = 0x100+shift, 0x300+shift
    table, entry = body-60, body-20
    struct.pack_into('<I',image,0,0xEA000000|((reset-8)//4&0xFFFFFF))
    struct.pack_into('<5I',image,reset,0xE59F4078,0xE3140001,
                     0x159FE074,0x059FE074,0xE12FFF14)
    struct.pack_into('<3I',image,reset+0x80,entry,reset+0x15,reset+0x18)
    struct.pack_into('<I',image,reset+0x14,0x00004778)
    struct.pack_into('<10I',image,table,0x14000000,0x7FFFFF,0x10,
                     0x55AA0F,0xAA0F,0x55,0x030006D0,
                     0x147FFFFE,0x147FFDFE,0x14000130)
    image[entry:body]=bytes.fromhex('5c019fe558019fe554019fe554019fe554019fe5')
    image[body:body+len(_readback_body())] = _readback_body()
    for offset,field in ((0,0),(0x10,8),(0x40,24),(0x6C,4),
                         (0x80,4),(0xF4,12),(0x108,16),(0x11C,20)):
        instruction=struct.unpack_from('<I',image,body+offset)[0]
        struct.pack_into('<I',image,body+offset+8+(instruction&0xFFF),table+field)
    for offset,field in ((0,28),(4,28),(8,28),(12,32),(16,36)):
        instruction=struct.unpack_from('<I',image,entry+offset)[0]
        struct.pack_into('<I',image,entry+offset+8+(instruction&0xFFF),table+field)
    return image,dict(reset=reset,entry=entry,body=body,table=table)


class PrefixedHighRAMBootstrapTests(unittest.TestCase):
    def test_relocated_closed_prelude(self):
        for shift in (0,4,0x100):
            image,p=prefixed_fixture(shift)
            self.assertEqual(find_high_ram_readback_tests(bytes(image)),[p['body']])
            self.assertEqual(high_ram_bootstrap_profile(bytes(image)),(0x14000000,0x800000))

    def test_each_prelude_opcode_and_literal_relation(self):
        image,p=prefixed_fixture()
        for offset in range(0,20,4):
            # AL -> EQ, R0 -> R1, and PC offset mutation.
            for mask in (0xE0000000,0x1000,4):
                changed=image.copy();at=p['entry']+offset
                struct.pack_into('<I',changed,at,struct.unpack_from('<I',changed,at)[0]^mask)
                self.assertIsNone(high_ram_bootstrap_profile(bytes(changed)))
            instruction=struct.unpack_from('<I',image,p['entry']+offset)[0]
            pool=p['entry']+offset+8+(instruction&0xFFF)
            changed=image.copy();struct.pack_into('<I',changed,pool,p['table']+40)
            self.assertIsNone(high_ram_bootstrap_profile(bytes(changed)))
        # Moving the descriptor without rebinding all consumer literals is not a layout.
        changed=image.copy();changed[p['table']-4:p['table']+36]=image[p['table']:p['table']+40]
        self.assertIsNone(high_ram_bootstrap_profile(bytes(changed)))

    def test_body_table_reset_and_missing_controls(self):
        image,p=prefixed_fixture()
        for offset,value in ((p['reset']+0x80,p['body']),
                             (p['reset']+0x80,p['entry']+4),
                             (p['reset']+0x88,p['reset']+28),
                             (p['table'],0x01000000),(p['table']+4,0x5FFFFF),
                             (p['table']+8,0x20),(p['body']+0x1C,0)):
            changed=image.copy();struct.pack_into('<I',changed,offset,value)
            self.assertIsNone(high_ram_bootstrap_profile(bytes(changed)))
        for delta in (0,0x10,0x40,0x6C,0x80,0xF4,0x108,0x11C):
            at=p['body']+delta;instruction=struct.unpack_from('<I',image,at)[0]
            pool=at+8+(instruction&0xFFF)
            changed=image.copy();changed[pool]^=4
            self.assertIsNone(high_ram_bootstrap_profile(bytes(changed)))
        for end in (0,3,p['entry']+16,p['body']+0x14F,p['body']+0x177):
            self.assertIsNone(high_ram_bootstrap_profile(bytes(image[:end])))
        changed=image.copy();struct.pack_into('<I',changed,p['reset']+0x80,0x800)
        self.assertIsNone(high_ram_bootstrap_profile(bytes(changed)))

    def test_connected_prefixed_geometry_consensus_and_conflict(self):
        image,p=prefixed_fixture()
        # Second complete group and a second gate in the same reset scan.
        other,q=prefixed_fixture(0x500)
        image[0x500:]=other[0x500:]
        gate=p['reset']+0x20
        struct.pack_into('<5I',image,gate,0xE59F4058,0xE3140001,
                         0x159FE054,0x059FE054,0xE12FFF14)
        struct.pack_into('<3I',image,p['reset']+0x80,q['entry'],gate+0x15,gate+0x18)
        # First gate uses a distinct pool while preserving its return contract.
        struct.pack_into('<5I',image,p['reset'],0xE59F4098,0xE3140001,
                         0x159FE094,0x059FE094,0xE12FFF14)
        struct.pack_into('<3I',image,p['reset']+0xA0,p['entry'],p['reset']+0x15,p['reset']+0x18)
        self.assertEqual(high_ram_bootstrap_profile(bytes(image)),(0x14000000,0x800000))
        struct.pack_into('<I',image,q['table']+4,0x3FFFFF)
        self.assertIsNone(high_ram_bootstrap_profile(bytes(image)))

    def test_caller_normalisation_and_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'anonymous.bin'
            image,_p=prefixed_fixture()
            path.write_bytes(image)
            config=detect(path)
            self.assertEqual((config.ram_base,config.ram_size),(0x14000000,0x800000))
            overridden=detect(path,argparse.Namespace(ram_base=0x01800000,ram_size=0x800000))
            self.assertEqual((overridden.ram_base,overridden.ram_size),(0x01800000,0x800000))
            explicit_seed=detect(path,argparse.Namespace(ram_image_offset=0x800,ram_image_size=0x20))
            self.assertEqual((explicit_seed.ram_image_offset,explicit_seed.ram_image_size),(0x800,0x20))
            rebased=detect(path,argparse.Namespace(load_address=0x10000000))
            self.assertFalse(any('high-RAM readback/extent profile detected' in note for note in rebased.detection_notes))
            # A synthetic no-linker32MiB input exercises the existing caller's
            # post-selection flash normalization; actual input conflicts stay gated.
            image.extend(bytes(0x2000000-len(image)));path.write_bytes(image)
            config=detect(path)
            self.assertEqual((config.ram_base,config.ram_size),(0x14000000,0x800000))
            self.assertEqual((config.flash_size,config.ram_image_size),(0x2000000,0))

            # A conflicting existing linker remains authoritative: this mirrors
            # the actual input's caller rejection, without importing its data.
            struct.pack_into('<5I',image,0x900,0x20000,0x01000000,0x20000,
                             0x01020000,0x20000)
            path.write_bytes(image)
            conflicted=detect(path)
            self.assertIsNotNone(conflicted.linker)
            self.assertEqual((conflicted.ram_base,conflicted.ram_size),
                             (0x01000000,0x800000))
            self.assertEqual((conflicted.flash_size,conflicted.ram_image_size),
                             (0x1000000,0x800000))
            self.assertFalse(any('high-RAM readback/extent profile detected' in note
                                 for note in conflicted.detection_notes))


class RegularPairArrayLinkerTests(unittest.TestCase):
    @staticmethod
    def image(count=9):
        image=bytearray(0x5000)
        start,base,span=0x3000,0x01000000,0x1000
        for i in range(count):
            struct.pack_into('<II',image,start+i*8,base+i*span,span)
        return image,start,base,span

    def test_every_contained_three_pair_phase_and_default(self):
        image,start,base,span=self.image()
        # A preceding zero source word is not a proven member of the run.
        self.assertEqual(find_linker_layout(bytes(image)).table_offset,start-4)
        for phase in range(7):
            with self.subTest(phase=phase):
                required=(base+(phase+1)*span+0x16,3)
                self.assertIsNone(find_linker_layout(bytes(image),required_span=required))

    def test_damaged_or_truncated_exact_nine_keeps_old_candidate(self):
        image,start,base,span=self.image()
        required=(base+span+0x16,3)
        # Break neighbors outside the candidate's three records.
        for neighbor in range(3,9):
            changed=image.copy();changed[start+neighbor*8+4]^=1
            layout=find_linker_layout(bytes(changed),required_span=required)
            self.assertIsNotNone(layout)
            self.assertEqual(layout.table_offset,start+4)
        for end in (start+3*8,start+8*8,start+9*8-1):
            layout=find_linker_layout(bytes(image[:end]),required_span=required)
            self.assertIsNotNone(layout)
            self.assertEqual(layout.table_offset,start+4)

    def test_no_nine_proof_and_large_array_alternate_window(self):
        short,start,base,span=self.image(8)
        self.assertIsNotNone(find_linker_layout(bytes(short),required_span=(base+span,3)))
        longer,start,base,span=self.image(18)
        # One bad neighbor does not undo another complete nine-pair proof.
        longer[start+4]^=1
        self.assertIsNone(find_linker_layout(bytes(longer),required_span=(base+8*span,3)))

    def test_nonregular_true_layout_and_required_span_ambiguity(self):
        image=bytearray(0x5000)
        struct.pack_into('<5I',image,0x800,0x1000,0x01000000,0x1000,0x01001000,0x1000)
        self.assertEqual(find_linker_layout(bytes(image)).table_offset,0x800)
        self.assertEqual(find_linker_layout(bytes(image),required_span=(0x01000016,3)).table_offset,0x800)
        struct.pack_into('<5I',image,0x900,0x2000,0x01000000,0x1000,0x01001000,0x1000)
        self.assertIsNone(find_linker_layout(bytes(image),required_span=(0x01000016,3)))


    def test_variable_length_contiguous_extent_array(self):
        image=bytearray(0x10000)
        start,address=0x6000,0x01000000
        spans=(0x1000,0x2000,0x3000,0x1000,0x4000,0x1000,0x2000,0x1000,0x3000)
        addresses=[]
        for i,length in enumerate(spans):
            addresses.append(address)
            struct.pack_into('<II',image,start+i*8,address,length)
            address+=length
        for phase in range(7):
            required=(addresses[phase+1]+0x16,3)
            self.assertIsNone(find_linker_layout(bytes(image),required_span=required))
        # A gap, overlap or non-page neighbor is not complete extent-array proof.
        required=(addresses[1]+0x16,3)
        for neighbor in range(3,9):
            for delta in (-0x1000,0x1000,1):
                changed=image.copy()
                struct.pack_into('<I',changed,start+neighbor*8,addresses[neighbor]+delta)
                layout=find_linker_layout(bytes(changed),required_span=required)
                self.assertIsNotNone(layout)
                self.assertEqual(layout.table_offset,start+4)
        for end in (start+3*8,start+8*8,start+9*8-1):
            layout=find_linker_layout(bytes(image[:end]),required_span=required)
            self.assertIsNotNone(layout)
            self.assertEqual(layout.table_offset,start+4)
        overflow=image.copy()
        struct.pack_into('<I',overflow,start+8*8+4,0xFFFFF000)
        self.assertEqual(find_linker_layout(bytes(overflow),required_span=required).table_offset,start+4)


    def test_zero_based_extent_array_default_and_required_span(self):
        image=bytearray(0x800000)
        start,span=0x3000,0x400000
        for i in range(9):
            struct.pack_into('<II',image,start+i*8,i*span,span)
        # The first otherwise-valid sliding tuple starts inside the zero-based run.
        self.assertIsNone(find_linker_layout(bytes(image)))
        self.assertIsNone(find_linker_layout(bytes(image),required_span=(0x01000016,3)))
