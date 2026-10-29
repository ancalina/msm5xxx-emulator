import dataclasses
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from msm5xxx_emulator.detection.model import (
    _product_constructor_model, detect_model, embedded_model_scores,
    verified_embedded_model,
)


_BODY = bytes.fromhex(
    '90b5742000f0cefa2ba101602ca141602ba181600124846104730221071c79733422'
    'ba733221f9733321397430237b740021b974f97436213a757975bb753c77022000f0'
    'affa24a13862098801802349f81d1930f9860471786a230298435900084349000843'
    '0f23db029843490108434b00984389000843490008434b00984349030843c90a0843'
    '07235b0598430901084303235b069843c9000843490008431b019843011c7962'
    'b86a010a0902b962381c90bc08bc1847'
)
_ALLOCATOR = bytes.fromhex(
    '80b40c4f021c9108386849000b1801219207920f002a00dc0021490059180122d203'
    '8a188a42396001d23860002080bc7047'
)


def fixture(start=0x100, *, at_product=b'LG-AB123', company=b'LG ELECTRONICS CO. LTD'):
    raw = bytearray(b'\xff' * (start + 0x600))
    raw[start:start + len(_BODY)] = _BODY
    model = (start + 0xBB) & ~3
    vendor = model + 8
    locale = model + 0x28
    literal = model + 0x30
    allocator = start + 0x300
    raw[allocator:allocator + len(_ALLOCATOR)] = _ALLOCATOR
    literal_pc = (allocator + 6) & ~3
    allocator_literal = (allocator + 0x37) & ~3
    struct.pack_into('<H', raw, allocator + 2,
                     0x4F00 | ((allocator_literal - literal_pc) // 4))
    struct.pack_into('<I', raw, allocator_literal, 0x01800000)
    for offset in (4, 0x42):
        delta = allocator - (start + offset) - 4
        struct.pack_into('<2H', raw, start + offset,
                         0xF000 | (delta >> 12 & 0x7FF), 0xF800 | (delta >> 1 & 0x7FF))
    for offset, target in ((8, model), (12, vendor), (16, vendor), (0x46, locale)):
        pc = (start + offset + 4) & ~3
        struct.pack_into('<H', raw, start + offset, 0xA100 | ((target - pc) // 4))
    pc = (start + 0x4E + 4) & ~3
    struct.pack_into('<H', raw, start + 0x4E, 0x4900 | ((literal - pc) // 4))
    raw[model:model + 6] = b'AB123\0'
    raw[vendor:vendor + len(company) + 1] = company + b'\0'
    raw[locale:locale + 3] = b'en\0'
    struct.pack_into('<I', raw, literal, 0xFFFF)
    record = b'LG Electronics Inc.\0' + at_product + b' \0\0OK\0CONNECT\0RING\0NO CARRIER\0'
    raw[start + 0x400:start + 0x400 + len(record)] = record
    return raw


class ModelIdentityTests(unittest.TestCase):
    def test_full_detection_changes_identity_notes_without_hardware_or_state_layout(self):
        from msm5xxx_emulator.detection import detect
        raw = fixture()
        for offset in range(0, 32, 4):
            struct.pack_into('<I', raw, offset, 0xEA000000)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'SCH-X123.bin'
            path.write_bytes(raw)
            actual = detect(path)
            with patch('msm5xxx_emulator.detection.firmware.detect_model',
                       return_value='SCH-X123'):
                filename_only = detect(path)
        self.assertEqual(actual.model, 'LG-AB123')
        self.assertIsNone(actual.verified_model)
        self.assertIn('provisional-product-constructor-at', actual.detection_notes)
        before, after = dataclasses.asdict(filename_only), dataclasses.asdict(actual)
        for key in ('model', 'detection_notes'):
            before.pop(key)
            after.pop(key)
        self.assertEqual(after, before)

    def test_closed_identity_relocates_and_ignores_filename(self):
        for start in (0x100, 0x122, 0x2400):
            with self.subTest(start=start):
                raw = bytes(fixture(start))
                self.assertEqual(_product_constructor_model(raw),
                                 ('LG-AB123', 'provisional-product-constructor-at'))
                for name in ('neutral.bin', 'SCH-X123.bin', 'renamed-copy.bin'):
                    notes = []
                    self.assertEqual(detect_model(raw, Path(name), notes=notes), 'LG-AB123')
                    self.assertEqual(notes, ['provisional-product-constructor-at'])
                self.assertIsNone(verified_embedded_model(raw))

    def test_missing_mismatched_or_duplicate_independent_record(self):
        raw = fixture()
        for changed in (raw[:0x500], fixture(at_product=b'LG-CD456'),
                        fixture(company=b'OTHER ELECTRONICS CO. LTD')):
            self.assertIsNone(_product_constructor_model(bytes(changed))[0])
        for extra in (b'LG-AB123', b'LG-CD456'):
            changed = fixture()
            record = b'LG Electronics Inc.\0' + extra + b'\0OK\0CONNECT\0RING\0NO CARRIER\0'
            changed[0x620:0x620 + len(record)] = record
            self.assertEqual(_product_constructor_model(bytes(changed)),
                             (None, 'product-constructor-at-ambiguous'))

    def test_every_fixed_constructor_halfword_and_middle_clobber_rejects(self):
        variable = {4, 6, 8, 12, 16, 0x42, 0x44, 0x46, 0x4E}
        for offset in range(0, len(_BODY), 2):
            if offset in variable:
                continue
            with self.subTest(offset=offset):
                raw = fixture()
                raw[0x100 + offset] ^= 1
                self.assertIsNone(_product_constructor_model(bytes(raw))[0])
        for offset, opcode in ((10, 0x8001), (14, 0x7041), (0x70, 0x2700),
                               (len(_BODY) - 2, 0x4770)):
            raw = fixture()
            struct.pack_into('<H', raw, 0x100 + offset, opcode)
            self.assertIsNone(_product_constructor_model(bytes(raw))[0])

    def test_adr_calls_literal_bounds_and_truncation(self):
        for offset, opcode in ((8, 0xA200), (12, 0xA1FF), (16, 0xA100),
                               (0x46, 0xA200), (0x4E, 0x4800), (4, 0xF800),
                               (0x42, 0xF800)):
            with self.subTest(offset=offset):
                raw = fixture()
                struct.pack_into('<H', raw, 0x100 + offset, opcode)
                self.assertIsNone(_product_constructor_model(bytes(raw))[0])
        # Identical BLs must still land inside the image.
        raw = fixture()
        for offset in (4, 0x42):
            delta = 0x10000 - (0x100 + offset) - 4
            struct.pack_into('<2H', raw, 0x100 + offset,
                             0xF000 | (delta >> 12 & 0x7FF), 0xF800 | (delta >> 1 & 0x7FF))
        self.assertIsNone(_product_constructor_model(bytes(raw))[0])
        for end in (0x100, 0x1B6, 0x1BC, 0x1C5, 0x1EF):
            self.assertIsNone(_product_constructor_model(bytes(fixture()[:end]))[0])

    def test_allocator_must_preserve_saved_object_register(self):
        for offset in range(0, len(_ALLOCATOR), 2):
            if offset == 2:
                continue
            with self.subTest(offset=offset):
                raw = fixture()
                raw[0x400 + offset] ^= 1
                self.assertIsNone(_product_constructor_model(bytes(raw))[0])
        raw = fixture()
        struct.pack_into('<H', raw, 0x402, 0x4800)
        self.assertIsNone(_product_constructor_model(bytes(raw))[0])

    def test_duplicate_constructor_rejects(self):
        raw = fixture()
        # Duplicate the full PC-relative object at a four-aligned position.
        other = fixture(0x800)
        raw.extend(b'\xff' * max(0, len(other) - len(raw)))
        raw[0x800:] = other[0x800:]
        self.assertEqual(_product_constructor_model(bytes(raw)),
                         (None, 'product-constructor-ambiguous'))

    def test_inherited_at_empty_mobiletype_and_heuristic_behavior_preserved(self):
        at_only = b'LG Electronics Inc.\0LG-CD456\0OK\0CONNECT\0RING\0NO CARRIER\0+CIS707'
        self.assertIsNone(verified_embedded_model(at_only))
        self.assertEqual(detect_model(at_only, Path('SCH-X123.bin')), 'SCH-X123')
        empty = b'BRAND\0AB123\0MSM5000\0m_MobileType: \0\0\r\nm_authS2: '
        self.assertEqual(detect_model(empty, Path('neutral.bin'), chipset='MSM5000'), 'neutral')
        raw = bytes(fixture())
        notes = []
        self.assertEqual(detect_model(raw, Path('SCH-X123.bin'),
                                      {'SCH-X777': 10}, notes=notes), 'SCH-X123')
        self.assertIn('product-constructor-heuristic-conflict', notes)
        self.assertEqual(detect_model(b'none', Path('SCH-X123.bin')), 'SCH-X123')
        self.assertEqual(embedded_model_scores(at_only)['LG-CD456'], 2)


# Separate namespace: browser product software label, not the AT model alias.
def browser_fixture(start=0x100, label=b'CDM-1234/T10'):
    from msm5xxx_emulator.detection.model import _BROWSER_BODIES
    raw=bytearray(b'\xff'*0x6000)
    sites={'producer':start,'append':start+0x400,'span':start+0x500,
           'init':start+0x700,'strlen':start+0x900,'getter':start+0xb00,
           'caller':start+0xc00,'record':start+0x1000,'stub':start+0x2000}
    def bl(pc,target):
        delta=target-pc-4
        struct.pack_into('<HH',raw,pc,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
    raw[sites['stub']:sites['stub']+4]=bytes.fromhex('80b57047')
    for kind,(encoded,calls) in _BROWSER_BODIES.items():
        at=sites[kind];body=bytes.fromhex(encoded);raw[at:at+len(body)]=body
        for offset in calls:bl(at+offset,sites['stub'])
    producer=sites['producer']
    raw[producer-0x18:producer-0xc]=b'4.1.26l\0'+b'\0'*4
    raw[producer-0xc:producer]=b' WEAK\0\0\0 \0\0\0'
    for offset in (0x18,0x30,0x38,0x44,0x4c):bl(producer+offset,sites['append'])
    bl(producer+0xe,sites['init']);bl(producer+0x3c,sites['getter'])
    bl(sites['append']+8,sites['strlen']);bl(sites['append']+0x12,sites['span'])
    struct.pack_into('<I',raw,sites['strlen']+0x48,0x01010101)
    raw[producer+0x90:producer+0x98]=b' (\0\0)\0\0\0'
    raw[sites['getter']:sites['getter']+4]=bytes.fromhex('00487047')
    record=b'model\0\0\0'+label+b'\0\0\0\0oem\0SOURCECO\0psa.version\0version.software\0'
    raw[sites['record']:sites['record']+len(record)]=record
    struct.pack_into('<I',raw,sites['getter']+4,sites['record']+8)
    bl(sites['caller'],sites['getter']);raw[sites['caller']+4:sites['caller']+6]=bytes.fromhex('1190')
    bl(sites['caller']+6,sites['strlen']);raw[sites['caller']+10:sites['caller']+12]=bytes.fromhex('061c')
    return raw,sites


class BrowserModelIdentityTests(unittest.TestCase):
    def test_linked_browser_label_relocates_preserves_suffix_and_confidence(self):
        from msm5xxx_emulator.detection.model import _browser_product_model
        for start in (0x100,0x240,0x400):
            raw,sites=browser_fixture(start)
            self.assertEqual(_browser_product_model(bytes(raw)),
                             ('CDM-1234/T10','provisional-browser-product-constructor'))
            notes=[]
            self.assertEqual(detect_model(bytes(raw),Path('SCH-X123.bin'),notes=notes),'CDM-1234/T10')
            self.assertIsNone(verified_embedded_model(bytes(raw)))
            self.assertIn('provisional-browser-product-constructor',notes)
            notes=[]
            self.assertEqual(detect_model(bytes(raw),Path('SCH-X123.bin'),{'SCH-X777':10},notes=notes),'SCH-X123')
            self.assertIn('browser-product-strong-identity-conflict',notes)
    def test_existing_constructor_identity_keeps_priority(self):
        raw,_=browser_fixture();strong=fixture(0x3000)
        raw[0x3000:len(strong)]=strong[0x3000:]
        notes=[]
        self.assertEqual(detect_model(bytes(raw),Path('neutral.bin'),notes=notes),'LG-AB123')
        self.assertIn('browser-product-strong-identity-conflict',notes)
        raw,_=browser_fixture()
        record=b'BRAND\0X123\0MSM5000\0m_MobileType: BRAND-X123;FW'
        raw[0x5000:0x5000+len(record)]=record
        notes=[]
        self.assertEqual(detect_model(bytes(raw),Path('neutral.bin'),chipset='MSM5000',notes=notes),'BRAND-X123')
        self.assertIn('browser-product-strong-identity-conflict',notes)
    def test_raw_record_missing_or_foreign_callee_and_caller_reject(self):
        from msm5xxx_emulator.detection.model import _browser_product_model
        raw,sites=browser_fixture()
        self.assertIsNone(_browser_product_model(bytes(raw[sites['record']:]))[0])
        shifted,_=browser_fixture(0x122)
        self.assertIsNone(_browser_product_model(bytes(shifted))[0])
        for at in (sites['producer']-0xc,sites['producer']-0x17,sites['getter'],sites['getter']+2,sites['append'],sites['append']+24,
                   sites['span']+46,sites['init']+44,sites['strlen']+0x48,
                   sites['caller']+4,sites['caller']+6,sites['caller']+10,
                   sites['producer']+0x40,sites['producer']+0x8e,sites['producer']+0x90,
                   sites['record'],sites['record']+16,sites['getter']+4):
            changed=bytearray(raw);changed[at]^=1
            with self.subTest(at=at):self.assertIsNone(_browser_product_model(bytes(changed))[0])
        for key in ('getter','append','init','span','strlen','stub'):
            changed=bytearray(raw);at=sites[key];changed[at:at+4]=b'\xff'*4
            self.assertIsNone(_browser_product_model(bytes(changed))[0])
        from msm5xxx_emulator.detection.model import _BROWSER_BODIES
        for kind,(_,offsets) in _BROWSER_BODIES.items():
            for offset in offsets:
                changed=bytearray(raw);pc=sites[kind]+offset;delta=0x10000-pc-4
                struct.pack_into('<HH',changed,pc,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
                with self.subTest(kind=kind,call=offset):self.assertIsNone(_browser_product_model(bytes(changed))[0])
        for end in (sites['producer']+0x80,sites['getter']+7,sites['record']+20):
            self.assertIsNone(_browser_product_model(bytes(raw[:end]))[0])
    def test_every_fixed_producer_and_builder_halfword_and_duplicate_reject(self):
        from msm5xxx_emulator.detection.model import _browser_product_model,_BROWSER_BODIES
        raw,sites=browser_fixture()
        for kind,(encoded,calls) in _BROWSER_BODIES.items():
            variable={i for offset in calls for i in range(offset,offset+4)}
            for offset in range(0,len(bytes.fromhex(encoded)),2):
                if offset in variable:continue
                changed=bytearray(raw);changed[sites[kind]+offset]^=1
                with self.subTest(kind=kind,offset=offset):self.assertIsNone(_browser_product_model(bytes(changed))[0])
        other,_=browser_fixture(0x3000,label=b'CDM-5678/T20')
        raw[0x3000-0x18:]=other[0x3000-0x18:]
        self.assertEqual(_browser_product_model(bytes(raw)),(None,'browser-product-ambiguous'))


def adr_browser_fixture(start=0x100, label=b'XYZ-1234/T10'):
    from msm5xxx_emulator.detection.model import _BROWSER_ADR_BODIES, _BROWSER_LENGTH_FRAME
    raw=bytearray(b'\xff'*(start+0x2000))
    sites={kind:start+offset for kind,offset in
           (('producer',0),('getter',0x400),('append',0x500),('span',0x600),
            ('init',0x700),('strlen',0x800),('frame',0xa00),('record',0x1000),
            ('version',0x1200),('build',0x1300),('stub',0x1800))}
    sites['caller']=sites['frame']+0x160
    def bl(pc,target):
        delta=target-pc-4
        struct.pack_into('<HH',raw,pc,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
    raw[sites['stub']:sites['stub']+4]=bytes.fromhex('80b57047')
    for kind,(body,calls)in _BROWSER_ADR_BODIES.items():
        at=sites[kind];data=bytes.fromhex(body);raw[at:at+len(data)]=data
        for offset in calls:bl(at+offset,sites['stub'])
    at=sites['producer']
    bl(at+0xe,sites['init'])
    for offset in(0x16,0x28,0x34,0x3c,0x48,0x50):bl(at+offset,sites['append'])
    bl(at+0x40,sites['getter']);bl(sites['append']+8,sites['strlen']);bl(sites['append']+0x12,sites['span'])
    struct.pack_into('<I',raw,sites['strlen']+0x48,0x01010101)
    for pool,value in((0x90,sites['version']),(0xa0,sites['build']),(0xa8,0x500c)):
        struct.pack_into('<I',raw,at+pool,value)
    raw[at+0x94:at+0xa0]=b' (\0\0)\0\0\0v\0\0\0';raw[at+0xa4:at+0xa8]=b'i\0\0\0'
    raw[sites['version']:sites['version']+12]=b'7.2.1 (GUI)\0'
    raw[sites['build']:sites['build']+22]=b'Built on sample build\0'
    raw[sites['getter']:sites['getter']+4]=bytes.fromhex('00a07047')
    raw[sites['getter']+4:sites['getter']+5+len(label)]=label+b'\0'
    record=b'model\0\0\0'+label+b'\0\0\0\0oem\0SOURCECO\0psa.version\0version.software\0'
    raw[sites['record']:sites['record']+len(record)]=record
    raw[sites['frame']:sites['frame']+len(_BROWSER_LENGTH_FRAME)]=_BROWSER_LENGTH_FRAME
    bl(sites['caller'],sites['getter']);raw[sites['caller']+4:sites['caller']+8]=bytes.fromhex('11901198')
    bl(sites['caller']+8,sites['strlen']);raw[sites['caller']+12:sites['caller']+16]=bytes.fromhex('05042d14')
    return raw,sites


class ADRBrowserIdentityTests(unittest.TestCase):
    def test_relocated_neutral_and_generic_label_is_only_provisional(self):
        from msm5xxx_emulator.detection.model import _browser_product_model
        for start,label in((0x100,b'XYZ-1234/T10'),(0x400,b'ABC-4321/T20')):
            raw,_=adr_browser_fixture(start,label)
            self.assertEqual(_browser_product_model(bytes(raw)),(label.decode(),'provisional-browser-product-adr-constructor'))
            for filename in('neutral.bin','SCH-X123.bin','renamed.bin'):
                self.assertEqual(detect_model(bytes(raw),Path(filename)),label.decode())
            self.assertIsNone(verified_embedded_model(bytes(raw)))
            notes=[]
            self.assertEqual(detect_model(bytes(raw),Path('SCH-X123.bin'),{'SCH-X777':10},notes=notes),'SCH-X123')
            self.assertIn('browser-product-strong-identity-conflict',notes)
    def test_fixed_bodies_calls_getter_record_frame_and_bounds_fail_closed(self):
        from msm5xxx_emulator.detection.model import _BROWSER_ADR_BODIES,_browser_product_model
        raw,sites=adr_browser_fixture()
        for kind,(body,calls)in _BROWSER_ADR_BODIES.items():
            variable={i for offset in calls for i in range(offset,offset+4)}
            for offset in range(0,len(bytes.fromhex(body)),2):
                if offset in variable:continue
                changed=bytearray(raw);changed[sites[kind]+offset]^=1
                with self.subTest(kind=kind,offset=offset):self.assertIsNone(_browser_product_model(bytes(changed))[0])
            for offset in calls:
                changed=bytearray(raw);pc=sites[kind]+offset;delta=0x10000-pc-4
                struct.pack_into('<HH',changed,pc,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
                self.assertIsNone(_browser_product_model(bytes(changed))[0])
        for at in(sites['getter'],sites['getter']+2,sites['getter']+4,
                  sites['record'],sites['record']+8,sites['caller']+4,sites['caller']+6,
                  sites['caller']+8,sites['caller']+12,sites['caller']+14,
                  sites['frame']+2,sites['frame']+20,sites['producer']+0x94,
                  sites['producer']+0xa4,sites['producer']+0xa8):
            changed=bytearray(raw);changed[at]^=1
            with self.subTest(at=at):self.assertIsNone(_browser_product_model(bytes(changed))[0])
        for end in(sites['producer']+0x8d,sites['getter']+10,sites['record']+20,sites['version']+5):
            self.assertIsNone(_browser_product_model(bytes(raw[:end]))[0])
    def test_duplicate_foreign_record_and_mixed_classes_are_ambiguous(self):
        from msm5xxx_emulator.detection.model import _browser_product_model
        raw,sites=adr_browser_fixture()
        record=raw[sites['record']:sites['record']+80]
        changed=bytearray(raw);changed[sites['record']+0x100:sites['record']+0x150]=record
        self.assertIsNone(_browser_product_model(bytes(changed))[0])
        changed=bytearray(raw);changed[sites['record']+8:sites['record']+20]=b'ABC-9876/T20'
        self.assertIsNone(_browser_product_model(bytes(changed))[0])
        other,_=adr_browser_fixture(0x3000,b'ABC-4321/T20');raw.extend(b'\xff'*(len(other)-len(raw)));raw[0x3000:]=other[0x3000:]
        self.assertEqual(_browser_product_model(bytes(raw)),(None,'browser-product-ambiguous'))
        literal,_=browser_fixture();adr,_=adr_browser_fixture(0x3000);mixed=bytearray(adr);mixed[:0x2800]=literal[:0x2800]
        self.assertEqual(_browser_product_model(bytes(mixed)),(None,'browser-product-ambiguous'))
        # A partial new prefix cannot veto a complete existing literal class.
        partial=bytearray(literal);partial[0x5000:0x500e]=adr[0x3000:0x300e]
        self.assertEqual(_browser_product_model(bytes(partial))[0],'CDM-1234/T10')
    def test_two_supplied_full_and_partial_labels_only(self):
        import hashlib
        from msm5xxx_emulator.detection.model import _browser_product_model
        root=Path(__file__).resolve().parents[1]/'firmwares'
        cases=[('incoming-20260719-r1/MSM5100/T055BW1T19_1.242_JTAG.bin','24bf05931ac81cce005b1ad5e970e061b38daf25ea3d70f658e2fa66fb801491'),
               ('incoming-msm5xxx-candidates-20260726/Audiovox/CDM-8600/T055BM1T16_2.242_Memory/T055BM1T16_2.242_Memory.bin','3ce5fac1b66816972a11236f239d62207dd584f067c809a44922631e0cbd8753')]
        for relative,digest in cases:
            path=root/relative
            if not path.exists():self.skipTest('private supplied control unavailable')
            before=path.stat();raw=path.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
            self.assertEqual(_browser_product_model(raw),('CDM-8600/T10','provisional-browser-product-adr-constructor'))
            self.assertEqual(detect_model(raw,Path('neutral.bin')),'CDM-8600/T10')
            self.assertIsNone(verified_embedded_model(raw))
            self.assertEqual(path.stat().st_mtime_ns,before.st_mtime_ns)
    def test_old_literal_getter_still_requires_record_pointer_identity(self):
        from msm5xxx_emulator.detection.model import _browser_product_model
        raw,sites=browser_fixture();copy_at=0x5f00
        raw[copy_at:copy_at+13]=b'CDM-1234/T10\0'
        from msm5xxx_emulator.detection.arm import thumb_bl_target
        getter=thumb_bl_target(raw,sites['producer']+0x3c)
        struct.pack_into('<I',raw,getter+4,copy_at)
        self.assertIsNone(_browser_product_model(bytes(raw))[0])


if __name__ == '__main__':
    unittest.main()
