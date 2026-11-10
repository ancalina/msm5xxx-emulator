"""Synthetic registered-rule tests for the legacy NV bank selector."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.facts import CodeAddress, ScatterCandidate
from msm5xxx_emulator.detection.registry import device_domain
NORDeviceProfile = device_domain('storage.nor_protocol').NORDeviceProfile
NORHardwareEvidence = device_domain('storage.nor_protocol').NORHardwareEvidence
NORWrite = device_domain('storage.nor_protocol').NORWrite
from msm5xxx_emulator.detection.registry import device_domain
select_legacy_nv_nor = device_domain('storage.nv_nor').select_legacy_nv_nor
from msm5xxx_emulator.detection.registry import device_domain
ByteNORProof = device_domain('storage.nv_nor_byte').ByteNORProof
from msm5xxx_emulator.detection.registry import device_domain
WordNORDescriptor = device_domain('storage.nv_nor_word').WordNORDescriptor
WordNORProof = device_domain('storage.nv_nor_word').WordNORProof
from msm5xxx_emulator.detection.startup_facts import (
    CopyConsumerProof, CopyLoopTransfer, OrderedCopyTransfer,
    ResetPrefixProof, VectorCopyRow,
)


def config(**changes):
    fields = dict(load_address=0, flash_size=0x400000,
                  ram_base=0x01000000, ram_size=0x00800000,
                  secondary_flash_address=None,
                  secondary_flash_write_address=None,
                  secondary_flash_image=None, upper_flash_address=None,
                  nand_image=None, native_nand_profile=None,
                  primary_flash_probe_address=None, flash_id_address=None)
    fields.update(changes)
    return SimpleNamespace(**fields)


def word_proof():
    callbacks = tuple((name, CodeAddress(0x500 + index * 0x20, 'thumb'))
                      for index, name in enumerate(('read', 'program', 'erase', 'status')))
    descriptor = WordNORDescriptor(0x800, 0x400000, 0x200000, 0x100000,
                                  0x10000, 4, 0x225F, callbacks)
    copy = VectorCopyRow(0x100, 0x200, 0x1000000, 0x100, 0x1000100, 0x300)
    transfer = OrderedCopyTransfer(
        CodeAddress(0x320, 'thumb'),
        (
            CopyLoopTransfer((0x340, 0x330), CodeAddress(0x330, 'thumb'),
                             70, 71, 0x1000000, 0x1000080, 4, 32,
                             0x1000080, 0x200, 0x280),
            CopyLoopTransfer((0x360, 0x350), CodeAddress(0x350, 'thumb'),
                             70, 71, 0x1000080, 0x1000100, 4, 32,
                             0x1000100, 0x280, 0x300),
        ),
        (
            CopyLoopTransfer((0x380, 0x370), CodeAddress(0x370, 'thumb'),
                             70, None, 0x1000100, 0x1000110, 4, 4,
                             0x1000110),
            CopyLoopTransfer((0x3A0, 0x390), CodeAddress(0x390, 'thumb'),
                             70, None, 0x1000110, 0x1000120, 4, 4,
                             0x1000120),
        ),
        ((0x200, 0x280, 0x1000000, 0x1000080),
         (0x280, 0x300, 0x1000080, 0x1000100)),
        ((0x1000100, 0x1000110), (0x1000110, 0x1000120)),
        (0x200, 0x300), (0x1000000, 0x1000100),
        (0x1000100, 0x1000120),
    )
    sites = (CodeAddress(0x600, 'thumb'), CodeAddress(0x604, 'thumb'))
    return WordNORProof((0x400000, 0x200000, 0x10000, 4, 0x225F, 0),
                        descriptor, copy, 0x1001DF8,
                        CodeAddress(0x400, 'thumb'), CodeAddress(0x420, 'thumb'),
                        CodeAddress(0x440, 'thumb'), 0x1000020, sites, sites,
                        transfer, 0x220,
                        ResetPrefixProof(CodeAddress(0x80, 'arm'),
                                         transfer.entry,
                                         CodeAddress(0x3B0, 'thumb'),
                                         CodeAddress(0x3B4, 'thumb'),
                                         CodeAddress(0x500, 'thumb')))


def byte_proof():
    consumer = CopyConsumerProof(0x100, CodeAddress(0x400, 'thumb'),
                                 (0x420, 0x410), (0x440, 0x430), ())
    profile = NORDeviceProfile(0x400000, 0x200000, 4, 95)
    callbacks = tuple((name, CodeAddress(0x500 + index * 0x20, 'thumb'))
                      for index, name in enumerate(('read', 'program', 'erase')))
    helper = CodeAddress(0x700, 'arm')
    write = NORWrite(CodeAddress(0x704, 'arm'), 0xAAA, 0xAA, 2, 15)
    hardware = NORHardwareEvidence(
        profile, callbacks, (('bypass-enter', helper), ('sector-erase', helper)),
        consumer, (('bypass-enter', (write,)), ('sector-erase', (write,))))
    row = ScatterCandidate(0x100, 0x200, 0x1000000, 0x1000,
                           0x1001000, 0x1000)
    return ByteNORProof((0x400000, 0x200000, 4, 95), row, consumer,
                        0x800, 0x1000080, 0x1000070,
                        CodeAddress(0x400, 'thumb'), callbacks,
                        (CodeAddress(0x704, 'arm'),), (0x10000,) * 14,
                        hardware)


class NVNORCapabilityTests(unittest.TestCase):
    def test_word_profile_emits_native_properties_claim_and_captured_tuple(self):
        with (patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_embedded_fujitsu_x16_nor',
                    return_value=None),
              patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_word_nv_nor_proof',
                    return_value=word_proof()),
              patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_byte_nv_nor_proof',
                    return_value=None)):
            capability = select_legacy_nv_nor(b'', config())
        self.assertIsNotNone(capability)
        properties = dict(capability.properties)
        self.assertEqual(properties['amd-adjacent-nv'], 'on')
        self.assertEqual(properties['amd-x16-nor'], '400000:200000:10000:4:225f:0')
        self.assertEqual((capability.claims[0].start, capability.claims[0].end),
                         (0x400000, 0x600000))
        self.assertEqual(dict(capability.parameters), {
            'legacy-kind': 'word-offset-uniform',
            'legacy-profile': (0x400000, 0x200000, 0x10000, 4, 0x225F, 0),
        })
        self.assertTrue(all(item.locations for item in capability.evidence))
        evidence = {item.name: item for item in capability.evidence}
        self.assertEqual(
            evidence['nv-word-copy-transfer'].value[0],
            (0x200, 0x300))
        self.assertEqual(evidence['nv-word-copy-pool'].value[4], 0x220)

    def test_byte_profile_emits_existing_fujitsu_property(self):
        with (patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_embedded_fujitsu_x16_nor',
                    return_value=None),
              patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_word_nv_nor_proof',
                    return_value=None),
              patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_byte_nv_nor_proof',
                    return_value=byte_proof())):
            capability = select_legacy_nv_nor(b'', config())
        self.assertEqual(dict(capability.properties), {
            'fujitsu-x16-nor': '400000:400000:200000:4:5f',
        })
        self.assertEqual(dict(capability.parameters)['legacy-kind'],
                         'byte-offset-boot-sectors')

    def test_two_profiles_are_ambiguous_and_owner_guards_reject(self):
        with (patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_embedded_fujitsu_x16_nor',
                    return_value=None),
              patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_word_nv_nor_proof',
                    return_value=word_proof()),
              patch('msm5xxx_emulator.detection.devices.storage.nv_nor.find_byte_nv_nor_proof',
                    return_value=byte_proof())):
            self.assertIsNone(select_legacy_nv_nor(b'', config()))
            self.assertIsNone(select_legacy_nv_nor(b'', config(), claimed=True))
            self.assertIsNone(select_legacy_nv_nor(
                b'', config(secondary_flash_address=0x400000)))


if __name__ == '__main__':
    unittest.main()
