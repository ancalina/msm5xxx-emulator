"""Synthetic checks for bounded instruction probes and unchanged code views."""
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.external_bus.signal_memory import _upload_protocols
from msm5xxx_emulator.detection.devices.external_bus.signal_flat_memory import _parser_candidate
from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.image_view import ImageView, LoadOperation


def signature(instruction):
    return (instruction.id, instruction.address, instruction.size,
            bytes(instruction.bytes), instruction.mnemonic, instruction.op_str,
            instruction.groups, instruction.regs_access())


class TransientDecodeTests(unittest.TestCase):
    def test_transient_arm_and_thumb_reads_preserve_decoding_and_cached_identity(self):
        image = struct.pack('<4H2I', 0xB510, 0x2900, 0xD000, 0xBD10,
                            0xE3A00001, 0xE12FFF1E)
        reference, probes = FirmwareFacts(image), FirmwareFacts(image)
        for pc in (CodeAddress(0), CodeAddress(2), CodeAddress(8, 'arm')):
            expected = reference.decode(pc)
            for _ in range(8):
                self.assertEqual(signature(probes.decode(pc, cache=False)),
                                 signature(expected))
        self.assertEqual(probes._decoded, {})
        cached = probes.decode(CodeAddress(0))
        self.assertIs(probes.decode(CodeAddress(0), cache=False), cached)
        self.assertEqual(len(probes._decoded), 1)

    def test_transient_reads_keep_phase_bank_hole_and_alignment_guards(self):
        image = struct.pack('<2H', 0x2001, 0x4770)
        facts = FirmwareFacts(b'', view=ImageView.sparse(((0x1000, image),))).after_loads((
            LoadOperation('copy', 0x1000, 0x8000, 4, (0x20,)),
        ))
        copied = CodeAddress(0x8000, phase='post-copy')
        self.assertEqual(facts.decode(copied, cache=False).mnemonic, 'movs')
        for absent in (CodeAddress(0x1004), CodeAddress(0x8000),
                       CodeAddress(0x8001, phase='post-copy'),
                       CodeAddress(0x8000, phase='post-copy', bank='other'),
                       CodeAddress(0x1002, 'arm')):
            self.assertIsNone(facts.decode(absent, cache=False))
        self.assertEqual(facts._decoded, {})
        body = facts.function(copied, budget=8)
        self.assertTrue(body.complete)
        self.assertEqual(body.instructions,
                         (copied, CodeAddress(0x8002, phase='post-copy')))

    def test_rejected_upload_candidates_do_not_retain_instruction_details(self):
        facts = FirmwareFacts(struct.pack('<H', 0x46C0) * 1024)
        targets = tuple(range(0x20, 0x420, 0x10))
        with patch.object(facts, 'call_candidates',
                          return_value=tuple((0, target) for target in targets)):
            self.assertEqual(_upload_protocols(facts), [])
        for target in targets:
            self.assertFalse(_parser_candidate(facts, target))
        self.assertEqual(facts._decoded, {})


if __name__ == '__main__':
    unittest.main()
