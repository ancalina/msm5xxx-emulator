"""Shared reset-copy composition keeps existing proofs and bounds."""
from unittest.mock import patch
import unittest

from msm5xxx_emulator.detection.startup_block_copy import ResetLinkedBlockCopy
from msm5xxx_emulator.detection.startup_reset_copy import reset_linked_copy
from test_sparse_rows import _linked_copy_reset_fixture


class StartupCopyCompositionTests(unittest.TestCase):
    def setUp(self):
        self.image = bytes(_linked_copy_reset_fixture())
        self.options = dict(ram_base=0x01000000, ram_size=0x800000,
                            flash_size=len(self.image))
        self.copy = ResetLinkedBlockCopy(0x3000, 0x01010000, 20,
                                        ((0x100, 4), (0x3000, 40)), 40)

    def test_completed_block_extent_covers_requested_initialized_data(self):
        with patch("msm5xxx_emulator.detection.startup_block_copy.reset_linked_block_copies",
                   return_value=(self.copy,)):
            copy = reset_linked_copy(self.image, ((0x01010018, 8),), **self.options)
        self.assertIsNotNone(copy)
        self.assertEqual(copy.size, 40)
        self.assertEqual(copy.source_address(0x01010018, 8), 0x3018)

    def test_existing_copy_proof_does_not_borrow_a_new_route(self):
        with patch("msm5xxx_emulator.detection.startup_block_copy.reset_linked_block_copies",
                   side_effect=AssertionError("existing copy must retain precedence")):
            copy = reset_linked_copy(self.image, ((0x01000100, 0x38),), **self.options)
        self.assertEqual(copy.source_address(0x01000100, 0x38), 0x1100)

    def test_wrapped_route_only_follows_empty_earlier_routes(self):
        with patch("msm5xxx_emulator.detection.startup_block_copy.reset_linked_block_copies",
                   return_value=()), patch(
                "msm5xxx_emulator.detection.startup_wrapped_copy.reset_linked_wrapped_copies",
                return_value=(self.copy,)):
            copy = reset_linked_copy(self.image, ((0x01010018, 8),), **self.options)
        self.assertEqual(copy.source_address(0x01010018, 8), 0x3018)
        with patch("msm5xxx_emulator.detection.startup_block_copy.reset_linked_block_copies",
                   return_value=(self.copy,)), patch(
                "msm5xxx_emulator.detection.startup_wrapped_copy.reset_linked_wrapped_copies",
                side_effect=AssertionError("accepted block route retains precedence")):
            self.assertIsNotNone(reset_linked_copy(
                self.image, ((0x01010018, 8),), **self.options))

    def test_ambiguous_or_unbounded_completed_copies_do_not_map_bytes(self):
        alternatives = (
            (self.copy, ResetLinkedBlockCopy(0x3100, self.copy.target, 40, ((0x3100, 40),))),
            (ResetLinkedBlockCopy(len(self.image) - 4, self.copy.target, 40,
                                  ((0x100, 4),)),),
            (ResetLinkedBlockCopy(self.copy.source, 0x017ffff0, 40, ((0x100, 4),)),),
        )
        for copies in alternatives:
            with self.subTest(copies=copies), patch(
                    "msm5xxx_emulator.detection.startup_block_copy.reset_linked_block_copies",
                    return_value=copies):
                self.assertIsNone(reset_linked_copy(self.image, ((0x01010018, 8),),
                                                    **self.options))
