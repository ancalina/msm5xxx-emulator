"""Synthetic entry-return provenance checks for startup copy consumers."""
import struct
import unittest

from nor_fixtures import copy_consumer_fixture
from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.startup_facts import proven_startup_rows
from msm5xxx_emulator.detection.startup_entry import startup_load_operations


class StartupReturnTests(unittest.TestCase):
    def test_no_effect_helper_call_preserves_entry_return(self):
        entry = CodeAddress(0x100, 'thumb')
        image, _ = copy_consumer_fixture(saved_lr_call=True)
        facts = FirmwareFacts(image)
        found = proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),),
            initial_sp=0x8004)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0][1].procedure.helper_code_spans)
        image, _ = copy_consumer_fixture(outside_call=True)
        self.assertEqual(proven_startup_rows(
            FirmwareFacts(image), entry, target_ranges=((0x1000, 0x2000),),
            initial_sp=0x8004), ())
        image, _ = copy_consumer_fixture(
            saved_lr_call=True, overwrite_saved_lr=True)
        self.assertEqual(proven_startup_rows(
            FirmwareFacts(image), entry, target_ranges=((0x1000, 0x2000),),
            initial_sp=0x8004), ())

    def test_zeroed_entry_return_slot_rejects_only_full_procedure_claim(self):
        entry = CodeAddress(0x100, 'thumb')
        image, _ = copy_consumer_fixture(saved_lr_call=True)
        facts = FirmwareFacts(image)
        options = dict(target_ranges=((0x1000, 0x2000),), initial_sp=0x1048)
        self.assertEqual(proven_startup_rows(facts, entry, **options), ())

        call, _ = facts.function(entry).calls[0]
        prefix = proven_startup_rows(
            facts, entry, completion=call, **options)
        self.assertEqual(len(prefix), 1)
        view = facts.after_loads(
            startup_load_operations(prefix, completion=call),
            phase='copy-complete').view
        self.assertEqual(view.read(0x1044, 4, phase='copy-complete'), bytes(4))

        unaffected = proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),),
            initial_sp=0x8004)
        self.assertEqual(len(unaffected), 1)

    def test_call_free_leaf_requires_entry_lr_at_bx_lr(self):
        entry = CodeAddress(0x100, 'thumb')
        image, _ = copy_consumer_fixture(
            outside_store_address=0x03000620)
        options = dict(target_ranges=((0x1000, 0x2000),),
                       extra_write_ranges=((0x03000600, 0x03000780),))
        facts = FirmwareFacts(image)
        self.assertEqual(len(proven_startup_rows(facts, entry, **options)), 1)

        function = facts.function(entry, symbolic_registers={})
        clobber = next(
            pc for pc in function.instructions
            if facts.decode(pc).mnemonic == 'movs'
            and facts.decode(pc).op_str == 'r6, #1')
        changed = bytearray(image)
        struct.pack_into('<H', changed, clobber.address, 0x4686)  # MOV LR,R0
        mutated = FirmwareFacts(bytes(changed))
        self.assertEqual(proven_startup_rows(mutated, entry, **options), ())

