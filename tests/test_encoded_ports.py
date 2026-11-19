"""Synthetic instruction and table fixtures for encoded port keypads."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.input.encoded_ports import (
    _active_low_contact,
    _event_triplets,
    _helper_profiles,
    _producer_callback,
    encoded_ports_property,
)
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


def _put16(image: bytearray, address: int, value: int) -> None:
    struct.pack_into("<H", image, address, value)


def _put32(image: bytearray, address: int, value: int) -> None:
    struct.pack_into("<I", image, address, value)


def _bl(image: bytearray, site: int, target: int) -> None:
    delta = target - site - 4
    _put16(image, site, 0xF000 | ((delta >> 12) & 0x7FF))
    _put16(image, site + 2, 0xF800 | ((delta >> 1) & 0x7FF))


def _b16(site: int, target: int, condition: int | None = None) -> int:
    delta = target - site - 4
    assert delta % 2 == 0 and -256 <= delta // 2 <= 255
    return ((0xD000 | (condition << 8) | ((delta // 2) & 0xFF))
            if condition is not None else 0xE000 | ((delta // 2) & 0x7FF))


def _low_contact_image(event: int = 0x55) -> bytearray:
    image = bytearray(0x200)
    _put16(image, 0x20, _b16(0x20, 0x60, 1))  # BNE high/numeric decode.
    _put16(image, 0x22, 0x46C0)               # NOP on low-contact path.
    _put16(image, 0x24, 0x2700 | event)       # MOVS R7, #separate event.
    _put16(image, 0x26, _b16(0x26, 0x40))     # B common dispatcher.
    # Dispatcher state read and R7 event check, then event forwarded in R1.
    for address, word in ((0x40, 0x7898), (0x42, 0x2801), (0x44, 0x2802),
                          (0x46, 0x2803), (0x48, 0x2F00), (0x4A, 0x1C39),
                          (0x50, 0x4770)):
        _put16(image, address, word)
    _bl(image, 0x4C, 0x180)
    _put16(image, 0x180, 0x4778)              # Thumb BX PC.
    _put32(image, 0x184, 0xE51FF004)          # ARM LDR PC, [PC, #-4].
    _put16(image, 0x60, 0x2001)               # Separate numeric branch target.
    _put16(image, 0x62, 0x4770)
    return image


def _literal_load(image: bytearray, site: int, register: int, pool: int) -> None:
    displacement = pool - ((site + 4) & ~3)
    assert 0 <= displacement <= 1020 and displacement % 4 == 0
    _put16(image, site, 0x4800 | (register << 8) | (displacement // 4))


def _helper_image() -> bytearray:
    image = bytearray(0x500)
    helper, pool, descriptor = 0x100, 0x180, 0x01000100
    # LDR r0, [pc, #literal]; linked p24/p34 halfword mask and pack.
    _literal_load(image, helper, 0, pool)
    words = (0x6A41, 0x8809, 0x231E, 0x4019, 0x6B40, 0x0109,
             0x227F, 0x8800, 0x0252, 0x4311, 0x06C0, 0x0EC0,
             0x4308, 0x4770)
    for index, word in enumerate(words):
        _put16(image, helper + 2 + index * 2, word)
    _put32(image, pool, descriptor)
    return image


def _producer_image() -> bytearray:
    image = bytearray(0x500)
    producer, stub = 0x100, 0x300
    # Event-preserving callback route: enable byte, callback pointer, argument,
    # then a direct call to a BX R1 dispatch stub.
    words = (0xB5B8, 0x1C07, 0x4800, 0x4D00, 0x7800, 0x2800,
             0xD00A, 0x6B29, 0x2900, 0xD007, 0xAB00, 0x701F,
             0x9800)
    for index, word in enumerate(words):
        _put16(image, producer + 2 * index, word)
    _literal_load(image, producer + 4, 0, 0x200)
    _literal_load(image, producer + 6, 5, 0x204)
    _put32(image, 0x200, 0x01000200)
    _put32(image, 0x204, 0x01000220)
    _bl(image, producer + 0x1A, stub)
    _put16(image, producer + 0x1E, _b16(producer + 0x1E, producer + 0x24))
    _put16(image, producer + 0x24, 0xBDB8)  # POP saved registers and entry PC.
    _put16(image, stub, 0x4708)  # BX R1
    return image


def _triplets() -> tuple[tuple[int, int, int], ...]:
    keys = b"123456789*0#"
    tokens = list(keys) + [1, 2, 3, 4, 5, 6, 7]
    # Synthetic codes are generated independently of any firmware table.
    codes = [((0x31 + 13 * index) & 0xFF) for index in range(19)]
    identities = [((index * 7 + 5) & 0xFF) for index in range(19)]
    return tuple((identity, code, token)
                 for identity, code, token in zip(identities, codes, tokens))


class EncodedPortsTests(unittest.TestCase):
    def test_low_contact_event_is_separate_from_numeric_key_lookup(self):
        image = _low_contact_image()
        facts = facts_for(image)
        region = facts.function(CodeAddress(0x22, "thumb"), budget=128)
        gate = facts.decode(CodeAddress(0x20, "thumb"))
        evidence = _active_low_contact(facts, region, gate, 0x60,
                                       {ord(key) for key in "123456789*0#"})
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["event"], 0x55)
        self.assertEqual(evidence["event_site"], 0x24)
        self.assertEqual(evidence["dispatch_entry"], 0x40)
        self.assertEqual(evidence["dispatch_site"], 0x4C)
        self.assertEqual(evidence["dispatch_stub"], 0x180)

        # A numeric ASCII key is not an independent contact event; removing
        # the R7-to-R1 handoff also closes the source-to-dispatch proof.
        numeric = _low_contact_image(ord("1"))
        numeric_facts = facts_for(numeric)
        numeric_region = numeric_facts.function(CodeAddress(0x22, "thumb"), budget=128)
        numeric_gate = numeric_facts.decode(CodeAddress(0x20, "thumb"))
        self.assertIsNone(_active_low_contact(numeric_facts, numeric_region,
            numeric_gate, 0x60, {ord(key) for key in "123456789*0#"}))

        changed = bytearray(image)
        _put16(changed, 0x4A, 0x2100)          # MOVS R1, #0, no event forwarding.
        changed_facts = facts_for(changed)
        changed_region = changed_facts.function(CodeAddress(0x22, "thumb"), budget=128)
        changed_gate = changed_facts.decode(CodeAddress(0x20, "thumb"))
        self.assertIsNone(_active_low_contact(changed_facts, changed_region,
            changed_gate, 0x60, {ord(key) for key in "123456789*0#"}))

    def test_helper_requires_live_literal_and_full_pack_grammar(self):
        image = _helper_image()
        facts = facts_for(image)
        profile = _helper_profiles(image, facts)
        self.assertEqual(len(profile), 1)
        self.assertEqual(profile[0]["descriptor"], 0x01000100)
        self.assertEqual(profile[0]["helper_code"], (0x100, 30))

        mutated = bytearray(image)
        _put16(mutated, 0x100 + 2 + 4 * 2, 0x231F)
        self.assertEqual(_helper_profiles(mutated, facts_for(mutated)), [])

    def test_triplets_cover_all_keys_with_unique_synthetic_identities(self):
        image = bytearray(0x200)
        table = 0x80
        records = _triplets()
        image[table:table + 57] = bytes(value for row in records for value in row)
        parsed = _event_triplets(image, table)
        self.assertIsNotNone(parsed)
        self.assertEqual(set(parsed["key_to_code"]), set("123456789*0#"))
        self.assertEqual(len(set(parsed["key_to_code"].values())), 12)
        self.assertEqual(parsed["records"], list(records))

        duplicate = bytearray(image)
        duplicate[table + 3 + 1] = duplicate[table + 1]
        self.assertIsNone(_event_triplets(duplicate, table))

    def test_callback_dispatch_requires_direct_bx_r1_target(self):
        image = _producer_image()
        facts = facts_for(image)
        evidence = _producer_callback(image, facts, 0x100)
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["stub"], 0x300)
        self.assertIn((0x100, 0x1E), evidence["dependencies"])
        self.assertIn((0x300, 2), evidence["dependencies"])

        _put16(image, 0x300, 0x4710)  # BX R2 is not the callback in R1.
        self.assertIsNone(_producer_callback(image, facts_for(image), 0x100))

    def test_property_rejects_without_reset_linked_full_descriptor_copy(self):
        image = bytes(0x1000)
        profile = {
            "descriptor": 0x01000100,
            "descriptor_sources": [0x200],
            "dependencies": [(0x200, 0x38), (0x400, 2)],
            "producer_state_ranges": ((0x01000200, 1), (0x01000250, 4)),
        }
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x1000, flash_size=len(image))
        with patch("msm5xxx_emulator.detection.devices.input.encoded_ports.find_encoded_port_profiles",
                   return_value=[profile]):
            property_value, admitted = encoded_ports_property(image, config)
        self.assertIsNone(property_value)
        self.assertIsNone(admitted)

    def test_admitted_property_includes_both_live_poller_reads(self):
        image = bytes(0x1000)
        profile = {
            "descriptor": 0x01000100,
            "descriptor_sources": [0x200],
            "dependencies": [(0x200, 0x38), (0x400, 2)],
            "producer_state_ranges": ((0x01000200, 1), (0x01000250, 4)),
            "row_read_site": 0x300,
            "sense_read_site": 0x310,
            "presence_site": 0x320,
            "packed_row_read_site": 0x330,
            "packed_sense_read_site": 0x340,
            "aux_read_site": 0x350,
        }
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                 ram_size=0x1000, flash_size=len(image))

        class CopyProof:
            evidence = ()

            @staticmethod
            def source_address(address, size):
                return 0x200 if (address, size) == (0x01000100, 0x38) else None

        with (patch("msm5xxx_emulator.detection.devices.input.encoded_ports.find_encoded_port_profiles",
                    return_value=[profile]),
              patch("msm5xxx_emulator.detection.devices.input.encoded_ports.reset_linked_input_copy",
                    return_value=CopyProof()) as reset_copy):
            property_value, admitted = encoded_ports_property(image, config)
        self.assertEqual(property_value,
                         "matrix-encoded-ports=1000100:300:310:320:330:340:350")
        self.assertIsNotNone(admitted)
        reset_copy.assert_called_once_with(image, ((0x01000100, 0x38),),
            ram_base=0x01000000, ram_size=0x1000, flash_size=len(image))

        # Both callback state accesses must fit the actual configured RAM,
        # including the whole word loaded through the control structure.
        for ranges in ((), ((0x01800000, 1), (0x01800050, 4)),
                       ((0x00ffffff, 1), (0x01000250, 4)),
                       ((0x01000200, 1), (0x01000ffe, 4))):
            with self.subTest(ranges=ranges):
                candidate = dict(profile, producer_state_ranges=ranges)
                with (patch("msm5xxx_emulator.detection.devices.input.encoded_ports.find_encoded_port_profiles",
                            return_value=[candidate]),
                      patch("msm5xxx_emulator.detection.devices.input.encoded_ports.reset_linked_input_copy",
                            return_value=CopyProof()) as reset_copy):
                    self.assertEqual(encoded_ports_property(image, config), (None, None))
                reset_copy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
