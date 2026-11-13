"""Synthetic checks for source-linked flat catalog selection."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.external_bus import signal_flat_selector as selector
from msm5xxx_emulator.detection.facts import CodeAddress


class _Facts:
    def call_candidates(self, _mode):
        return ((0x180, 0x200),)

    def literal(self, address):
        return SimpleNamespace(pool=address, value=0x40)


def _binding_case(*, array_address=0x14000000, count=3,
                  linked_field=0x14, consumer_field=0x14,
                  second_consumer_field=0x18):
    image = bytearray(0x300)
    struct.pack_into('<I', image, 0x44, 0x80)  # input record -> selector
    struct.pack_into('<III', image, 0x80, 0, count, array_address)
    pointers = (0x180, 0x190, 0x1A0)
    for index, pointer in enumerate(pointers):
        struct.pack_into('<I', image, 0x100 + index * 4, pointer)
    parsed = {
        0x14: {'intervals': [(0x08000000, 0x08000002)], 'unit': 2},
        0x18: {'intervals': [(0x08800000, 0x08800004)], 'unit': 4},
    }
    fields = linked_field if isinstance(linked_field, tuple) else (linked_field,)
    records = [(pointer, [(field, 0x220 + index * 8 + offset,
                           parsed.get(field, parsed[0x14]))
                          for offset, field in enumerate(fields)])
               for index, pointer in enumerate(pointers)]
    region = {'kind': 'rw-copy', 'load': 0x100, 'size': 12,
              'exec': 0x14000000,
              'evidence': {'table_offset': 0x20, 'references': []}}
    catalog = {'span': [0x100, 12], 'records': records, 'region': region}
    consumer_body = SimpleNamespace(entry=CodeAddress(0x200, 'thumb'))
    second_body = SimpleNamespace(entry=CodeAddress(0x240, 'thumb'))
    consumers = [{'caller_body': consumer_body, 'field': consumer_field},
                 {'caller_body': second_body,
                  'field': second_consumer_field}]
    selector_body = SimpleNamespace(entry=CodeAddress(0x180, 'thumb'),
                                    instructions=(), literals=())
    input_body = SimpleNamespace(entry=CodeAddress(0x40, 'thumb'),
                                 instructions=(), literals=())
    shape = {'consumer_entry': 0x200, 'consumer_entries': [0x200, 0x240],
             'selector_field': 4}
    return (bytes(image), catalog, consumers, selector_body, input_body, shape)


class FlatSelectorTests(unittest.TestCase):
    def _bind(self, *, array_address=0x14000000, count=3,
              linked_field=(0x14, 0x18), consumer_field=0x14,
              second_consumer_field=0x18):
        image, catalog, consumers, selector_body, input_body, shape = \
            _binding_case(array_address=array_address, count=count,
                          linked_field=linked_field,
                          consumer_field=consumer_field,
                          second_consumer_field=second_consumer_field)
        with (patch.object(selector, '_owners', return_value=(selector_body,)),
              patch.object(selector, '_selector_shape', return_value=shape),
              patch.object(selector, '_copied_input',
                           return_value=((0x40, input_body, 0x24),))):
            result = selector.bind_flat_catalogs(
                image, _Facts(), {'regions': [catalog['region']]},
                [catalog], consumers)
        return result

    def test_matching_linked_catalog_is_bound_to_consumer_fields(self):
        result = self._bind()
        self.assertIsNotNone(result)
        self.assertEqual(result['runtime_base'], 0x14000000)
        self.assertEqual(result['records'], [0x180, 0x190, 0x1A0])
        self.assertEqual(result['consumer_entry'], 0x200)
        self.assertEqual(result['consumer_entries'], [0x200, 0x240])
        self.assertEqual(result['consumer_fields'], [0x14, 0x18])

    def test_pointer_array_and_count_must_match_reset_copy(self):
        self.assertIsNone(self._bind(array_address=0x14000004))
        self.assertIsNone(self._bind(count=2))

    def test_catalog_records_must_link_to_consumed_parser_field(self):
        self.assertIsNone(self._bind(linked_field=0x1C))
        self.assertIsNone(self._bind(consumer_field=0x20,
                                    second_consumer_field=0x24))


if __name__ == '__main__':
    unittest.main()
