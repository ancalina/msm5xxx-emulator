from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection import input_descriptor
from msm5xxx_emulator.detection.input_descriptor import _descriptor_mmio_provenance, _descriptor_pointer, _raw_consumer_metadata, _row_order, _row_register, _sense_roles, _table_base


class DescriptorColumnTableTests(unittest.TestCase):
    def test_descriptor_provenance_accepts_late_signed_scatter(self) -> None:
        image = bytearray(b"\xff" * 0x60000)
        scatter, source, target, descriptor = (
            0x50000, 0x58000, 0x01000000, 0x01000100,
        )
        struct.pack_into(
            "<8I", image, scatter,
            source, target, 0x1000, target + 0x1000, 0x2000,
            0x43192301, 0x43996001, 0x46F7C006,
        )
        for field, value in input_descriptor.DESCRIPTOR_MMIO_ROLES.items():
            struct.pack_into("<I", image, source + 0x100 + field, value)

        self.assertEqual(
            _descriptor_mmio_provenance(bytes(image), descriptor),
            {"kind": "validated-scatter", "source": source + 0x100,
             "scatter": scatter},
        )
        image[scatter + 20] ^= 1
        self.assertIsNone(
            _descriptor_mmio_provenance(bytes(image), descriptor)
        )

    def test_descriptor_pointer_survives_later_register_alias(self) -> None:
        image = bytearray(b"\xff" * 8)
        image[0:2] = (0x6B60).to_bytes(2, "little")  # ldr r0, [r4, #0x34]
        image[2:4] = (0x6B70).to_bytes(2, "little")  # ldr r0, [r6, #0x34]

        with patch.object(
            input_descriptor, "_last_literal",
            side_effect=lambda _image, _start, _site, register:
                0x01123400 if register == 4 else None,
        ):
            self.assertEqual(
                _descriptor_pointer(bytes(image), 0, [0, 2]),
                0x01123400,
            )

    def test_resolver_reuses_one_immutable_anchor_snapshot(self) -> None:
        seen: list[tuple[dict[str, object], ...]] = []

        def shapes(_image, _load_address, anchors):
            seen.append(anchors)
            return []

        def candidates(_image, _load_address, anchors):
            seen.append(anchors)
            return []

        anchor = {"function": 0x10}
        with (
            patch.object(input_descriptor, "find_descriptor_scan_anchors",
                         return_value=[anchor]) as scan,
            patch.object(input_descriptor, "find_descriptor_ram_scan_shapes",
                         side_effect=shapes),
            patch.object(input_descriptor,
                         "find_lg_descriptor_keypad_candidates",
                         side_effect=candidates),
        ):
            self.assertEqual(
                input_descriptor.resolve_lg_descriptor_input(b""),
                (None, "not-found", []),
            )
        scan.assert_called_once_with(b"", 0)
        self.assertEqual(len(seen), 2)
        self.assertIs(seen[0], seen[1])
        self.assertIsInstance(seen[0], tuple)
        self.assertIs(seen[0][0], anchor)

    def test_raw_consumer_metadata_requires_all_shared_edges(self) -> None:
        ring, load, enqueue, dequeue, task, dispatch = 0x018B0CE4, 0x10000000, 0x20, 0x100, 0x200, 0x300
        image = bytearray(b"\xff" * 0x500)
        # Exact regex bodies; literal/BL resolution is isolated below.
        image[enqueue:enqueue + 36] = bytes.fromhex(
            "004a04045078240c1378411cc906c90e99428018877050780130c006c00e5070")
        image[dequeue:dequeue + 40] = bytes.fromhex(
            "f0b5004c86b060782178884200000a199778000000381c06b0f0bc08bc1847")
        image[task:task + 12] = bytes.fromhex(
            "00f000f8071c00d000f000f8"
        )
        for offset, value in enumerate(b"1259"):
            image[dispatch + offset * 2:dispatch + offset * 2 + 2] = (0x2F00 | value).to_bytes(2, "little")

        def literal(_image, site, register):
            return ring if (site, register) in ((enqueue, 2), (dequeue + 2, 4)) else None
        def branch(_image, site):
            return dequeue if site in (task, task + 0x20) else dispatch if site in (task + 8, task + 0x28) else None
        with patch.object(input_descriptor, "thumb_literal_value", literal), patch.object(input_descriptor, "thumb_bl_target", branch):
            positive = _raw_consumer_metadata(bytes(image), load + enqueue, list(b"1259"), load)
            self.assertEqual(positive, {
                "raw_ring": ring, "raw_ring_capacity": 32,
                "raw_enqueue_store": load + enqueue + 20, "raw_enqueue_register": 7,
                "raw_dequeue": load + dequeue, "raw_dequeue_return": load + task + 4,
                "raw_task_entry": load + dispatch, "raw_task_register": 7,
                "raw_consumer_evidence": "shared-byte-ring32-r0-task-dispatch-v1",
            })
            for name, mutate in (
                ("ring", lambda data: data.__setitem__(slice(dequeue, dequeue + 1), b"\xf1")),
                ("store", lambda data: data.__setitem__(slice(enqueue + 20, enqueue + 22), b"\x00\xbf")),
                ("transfer", lambda data: data.__setitem__(slice(task + 4, task + 6), b"\x06\x1c")),
                ("duplicate", lambda data: data.__setitem__(
                    slice(task + 0x20, task + 0x2C),
                    bytes.fromhex("00f000f8071c00d000f000f8"),
                )),
            ):
                with self.subTest(name=name):
                    broken = bytearray(image); mutate(broken)
                    self.assertIsNone(_raw_consumer_metadata(bytes(broken), load + enqueue, list(b"1259"), load))

    def test_raw_consumer_metadata_rejects_adjacent_unreachable_store(self) -> None:
        ring, load, enqueue, store, dequeue, task, dispatch = (
            0x018B0CE4, 0x10000000, 0x20, 0x40, 0x100, 0x200, 0x300,
        )
        image = bytearray(b"\xff" * 0x500)
        # enqueue branches over a nearby lookalike store function.
        image[enqueue:enqueue + 4] = bytes.fromhex("00b520e0")
        image[0x66:0x68] = bytes.fromhex("7047")
        image[store:store + 36] = bytes.fromhex(
            "004a04045078240c1378411cc906c90e99428018877050780130c006c00e5070"
        )
        image[dequeue:dequeue + 40] = bytes.fromhex(
            "f0b5004c86b060782178884200000a199778000000381c06b0f0bc08bc1847"
        )
        image[task:task + 12] = bytes.fromhex("00f000f8071c00d000f000f8")
        for offset, value in enumerate(b"1259"):
            image[dispatch + offset * 2:dispatch + offset * 2 + 2] = (
                0x2F00 | value
            ).to_bytes(2, "little")

        def literal(_image, site, register):
            return ring if (site, register) in ((store, 2), (dequeue + 2, 4)) else None

        def branch(_image, site):
            return dequeue if site == task else dispatch if site == task + 8 else None

        with (patch.object(input_descriptor, "thumb_literal_value", literal),
              patch.object(input_descriptor, "thumb_bl_target", branch)):
            self.assertIsNone(_raw_consumer_metadata(
                bytes(image), load + enqueue, list(b"1259"), load,
            ))
    def test_low5_table_inverts_firmware_columns(self) -> None:
        image = bytearray(b"\xff" * 0x100)
        # ldr r2, literal; ldrb r0, [r2, r1].  The scanner's r1 is sense.
        image[0:4] = bytes((0x0F, 0x4A, 0x50, 0x5C))
        image[0x40:0x44] = (0x80).to_bytes(4, "little")
        table = [0xFF] * 32
        for sense, column in zip((30, 29, 27, 23, 15), (2, 4, 0, 3, 1)):
            table[sense] = column
        image[0x80:0xA0] = bytes(table)

        address, recovered = _table_base(bytes(image), 0, 8, 1) or (None, None)

        self.assertEqual(address, 0x80)
        self.assertEqual([next(value for value in (30, 29, 27, 23, 15) if recovered[value] == column) for column in range(5)], [27, 15, 30, 23, 29])

    def test_low5_table_rejects_duplicate_columns(self) -> None:
        image = bytearray(b"\xff" * 0x100)
        image[0:4] = bytes((0x0F, 0x4A, 0x50, 0x5C))
        image[0x40:0x44] = (0x80).to_bytes(4, "little")
        table = [0xFF] * 32
        for sense, column in zip((30, 29, 27, 23, 15), (0, 1, 1, 3, 4)):
            table[sense] = column
        image[0x80:0xA0] = bytes(table)

        self.assertIsNone(_table_base(bytes(image), 0, 8, 1))

    def test_row_register_requires_same_register_backedge_loop(self) -> None:
        image = bytearray(b"\xff" * 0x40)
        image[0:16] = bytes.fromhex(
            "0025485d00bf01352d062d0e062df8db"
        )

        self.assertEqual(_row_register(bytes(image), 0, 16, [4]), 5)

        image[2:4] = bytes((0x48, 0x5C))
        self.assertIsNone(_row_register(bytes(image), 0, 16, [4]))

    def test_row_order_accepts_exact_descending_index_loop(self) -> None:
        image = bytearray(b"\xff" * 0x20)
        # MOV r5,#5; loop; D+34 read; table[r5]; decrement; BPL loop.
        image[0:18] = bytes.fromhex(
            "0525052d686b0088445d013d2d062d0ef7d5"
        )

        self.assertEqual(
            _row_order(bytes(image), 0, 18, 4),
            (list(range(6)), "direct-descending-loop"),
        )
        image[16:18] = (0xD0F7).to_bytes(2, "little")
        self.assertIsNone(_row_order(bytes(image), 0, 18, 4))

    def test_row_sense_accepts_late_six_row_bound(self) -> None:
        image = bytearray(b"\xff" * 0x120)
        descriptor, sense = 0x01000000, 0x20
        # LDR r5,literal; D+34 LDR/LDRH; low5 guard; late CMP #6.
        image[0:2] = (0x4D3F).to_bytes(2, "little")
        image[0x100:0x104] = descriptor.to_bytes(4, "little")
        image[sense:sense + 4] = bytes.fromhex("686b0088")
        image[sense + 8:sense + 10] = (0x281F).to_bytes(2, "little")
        image[sense + 0x78:sense + 0x7A] = (0x2806).to_bytes(2, "little")
        image[sense + 0x7A:sense + 0x7C] = (0xE7C1).to_bytes(2, "little")

        self.assertEqual(
            _sense_roles(bytes(image), 0, 0xC0, descriptor, sense),
            ([], [sense]),
        )
        image[sense + 0x7A:sense + 0x7C] = b"\xff\xff"
        self.assertEqual(
            _sense_roles(bytes(image), 0, 0xC0, descriptor, sense),
            ([], []),
        )


if __name__ == "__main__":
    unittest.main()
