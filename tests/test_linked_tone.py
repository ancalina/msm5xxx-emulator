from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.registry import device_domain

find_tone_generator = device_domain("audio.tone").find_tone_generator

_DIVIDERS = (307500, 2152500, 4305000, 8610000)
_WRITES = (
    0x030006C8, 0x030006DC, 0x030006BC, 0x030006B8,
    0x030006C4, 0x030006C0, 0x030006D0, 0x030006CC,
    0x030006D8, 0x030006D4,
)


def _ldr_literal(pc: int, register: int, pool: int) -> int:
    displacement = pool - ((pc + 4) & ~3)
    assert 0 <= displacement <= 1020 and displacement % 4 == 0
    return 0x4800 | register << 8 | displacement // 4


def _bl(pc: int, target: int) -> tuple[int, int]:
    displacement = target - (pc + 4)
    assert displacement % 2 == 0
    return (0xF000 | ((displacement >> 12) & 0x7FF),
            0xF800 | ((displacement >> 1) & 0x7FF))


def _fixture(*, missing_divider=False, reorder=False, skip_store=False,
             broken_call=False, converter_pool_outside=False,
             extra_store=False, controls=False, control_order=False,
             partial_control=False, control_without_enable=False,
             direct_control=False) -> bytes:
    image = bytearray(0x500)
    writer = 0x100
    converter = 0x300

    # Writer: initialize three MMIO bases, call the converter, then emit the
    # exact tone-register sequence. The call is on every path to the stores.
    struct.pack_into("<H", image, writer, 0xB500)  # PUSH {lr}
    struct.pack_into("<2H", image, 0x102,
                     *_bl(0x102, 0x400 if broken_call else converter))
    for pc, register, pool in ((0x106, 2, 0x180),
                               (0x108, 3, 0x184),
                               (0x10A, 5, 0x188)):
        struct.pack_into("<H", image, pc, _ldr_literal(pc, register, pool))

    addresses = list(_WRITES)
    if reorder:
        addresses[0], addresses[1] = addresses[1], addresses[0]
    store_start = 0x10C
    if skip_store:
        displacement = (store_start + 4) - (store_start + 4)
        struct.pack_into("<H", image, store_start,
                         0xE000 | ((displacement >> 1) & 0x7FF))
    else:
        for index, address in enumerate(addresses):
            if address < 0x030006C0:
                base, base_register = 0x030006B0, 2
            elif address < 0x030006D0:
                base, base_register = 0x030006C0, 3
            else:
                base, base_register = 0x030006D0, 5
            immediate = address - base
            instruction = 0x7000 | immediate << 6 | base_register << 3
            struct.pack_into("<H", image, store_start + index * 2, instruction)
    return_pc = store_start + len(_WRITES) * 2
    if controls:
        # Stage selector|0x40 in two stack slots, then copy each byte to its
        # control register after the ten divider/data stores.
        if control_without_enable:
            struct.pack_into("<H", image, return_pc, 0x2003)  # MOVS r0, #3
        else:
            struct.pack_into("<H", image, return_pc, 0x783E)  # LDRB r6, [r7, #0]
            struct.pack_into("<H", image, return_pc + 2, 0x2340)  # MOVS r3, #0x40
            struct.pack_into("<H", image, return_pc + 4, 0x431E)  # ORRS r6, r3
        struct.pack_into("<H", image, return_pc + 6, 0x9600)  # STR r6, [sp]
        struct.pack_into("<H", image, return_pc + 8, 0xA400)  # ADD r4, sp, #0
        if control_without_enable:
            struct.pack_into("<H", image, return_pc + 10, 0x2003)  # MOVS r0, #3
        else:
            struct.pack_into("<H", image, return_pc + 10, 0x783E)  # LDRB r6, [r7, #0]
            struct.pack_into("<H", image, return_pc + 12, 0x2340)  # MOVS r3, #0x40
            struct.pack_into("<H", image, return_pc + 14, 0x431E)  # ORRS r6, r3
        struct.pack_into("<H", image, return_pc + 16, 0x9601)  # STR r6, [sp, #4]
        struct.pack_into("<H", image, return_pc + 18, 0x9E00)  # LDR r6, [sp]
        if direct_control and not control_without_enable:
            struct.pack_into("<H", image, return_pc + 18, 0x1C37)  # ADDS r7, r6, #0
            struct.pack_into("<H", image, return_pc + 20, 0x7617)  # STRB r7, [r2, #24]
        else:
            struct.pack_into("<H", image, return_pc + 20, 0x7616)  # STRB r6, [r2, #24]
        struct.pack_into("<H", image, return_pc + 22, 0x9E01)  # LDR r6, [sp, #4]
        struct.pack_into("<H", image, return_pc + 24, 0x732E)  # STRB r6, [r5, #12]
        # The final two addresses must be c8 then dc. They are emitted by
        # modifying the base/immediate pairs above when an order-negative is
        # requested, while preserving the value-flow instructions.
        if not partial_control:
            # Re-encode c8 at the first endpoint and dc at the second.
            if direct_control and not control_without_enable:
                struct.pack_into("<H", image, return_pc + 20, 0x7617)  # [r2, #24]
            else:
                struct.pack_into("<H", image, return_pc + 20, 0x7616)  # [r2, #24]
            struct.pack_into("<H", image, return_pc + 24, 0x732E)  # [r5, #12]
        else:
            struct.pack_into("<H", image, return_pc + 24, 0x712E)  # wrong: [r5, #4]
        if control_order:
            struct.pack_into("<H", image, return_pc + 20, 0x732E)  # dc first
            struct.pack_into("<H", image, return_pc + 24, 0x7616)  # c8 last
        return_pc += 26
    if extra_store:
        # A third control write is outside either supported configuration form.
        struct.pack_into("<H", image, return_pc, 0x7000 | (24 << 6) | (2 << 3))
        return_pc += 2
    struct.pack_into("<H", image, return_pc, 0xBD00)  # POP {pc}

    # The converter prologue is more than the legacy 0x50-byte lookback from
    # its first literal load. Its complete reachable body still loads all four
    # divider constants through a direct call from the writer.
    struct.pack_into("<H", image, converter, 0xB500)  # PUSH {lr}
    for pc in range(converter + 2, 0x35A, 2):
        struct.pack_into("<H", image, pc, 0x46C0)  # MOV r8, r8 (NOP)
    literal_pools = (0x3C0, 0x3C4, 0x3C8, 0x3CC)
    for index, (pc, pool, value) in enumerate(
            zip((0x35A, 0x35C, 0x35E, 0x360), literal_pools, _DIVIDERS)):
        struct.pack_into("<H", image, pc,
                         _ldr_literal(pc, index, len(image) + 4
                                      if converter_pool_outside and index == 0
                                      else pool))
        if not (missing_divider and index == 3):
            struct.pack_into("<I", image, pool, value)
    struct.pack_into("<H", image, 0x362, 0xBD00)  # POP {pc}
    for pool, value in zip((0x180, 0x184, 0x188),
                           (0x030006B0, 0x030006C0, 0x030006D0)):
        struct.pack_into("<I", image, pool, value)
    return bytes(image)


class LinkedToneDetectionTests(unittest.TestCase):
    def test_linked_cfg_converter_accepts_beyond_legacy_prologue_window(self):
        result = find_tone_generator(_fixture())
        self.assertEqual(result["static_status"], "accepted")
        self.assertEqual(result["grammar"],
                         "linked-divider-cfg-plus-ten-strb-v1")
        self.assertEqual(result["writer_offset"], 0x100)
        self.assertEqual(result["converter_offset"], 0x300)
        self.assertEqual(len(result["writer_store_offsets"]), len(_WRITES))
        self.assertTrue(all(0 <= dependency["offset"]
                            and dependency["offset"] + dependency["size"]
                            <= len(_fixture())
                            for dependency in result["source_dependencies"]))

    def test_linked_control_pair_accepts_selector_enable_dataflow(self):
        result = find_tone_generator(_fixture(controls=True))
        self.assertEqual(result["static_status"], "accepted")
        self.assertEqual(result["grammar"],
                         "linked-divider-cfg-plus-control-strb-v1")
        self.assertEqual(len(result["writer_store_offsets"]), len(_WRITES) + 2)

    def test_linked_control_pair_accepts_register_held_enable_dataflow(self):
        result = find_tone_generator(_fixture(controls=True, direct_control=True))
        self.assertEqual(result["static_status"], "accepted")

    def test_linked_path_rejects_missing_divider_or_writer_mutations(self):
        for options in (
                {"missing_divider": True},
                {"reorder": True},
                {"skip_store": True},
                {"broken_call": True},
                {"converter_pool_outside": True},):
            with self.subTest(options=options):
                self.assertNotEqual(
                    find_tone_generator(_fixture(**options))["static_status"],
                    "accepted",
                )

    def test_linked_path_rejects_an_owned_port_write_after_the_sequence(self):
        self.assertNotEqual(find_tone_generator(_fixture(controls=True, extra_store=True))["static_status"],
                            "accepted")

    def test_linked_path_rejects_partial_or_reordered_control_pair(self):
        for options in ({"controls": True, "partial_control": True},
                        {"controls": True, "control_order": True},
                        {"controls": True, "control_without_enable": True}):
            with self.subTest(options=options):
                self.assertNotEqual(find_tone_generator(_fixture(**options))["static_status"],
                                    "accepted")


if __name__ == "__main__":
    unittest.main()
