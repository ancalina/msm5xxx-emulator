"""Focused static-only auxiliary completion shape tests."""
from __future__ import annotations

import struct
import os
from pathlib import Path
import unittest
from corpus import snippet

from msm5xxx_emulator.detection.baseband import (
    detect_aux_completion_shape,
    detect_search2_result_shape,
    find_search2_transport_profile,
    find_search1_transport_profile,
    find_search1_abort_profile,
    find_tx_init_profile,
    find_tx_frame_profile,
    find_finger_transport_profile,
    find_decoder_init_profile,
    find_combiner_clock_profile,
    find_paging_decoder_profile,
    find_traffic_decoder_profile,
    _find_finger_quality,
)
from msm5xxx_emulator.detection.rex import find_rex_5ms_sleep_timer
from corpus import FIRMWARE_ROOT


def _image() -> bytearray:
    image = bytearray(b"\xff" * 0x100)
    words = (
        0xB5F0, 0x1C02, 0x1C0B, 0x2400, 0x481D, 0x7801, 0x2601, 0x40A6,
        0x4F1F, 0x703E, 0x250A, 0x4365, 0x18AD, 0x8028, 0x8068, 0x80A8,
        0x60A8, 0x4818, 0x8801, 0x4818, 0x7801, 0x4818, 0x8801, 0x429C,
        0xD1F1, 0xE003, 0x80A8, 0x0000, 0x0000, 0x60A8, 0xBDF0,
    )
    struct.pack_into(f"<{len(words)}H", image, 0, *words)
    struct.pack_into("<5I", image, 0x80, 0x1000, 0x1004, 0x1008, 0x100C, 0x1010)
    return image


def _literal_clobber_image() -> bytearray:
    image = bytearray(b"\xff" * 0x100)
    words = (
        0xB5F0, 0x1C02, 0x1C0B, 0x2400, 0x491D, 0x2100, 0x780A, 0x2601,
        0x40A6, 0x4F1F, 0x703E, 0x250A, 0x4365, 0x18AD, 0x8028, 0x8068,
        0x80A8, 0x60A8, 0x4811, 0x8801, 0x480F, 0x7801, 0x480F, 0x8801,
        0x429C, 0xD1F1, 0xE003, 0x80A8, 0x0000, 0x0000, 0x60A8, 0xBDF0,
    )
    struct.pack_into(f"<{len(words)}H", image, 0, *words)
    struct.pack_into("<5I", image, 0x80, 0x1000, 0x1004, 0x1008, 0x100C, 0x1010)
    return image


class BasebandDetectionTests(unittest.TestCase):
    def _traffic_images(self):
        root = FIRMWARE_ROOT
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        return [(path, image, find_rex_5ms_sleep_timer(image)[1])
                for path in paths for image in (path.read_bytes(),)]

    def test_conditional_search1_and_compact_paging_protocol_class(self):
        from msm5xxx_emulator.detection.arm import thumb_bl_target
        root = FIRMWARE_ROOT
        path = root / "SPH-X4500.bin"
        if not path.is_file():
            self.skipTest("conditional class firmware unavailable")
        image = path.read_bytes()
        tick = find_rex_5ms_sleep_timer(image)[1]
        search = find_search1_transport_profile(image, tick)
        self.assertTrue(search["accepted"], search.get("reject_reason"))
        self.assertFalse(search["active"])
        self.assertEqual(search["grammar"], "conditional-config-cache-v1")
        self.assertEqual(search["optional_config_lanes"], [4, 5, 6, 7])
        self.assertEqual(len(search["stores"]), 17)
        paging = find_paging_decoder_profile(image, tick)
        self.assertTrue(paging["accepted"], paging.get("reject_reason"))
        for delta in (52, 78):
            damaged = bytearray(image)
            damaged[search["first_store"] + delta] ^= 1
            self.assertFalse(find_search1_transport_profile(bytes(damaged), tick)["accepted"])
        returned = thumb_bl_target(image, paging["isr"] + 0x1e8)
        self.assertIsNotNone(returned)
        damaged = bytearray(image)
        damaged[returned] ^= 1
        self.assertFalse(find_paging_decoder_profile(bytes(damaged), tick)["accepted"])

    def test_traffic_decoder_two_rom_class_and_dependency_bounds(self):
        from msm5xxx_emulator.detection.firmware import detect
        from msm5xxx_emulator.detection.memory_layout import find_linker_layout
        for path, image, tick in self._traffic_images():
            with self.subTest(firmware=path.name):
                profile = find_traffic_decoder_profile(image, tick)
                self.assertTrue(profile["accepted"], profile["reject_reason"])
                self.assertFalse(profile["active"])
                self.assertIn("mode1 erasure-only", profile["semantic_limit"])
                decoder = find_decoder_init_profile(image, tick)
                for key in ("descriptor_template", "irq_callback_slot", "irq_status", "irq_enable", "irq_mask"):
                    self.assertEqual(profile[key], decoder[key])
                layout = find_linker_layout(image, required_span=(profile["layout_address"], 48))
                self.assertEqual(profile["linker_table_offset"], layout.table_offset)
                self.assertEqual(profile["layout_source"], layout.data_source + profile["layout_address"] - layout.data_target)
                row = image[profile["layout_source"] + 8:profile["layout_source"] + 16]
                self.assertEqual(row, bytes.fromhex("001c2c36180c0604"))
                self.assertEqual((row[3] + row[7] + 4) // 2, 31)
                config = detect(path)
                for at, size in profile["code_dependencies"]:
                    self.assertGreaterEqual(at, 0)
                    self.assertLessEqual(at + size, min(len(image), config.flash_size))
                for at, size in profile["ram_dependencies"]:
                    self.assertGreaterEqual(at, config.ram_base)
                    self.assertLessEqual(at + size, config.ram_base + config.ram_size)
                for key in ("isr", "reader", "status_reader", "initializer", "mode_base", "layout_address",
                            "layout_source", "linker_table_offset", "copy_helper", "registration", "quality_dispatcher",
                            "quality_ordinary", "quality_variant3"):
                    self.assertIs(type(profile[key]), int)
                self.assertIn((profile["layout_source"], 48), profile["code_dependencies"])
                self.assertIn((profile["layout_address"], 48), profile["ram_dependencies"])
                # Original submode ==3 versus else is code, not an initial-RAM zero constraint.
                submode = layout.data_source + profile["mode_base"] + 2 - layout.data_target
                for value in (0, 3, 0xffff):
                    changed = bytearray(image)
                    struct.pack_into("<H", changed, submode, value)
                    self.assertTrue(find_traffic_decoder_profile(bytes(changed), tick)["accepted"])
                # Diagnostic strings are not part of this instruction/dataflow class.
                isr = profile["isr"]
                pc = isr + 0xaa
                pool = ((pc + 4) & ~3) + (struct.unpack_from("<H", image, pc)[0] & 255) * 4
                text = struct.unpack_from("<I", image, pool)[0]
                changed = bytearray(image); changed[text:text + 4] = b"test"
                self.assertTrue(find_traffic_decoder_profile(bytes(changed), tick)["accepted"])

    def test_traffic_decoder_coupled_mutations_fail_closed(self):
        def pool(image, pc):
            return ((pc + 4) & ~3) + (struct.unpack_from("<H", image, pc)[0] & 255) * 4

        for path, image, tick in self._traffic_images():
            profile = find_traffic_decoder_profile(image, tick)
            self.assertTrue(profile["accepted"], profile)
            reader, metrics, init, isr = (profile[k] for k in ("reader", "status_reader", "initializer", "isr"))
            changes = [reader + 0x1e, reader + 0x2c, pool(image, reader + 0x12),
                       pool(image, reader + 0x2a), profile["copy_helper"] + 6,
                       metrics + 0x18, pool(image, metrics + 0xe), pool(image, metrics + 0x16),
                       profile["registration"] - 2, isr + 0x22, isr + 0x18c, isr + 0x5c6,
                       isr + 0x5de, pool(image, isr + 0x5da), init + 0x7c, init + 0xa0,
                       init + 0x16, init + 0x86, pool(image, init + 0x40),
                       profile["quality_dispatcher"] + 0x14, profile["quality_dispatcher"] + 0x1c,
                       profile["quality_ordinary"] + 0x28, profile["quality_variant3"] + 0xe,
                       pool(image, profile["quality_variant3"] + 2),
                       profile["descriptor_template"] + 8, profile["layout_source"] + 8,
                       profile["layout_source"] + 12, profile["layout_source"],
                       profile["linker_table_offset"] + 8]
            for at in changes:
                with self.subTest(firmware=path.name, mutation=hex(at)):
                    changed = bytearray(image); changed[at] ^= 1
                    rejected = find_traffic_decoder_profile(bytes(changed), tick)
                    self.assertFalse(rejected["accepted"], (at, rejected))
                    self.assertTrue(rejected["reject_reason"])
            # Relocating an LDR beyond the dump must reject, not raise or use guessed data.
            changed = bytearray(image)
            struct.pack_into("<I", changed, pool(image, isr + 0xa0), 0xffffffff)
            self.assertFalse(find_traffic_decoder_profile(bytes(changed), tick)["accepted"])

    def test_traffic_decoder_missing_ambiguous_and_linker_mapping(self):
        for image in (b"", bytes(1024), b"\xff" * 1024):
            self.assertFalse(find_traffic_decoder_profile(image, 0)["accepted"])
        for path, image, tick in self._traffic_images():
            profile = find_traffic_decoder_profile(image, tick)
            self.assertFalse(find_traffic_decoder_profile(image, tick | 1)["accepted"])
            # A second complete reader with relocated BLs is genuinely ambiguous.
            reader, helper = profile["reader"], profile["copy_helper"]
            changed = bytearray(image)
            at = (len(changed) + 3) & ~3
            changed.extend(bytes(at - len(changed)))
            changed.extend(image[reader:reader + 160])
            for offset in (0x2c, 0x4c, 0x6c, 0x8c):
                delta = helper - (at + offset + 4)
                struct.pack_into("<HH", changed, at + offset,
                                 0xf000 | ((delta >> 12) & 0x7ff), 0xf800 | ((delta >> 1) & 0x7ff))
            self.assertEqual(find_traffic_decoder_profile(bytes(changed), tick)["reject_reason"],
                             "traffic-reader-cardinality:2")
            # Required RAM span must have one scatter-load mapping, never first-match fallback.
            changed = bytearray(image); table = profile["linker_table_offset"]
            changed[0x1f000:0x1f014] = image[table:table + 20]
            self.assertEqual(find_traffic_decoder_profile(bytes(changed), tick)["reject_reason"],
                             "traffic-layout-linker-unclosed")
            changed = bytearray(image); changed[table:table + 20] = bytes(20)
            self.assertEqual(find_traffic_decoder_profile(bytes(changed), tick)["reject_reason"],
                             "traffic-layout-linker-unclosed")

    def test_tx_frame_full_data_helper_writer_tables_and_mutations(self):
        self.assertFalse(find_tx_frame_profile(b"", 0)["accepted"])
        root = FIRMWARE_ROOT
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        from msm5xxx_emulator.detection.firmware import detect
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            profile = find_tx_frame_profile(image, tick)
            self.assertTrue(profile["accepted"], profile["reject_reason"])
            self.assertFalse(profile["active"])
            self.assertEqual(profile["fifo_port"], 0x03000298)
            self.assertEqual(profile["mode_address"], profile["mode_base"] + 12)
            self.assertEqual(profile["mode_literal_load"], profile["data_helper"] + 2)
            self.assertEqual(profile["mode_byte_load"], profile["data_helper"] + 6)
            self.assertEqual(profile["working_base"], profile["counter_address"] - 0xa4)
            self.assertEqual(profile["mode_range"], (1, 4))
            self.assertEqual(profile["maximum_buffer_bytes"], 18)
            self.assertEqual(len(profile["unclosed_auxiliary_calls"]), 5)
            self.assertIn((profile["data_helper"], 0x110), profile["code_dependencies"])
            self.assertIn((profile["fixed_writer"], 38), profile["code_dependencies"])
            self.assertIn((profile["table"] - 8, 0xc0), profile["code_dependencies"])
            self.assertIn((profile["working_base"], 0xa4), profile["ram_dependencies"])
            config = detect(path)
            for address, size in profile["code_dependencies"]:
                self.assertGreaterEqual(address, 0)
                self.assertLessEqual(address + size, min(len(image), config.flash_size))
            for address, size in profile["ram_dependencies"]:
                self.assertGreaterEqual(address, config.ram_base)
                self.assertLessEqual(address + size, config.ram_base + config.ram_size)

            def literal_at(pc):
                return ((pc + 4) & ~3) + (struct.unpack_from("<H", image, pc)[0] & 255) * 4

            data = profile["data_helper"]
            changed = bytearray(image)
            changed[profile["table"] - 8:profile["table"]] = b"diag\0\0\0\0"
            self.assertTrue(find_tx_frame_profile(bytes(changed), tick)["accepted"])
            mutations = [data + 6, data + 0x54, data + 0x10e,
                         data + 0xe4, data + 0xb8, data + 0x10a,
                         literal_at(data + 0x108), profile["fixed_writer"] + 16,
                         literal_at(data + 2), literal_at(data + 0xbc),
                         literal_at(data + 0x78), profile["table"],
                         literal_at(profile["callback"] + 0x14)]
            for address in mutations:
                with self.subTest(firmware=path.name, mutation=hex(address)):
                    changed = bytearray(image)
                    changed[address] ^= 1
                    rejected = find_tx_frame_profile(bytes(changed), tick)
                    self.assertFalse(rejected["accepted"], (address, rejected))
            changed = bytearray(image)
            struct.pack_into("<I", changed, literal_at(data + 2), 0x02000000)
            self.assertFalse(find_tx_frame_profile(bytes(changed), tick)["accepted"])
            # A syntactically valid BL outside the image must fail closed.
            changed = bytearray(image)
            call = data + 0xf4
            delta = -2 - call - 4
            struct.pack_into("<HH", changed, call, 0xf000 | ((delta >> 12) & 0x7ff),
                             0xf800 | ((delta >> 1) & 0x7ff))
            self.assertFalse(find_tx_frame_profile(bytes(changed), tick)["accepted"])

    def test_tx_frame_opaque_diagnostic_record_ids(self):
        root = FIRMWARE_ROOT
        path = root / "SCH-x127.bin"
        if not path.is_file():
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        image = path.read_bytes()
        tick = find_rex_5ms_sleep_timer(image)[1]
        profile = find_tx_frame_profile(image, tick)
        self.assertTrue(profile["accepted"], profile["reject_reason"])
        self.assertFalse(profile["active"])
        self.assertEqual(profile["fifo_port"], 0x03000298)
        from msm5xxx_emulator.detection.firmware import detect
        config = detect(path)
        for address, size in profile["code_dependencies"]:
            self.assertTrue(0 <= address <= min(len(image), config.flash_size) - size)
        for address, size in profile["ram_dependencies"]:
            self.assertTrue(config.ram_base <= address <= config.ram_base + config.ram_size - size)
        data = profile["data_helper"]
        pools = [((data + at + 4) & ~3) + image[data + at] * 4
                 for at in (0x14, 0x20)]
        for first, second, accepted in ((0x1234, 0x1235, True),
                (0xfffe, 0xffff, True), (0x1234, 0x1236, False),
                (0x10000, 0x10001, False), (0xffff, 0x10000, False)):
            with self.subTest(first=first, second=second):
                changed = bytearray(image)
                struct.pack_into("<I", changed, pools[0], first)
                struct.pack_into("<I", changed, pools[1], second)
                result = find_tx_frame_profile(bytes(changed), tick)
                self.assertEqual(result["accepted"], accepted, result["reject_reason"])
                if accepted:
                    self.assertEqual(result, profile)

    def test_tx_init_complete_callback_controller_and_mutations(self):
        self.assertFalse(find_tx_init_profile(b"", 0)["accepted"])
        root = FIRMWARE_ROOT
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            profile = find_tx_init_profile(image, tick)
            self.assertTrue(profile["accepted"], profile["reject_reason"])
            self.assertFalse(profile["active"])
            self.assertEqual(profile["irq_mask"], 8)
            self.assertIn(profile["callback_size"], (0x100, 0x102))
            self.assertEqual(profile["armed_flag"] + 12, profile["counter_address"])
            self.assertEqual(profile["first_flag_load"], profile["callback"] + 0x18)
            from msm5xxx_emulator.detection.firmware import detect
            config = detect(path)
            self.assertEqual(profile["code_dependencies"], (
                (profile["callback"], profile["callback_size"]),
                (profile["control_helper"], 0xa0), (profile["registrar"], 0x6e),
                (profile["signal_setter"], 20),
                *((pc - 4, 28) for pc in profile["registrations"])))
            self.assertEqual(profile["ram_dependencies"], (
                (profile["callback_slot"] - 20, 24), (profile["armed_flag"], 16),
                (profile["tx_tcb"], 0x18), (profile["counter_address"], 0x140),
                (profile["control_shadow"], 0x180), (profile["input_shadow"], 1)))
            for address, size in profile["code_dependencies"]:
                self.assertGreaterEqual(address, 0)
                self.assertLessEqual(address + size, min(len(image), config.flash_size))
            for address, size in profile["ram_dependencies"]:
                self.assertGreaterEqual(address, config.ram_base)
                self.assertLessEqual(address + size, config.ram_base + config.ram_size)
            self.assertEqual(image[profile["signal10_call"] - 4:
                                   profile["signal10_call"] - 2], bytes.fromhex("1021"))
            self.assertEqual(image[profile["signal4_call"] - 2:
                                   profile["signal4_call"]], bytes.fromhex("0421"))

            def literal_at(pc):
                return ((pc + 4) & ~3) + (struct.unpack_from("<H", image, pc)[0] & 255) * 4

            callback = profile["callback"]
            mutations = [callback + 0x18, callback + 0x1c, callback + 0x28,
                         profile["flag_clear_store"], profile["signal10_call"] - 4,
                         profile["signal4_call"] - 2,
                         literal_at(callback + 2), literal_at(callback + 0x14),
                         literal_at(profile["signal10_call"] - 2),
                         profile["descriptor_template"] + 8,
                         profile["descriptor_template"],
                         profile["control_helper"] + 0x20,
                         literal_at(profile["control_helper"] + 4),
                         profile["registrations"][0] - 2]
            for at in mutations:
                with self.subTest(firmware=path.name, mutation=hex(at)):
                    changed = bytearray(image)
                    changed[at] ^= 1
                    rejected = find_tx_init_profile(bytes(changed), tick)
                    self.assertFalse(rejected["accepted"], (at, rejected))
            self.assertFalse(find_tx_init_profile(image, tick + 2)["accepted"])
            # A second real slot-4 registration is ambiguous, even for the same callback.
            ambiguous = bytearray(image)
            at = (profile["registrations"][0] + 0x103) & ~3
            self.assertLess(at + 12, callback)
            call = at + 4
            delta = profile["registrar"] - call - 4
            struct.pack_into("<4HI", ambiguous, at, 0x4901, 0x2004,
                             0xf000 | ((delta >> 12) & 0x7ff),
                             0xf800 | ((delta >> 1) & 0x7ff), callback | 1)
            self.assertFalse(find_tx_init_profile(bytes(ambiguous), tick)["accepted"])

    def test_search1_abort_shared_owner_and_zero_store_shape(self):
        self.assertFalse(find_search1_abort_profile(b"", 0)["accepted"])
        root = FIRMWARE_ROOT
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            profile = find_search1_abort_profile(image, tick)
            self.assertTrue(profile["accepted"], profile["reject_reason"])
            self.assertFalse(profile["active"])
            entry = profile["entry"]
            self.assertEqual(profile["first_store"], entry + 0x3e)
            self.assertEqual(profile["second_store"], entry + 0x40)
            self.assertNotEqual(profile["owner_address"], profile["control_address"])
            transport = find_search1_transport_profile(image, tick)
            shared = transport["shared_search2_profile"]

            def literal_at(pc):
                return ((pc + 4) & ~3) + image[pc] * 4

            mutations = [entry + 4, entry + 6, entry + 0xe, entry + 0x36,
                         entry + 0x3a, entry + 0x3e, entry + 0x40,
                         entry + 0x50, entry + 0x52, entry + 0x78,
                         literal_at(entry + 2), literal_at(entry + 8),
                         literal_at(entry + 0xa), literal_at(entry + 0x3c),
                         literal_at(transport["consumer_entry"] + 0xc),
                         literal_at(shared["worker"] + 4)]
            for at in mutations:
                with self.subTest(firmware=path.name, mutation=hex(at)):
                    changed = bytearray(image)
                    changed[at] ^= 1
                    rejected = find_search1_abort_profile(bytes(changed), tick)
                    self.assertFalse(rejected["accepted"], (at, rejected))

    def test_paging_decoder_coupled_readers_irq_mode_and_carry(self):
        self.assertFalse(find_paging_decoder_profile(b"", 0)["accepted"])
        root = FIRMWARE_ROOT
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            profile = find_paging_decoder_profile(image, tick)
            self.assertTrue(profile["accepted"], profile["reject_reason"])
            self.assertFalse(profile["active"])
            self.assertEqual((profile["head_bits"], profile["data_words"], profile["irq_mask"]),
                             (72, [12, 6], 0x10))
            self.assertEqual(profile["init_write"], profile["initializer"] + 0x36)
            literal_pc = profile["reader"] + 8
            literal_at = ((literal_pc + 4) & ~3) + image[literal_pc] * 4
            mutations = [profile["reader"] + 10, profile["status_reader"] + 10,
                         literal_at, profile["isr"] + 0x162,
                         profile["isr"] + 0xda, profile["isr"] + 0x1e2,
                         profile["init_write"], profile["initializer"] + 0x16,
                         profile["mode_initializer"] + 0x10,
                         profile["consumer"] + 0x54, profile["consumer"] + 0x10,
                         profile["pipeline_layout"] + 10,
                         profile["registration"] - 2,
                         profile["descriptor_template"] + 8]
            for at in mutations:
                with self.subTest(firmware=path.name, mutation=hex(at)):
                    changed = bytearray(image)
                    changed[at] ^= 1
                    rejected = find_paging_decoder_profile(bytes(changed), tick)
                    self.assertFalse(rejected["accepted"], (at, rejected))

    def test_combiner_position_roll_and_descriptor_class(self):
        self.assertFalse(find_combiner_clock_profile(b"", 0)["accepted"])
        root = FIRMWARE_ROOT
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            profile = find_combiner_clock_profile(image, tick)
            self.assertTrue(profile["accepted"], profile["reject_reason"])
            self.assertFalse(profile["active"])
            self.assertEqual(profile["irq_mask"], 0x100)
            for at, bit in [(profile["position_getter"] + 14, 1),
                            (profile["roll_isr"] + 0x1aa, 1),
                            (profile["descriptor_template"] + 8, 0x20),
                            (profile["sync_consumer"] + 0x20, 1)]:
                changed = bytearray(image)
                changed[at] ^= bit
                self.assertFalse(find_combiner_clock_profile(bytes(changed), tick)["accepted"])

    def test_decoder_init_probe_signature_and_coupled_irq_descriptor(self):
        self.assertFalse(find_decoder_init_profile(b"", 0)["accepted"])
        root = FIRMWARE_ROOT
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            profile = find_decoder_init_profile(image, tick)
            self.assertTrue(profile["accepted"], profile["reject_reason"])
            self.assertFalse(profile["active"])
            self.assertEqual((profile["data_words"], profile["irq_mask"]), (6, 0x10))
            for at, bit in [(profile["reader"] + 8, 1),
                            (profile["copy_helper"] + 6, 1),
                            (profile["isr"] + 0x56, 1),
                            (profile["init_write"], 1),
                            (profile["descriptor_template"] + 8, 0x20)]:
                changed = bytearray(image)
                changed[at] ^= bit
                rejected = find_decoder_init_profile(bytes(changed), tick)
                self.assertFalse(rejected["accepted"], (path.name, at, rejected))

    def test_finger_selected_rssi_scale_and_position_class(self):
        self.assertFalse(find_finger_transport_profile(b"", 0)["accepted"])
        root = FIRMWARE_ROOT
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            profile = find_finger_transport_profile(image, tick)
            self.assertTrue(profile["accepted"], profile["reject_reason"])
            self.assertFalse(profile["active"])
            self.assertEqual((profile["rss_address"], profile["rss_width"]), (0x0300008c, 2))
            self.assertEqual((profile["stride"], profile["quality_offset"]), (72, 58))
            offsets = list(range(0, 68, 2)) + [-56,-54,-52,-50,-48,-46,-44,-42,-40,-38,-36,-34,-32,-30,-28,-2]
            for offset in offsets:
                changed = bytearray(image)
                changed[profile["rss_word_read"] + offset] ^= 1
                with self.subTest(firmware=path.name, mutation=offset):
                    self.assertIsNone(_find_finger_quality(bytes(changed)))

    def test_search1_command_queue_and_selected_results_in_independent_firmware(self):
        self.assertFalse(find_search1_transport_profile(b"", 0)["accepted"])
        root = FIRMWARE_ROOT
        files = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in files):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in files:
            image = path.read_bytes()
            timer = find_rex_5ms_sleep_timer(image)
            self.assertIsNotNone(timer)
            profile = find_search1_transport_profile(image, timer[1])
            self.assertTrue(profile["accepted"], profile["reject_reason"])
            self.assertFalse(profile["active"])
            self.assertEqual(len(profile["stores"]), 17)
            self.assertEqual(profile["consumer"]["record_offsets"], [44, 36])
            first, loop = profile["first_store"], profile["consumer"]["loop_file_offset"]
            points = [site["pc"] for site in profile["stores"]]
            points += [first - 4, first + 124, first + 130, profile["consumer_entry"] + 2]
            points += [loop + offset for offset in range(-2, 24, 2)]
            for pc in points:
                changed = bytearray(image)
                changed[pc] ^= 1
                with self.subTest(firmware=path.name, mutation=pc):
                    rejected = find_search1_transport_profile(bytes(changed), timer[1])
                    self.assertFalse(rejected["accepted"])
                    self.assertFalse(rejected["active"])

    def test_transport_requires_unique_writer_tables_and_connected_consumer(self):
        image = bytearray(b"\xff" * 0x1400)
        image[:0x68] = bytes.fromhex("c046") * (0x68 // 2)
        struct.pack_into("<H", image, 0, 0xB5F0)
        struct.pack_into("<H", image, 0x2C, 0x4935)
        struct.pack_into("<H", image, 0x2E, 0x5A0A)
        struct.pack_into("<H", image, 0x30, 0x4935)
        struct.pack_into("<H", image, 0x34, 0x5A0A)
        struct.pack_into("<H", image, 0x3E, 0x4930)
        image[0x40:0x64] = snippet("test_baseband_detection", "transport_consumer_code")
        struct.pack_into("<H", image, 0x64, 0xBDF0)
        struct.pack_into("<3I", image, 0x100, 0x03000800, 0x200, 0x600)
        struct.pack_into("<512H", image, 0x200, *range(1, 513))
        struct.pack_into("<512H", image, 0x600, *range(513, 1025))
        reason = lambda data: find_search2_transport_profile(bytes(data), 0)["reject_reason"]
        self.assertEqual(reason(image), "search2-consumer-cardinality:0")
        for offset, value in ((0x100, 0), (0x200, 0), (0x600, 0), (0x34, 0)):
            with self.subTest(offset=offset):
                changed = bytearray(image)
                struct.pack_into("<H", changed, offset, value)
                self.assertEqual(reason(changed), "search2-writer-cardinality:0")
        duplicate = bytearray(image)
        duplicate[0x1000:0x1110] = image[:0x110]
        self.assertEqual(reason(duplicate), "search2-writer-cardinality:2")
        words = (0xB5F0, 0x4E1F, 0x46C0, 0x2100, 0x89B5, 0x004A,
                 0x1812, 0x8595, 0x89B5, 0x3101, 0x0609, 0x1609,
                 0x2904, 0x8495, 0xDBF4, 0xBDF0)
        struct.pack_into(f"<{len(words)}H", image, 0x180, *words)
        struct.pack_into("<I", image, 0x200, 0x03000800)
        self.assertEqual(reason(image), "search2-worker-cardinality:0")
        self.assertFalse(find_search2_transport_profile(bytes(image), 0)["active"])

    def test_search2_result_order_and_rejected_near_misses(self) -> None:
        image = bytearray(b"\xff" * 0x100)
        words = (0xB5F0, 0x4E1F, 0x46C0, 0x2100, 0x89B5, 0x004A,
                 0x1812, 0x8595, 0x89B5, 0x3101, 0x0609, 0x1609,
                 0x2904, 0x8495, 0xDBF4, 0xBDF0)
        struct.pack_into(f"<{len(words)}H", image, 0, *words)
        struct.pack_into("<I", image, 0x80, 0x03000800)
        accepted = detect_search2_result_shape(bytes(image), 0)
        self.assertEqual(accepted["confidence"], "static-shape")
        self.assertEqual(accepted["word_pair_record_offsets"], (44, 36))
        self.assertEqual(accepted["words_per_record"], 8)
        self.assertEqual(accepted["aperture"], 0x03000800)
        self.assertIn("IRQ unknown", accepted["semantic_limit"])
        rebased = detect_search2_result_shape(bytes(image), 0x1000, 0x1000)
        self.assertEqual(rebased["confidence"], "static-shape")
        self.assertEqual(rebased["loop_file_offset"], 0x1008)
        for offset, word in ((4, 0x2600), (6, 0x2101), (14, 0x7595),
                             (18, 0x3102), (24, 0x2903), (26, 0x8595),
                             (28, 0xDBF3), (10, 0x004B), (16, 0x89AD)):
            with self.subTest(offset=offset, word=word):
                near_miss = bytearray(image)
                struct.pack_into("<H", near_miss, offset, word)
                self.assertEqual(
                    detect_search2_result_shape(bytes(near_miss), 0)["confidence"],
                    "rejected",
                )
        ambiguous = bytearray(image)
        ambiguous[38:64] = image[6:32]
        struct.pack_into("<H", ambiguous, 4, 0xD00F)
        self.assertEqual(
            detect_search2_result_shape(bytes(ambiguous), 0)["reject_reason"],
            "search2-result-loop-cardinality:2",
        )
        for entry in (-2, 1, len(image), 0x100000):
            with self.subTest(entry=entry):
                self.assertEqual(
                    detect_search2_result_shape(bytes(image), entry)["confidence"],
                    "rejected",
                )

    def test_unique_shape_and_fail_closed_variants(self) -> None:
        image = _image()
        accepted = detect_aux_completion_shape(bytes(image), 0).as_dict()
        self.assertEqual(accepted["confidence"], "static-shape")
        self.assertEqual(accepted["work_stride"], 10)
        self.assertEqual(accepted["record_u16_offsets"], (0, 2, 4))
        self.assertEqual(
            (accepted["saved_work_register"], accepted["saved_count_register"],
             accepted["index_register"]),
            (2, 3, 4),
        )
        self.assertEqual(accepted["selector"], {"pc": 16, "base": 0x1010, "offset": 0})
        self.assertEqual(accepted["loads"], {
            "E": {"pc": 8, "use_pc": 10, "base": 0x1000, "width": "u8", "offset": 0, "value_register": 1},
            "M": {"pc": 34, "use_pc": 36, "base": 0x1004, "width": "u16", "offset": 0, "value_register": 1},
            "L": {"pc": 38, "use_pc": 40, "base": 0x1008, "width": "u8", "offset": 0, "value_register": 1},
            "S": {"pc": 42, "use_pc": 44, "base": 0x100C, "width": "u16", "offset": 0, "value_register": 1},
        })
        rebased = detect_aux_completion_shape(bytes(image), 0x1000, 0x1000)
        self.assertEqual(rebased.confidence, "static-shape")
        self.assertEqual(rebased.entry_file_offset, 0x1000)
        self.assertEqual(rebased.return_file_offset, 0x103C)
        self.assertEqual(rebased.selector.pc, 0x1010)

        near_miss = bytearray(image)
        struct.pack_into("<H", near_miss, 30, 0x7028)
        self.assertEqual(
            detect_aux_completion_shape(bytes(near_miss), 0).reject_reason,
            "aux-w-3xu16-u32-store-shape-missing",
        )

        stale_alias = bytearray(image)
        struct.pack_into("<2H", stale_alias, 30, 0x7028, 0x7028)
        struct.pack_into(
            "<5H", stale_alias, 50,
            0x1C28, 0x2000, 0x8081, 0x6081, 0xE7FF,
        )
        self.assertEqual(
            detect_aux_completion_shape(bytes(stale_alias), 0).reject_reason,
            "aux-w-3xu16-u32-store-shape-missing",
        )

        self.assertEqual(
            detect_aux_completion_shape(
                bytes(_literal_clobber_image()), 0
            ).reject_reason,
            "aux-e-m-l-s-width-shape-missing",
        )

        ambiguous = bytearray(image)
        struct.pack_into("<2H", ambiguous, 32, 0x4365, 0x18AD)
        self.assertEqual(
            detect_aux_completion_shape(bytes(ambiguous), 0).reject_reason,
            "aux-record-base-cardinality:2",
        )
