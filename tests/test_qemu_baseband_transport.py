"""Explicit virtual-cell configuration and same-image binding."""
from copy import deepcopy
from pathlib import Path
import os
import sys
from types import SimpleNamespace
import unittest
from msm5xxx_emulator.qemu.transport import qemu_virtual_cell_property
from msm5xxx_emulator.detection.rex import find_rex_5ms_sleep_timer


# Fixed synthetic full-view pair; CRC outcome belongs to the decoder hardware.
TRAFFIC_FRAME_VALID = "00000000000000000000000000000000000000000003d700"
TRAFFIC_FRAME_BAD_CRC = "80000000000000000000000000000000000000000003d700"


CELL = {
    "pilot_phase": 130088, "raw_energy": 64000,
    "virtual_delay_ns": 1000000, "decoder_init_delay_ns": 80000000,
    "sync_message_hex": "1a010303115dfffe00000000000040000000000000076374e349",
    "paging_messages_hex": [
        "2101000022bbfffc00000000408000000000000000002aa800001c811032d5858d",
        "130200000000000000000000000880150f5501",
        "09030000202ddb8355", "09040000077f201358",
    ],
}


class QEMUBasebandTransportTests(unittest.TestCase):
    def test_disabled_and_invalid_cell_before_any_image_binding(self):
        self.assertEqual(qemu_virtual_cell_property(b"", object(), None), (None, None))
        invalid = [{}, {**CELL, "sip": True}, {**CELL, "raw_energy": True},
                   {**CELL, "pilot_phase": 0x40000}, {**CELL, "virtual_delay_ns": 0},
                   {**CELL, "virtual_delay_ns": 1000000001},
                   {**CELL, "decoder_init_delay_ns": 1000000001},
                   {**CELL, "decoder_init_delay_ns": 1},
                   {**CELL, "decoder_init_delay_ns": 1 << 63},
                   {**CELL, "paging_messages_hex": CELL["paging_messages_hex"][:3]},
                   {**CELL, "sync_message_hex": CELL["sync_message_hex"][:-2] + "00"}]
        changed = deepcopy(CELL)
        changed["paging_messages_hex"][1] = CELL["paging_messages_hex"][0]
        invalid.append(changed)
        invalid.extend({**CELL, "tx_init_delay_ns": value}
                       for value in (None, True, 0, -1, 1.5, 1000000001))
        for field, maximum in (("sid", 1 << 15), ("nid", 1 << 16), ("channel", 1 << 11)):
            invalid.extend({**CELL, field: value} for value in (-1, maximum, True, 1.5, None))
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                qemu_virtual_cell_property(b"", object(), value)
        self.assertEqual(qemu_virtual_cell_property(b"", object(), CELL),
                         (None, "primary-map-unsupported"))
        conflicting = SimpleNamespace(load_address=0, image_offset=0,
                                      rex_static_controller_experimental=True)
        self.assertEqual(qemu_virtual_cell_property(b"", conflicting, CELL),
                         (None, "controller-mode-unsupported"))

    def test_two_images_auto_bind_and_mutations_fall_back(self):
        root = Path(os.environ.get(
            "MSM5XXX_TEST_FIRMWARE_ROOT", Path(__file__).resolve().parents[2] / "firmwares"))
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            config = SimpleNamespace(load_address=0, image_offset=0, rex_tick_address=tick)
            prop, reason = qemu_virtual_cell_property(image, config, CELL)
            self.assertIsNone(reason)
            properties = dict(part.split("=", 1) for part in prop.split(","))
            self.assertEqual(set(properties), {
                "search2-virtual", "search1-virtual", "finger-virtual",
                "decoder-init-probe", "decoder-sync-source", "decoder-paging-source"})
            search = [int(x, 16) for x in properties["search2-virtual"].split(":")]
            self.assertEqual(len(search), 12)
            self.assertEqual(search[8:], [0x80, CELL["virtual_delay_ns"],
                                         CELL["pilot_phase"], CELL["raw_energy"]])
            self.assertEqual(properties["decoder-paging-source"].split(":")[-4:],
                             CELL["paging_messages_hex"])
            self.assertEqual(properties["decoder-sync-source"].split(":")[-1],
                             CELL["sync_message_hex"])
            named, named_reason = qemu_virtual_cell_property(
                image, config, {**CELL, "sid": 1, "nid": 2, "channel": 3})
            self.assertIsNone(named_reason)
            named_properties = dict(part.split("=", 1) for part in named.split(","))
            self.assertEqual(named_properties["decoder-sync-source"].split(":")[-1],
                             "1a010303000200040000000000004000000000000000d40c3501")
            self.assertEqual(named_properties["decoder-paging-source"].split(":")[-4:], [
                "210100000004000800000000408000000000000000002aa800001c8110346d94c9",
                CELL["paging_messages_hex"][1], CELL["paging_messages_hex"][2],
                "0904000000fce96834"])
            unchanged, unchanged_reason = qemu_virtual_cell_property(
                image, config, {**CELL, "sid": 2222, "nid": 65535, "channel": 29})
            self.assertIsNone(unchanged_reason)
            self.assertEqual(unchanged, prop)
            before = deepcopy(CELL)
            zero = {**CELL, "raw_energy": 0}
            zero_prop, zero_reason = qemu_virtual_cell_property(image, config, zero)
            self.assertIsNone(zero_reason)
            self.assertEqual(zero_prop, prop.replace(f":{CELL['raw_energy']:x},", ":0,", 1))
            self.assertEqual(CELL, before)
            abort_pc = int(properties["search1-virtual"].split(":")[-1], 16)
            changed = bytearray(image)
            changed[abort_pc] ^= 1
            rejected, reason = qemu_virtual_cell_property(bytes(changed), config, CELL)
            self.assertIsNone(rejected)
            self.assertTrue(reason)
            config.rex_tick_address += 2
            self.assertEqual(qemu_virtual_cell_property(image, config, CELL),
                             (None, "tick-image-mismatch"))

    def test_named_fields_require_the_legacy_sync_layout(self):
        extended = {**CELL, "sync_message_hex":
                    "1a010603115dfffe0000000000004000000000000007436eb961"}
        self.assertEqual(qemu_virtual_cell_property(b"", object(), extended),
                         (None, "primary-map-unsupported"))
        with self.assertRaisesRegex(ValueError, "field layout"):
            qemu_virtual_cell_property(b"", object(), {**extended, "sid": 1})

    def test_tx_init_is_explicit_same_image_bound_and_mapped(self):
        from msm5xxx_emulator.detection.baseband import find_tx_init_profile
        root = Path(os.environ.get(
            "MSM5XXX_TEST_FIRMWARE_ROOT", Path(__file__).resolve().parents[2] / "firmwares"))
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            config = SimpleNamespace(load_address=0, image_offset=0, rex_tick_address=tick,
                                     flash_size=len(image), ram_base=0x1000000, ram_size=0x800000)
            cell = {**CELL, "tx_init_delay_ns": 1000000}
            before = deepcopy(cell)
            prop, reason = qemu_virtual_cell_property(image, config, cell)
            self.assertIsNone(reason)
            properties = dict(part.split("=", 1) for part in prop.split(","))
            tx = find_tx_init_profile(image, tick)
            self.assertEqual([int(x, 16) for x in properties["tx-init-probe"].split(":")], [
                tx["callback"], tx["callback_slot"], tx["armed_flag"], tx["tx_tcb"],
                tx["signal10_call"], tx["control_helper"], tx["registrations"][0], 1000000])
            plain, plain_reason = qemu_virtual_cell_property(image, config, CELL)
            self.assertIsNone(plain_reason)
            self.assertEqual(prop.rsplit(",tx-init-probe=", 1)[0], plain)
            self.assertEqual(cell, before)
            config.ram_size = 0
            self.assertEqual(qemu_virtual_cell_property(image, config, cell),
                             (None, "tx-init-state-unmapped"))
            config.ram_size = 0x800000
            config.flash_size = tx["callback"]
            self.assertEqual(qemu_virtual_cell_property(image, config, cell),
                             (None, "tx-init-code-unmapped"))

    def test_tx_frame_period_is_explicit_and_extends_existing_binding(self):
        for value in (None, True, False, 0, -1, 1.5, "20000000", 1000000001):
            with self.subTest(invalid=value), self.assertRaisesRegex(ValueError, "tx_frame_period_ns"):
                qemu_virtual_cell_property(b"", object(), {
                    **CELL, "tx_init_delay_ns": 1000000, "tx_frame_period_ns": value})
        with self.assertRaisesRegex(ValueError, "requires tx_init_delay_ns"):
            qemu_virtual_cell_property(b"", object(), {**CELL, "tx_frame_period_ns": 20000000})
        root = Path(os.environ.get(
            "MSM5XXX_TEST_FIRMWARE_ROOT", Path(__file__).resolve().parents[2] / "firmwares"))
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path in paths:
            image = path.read_bytes()
            tick = find_rex_5ms_sleep_timer(image)[1]
            config = SimpleNamespace(load_address=0, image_offset=0, rex_tick_address=tick,
                                     flash_size=len(image), ram_base=0x1000000, ram_size=0x800000)
            cell = {**CELL, "tx_init_delay_ns": 1000000}
            original, reason = qemu_virtual_cell_property(image, config, cell)
            self.assertIsNone(reason)
            from msm5xxx_emulator.detection.baseband import find_tx_frame_profile
            frame = find_tx_frame_profile(image, tick)
            for period in (1, 20000000, 1000000000):
                scenario = {**cell, "tx_frame_period_ns": period}
                before = deepcopy(scenario)
                extended, reason = qemu_virtual_cell_property(image, config, scenario)
                self.assertIsNone(reason)
                self.assertEqual(extended, original +
                                 f":{period:x}:{frame['mode_base']:x}:{frame['fixed_writer']:x}")
                self.assertEqual(scenario, before)
                if period == 20000000:
                    self.assertEqual(qemu_virtual_cell_property(
                        image, config, {**scenario, "access_response_probe": False}),
                        (extended, None))
                    response, response_reason = qemu_virtual_cell_property(
                        image, config, {**scenario, "access_response_probe": True})
                    self.assertIsNone(response_reason)
                    self.assertEqual(response, extended + ",access-response-probe=on")
                    assigned, assignment_reason = qemu_virtual_cell_property(
                        image, config, {**scenario, "access_response_probe": True,
                                        "access_assignment_code": 1})
                    self.assertIsNone(assignment_reason)
                    self.assertEqual(assigned, response + ",access-assignment-code=1")
                    self.assertEqual(qemu_virtual_cell_property(
                        image, config, {**scenario, "access_response_probe": True,
                                        "access_assignment_code": 0}), (response, None))
                    binding = dict(part.split("=", 1) for part in response.split(","))
                    self.assertEqual(len(binding["tx-init-probe"].split(":")), 11)
                    self.assertEqual(scenario, before)
            changed = bytearray(image)
            changed[frame["fixed_writer"] + 0x16] ^= 1
            self.assertEqual(qemu_virtual_cell_property(bytes(changed), config, scenario),
                             (None, "tx-frame-fixed-writer-unclosed"))
            self.assertEqual(qemu_virtual_cell_property(bytes(changed), config, cell),
                             (original, None))
            config.ram_size = 0
            self.assertEqual(qemu_virtual_cell_property(image, config, scenario),
                             (None, "tx-init-state-unmapped"))

    def test_access_assignment_code_requires_integer_and_response(self):
        for value in (None, True, False, -1, 129, 1.5, "1", []):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "access_assignment_code"):
                qemu_virtual_cell_property(b"", object(), {**CELL, "access_assignment_code": value})
        for value in (1, 128):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "requires access_response_probe"):
                qemu_virtual_cell_property(b"", object(), {**CELL, "access_assignment_code": value})
        self.assertEqual(qemu_virtual_cell_property(b"", object(), {**CELL, "access_assignment_code": 0}),
                         qemu_virtual_cell_property(b"", object(), CELL))

    def test_access_response_probe_requires_strict_bool_and_legacy_frame(self):
        frame = {**CELL, "tx_init_delay_ns": 1000000, "tx_frame_period_ns": 20000000}
        for value in (None, 0, 1, "true", []):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "access_response_probe"):
                qemu_virtual_cell_property(b"", object(), {**frame, "access_response_probe": value})
        with self.assertRaisesRegex(ValueError, "requires tx_frame_period_ns"):
            qemu_virtual_cell_property(b"", object(), {**CELL, "access_response_probe": True})
        with self.assertRaisesRegex(ValueError, "requires tx_init_delay_ns"):
            qemu_virtual_cell_property(b"", object(), {
                **CELL, "tx_frame_period_ns": 20000000, "access_response_probe": True})
        for sync in ("1a010603115dfffe0000000000004000000000000007436eb961",
                     "070103034f4264"):
            scenario = {**frame, "sync_message_hex": sync}
            self.assertEqual(qemu_virtual_cell_property(b"", object(), scenario),
                             (None, "primary-map-unsupported"))
            self.assertEqual(qemu_virtual_cell_property(
                b"", object(), {**scenario, "access_response_probe": False}),
                (None, "primary-map-unsupported"))
            with self.assertRaisesRegex(ValueError, "requires legacy packet layout"):
                qemu_virtual_cell_property(b"", object(), {**scenario, "access_response_probe": True})

    def test_traffic_decoder_probe_requires_explicit_boolean_and_assignment(self):
        for value in (None, 0, 1, "on", [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "traffic_decoder_probe"):
                qemu_virtual_cell_property(b"", object(), {**CELL, "traffic_decoder_probe": value})
        with self.assertRaisesRegex(ValueError, "requires access_assignment_code"):
            qemu_virtual_cell_property(b"", object(), {**CELL, "traffic_decoder_probe": True})
        self.assertEqual(qemu_virtual_cell_property(
            b"", object(), {**CELL, "traffic_decoder_probe": False}),
            (None, "primary-map-unsupported"))

    def test_traffic_frame_schema_before_image_binding(self):
        class AutoString(str):
            pass

        class AutoEqual:
            def __eq__(self, other):
                raise AssertionError("non-str equality must not run")

        cell = {**CELL, "tx_init_delay_ns": 1000000, "tx_frame_period_ns": 20000000,
                "access_response_probe": True, "access_assignment_code": 1,
                "traffic_decoder_probe": True}
        for value in (None, True, 24, b"00" * 24, "", "00" * 23, "00" * 25,
                      "gg" * 24, "00" * 23 + "01", "00" * 23 + " 0",
                      "AUTO", "Auto", " auto", "auto ", "auto00",
                      b"auto", AutoString("auto"), AutoEqual()):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "traffic_frame_hex"):
                qemu_virtual_cell_property(b"", object(), {**cell, "traffic_frame_hex": value})
        for frame in ("00" * 24, "auto"):
            for enabled in (False, None):
                scenario = {**cell, "traffic_frame_hex": frame}
                if enabled is None:
                    scenario.pop("traffic_decoder_probe")
                else:
                    scenario["traffic_decoder_probe"] = enabled
                with self.assertRaisesRegex(ValueError, "requires traffic_decoder_probe"):
                    qemu_virtual_cell_property(b"", object(), scenario)
        # CRC is a hardware result; the host accepts either protected-bit content.
        for frame in (TRAFFIC_FRAME_VALID, TRAFFIC_FRAME_BAD_CRC, "auto"):
            self.assertEqual(qemu_virtual_cell_property(
                b"", object(), {**cell, "traffic_frame_hex": frame}),
                (None, "primary-map-unsupported"))

    def test_traffic_decoder_binding_and_disabled_preservation(self):
        from contextlib import ExitStack
        from functools import lru_cache
        from unittest.mock import patch
        from msm5xxx_emulator.detection import baseband
        root = Path(os.environ.get(
            "MSM5XXX_TEST_FIRMWARE_ROOT", Path(__file__).resolve().parents[2] / "firmwares"))
        paths = [root / name for name in ("schx150.bin", "x350_VC22.bin")]
        if not all(path.is_file() for path in paths):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        # Reuse real immutable-image analyses across wiring-only counterexamples.
        with ExitStack() as stack:
            for name in ("find_search2_transport_profile", "find_search1_transport_profile",
                         "find_search1_abort_profile", "find_finger_transport_profile",
                         "find_decoder_init_profile", "find_combiner_clock_profile",
                         "find_paging_decoder_profile", "find_tx_init_profile",
                         "find_tx_frame_profile", "find_traffic_decoder_profile"):
                stack.enter_context(patch.object(
                    baseband, name, lru_cache(maxsize=4)(getattr(baseband, name))))
            for path in paths:
                image = path.read_bytes()
                tick = find_rex_5ms_sleep_timer(image)[1]
                config = SimpleNamespace(load_address=0, image_offset=0, rex_tick_address=tick,
                                         flash_size=len(image), ram_base=0x1000000, ram_size=0x800000)
                cell = {**CELL, "tx_init_delay_ns": 1000000, "tx_frame_period_ns": 20000000,
                        "access_response_probe": True, "access_assignment_code": 1}
                traffic = baseband.find_traffic_decoder_profile(image, tick)
                self.assertTrue(traffic["accepted"])
                with patch.object(baseband, "find_traffic_decoder_profile",
                                  wraps=baseband.find_traffic_decoder_profile) as finder:
                    enabled, reason = qemu_virtual_cell_property(
                        image, config, {**cell, "traffic_decoder_probe": True})
                    self.assertIsNone(reason)
                    disabled, reason = qemu_virtual_cell_property(
                        image, config, {**cell, "traffic_decoder_probe": False})
                    self.assertIsNone(reason)
                    absent, reason = qemu_virtual_cell_property(image, config, cell)
                    self.assertIsNone(reason)
                    self.assertEqual(disabled, absent)
                    self.assertEqual(finder.call_count, 1)
                value = ":".join(f"{traffic[key]:x}" for key in (
                    "isr", "reader", "status_reader", "initializer", "mode_base",
                    "layout_address", "layout_source", "linker_table_offset"))
                self.assertEqual(enabled, absent + ",decoder-traffic-source=" + value)
                for frame in (TRAFFIC_FRAME_VALID.upper(), TRAFFIC_FRAME_BAD_CRC.upper()):
                    received, reason = qemu_virtual_cell_property(
                        image, config, {**cell, "traffic_decoder_probe": True,
                                        "traffic_frame_hex": frame})
                    self.assertIsNone(reason)
                    self.assertEqual(received, enabled + ",decoder-traffic-frame=" + frame.lower())
                automatic, reason = qemu_virtual_cell_property(
                    image, config, {**cell, "traffic_decoder_probe": True,
                                    "traffic_frame_hex": "auto"})
                self.assertIsNone(reason)
                from msm5xxx_emulator.detection.service import find_origination_service_profile
                service = find_origination_service_profile(image, config.ram_base, config.ram_size)
                self.assertTrue(service["accepted"])
                service_fields = ":".join(f"{service[key]:x}" for key in (
                    "entry", "header_packer", "dispatcher", "revision_address"))
                self.assertEqual(automatic, enabled + ",traffic-service-source=" + service_fields)
                self.assertNotIn("decoder-traffic-frame=", automatic)
                from msm5xxx_emulator.detection import service as service_detector
                rejected_service = {"accepted": False, "reject_reason": "service-packer-unmatched"}
                with patch.object(service_detector, "find_origination_service_profile", return_value=rejected_service):
                    fallback, limit = qemu_virtual_cell_property(
                        image, config, {**cell, "traffic_decoder_probe": True, "traffic_frame_hex": "auto"})
                    self.assertEqual(fallback, enabled + ",decoder-traffic-frame=" + TRAFFIC_FRAME_VALID)
                    self.assertEqual(limit, "service-packer-unmatched")
                for key, broken_value, expected in (
                    ("code_dependencies", [(len(image), 4)], "service-packer-code-unmapped"),
                    ("ram_dependencies", [(config.ram_base+config.ram_size, 1)], "service-packer-state-unmapped")):
                    bad_service = {**service, key: broken_value}
                    with patch.object(service_detector, "find_origination_service_profile", return_value=bad_service):
                        fallback, limit = qemu_virtual_cell_property(
                            image, config, {**cell, "traffic_decoder_probe": True, "traffic_frame_hex": "auto"})
                        self.assertEqual(fallback, enabled + ",decoder-traffic-frame=" + TRAFFIC_FRAME_VALID)
                        self.assertEqual(limit, expected)
                self.assertNotEqual(image[traffic["layout_source"] + 20], 24)
                for layout_source in (traffic["layout_source"] + 8, len(image)):
                    unsupported_layout = {**traffic, "layout_source": layout_source}
                    with patch.object(baseband, "find_traffic_decoder_profile", return_value=unsupported_layout):
                        self.assertEqual(qemu_virtual_cell_property(
                            image, config, {**cell, "traffic_decoder_probe": True,
                                            "traffic_frame_hex": TRAFFIC_FRAME_VALID}),
                            (None, "traffic-full-frame-layout-unsupported"))
                for layout_source in (traffic["layout_source"] + 8, len(image), None, True):
                    unsupported_layout = {**traffic, "layout_source": layout_source}
                    with patch.object(baseband, "find_traffic_decoder_profile", return_value=unsupported_layout):
                        automatic = qemu_virtual_cell_property(
                            image, config, {**cell, "traffic_decoder_probe": True,
                                            "traffic_frame_hex": "auto"})
                        if layout_source == traffic["layout_source"] + 8:
                            erasure = qemu_virtual_cell_property(
                                image, config, {**cell, "traffic_decoder_probe": True})
                            self.assertEqual(automatic, erasure)
                            self.assertIsNone(automatic[1])
                            self.assertNotIn("decoder-traffic-frame=", automatic[0])
                        else:
                            self.assertEqual(automatic, (None, "traffic-full-frame-layout-unsupported"))
                for field, change, expected in (
                    ("code_dependencies", (len(image), 2), "traffic-decoder-code-unmapped"),
                    ("ram_dependencies", (0x1800000, 4), "traffic-decoder-state-unmapped"),
                    ("irq_mask", None, "traffic-decoder-controller-mismatch")):
                    broken = deepcopy(traffic)
                    if change is None:
                        broken[field] ^= 1
                    else:
                        broken[field] = [*broken[field], change]
                    with patch.object(baseband, "find_traffic_decoder_profile", return_value=broken):
                        for frame_fields in ({}, {"traffic_frame_hex": "auto"},
                                             {"traffic_frame_hex": TRAFFIC_FRAME_VALID}):
                            self.assertEqual(qemu_virtual_cell_property(
                                image, config, {**cell, "traffic_decoder_probe": True, **frame_fields}),
                                (None, expected))
                with patch.object(baseband, "find_traffic_decoder_profile",
                                  return_value={"accepted": False, "reject_reason": "unclosed"}):
                    for frame_fields in ({}, {"traffic_frame_hex": "auto"},
                                         {"traffic_frame_hex": TRAFFIC_FRAME_VALID}):
                        self.assertEqual(qemu_virtual_cell_property(
                            image, config, {**cell, "traffic_decoder_probe": True, **frame_fields}),
                            (None, "unclosed"))
