"""Independent external-bus capabilities and transport binding checks."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection import external_bus
from msm5xxx_emulator.detection.external_bus import (
    _available_external_ram,
    detect_external_bus,
)
from msm5xxx_emulator.qemu.transport import qemu_external_bus_property
from test_external_devices import (
    ldr_literal, put16, put32, _ram_readback_image, _boot_gpio_bit9_image,
    _external_status_image,
)


def chip_select_only_image() -> bytes:
    image = bytearray(0x180)
    # Store controller reset values, then program its config register.
    put16(image, 0x20, ldr_literal(1, 0x20, 0x100), 0x6208, 0x2000,
          0x6288, 0x6248, ldr_literal(1, 0x2A, 0x100), 0x3140, 0x6108)
    put32(image, 0x100, 0x0A000080)
    return bytes(image)


def lcd_writer_image() -> bytes:
    image = bytearray(0x80)
    # Build 0x1C000000, shift it to the panel base, and store a byte at +0.
    put16(image, 0x10, 0x2007, 26 << 6, 0x7000)
    return bytes(image)


def ready_spin_image() -> bytes:
    image = bytearray(0x80)
    put16(image, 0x10, ldr_literal(1, 0x10, 0x40),
          0x6848, 0x6800, 10 << 6, 0xD400, 0xE7FE)
    put32(image, 0x40, 0x60)
    put32(image, 0x60, 0, 0x03000720)
    return bytes(image)


class ExternalBusTransportTests(unittest.TestCase):
    def test_chip_select_only_does_not_admit_external_ram(self) -> None:
        image = chip_select_only_image()
        plan, reason = detect_external_bus(image, ram_base=0x01000000, ram_size=0x800000)
        self.assertEqual(reason, "accepted")
        self.assertNotIn("external_ram", plan["capabilities"])
        self.assertNotIn("external-ram-base", plan["machine_properties"])
        self.assertTrue(plan["machine_properties"]["external-cs0a"])
        self.assertFalse(plan["machine_properties"]["external-cs09"])
        wire, reason = qemu_external_bus_property(
            plan, image, 0x01000000, 0x800000)
        self.assertIsNone(reason)
        self.assertEqual(wire, "external-cs0a=on")

    def test_existing_primary_ram_does_not_get_a_conflicting_window(self) -> None:
        image = chip_select_only_image()
        plan, _ = detect_external_bus(image, ram_base=0x0A000000, ram_size=0x100000)
        self.assertIsNone(plan)
        lcd = lcd_writer_image()
        plan, _ = detect_external_bus(lcd, ram_base=0x1C000000, ram_size=0x100000)
        self.assertIsNone(plan)

    def test_lcd_writer_and_ready_level_are_independent(self) -> None:
        lcd_image = lcd_writer_image()
        lcd_plan, reason = detect_external_bus(lcd_image)
        self.assertEqual(reason, "accepted")
        lcd_properties = lcd_plan["machine_properties"]
        self.assertTrue(lcd_properties["external-lcd-1c"])
        self.assertFalse(lcd_properties["gpio-ready-bit21"])

        ready_image = ready_spin_image()
        ready_plan, reason = detect_external_bus(ready_image)
        self.assertEqual(reason, "accepted")
        ready_properties = ready_plan["machine_properties"]
        self.assertTrue(ready_properties["gpio-ready-bit21"])
        self.assertFalse(ready_properties["external-lcd-18"])
        self.assertFalse(ready_properties["external-lcd-1a"])
        self.assertFalse(ready_properties["external-lcd-1c"])

    def test_ram_reset_halt_does_not_veto_independent_device_consumers(self) -> None:
        image = bytearray(_ram_readback_image(halt_last_page=True))
        image[0x400:0x412] = chip_select_only_image()[0x20:0x32]
        put16(image, 0x400, ldr_literal(1, 0x400, 0x480))
        put16(image, 0x40A, ldr_literal(1, 0x40A, 0x480))
        put32(image, 0x480, 0x0A000080)
        put16(image, 0x500, 0x2007, 26 << 6, 0x7000)
        put16(image, 0x540, ldr_literal(0, 0x540, 0x584), 0x6001)
        put32(image, 0x584, 0x09000010)
        plan, reason = detect_external_bus(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertNotIn("external-ram-base", plan["machine_properties"])
        self.assertIn("last-page-halt", plan["rejections"]["external_ram"])
        self.assertTrue(plan["machine_properties"]["external-cs0a"])
        self.assertTrue(plan["machine_properties"]["external-cs09"])
        self.assertTrue(plan["machine_properties"]["external-lcd-1c"])
        for name in ("external_cs0a", "external_cs09", "lcd_trace_1c"):
            self.assertEqual(plan["capabilities"][name]["status"], "experimental-contract")
            self.assertTrue(plan["capabilities"][name]["evidence"])
        self.assertEqual(plan["capabilities"]["panel_protocol_1c"]["status"], "unknown")
        self.assertIn("panel_command_writes_1c", plan["capabilities"])

    def test_panel_input_contract_is_independent_and_source_guarded(self) -> None:
        image = _boot_gpio_bit9_image()
        plan, reason = detect_external_bus(image)
        self.assertEqual(reason, "accepted")
        props = plan["machine_properties"]
        self.assertTrue(props["experimental-contract-gpio-bit9-low"])
        self.assertFalse(props["gpio-ready-bit21"])
        self.assertFalse(any(props.get(name) for name in (
            "external-lcd-18", "external-lcd-1a", "external-lcd-1c")))
        wire, reason = qemu_external_bus_property(plan, image, None, None)
        self.assertEqual(wire, "experimental-contract-gpio-bit9-low=on")
        self.assertIsNone(reason)
        changed = bytearray(image)
        changed[0x4180] ^= 1
        self.assertEqual(qemu_external_bus_property(plan, bytes(changed), None, None),
                         (None, "source-guard-mismatch"))

    def test_memory_context_must_match_exactly(self) -> None:
        image = chip_select_only_image()
        plan, _ = detect_external_bus(
            image, ram_base=0x01000000, ram_size=0x800000)
        accepted, reason = qemu_external_bus_property(
            plan, image, 0x01000000, 0x800000)
        self.assertEqual(accepted, "external-cs0a=on")
        self.assertIsNone(reason)
        for base, size, reservation in (
                (0x01000000, 0x400000, None),
                (0x01001000, 0x800000, None),
                (0x01000000, 0x800000, (0x01001000, 0x1000)),
        ):
            self.assertEqual(
                qemu_external_bus_property(plan, image, base, size, reserved_ram=reservation),
                (None, "memory-context-mismatch"),
            )

    def test_zero_strap_and_uart_logging_without_uart_are_rejected(self) -> None:
        image = chip_select_only_image()
        plan, _ = detect_external_bus(image)
        plan["machine_properties"]["external-strap-value"] = 0
        self.assertEqual(qemu_external_bus_property(plan, image, None, None),
                         (None, "invalid-strap-value"))
        del plan["machine_properties"]["external-strap-value"]
        plan["machine_properties"]["external-uart-tx-log"] = True
        plan["capabilities"]["boot_uart"] = copy.deepcopy(
            plan["capabilities"]["external_cs0a"])
        self.assertEqual(qemu_external_bus_property(plan, image, None, None),
                         (None, "uart-log-without-uart"))

    def test_source_and_loaded_image_guards_reject_stale_plans(self) -> None:
        image = chip_select_only_image()
        plan, _ = detect_external_bus(image)
        guard = plan["source_guards"][0]
        stale_source = bytearray(image)
        stale_source[guard["start"]] ^= 1
        self.assertEqual(
            qemu_external_bus_property(plan, bytes(stale_source), None, None),
            (None, "source-guard-mismatch"),
        )
        stale_loaded = bytearray(image)
        stale_loaded[guard["start"]] ^= 1
        self.assertEqual(
            qemu_external_bus_property(plan, image, None, None, bytes(stale_loaded)),
            (None, "loaded-source-guard-mismatch"),
        )

    def test_loaded_status_function_entry_and_branch_are_guarded(self) -> None:
        image = bytes(_external_status_image())
        plan, reason = detect_external_bus(image)
        self.assertEqual(reason, "accepted")
        for offset in (0x80, 0x8C):
            with self.subTest(offset=hex(offset)):
                loaded = bytearray(image)
                loaded[offset] ^= 1
                self.assertEqual(
                    qemu_external_bus_property(plan, image, None, None, bytes(loaded)),
                    (None, "loaded-source-guard-mismatch"),
                )

    def test_arm_negative_literal_and_full_access_are_guarded(self) -> None:
        image = bytearray(0x60)
        # LDR r1, [pc, #-0x18] at 0x40 reads the literal at 0x30.
        # STRB r0, [r1, #4] at 0x44 accesses 0x09000004.
        put32(image, 0x30, 0x09000000)
        put32(image, 0x40, 0xE51F1018, 0xE5C10004)
        original = bytes(image)
        plan, reason = detect_external_bus(original)
        self.assertEqual(reason, "accepted")
        self.assertTrue(plan["machine_properties"]["external-cs09"])
        guards = {(guard["start"], guard["end"]) for guard in plan["source_guards"]}
        self.assertIn((0x30, 0x34), guards)
        self.assertTrue(any(start <= 0x44 and end >= 0x48
                            for start, end in guards))
        self.assertIsNone(qemu_external_bus_property(plan, original, None, None)[1])

        stale_literal = bytearray(original)
        stale_literal[0x33] ^= 1
        self.assertEqual(
            qemu_external_bus_property(plan, bytes(stale_literal), None, None),
            (None, "source-guard-mismatch"),
        )
        stale_access = bytearray(original)
        stale_access[0x47] ^= 1
        self.assertEqual(
            qemu_external_bus_property(plan, bytes(stale_access), None, None),
            (None, "source-guard-mismatch"),
        )

    def test_transport_serializer_does_not_rerun_detectors(self) -> None:
        image = chip_select_only_image()
        plan, _ = detect_external_bus(image)
        detector_names = (
            "detect_external_ram", "detect_external_cs0a", "detect_external_cs09",
            "detect_boot_uart", "detect_boot_strap", "detect_boot_gpio_bit9",
            "detect_external_status",
            "detect_external_lcd", "detect_external_windows",
        )
        with patch.multiple(external_bus, **{
                name: patcher for name in detector_names
                for patcher in (unittest.mock.Mock(side_effect=AssertionError(name)),)
        }):
            wire, reason = qemu_external_bus_property(plan, image, None, None)
        self.assertEqual(wire, "external-cs0a=on")
        self.assertIsNone(reason)

    def test_property_requires_its_own_capability(self) -> None:
        image = chip_select_only_image()
        plan, _ = detect_external_bus(image)
        altered = copy.deepcopy(plan)
        altered["machine_properties"]["gpio-ready-bit21"] = True
        self.assertEqual(qemu_external_bus_property(altered, image, None, None),
                         (None, "missing-property-capability"))

    def test_linker_extent_is_preferred_without_inventing_capacity(self) -> None:
        image = bytearray(0x300)
        put32(image, 0, 0xEA000006)
        put32(image, 0x20, 0xE59F0004, 0xEAFFFFFE)
        put32(image, 0x2C, 0x100)
        put32(image, 0x100, 0x200, 0x14000000, 0x20, 0x14000020, 0x40)
        plan, reason = detect_external_bus(bytes(image))
        self.assertEqual(reason, "accepted")
        ram = plan["capabilities"]["external_ram"]["parameters"]
        self.assertEqual(ram["source"], "linker")
        self.assertEqual(ram["allocation"], [0x14000000, 0x1000])

    def test_linker_ram_extent_rounds_to_pages_not_power_of_two(self) -> None:
        image = bytes(0x100)
        linker = {
            "ram_windows": [{"base": 0x14000000, "size": 0x3000}],
            "regions": [],
            "reset": {"offset": 0x20},
        }
        with patch.object(external_bus, "detect_linker_memory_map",
                          return_value=(linker, "accepted")), \
             patch.object(external_bus, "detect_external_ram",
                          return_value=(None, "external-ram-shape-absent")):
            plan, reason = detect_external_bus(image)
        self.assertEqual(reason, "accepted")
        ram = plan["capabilities"]["external_ram"]["parameters"]
        self.assertEqual(ram["size"], 0x3000)
        self.assertEqual(ram["allocation"], [0x14000000, 0x3000])

    def test_readback_bank_allocation_is_exported_before_transport(self) -> None:
        image = _ram_readback_image(halt_last_page=False)
        plan, _ = detect_external_bus(image, ram_base=0x14000000, ram_size=0x400000)
        self.assertEqual(plan["machine_properties"]["external-ram-base"], 0x14400000)
        wire, reason = qemu_external_bus_property(plan, image, 0x14000000, 0x400000)
        self.assertIsNone(reason)
        self.assertIn("external-ram-size=4194304", wire)
        covered, _ = detect_external_bus(image, ram_base=0x14000000, ram_size=0x800000)
        self.assertIsNone(covered)

    def test_detection_exports_the_final_memory_context(self) -> None:
        from msm5xxx_emulator.detection import detect
        image = bytearray(chip_select_only_image())
        for offset in range(0, 32, 4):
            put32(image, offset, 0xEA000006)
        put32(image, 0x20, 0xEAFFFFFE)
        # Place the controller sequence outside the reset-vector landing.
        original = chip_select_only_image()
        image[0x60:0x72] = original[0x20:0x32]
        put16(image, 0x60, ldr_literal(1, 0x60, 0x100))
        put16(image, 0x6A, ldr_literal(1, 0x6A, 0x100))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.bin"
            path.write_bytes(image)
            config = detect(path)
        plan = config.external_bus
        self.assertIsNotNone(plan)
        self.assertEqual(plan["memory_context"]["ram_base"], config.ram_base)
        self.assertEqual(plan["memory_context"]["ram_size"], config.ram_size)
        self.assertIsNone(qemu_external_bus_property(
            plan, bytes(image), config.ram_base, config.ram_size)[1])

    def test_primary_overlap_and_reserved_aperture_allocation(self) -> None:
        external = (0x14000000, 0x800000)
        self.assertEqual(_available_external_ram(*external, None, ()), external)
        self.assertEqual(
            _available_external_ram(*external, (0x14000000, 0x400000), ()),
            (0x14400000, 0x400000),
        )
        self.assertEqual(
            _available_external_ram(*external, (0x14000000, 0x800000), ()),
            (0, 0)
        )
        self.assertEqual(
            _available_external_ram(
                *external, (0x14000000, 0x800000),
                ((0x147FF000, 0x1000),)),
            (0x147FF000, 0x1000),
        )
        self.assertIsNone(
            _available_external_ram(
                *external, (0x13F00000, 0x600000),
                ((0x14200000, 0x1000),)),
            "an interior reserved aperture splits the external bank",
        )


if __name__ == "__main__":
    unittest.main()
