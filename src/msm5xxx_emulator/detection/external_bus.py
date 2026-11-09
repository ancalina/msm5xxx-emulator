"""Compose external-device properties from independent code evidence."""
from __future__ import annotations

import struct

from .external_devices import (
    detect_boot_strap,
    detect_boot_gpio_bit9,
    detect_boot_uart,
    detect_external_cs0a,
    detect_external_cs09,
    detect_external_lcd,
    detect_external_ram,
    detect_external_status,
    detect_external_windows,
    _thumb_literal,
)
from .external_plan import EXTERNAL_BUS_CONTRACTS, _resolve_external_claims
from .memory_map import detect_linker_memory_map
from .gpio_pmic import find_gpio_pmic_profile
from .selector_lcd import find_selector_lcd_profile


def _capability(evidence: list[dict], **parameters: object) -> dict:
    return {
        "status": "experimental-contract",
        "parameters": parameters,
        "evidence": evidence,
    }


def _guard(image: bytes, start: int, length: int, role: str) -> dict | None:
    if start < 0 or length <= 0 or start + length > len(image):
        return None
    return {"start": start, "end": start + length,
            "expected": image[start:start + length].hex(), "role": role}


def _thumb_literal_guard(image: bytes, pc: int, role: str) -> dict | None:
    if pc < 0 or pc + 2 > len(image):
        return None
    word = struct.unpack_from("<H", image, pc)[0]
    if word & 0xF800 != 0x4800:
        return None
    pool = ((pc + 4) & ~3) + (word & 0xFF) * 4
    return _guard(image, pool, 4, role)


def _literal_span(image: bytes, pc: int, *, thumb: bool = True) -> list[int] | None:
    if thumb:
        guard = _thumb_literal_guard(image, pc, "literal")
        return None if guard is None else [guard["start"], guard["end"] - guard["start"]]
    if pc < 0 or pc & 3 or pc + 4 > len(image):
        return None
    word = struct.unpack_from("<I", image, pc)[0]
    if word & 0x0F7F0000 != 0x051F0000:
        return None
    delta = word & 0xFFF
    literal = pc + 8 + (delta if word & 0x00800000 else -delta)
    return [literal, 4] if 0 <= literal <= len(image) - 4 else None


def _guards_for(image: bytes, capability: dict, role: str) -> list[dict]:
    """Capture only code/data spans named by detector evidence."""
    guards = []
    seen = set()
    for item in capability.get("evidence", []):
        if not isinstance(item, dict):
            continue
        span = item.get("span")
        if (isinstance(span, (tuple, list)) and len(span) == 2
                and all(isinstance(value, int) for value in span)):
            guard = _guard(image, span[0], span[1], role)
            if guard is not None:
                guards.append(guard)
            for extra in item.get("extra_spans", []):
                if (isinstance(extra, (tuple, list)) and len(extra) == 2
                        and all(isinstance(value, int) for value in extra)):
                    guard = _guard(image, extra[0], extra[1], role)
                    if guard is not None:
                        guards.append(guard)
            continue
        for key in ("body", "table", "at", "load", "use", "branch", "spin",
                    "store", "mov", "lsl", "struct", "table_offset"):
            offset = item.get(key)
            if not isinstance(offset, int) or (offset, key) in seen:
                continue
            seen.add((offset, key))
            length = (0x17C if key == "body" else 28 if key == "table"
                      else 20 if key == "table_offset" else 2)
            guard = _guard(image, offset, length, f"{role}:{key}")
            if guard is not None:
                guards.append(guard)
    return guards


def _available_external_ram(base: int, size: int,
                            primary: tuple[int, int] | None,
                            reservations: tuple[tuple[int, int], ...]
                            ) -> tuple[int, int] | None:
    """Subtract backed primary RAM, preserving its reserved apertures."""
    if (type(base) is not int or type(size) is not int or size <= 0
            or (base | size) & 0xfff or base + size > 0x100000000):
        return None
    covered = []
    if primary is not None:
        start, length = primary
        if type(start) is not int or type(length) is not int or start < 0 or length < 0:
            return None
        covered = [(start, start + length)] if length else []
    for start, length in reservations:
        if (type(start) is not int or type(length) is not int or length <= 0
                or (start | length) & 0xfff or primary is None
                or not primary[0] <= start < start + length <= sum(primary)):
            return None
        next_covered = []
        for low, high in covered:
            if high <= start or start + length <= low:
                next_covered.append((low, high))
            else:
                if low < start:
                    next_covered.append((low, start))
                if start + length < high:
                    next_covered.append((start + length, high))
        covered = next_covered
    remaining = [(base, base + size)]
    for start, end in covered:
        next_remaining = []
        for low, high in remaining:
            if high <= start or end <= low:
                next_remaining.append((low, high))
            else:
                if low < start:
                    next_remaining.append((low, start))
                if end < high:
                    next_remaining.append((end, high))
        remaining = next_remaining
    if not remaining:
        return 0, 0
    if len(remaining) != 1:
        return None
    low, high = remaining[0]
    if (low | high) & 0xfff:
        return None
    return low, high - low


def _ram_reset_guards(image: bytes, targets: set[int]) -> list[dict]:
    """Guard the reset interworking helper that reaches a RAM test entry."""
    if len(image) < 8:
        return []
    vector = struct.unpack_from("<I", image, 0)[0]
    if vector & 0xFF000000 != 0xEA000000:
        return []
    delta = (vector & 0xFFFFFF) << 2
    if delta & 0x02000000:
        delta -= 0x04000000
    reset = 8 + delta
    if reset < 0 or reset >= len(image):
        return []
    result = [{"span": [0, 4]}, {"span": [reset, min(0x40, len(image) - reset)]}]
    for pc in range(reset, min(reset + 0x400, len(image) - 24), 4):
        words = struct.unpack_from("<5I", image, pc)
        if not (words[0] & 0xFFFFF000 == 0xE59F4000
                and words[1] == 0xE3140001
                and words[2] & 0xFFFFF000 == 0x159FE000
                and words[3] & 0xFFFFF000 == 0x059FE000
                and words[4] == 0xE12FFF14):
            continue
        target_pool = pc + 8 + (words[0] & 0xFFF)
        if target_pool > len(image) - 4:
            continue
        target = struct.unpack_from("<I", image, target_pool)[0]
        if target not in targets:
            continue
        result.extend((
            {"span": [pc, 24]},
            {"span": [target_pool, 4]},
            {"span": [pc + 20 + (words[3] & 0xFFF), 4]},
            {"span": [pc + 16 + (words[2] & 0xFFF), 4]},
        ))
    return result


def detect_external_bus(
    image: bytes,
    *,
    ram_base: int | None = None,
    ram_size: int | None = None,
    reserved_ram: tuple[tuple[int, int], ...] = (),
) -> tuple[dict | None, str]:
    """Build the final QEMU property set from per-capability evidence.

    Linker descriptors are the preferred source for a 0x14000000 RAM extent;
    the closed reset-linked readback detector is the fallback. Chip-select
    writes, status readers, panel stores, and GPIO polls remain independent.
    ``ram_base``/``ram_size`` describe the primary RAM interval to subtract
    from the external bank. Reserved apertures remain available for backing.
    """
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-bus-image-not-bytes"

    linker, _ = detect_linker_memory_map(image)
    ram_test, ram_reason = detect_external_ram(image)
    linker_windows = [] if linker is None else [
        window for window in linker.get("ram_windows", [])
        if 0x14000000 <= window.get("base", -1)
        < window.get("base", -1) + window.get("size", 0) <= 0x15000000
        and window.get("size", 0) > 0
    ]
    linked_ram = bool(linker_windows)
    ram = None
    if linked_ram:
        start = 0x14000000
        end = max(window["base"] + window["size"] for window in linker_windows)
        if ram_test is not None:
            end = max(end, ram_test["ram_test"]["base"] + ram_test["ram_test"]["size"])
        size = max(0x1000, (end - start + 0xFFF) & ~0xFFF)
        source_evidence = [{"span": [region["evidence"]["table_offset"], 20],
                            "kind": region.get("kind"), "exec": region.get("exec"),
                            "size": region.get("size")}
                           for region in linker.get("regions", [])
                           if start <= region.get("exec", -1)
                           < region.get("exec", -1) + region.get("size", 0) <= end
                           and isinstance(region.get("evidence", {}).get("table_offset"), int)]
        for region in linker.get("regions", []):
            if not (start <= region.get("exec", -1)
                    < region.get("exec", -1) + region.get("size", 0) <= end):
                continue
            refs = region.get("evidence", {}).get("references", [])
            for ref in refs:
                instruction = ref.get("instruction")
                literal = ref.get("literal")
                if isinstance(instruction, int):
                    source_evidence.append({"span": [instruction, 2 if ref.get("thumb") else 4]})
                if isinstance(literal, int):
                    source_evidence.append({"span": [literal, 4]})
        if isinstance(linker.get("reset", {}).get("offset"), int):
            source_evidence.extend(({"span": [0, 4]},
                                    {"span": [linker["reset"]["offset"],
                                              min(0x40, len(image) - linker["reset"]["offset"])]}))
        if ram_test is not None:
            test = ram_test["ram_test"]
            source_evidence.extend([test] + _ram_reset_guards(
                image, {test["entry"], test["entry"] | 1,
                        test["body"], test["body"] | 1}))
        ram = {"base": start, "size": size, "source": "linker",
               "evidence": source_evidence}
    elif ram_test is not None:
        test = ram_test["ram_test"]
        ram = {"base": test["base"], "size": test["size"], "source": "readback-test",
               "evidence": [test] + _ram_reset_guards(
                   image, {test["entry"] | 1, test["entry"], test["body"] | 1,
                           test["body"]})}

    ram_allocation = None
    allocation_rejection = None
    if ram is not None:
        if (ram_base is None) != (ram_size is None):
            allocation_rejection = "primary-ram-context-incomplete"
        else:
            primary = None if ram_base is None else (ram_base, ram_size)
            available = _available_external_ram(ram["base"], ram["size"], primary, reserved_ram)
            if available is None:
                allocation_rejection = "external-ram-allocation-conflict"
            elif available[1]:
                ram_allocation = available

    selector_lcd, _ = find_selector_lcd_profile(image)
    pmic, _ = find_gpio_pmic_profile(image)
    cs0a, _ = detect_external_cs0a(image)
    cs09, _ = detect_external_cs09(image)
    uart, _ = detect_boot_uart(image)
    gpio_boot, _ = detect_boot_gpio_bit9(image)
    strap, _ = detect_boot_strap(image)
    status, _ = detect_external_status(image)
    lcd, _ = detect_external_lcd(image)
    windows, _ = detect_external_windows(image)
    windows = windows or {}

    capabilities: dict[str, dict] = {}
    if ram is not None:
        capabilities["external_ram"] = _capability(
            ram["evidence"], base=ram["base"], size=ram["size"], source=ram["source"],
            allocation=list(ram_allocation) if ram_allocation else None)
    if cs0a is not None:
        evidence = []
        for site in cs0a["sites"]:
            if site["kind"] == "literal-access":
                evidence.append({**site,
                    "span": [site["load"], site["use"] + site["instruction_width"] - site["load"]],
                    "extra_spans": [*site.get("extra_spans", []), [site["literal"], 4]]})
                continue
            at = site["at"]
            extras = []
            loads = (at,) if site["kind"] == "controller-config" else (at + 4, at + 10)
            for pc in loads:
                span = _literal_span(image, pc)
                if span is not None:
                    extras.append(span)
            evidence.append({**site, "span": [max(0, at - 12), 32],
                             "extra_spans": extras})
        capabilities["external_cs0a"] = _capability(evidence)
    if cs09 is not None:
        evidence = []
        for item in cs09["accesses"]:
            evidence_item = {**item, "span": [item["load"],
                                                  item["use"] + item.get("instruction_width", 2) - item["load"]]}
            literal = _literal_span(image, item["load"], thumb=item.get("thumb", True))
            if literal is not None:
                evidence_item["extra_spans"] = [literal]
            evidence.append(evidence_item)
        capabilities["external_cs09"] = _capability(evidence)
    if strap is not None:
        evidence = []
        for item in strap["sites"]:
            evidence_item = {**item, "span": [item["at"],
                                                  item["branch"] + 2 - item["at"]]}
            literal = _literal_span(image, item["at"])
            if literal is not None:
                evidence_item["extra_spans"] = [literal]
            evidence.append(evidence_item)
        capabilities["strap_bit2"] = _capability(evidence, value=4)
    if status is not None:
        evidence = []
        for item in status["sites"]:
            evidence_item = {**item}
            if "span" not in evidence_item:
                evidence_item["span"] = [item["at"], 10]
            extras = list(evidence_item.get("extra_spans", []))
            literal = _literal_span(image, item["at"])
            if literal is not None and literal not in extras:
                extras.append(literal)
            if extras:
                evidence_item["extra_spans"] = extras
            evidence.append(evidence_item)
        capabilities["status_0b000408"] = _capability(evidence, initial_value=0, write_policy="readback")
    for address, name in ((0x08C00000, "08c"), (0x1A000000, "1a"),
                          (0x0B000000, "0b"), (0x18000000, "18"),
                          (0x1C000000, "1c")):
        accesses = windows.get(f"{address:08x}", [])
        if address == 0x0B000000:
            accesses = [item for item in accesses if item["address"] != 0x0B000408
                        or item.get("access_size", 2) > 2]
        evidence = []
        for item in accesses:
            evidence_item = {**item, "span": [item["load"],
                                                  item["use"] + item.get("instruction_width", 2) - item["load"]]}
            literal = _literal_span(image, item["load"], thumb=item.get("thumb", True))
            if literal is not None:
                evidence_item["extra_spans"] = [literal]
            evidence.append(evidence_item)
        if evidence:
            capabilities[f"window_{name}"] = _capability(
                evidence, base=address, initial_value=0, write_policy="readback",
                hardware_semantics="unknown")
    if selector_lcd is not None and lcd is not None and any(
            item["address"] == 0x1c000000 for item in lcd["writers"]):
        capabilities["lcd_1c_selector"] = _capability(
            selector_lcd["evidence"], mode="selector-data",
            width=selector_lcd["width"], height=selector_lcd["height"])
    if pmic is not None:
        capabilities["gpio_pmic_serial"] = _capability(
            pmic["evidence"] + pmic.get("extra_spans", []), ports=[0x030006e8, 0x03000720, 0x030006f4],
            register_count=64, reset_value=0, write_policy="readback")
    if gpio_boot is not None:
        capabilities["boot_gpio_bit9"] = _capability(
            gpio_boot["sites"], gpio=0x03000720, bit=9, read_value=0)
    if uart is not None:
        uart_evidence = []
        for at in uart["polls"]:
            uart_evidence.append({"span": [at, 20]})
            for pc in (at, at + 10):
                literal = _thumb_literal_guard(image, pc, "uart-literal")
                if literal is not None:
                    uart_evidence.append({"span": [literal["start"],
                                                   literal["end"] - literal["start"]]})
        for at in uart["inits"]:
            uart_evidence.append({"span": [at, 10]})
            begin = max(0, at - 0x30)
            for pc in range(at + 2, begin - 1, -2):
                if pc + 2 > len(image):
                    continue
                word = struct.unpack_from("<H", image, pc)[0]
                if word & 0xF800 == 0x4800 and (word >> 8) & 7 == 1:
                    literal = _thumb_literal_guard(image, pc, "uart-cr-literal")
                    if literal is not None:
                        uart_evidence.append({"span": [pc, 2]})
                        uart_evidence.append({"span": [literal["start"],
                                               literal["end"] - literal["start"]]})
                    break
        for link in uart["links"]:
            if link["link"] == "bl":
                uart_evidence.append({"span": [link["bl"], 4]})
            else:
                uart_evidence.append({"span": [link["init"], link["poll"] - link["init"] + 2]})
        capabilities["boot_uart"] = _capability(
            uart_evidence, base=0x03000B10, status_offset=4,
            tx_offset=8, command_offset=12)
    if lcd is not None:
        writers = lcd["writers"]
        spins = lcd["bit21"]
        if writers:
            by_base: dict[int, list[dict]] = {}
            for item in writers:
                by_base.setdefault(item["address"], []).append(item)
            writer_evidence = []
            for item in writers:
                start = item.get("mov", item.get("load"))
                evidence = {**item, "span": [start,
                    item["store"] + item.get("instruction_width", 2) - start]}
                if isinstance(item.get("literal"), int):
                    evidence["extra_spans"] = [*item.get("extra_spans", []),
                                                [item["literal"], 4]]
                writer_evidence.append(evidence)
            capabilities["external_bus_binding"] = _capability(writer_evidence)
            for base, name in ((0x18000000, "18"), (0x1A000000, "1a"),
                               (0x1C000000, "1c")):
                if base not in by_base:
                    continue
                evidence = [item for item in writer_evidence
                            if item["address"] == base]
                capabilities[f"panel_command_writes_{name}"] = _capability(
                    evidence, base=base)
                capabilities[f"panel_protocol_{name}"] = {
                    "status": "unknown",
                    "parameters": {"reason": "addressed stores do not establish panel framing"},
                    "evidence": evidence,
                }
                capabilities[f"lcd_trace_{name}"] = _capability(evidence, base=base)
        if spins:
            evidence = []
            for item in spins:
                evidence_item = {**item, "span": [item["at"],
                                                     item["spin"] + 4 - item["at"]]}
                literal = _literal_span(image, item["at"])
                extras = [] if literal is None else [literal]
                extras.append([item["struct"] + 4, 4])
                evidence_item["extra_spans"] = extras
                evidence.append(evidence_item)
            capabilities["gpio_ready_bit21"] = _capability(
                evidence, gpio=0x03000720, bit=21)

    props: dict[str, bool | int] = {}
    if ram_allocation is not None:
        props["external-ram-base"], props["external-ram-size"] = ram_allocation
    props["external-cs09"] = cs09 is not None
    props["external-cs0a"] = cs0a is not None
    if strap is not None:
        props["external-strap-value"] = 4
    if status is not None:
        props["experimental-contract-status-0b408"] = True
    if windows.get("08c00000"):
        props["external-window-08c"] = True
    if windows.get("1a000000"):
        props["external-window-1a"] = True
    if lcd is not None:
        for address, prop in ((0x18000000, "external-lcd-18"),
                              (0x1A000000, "external-lcd-1a"),
                              (0x1C000000, "external-lcd-1c")):
            props[prop] = any(
                item["address"] == address for item in lcd["writers"])
    for address, name in ((0x0B000000, "0b"), (0x18000000, "18"),
                          (0x1C000000, "1c")):
        accesses = windows.get(f"{address:08x}", [])
        if address == 0x0B000000:
            accesses = [item for item in accesses if item["address"] != 0x0B000408
                        or item.get("access_size", 2) > 2]
        if accesses:
            props[f"experimental-contract-window-{name}"] = True
    props["external-uart"] = uart is not None
    props["gpio-ready-bit21"] = bool(lcd and lcd["bit21"])
    props["experimental-contract-gpio-bit9-low"] = gpio_boot is not None

    if pmic is not None:
        props["experimental-contract-gpio-pmic-serial"] = True

    if "lcd_1c_selector" in capabilities:
        props["experimental-contract-lcd-1c-selector"] = True

    window_rejections = {}
    if ram_base is not None and ram_size is not None:
        window_properties = ((prop, contract.capability, contract.allocation_base)
                             for prop, contract in EXTERNAL_BUS_CONTRACTS.items()
                             if contract.allocation_base is not None)
        for prop, name, base in window_properties:
            if not props.get(prop):
                continue
            available = _available_external_ram(
                base, 0x1000, (ram_base, ram_size), reserved_ram)
            if available == (base, 0x1000):
                continue
            reason = ("window-already-backed-by-primary-ram" if available == (0, 0)
                      else "window-allocation-conflict")
            window_rejections[name] = reason
            capabilities[name]["status"] = "unknown"
            capabilities[name]["parameters"]["mapping_rejection"] = reason
            if prop == "external-strap-value":
                del props[prop]
            else:
                props[prop] = False

    if not any(props.values()):
        if window_rejections:
            reason = ("external-window-allocation-conflict" if
                      "window-allocation-conflict" in window_rejections.values()
                      else "external-windows-already-backed-by-primary-ram")
            return None, reason
        return None, (ram_reason if ram is None else "external-device-mapping-not-required")

    if (props.get("experimental-contract-lcd-1c-selector")
            and not props.get("external-lcd-1c")):
        del props["experimental-contract-lcd-1c-selector"]

    def source_guards():
        selected_roles = {EXTERNAL_BUS_CONTRACTS[name].capability
                          for name, value in props.items() if value}
        guards = [guard for name in sorted(selected_roles)
                  for guard in _guards_for(image, capabilities[name], name)]
        unique = {(item["start"], item["end"], item["expected"]): item for item in guards}
        return sorted(unique.values(), key=lambda item: (item["start"], item["end"]))

    plan = {
        "version": 1,
        "memory_context": {
            "ram_base": ram_base,
            "ram_size": ram_size,
            "reserved_ram": [list(interval) for interval in reserved_ram],
        },
        "capabilities": capabilities,
        "machine_properties": props,
        "source_guards": source_guards(),
        "rejections": ({"external_ram": ram_reason} if ram is None else
                       {"external_ram": allocation_rejection} if allocation_rejection else {}),
    }
    plan["rejections"].update(window_rejections)
    if not plan["source_guards"]:
        return None, "external-device-source-unclosed"
    resolution = _resolve_external_claims(plan)
    conflicts = [item for item in resolution.decisions if item.status == "conflict"]
    if conflicts:
        surviving = dict(resolution.plan.properties)
        for name in tuple(props):
            if props[name] and name not in surviving:
                if type(props[name]) is bool:
                    props[name] = False
                else:
                    del props[name]
        for decision in conflicts:
            role = decision.capability.name.removeprefix("external:")
            capabilities[role]["status"] = "unknown"
            capabilities[role]["parameters"]["mapping_rejection"] = decision.reason
            plan["rejections"][role] = decision.reason
        plan["source_guards"] = source_guards()
        if not any(props.values()):
            return None, "external-device-resource-conflict"
    return plan, "accepted"
