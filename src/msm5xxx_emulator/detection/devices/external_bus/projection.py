"""Validation and serialization for source-derived external bus plans."""
from __future__ import annotations
from types import MappingProxyType
from typing import NamedTuple
from msm5xxx_emulator.detection.capabilities import Capability, Decision, Evidence, ResourceClaim, resolve_proposals
from msm5xxx_emulator.detection.facts import facts_for

class ExternalProperty(NamedTuple):
    kind: str
    capability: str
    allocation_base: int | None = None
    claim: ResourceClaim | None = None

def _mapping(role, base, size=0x1000, *, shared=None, allocation=True, allocation_base=None, kind="boolean"):
    # Explicit sharing describes native routing/overlays, never resemblance
    # between two firmware families or an arbitrary priority score.
    claim = ResourceClaim("address", role, base, base + size, shared_resource=shared, semantics=shared)
    reservation = (base if allocation_base is None else allocation_base) if allocation else None
    return ExternalProperty(kind, role, reservation, claim)

def _pin(role, bit):
    return ExternalProperty("boolean", role, claim=ResourceClaim("gpio", role, 0x03000720, 0x03000724, mask=1 << bit))

EXTERNAL_BUS_CONTRACTS = MappingProxyType({ "external-lcd-18-dcs": ExternalProperty("boolean", "lcd_18_window"), "external-lcd-18-window": ExternalProperty("boolean", "lcd_18_window"), "external-lcd-18-data-offset": ExternalProperty("integer", "lcd_18_window"), "external-indexed-18": ExternalProperty("boolean", "indexed_18"), "external-cs09": _mapping("external_cs09", 0x09000000, shared= "cs09-strap"), "external-cs0a": _mapping("external_cs0a",
    0x0A000000), "external-window-08c": _mapping("window_08c", 0x08C00000), "external-window-1a": _mapping("window_1a", 0x1A000000, shared="window-panel-1a"),
    "experimental-contract-status-0b408": _mapping("status_0b000408", 0x0B000408, 2, shared= "window-status-0b", allocation_base=0x0B000000),
    "experimental-contract-window-0b": _mapping("window_0b", 0x0B000000, shared="window-status-0b"), "experimental-contract-window-18": _mapping("window_18",
    0x18000000, shared="window-panel-18"), "experimental-contract-window-1c": _mapping("window_1c", 0x1C000000, shared= "window-panel-1c"), "external-uart":
    _mapping("boot_uart", 0x03000B10, 0x14, allocation=False), "external-uart-tx-log": ExternalProperty("boolean", "boot_uart"), "external-lcd-18": _mapping("lcd_trace_18",
    0x18000000, shared="window-panel-18"), "external-lcd-1a": _mapping("lcd_trace_1a", 0x1A000000, shared= "window-panel-1a"), "external-lcd-1c": _mapping("lcd_trace_1c",
    0x1C000000, shared="window-panel-1c"), "gpio-ready-bit21": _pin("gpio_ready_bit21", 21), "experimental-contract-gpio-bit9-low": _pin("boot_gpio_bit9", 9),
    "experimental-contract-gpio-pmic-serial": _mapping("gpio_pmic_serial", 0x030006E8, 0x3C, allocation=False), "experimental-contract-lcd-1c-selector":
    _mapping("lcd_1c_selector", 0x1C000000, shared="window-panel-1c", allocation=False), "external-ram-base": ExternalProperty("integer", "external_ram"),
    "external-ram-size": ExternalProperty("integer", "external_ram"), "external-strap-value": _mapping("strap_bit2", 0x09000070, 1, shared="cs09-strap",
    allocation_base=0x09000000, kind="integer"), })
EXTERNAL_BUS_BOOLEAN_PROPERTIES = frozenset(name for name, contract in EXTERNAL_BUS_CONTRACTS.items() if contract.kind == "boolean")
EXTERNAL_BUS_INTEGER_PROPERTIES = frozenset(name for name, contract in EXTERNAL_BUS_CONTRACTS.items() if contract.kind == "integer")

def _validated_properties(profile: object, image: bytes, ram_base: int, ram_size: int, loaded_image: bytes | None = None, reserved_ram: tuple[int, int] | None =
    None) -> tuple[dict | None, str | None]:
    """Validate the compatibility projection without rerunning detection."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict) or type(profile.get("version")) is not int or profile["version"] != 1:
        return None, "invalid-plan-version"
    reservations = [] if reserved_ram is None else[list(reserved_ram)]
    context = {"ram_base": ram_base, "ram_size": ram_size, "reserved_ram": reservations}
    if profile.get("memory_context") != context:
        return None, "memory-context-mismatch"
    properties = profile.get("machine_properties")
    if not isinstance(properties, dict):
        return None, "invalid-machine-properties"
    if not all(isinstance(name, str) for name in properties):
        return None, "invalid-machine-properties"
    capabilities = profile.get("capabilities")
    if not isinstance(capabilities, dict):
        return None, "invalid-capabilities"
    for name, value in sorted(properties.items()):
        contract = EXTERNAL_BUS_CONTRACTS.get(name)
        if contract is None:
            return None, "unknown-machine-property"
        kind, capability_name = contract.kind, contract.capability
        if kind == "boolean":
            if type(value) is not bool:
                return None, "invalid-boolean-property"
        else:
            if type(value) is not int or not 0 <= value <= 0xffffffff:
                return None, "invalid-integer-property"
        if value:
            capability = capabilities.get(capability_name)
            if (not isinstance(capability, dict) or capability.get("status") != "experimental-contract" or not isinstance(capability.get("evidence"), list) or
                not capability["evidence"] or not all(isinstance (item, dict) for item in capability["evidence"])):
                return None, "missing-property-capability"
            parameters = capability.get("parameters")
            if not isinstance(parameters, dict):
                return None, "invalid-capability-parameters"
            if name == "experimental-contract-gpio-pmic-serial" and parameters != { "ports":[0x030006e8, 0x03000720, 0x030006f4], "register_count": 64,
                "reset_value": 0, "write_policy": "readback"}:
                return None, "serial-contract-parameter-mismatch"
            if name == "external-indexed-18" and parameters != {
                    "ports": [0x18080000, 0x180C0000], "width": 2,
                    "register_count": 65536, "reset_value": 0, "write_policy": "readback"}:
                return None, "indexed-contract-parameter-mismatch"
            if (name == "experimental-contract-lcd-1c-selector" and parameters.get("mode") != "selector-data"):
                return None, "selector-contract-parameter-mismatch"
            if name in ("external-ram-base", "external-ram-size"):
                allocation = parameters.get("allocation")
                if (not isinstance(allocation, (list, tuple)) or len(allocation) != 2 or value != allocation[name == "external-ram-size"]):
                    return None, "ram-allocation-mismatch"
            elif name == "external-strap-value" and value != parameters.get("value"):
                return None, "strap-value-mismatch"
    base, size = properties.get("external-ram-base", 0), properties.get("external-ram-size", 0)
    if (bool(base) != bool(size) or (base | size) & 0xfff or base + size > 0x100000000):
        return None, "invalid-external-ram-allocation"
    if (properties.get("experimental-contract-lcd-1c-selector") and not properties.get("external-lcd-1c")):
        return None, "selector-without-lcd"
    if properties.get("external-lcd-18-window") and properties.get("external-lcd-18-dcs"):
        return None, "conflicting-lcd-protocols"
    if properties.get("external-lcd-18-window") or properties.get("external-lcd-18-dcs"):
        if not properties.get("external-lcd-18"):
            return None, "window-without-lcd"
        offset = properties.get("external-lcd-18-data-offset")
        parameters = capabilities["lcd_18_window"]["parameters"]
        expected_protocol = "dcs" if properties.get("external-lcd-18-dcs") else "window51"
        if parameters.get("protocol") != expected_protocol:
            return None, "window-protocol-mismatch"
        pool = parameters.get("data_literal")
        if (offset not in (0x40000, 0x80000)
                or parameters.get("command_port") != 0x18000000
                or parameters.get("data_port") != 0x18000000 + offset
                or type(pool) is not int or not 0 <= pool <= len(image) - 4
                or int.from_bytes(image[pool:pool + 4], "little") != parameters["data_port"]):
            return None, "window-data-port-mismatch"
    elif "external-lcd-18-data-offset" in properties:
        return None, "window-data-without-lcd"
    if properties.get("external-uart-tx-log") and not properties.get("external-uart"):
        return None, "uart-log-without-uart"
    if "external-strap-value" in properties and not 0 < properties["external-strap-value"] <= 0xff:
        return None, "invalid-strap-value"
    guards = profile.get("source_guards")
    if not isinstance(guards, list) or not guards:
        return None, "missing-source-guards"
    facts = facts_for(image)
    for guard in guards:
        if not isinstance(guard, dict):
            return None, "invalid-source-guard"
        start, end, expected = guard.get("start"), guard.get("end"), guard.get("expected")
        if (type(start) is not int or type(end) is not int or not isinstance(expected, str) or not 0 <= start < end <= len(image)):
            return None, "invalid-source-guard"
        try:
            expected = bytes.fromhex(expected)
        except ValueError:
            return None, "invalid-source-guard"
        if len(expected) != end - start or image[start:end] != expected:
            return None, "source-guard-mismatch"
        if not facts.view.covers(facts.base + start, end - start, phase='reset', bank='primary'):
            return None, "source-guard-not-supplied"
        if loaded_image is not None and loaded_image[start:end] != expected:
            return None, "loaded-source-guard-mismatch"
    return properties, None

def _resource_claims(role, properties):
    if role == "lcd_18_window":
        base = 0x18000000 + properties["external-lcd-18-data-offset"]
        return (ResourceClaim("address", role, base, base + 2),)
    if role == "indexed_18":
        return tuple(ResourceClaim("address", role, base, base + 2)
                     for base in (0x18080000, 0x180C0000))
    if role == "external_ram" and properties.get("external-ram-size"):
        base = properties["external-ram-base"]
        return (ResourceClaim("address", role, base, base + properties["external-ram-size"]),)
    return tuple(dict.fromkeys(contract.claim for contract in EXTERNAL_BUS_CONTRACTS.values() if contract.capability == role and contract.claim is not None))

def external_bus_plan(profile: object, image: bytes, ram_base: int, ram_size: int, loaded_image: bytes | None = None, reserved_ram: tuple[int, int] | None =
    None):
    """Project source-validated legacy evidence into independent device claims."""
    properties, reason = _validated_properties(profile, image, ram_base, ram_size, loaded_image, reserved_ram)
    if properties is None:
        return resolve_proposals(()), reason
    return _resolve_external_claims(profile), None

def _resolve_external_claims(profile):
    properties = profile["machine_properties"]
    by_role = {}
    for name, value in properties.items():
        if value or type(value) is int:
            by_role.setdefault(EXTERNAL_BUS_CONTRACTS[name].capability, {})[name] = value
    # The compatibility profile already records guarded instruction/data spans.
    # Keep its complete source binding while each role moves to typed facts.
    locations = tuple(sorted({guard["start"] for guard in profile["source_guards"]}))
    proposals = []
    for role, assignments in sorted(by_role.items()):
        legacy = profile["capabilities"].get(role, {})
        evidence = Evidence("external-code:" + role, (legacy.get("evidence", ()), legacy.get("parameters", {})), locations, "linkage")
        capability = Capability("external:" + role, (evidence.name,), (evidence,), properties=tuple(assignments.items()), claims=_resource_claims(role,
            properties))
        proposals.append(Decision("accepted", capability=capability))
    return resolve_proposals(proposals)

def external_bus_property(profile: object, image: bytes, ram_base: int, ram_size: int, loaded_image: bytes | None = None, reserved_ram: tuple[int, int] | None =
    None) -> tuple[str | None, str | None]:
    resolution, reason = external_bus_plan(profile, image, ram_base, ram_size, loaded_image, reserved_ram)
    if reason is not None:
        return None, reason
    rendered = [f"{name}={'on' if type(value) is bool else value}"
                for name, value in resolution.plan.properties]
    return ",".join(rendered) or None, None
