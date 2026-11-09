"""EEPROM projection owned by the device domain."""
from __future__ import annotations

from ...capabilities import (
    Capability, CapabilityPredicate, CapabilityRegistry, Decision, Evidence, ResourceClaim,
    Resolution,
)
from ...facts import facts_for
from .rules import _select_eeprom_gpio_profile
from types import SimpleNamespace


def _eeprom_evidence(image: bytes, config: object,
                     profile: tuple[int, int, int, int, int, int, int]
                     ) -> tuple[Evidence, ...]:
    base, data, data_mask, clock, clock_mask, direction, capacity = profile
    load = getattr(config, "load_address", 0)
    read = getattr(config, "eeprom_read_address", None)
    write = getattr(config, "eeprom_write_address", None)
    geometry = getattr(config, "eeprom_geometry_address", None)
    if not all(type(value) is int for value in (load, read, write, geometry)):
        return ()
    code_sites = tuple(sorted({read, write}))
    context = facts_for(image)
    lower = max(context.base, min(read, write) - 0x1000)
    upper = min(context.base + len(image), max(read, write) + 0x1000)

    def literal_sites(values):
        return tuple(sorted({item.instruction.address
                             for value in values
                             for item in context.literal_references(value)
                             if lower <= item.instruction.address < upper}))

    pin_sites = literal_sites({base + data, base + clock, base + direction})
    # Descriptor-backed compiler variants carry the pin relation through a
    # linked read/write entry and RAM pointer table rather than a local MMIO
    # literal. Their matched entry locations remain the code provenance until
    # a startup consumer proof supplies the materialized table source.
    pin_sites = pin_sites or code_sites
    geometry_sites = literal_sites({geometry}) or code_sites
    return (
        Evidence("eeprom-gpio-driver", (read, write), code_sites, "instruction"),
        Evidence("eeprom-gpio-pins",
                 (base, data, data_mask, clock, clock_mask, direction),
                 pin_sites, "instruction"),
        Evidence("eeprom-gpio-capacity", (capacity, geometry),
                 geometry_sites, "linkage"),
    )


def _capability_for_eeprom_profile(
        profile: tuple[int, int, int, int, int, int, int],
        evidence: tuple[Evidence, ...]) -> Decision:
    base, data, data_mask, clock, clock_mask, direction, capacity = profile
    if (base + 0x20 > 1 << 32
            or any(type(offset) is not int or not 0 <= offset < 0x20
                   for offset in (data, clock, direction))
            or any(type(mask) is not int or not 0 < mask <= 0xFF
                   or mask & (mask - 1) for mask in (data_mask, clock_mask))):
        return Decision("missing", reason="gpio-profile-outside-native-aperture")
    if len(evidence) != 3 or any(not item.locations for item in evidence):
        return Decision("missing", reason="gpio-source-evidence-incomplete")
    value = ":".join(f"{item:x}" for item in profile)
    capability = Capability(
        name="eeprom-24lcxx-gpio",
        required_evidence=("eeprom-gpio-driver", "eeprom-gpio-pins",
                           "eeprom-gpio-capacity"),
        evidence=evidence,
        properties=(("eeprom-24lcxx-gpio", value),),
        claims=(ResourceClaim("address", "eeprom-gpio-backing",
                              base, base + 0x20),),
        parameters=(("eeprom-gpio-profile", profile),),
    )
    return Decision("accepted", capability=capability)


def _eeprom_capability(image: bytes, config: object) -> Decision:
    profile, reason = _select_eeprom_gpio_profile(image, config)
    if profile is None:
        return Decision("missing", reason=reason)
    return _capability_for_eeprom_profile(
        profile, _eeprom_evidence(image, config, profile))

_EEPROM_GPIO_REGISTRY = CapabilityRegistry()

_EEPROM_GPIO_REGISTRY.register(CapabilityPredicate(
    "eeprom-24lcxx-gpio", (),
    lambda request: _eeprom_capability(request.image, request.config)))


def eeprom_gpio_plan(image: bytes, config: object) -> Resolution:
    """Resolve the legacy GPIO profile as one located machine capability."""
    try:
        source = bytes(image)
    except (TypeError, ValueError):
        return _EEPROM_GPIO_REGISTRY.resolve(SimpleNamespace(
            image=b"", config=config, evidence=()))
    return _EEPROM_GPIO_REGISTRY.resolve(
        SimpleNamespace(image=source, config=config, evidence=()))


def eeprom_gpio_profile(
        image: bytes, config: object,
        ) -> tuple[tuple[int, int, int, int, int, int, int] | None,
                   str | None]:
    """Compatibility projection to the existing native tuple and reason."""
    resolution = eeprom_gpio_plan(image, config)
    if len(resolution.plan.capabilities) == 1:
        parameters = dict(resolution.plan.capabilities[0].parameters)
        return parameters["eeprom-gpio-profile"], None
    decision = next((item for item in resolution.decisions
                     if item.status in {"missing", "ambiguous", "conflict"}), None)
    return None, decision.reason if decision is not None else None


def eeprom_gpio_property(profile: tuple[int, ...]) -> str:
    """Project parameters captured by the admitted GPIO plan."""
    return "eeprom-24lcxx-gpio=" + ":".join(f"{value:x}" for value in profile)


def eeprom_gpio_window(profile: tuple[int, ...] | None):
    return (profile[0], 32) if profile is not None else None


def eeprom_gpio_capacity(profile: tuple[int, ...]) -> int:
    return profile[6]
