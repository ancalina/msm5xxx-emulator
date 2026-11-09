"""Capability resolution and property projection for ready-poll devices."""
from __future__ import annotations

from types import SimpleNamespace
from ...facts import source_prefix
from ...capabilities import (
    Capability, CapabilityPredicate, CapabilityRegistry, Decision, Evidence,
    MachinePlan, Resolution, ResourceClaim,
)
from .helpers import READY_POLL_SITE_LIMIT
from .display import (
    _find_lcd_halfword_ready_poll_profile, _copy_profile,
    find_ready_poll_profile, find_arm_tx_empty_ready_poll_profile,
)

# The native property grammar belongs to the same device contract as its proof.
_POLL_COMMON = ('status_address', 'mask', 'pulse_address')
_POLL_SITES = ('status_read_pc_offset', 'pulse_set_pc_offset', 'pulse_clear_pc_offset')
_CONTROL_FIELDS = (*_POLL_COMMON, 'control_address', 'control_value',
                   *_POLL_SITES, 'control_pc_offset')
_POLL_PROTOCOLS = {
    'thumb-lsrs-bhs-pulse-v1': ('ready-poll', _POLL_COMMON),
    'thumb-lsrs-bcc-pulse-rotated-v1': ('ready-poll', (*_POLL_COMMON, *_POLL_SITES)),
    'arm-byte-tx-empty-pulse-v1': ('ready-poll', (*_POLL_COMMON, *_POLL_SITES)),
    'thumb-uart-csr-sr-rx-empty-v1': ('ready-poll', (*_POLL_COMMON, *_POLL_SITES,
                                               'uart_rx_empty_read_pc_offset')),
    'thumb-byte-ready-pulse-control-v1': ('ready-poll-control', _CONTROL_FIELDS),
    'thumb-byte-ready-pulse-control-uart-empty-v1': ('ready-poll-control',
        (*_CONTROL_FIELDS, 'uart_rx_empty_read_pc_offset')),
    'thumb-lcd-halfword-busy-clear-v1': ('lcd-status-poll',
        ('status_address', 'mask', 'command_address', 'command_value',
         'status_read_pc_offset', 'command_write_pc_offset')),
}


def ready_poll_property(
        profile: object) -> tuple[str | None, str | None]:
    """Serialize only recognized, unambiguous ready-poll contracts."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict):
        return None, "malformed-profile"
    if profile.get("signature") == "thumb-byte-ready-pulse-variants-v1":
        if profile.get("admission") != "temporary-evidence-gated":
            return None, "unsupported-admission"
        variants = profile.get("variants")
        if not isinstance(variants, list) or not 2 <= len(variants) <= READY_POLL_SITE_LIMIT:
            return None, "malformed-variants"
        fields = ("status_address", "mask", "pulse_address")
        common = tuple(profile.get(field) for field in fields)
        if (any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in common)
                or not 0x03000000 <= common[0] < 0x04000000
                or not 0x03000000 <= common[2] < 0x04000000
                or common[0] == common[2] or not 0 < common[1] <= 0xFF
                or common[1] & (common[1] - 1)):
            return None, "malformed-fields"
        sites = []
        entries_seen = set()
        owned_pcs = set()
        for variant in variants:
            if (not isinstance(variant, dict) or variant.get("signature") not in (
                    "thumb-lsrs-bhs-pulse-v1",
                    "thumb-lsrs-bcc-pulse-rotated-v1",
                    "thumb-uart-csr-sr-rx-empty-v1",
                    "arm-byte-tx-empty-pulse-v1")):
                return None, "unsupported-variant"
            if tuple(variant.get(field) for field in fields) != common:
                return None, "variant-contract-mismatch"
            argument, reason = ready_poll_property(variant)
            if reason is not None or argument is None:
                return None, "variant-" + (reason or "malformed-profile")
            if variant["signature"] == "thumb-lsrs-bhs-pulse-v1":
                offsets = [2, 0xC, 0x10]
            else:
                offsets = [variant[field] for field in (
                    "status_read_pc_offset", "pulse_set_pc_offset",
                    "pulse_clear_pc_offset")]
                if variant["signature"] == "thumb-uart-csr-sr-rx-empty-v1":
                    offsets.append(variant["uart_rx_empty_read_pc_offset"])
                    if "uart_rx_empty_frame_read_pc_offset" in variant:
                        offsets.append(variant["uart_rx_empty_frame_read_pc_offset"])
            if (any(offset & 1 or offset > 0x1000 for offset in offsets)
                    or len(set(offsets)) != len(offsets)
                    or offsets[1] >= offsets[2]
                    or (len(offsets) > 3 and
                        (common[1] != 8 or offsets[3] <= offsets[2]))
                    or (len(offsets) > 4 and offsets[4] <= offsets[3])):
                return None, "malformed-variant-offsets"
            for entry in variant["entries"]:
                if entry in entries_seen:
                    return None, "duplicate-variant-entry"
                pcs = {entry + offset for offset in offsets}
                if max(pcs) > 0xFFFFFFFF:
                    return None, "wrapped-variant-pc"
                if pcs & owned_pcs:
                    return None, "overlapping-variant-sites"
                entries_seen.add(entry)
                owned_pcs.update(pcs)
                # QEMU -M encodes literal value commas as doubled commas.
                sites.append(",,".join(f"{value:x}" for value in [entry, *offsets]))
                if len(sites) > READY_POLL_SITE_LIMIT:
                    return None, "entry-count-limit"
        if len(sites) < 2:
            return None, "ambiguous-entry-count"
        prefix = ":".join(f"{value:x}" for value in common)
        return f"ready-poll-sites={prefix}:" + ";".join(sites), None
    entries = profile.get("entries")
    if not isinstance(entries, list):
        return None, "malformed-entries"
    if not entries:
        return None, "ambiguous-entry-count"
    signature = profile.get("signature")
    if len(entries) > 1 and signature != "thumb-lsrs-bhs-pulse-v1":
        return None, "ambiguous-entry-count"
    if len(entries) > READY_POLL_SITE_LIMIT:
        return None, "entry-count-limit"
    protocol = _POLL_PROTOCOLS.get(signature)
    if protocol is None:
        return None, 'unsupported-signature'
    property_name, fields = protocol
    if signature != 'thumb-lsrs-bhs-pulse-v1':
        if profile.get('admission') != 'temporary-evidence-gated':
            reason = ('unsupported-signature' if signature == 'arm-byte-tx-empty-pulse-v1'
                      else 'unsupported-admission')
            return None, reason
    elif len(entries) > 1:
        property_name = 'ready-poll-sites'
    if (signature == 'thumb-uart-csr-sr-rx-empty-v1'
            and 'uart_rx_empty_frame_read_pc_offset' in profile):
        fields += ('uart_rx_empty_frame_read_pc_offset',)
    values = [profile.get(field) for field in fields] + entries
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
           for value in values):
        return None, "malformed-fields"
    if any(entry & 1 for entry in entries) or len(set(entries)) != len(entries):
        return None, "malformed-entries"
    if property_name == "ready-poll-sites":
        prefix = ":".join(f"{value:x}" for value in values[:-len(entries)])
        sites = ";".join(f"{entry:x}" for entry in entries)
        return f"{property_name}={prefix}:{sites}", None
    if property_name == "ready-poll-control":
        values.insert(5, values.pop())
    elif property_name == "lcd-status-poll":
        values.insert(4, values.pop())
    elif property_name == "ready-poll" and len(fields) > 3:
        values.insert(3, values.pop())
    return f"{property_name}=" + ":".join(f"{value:x}" for value in values), None


def _profile_evidence(profile: dict[str, object]) -> tuple[Evidence, ...]:
    """Describe the closed code sites consumed by a validated poll profile."""
    members = profile.get("variants", [profile])
    if not isinstance(members, list) or not all(isinstance(x, dict) for x in members):
        return ()
    instruction_sites: list[int] = []
    status_sites: list[int] = []
    pulse_sites: list[int] = []
    control_sites: list[int] = []
    for member in members:
        signature = member.get("signature")
        entries = member.get("entries", [])
        if not isinstance(entries, list):
            continue
        if signature == "thumb-lsrs-bhs-pulse-v1":
            offsets = (2, 0xC, 0x10)
        elif signature == "thumb-lcd-halfword-busy-clear-v1":
            offsets = (member.get("status_read_pc_offset"),
                       member.get("command_write_pc_offset"))
        else:
            offsets = tuple(member.get(key) for key in _POLL_SITES)
            if signature in ("thumb-uart-csr-sr-rx-empty-v1",
                             "thumb-byte-ready-pulse-control-uart-empty-v1"):
                offsets += (member.get("uart_rx_empty_read_pc_offset"),)
        if any(type(offset) is not int for offset in offsets):
            continue
        for entry in entries:
            if type(entry) is not int:
                continue
            sites = [entry + offset for offset in offsets]
            instruction_sites.extend(sites)
            if signature == "thumb-lcd-halfword-busy-clear-v1":
                status_sites.append(sites[0])
                control_sites.append(sites[1])
            else:
                status_sites.append(sites[0])
                pulse_sites.extend(sites[1:3])
                if "control_pc_offset" in member:
                    control_sites.append(entry + member["control_pc_offset"])
    if not instruction_sites:
        return ()
    signature = profile.get("signature")
    evidence = [Evidence("ready-poll-code", signature,
                         tuple(sorted(set(instruction_sites))), "instruction")]
    evidence.append(Evidence("ready-poll-status", profile.get("status_address"),
                             tuple(sorted(set(status_sites))), "instruction"))
    if pulse_sites:
        evidence.append(Evidence("ready-poll-pulse", profile.get("pulse_address"),
                                 tuple(sorted(set(pulse_sites))), "instruction"))
    if control_sites:
        address = profile.get("command_address", profile.get("control_address"))
        evidence.append(Evidence("ready-poll-control", address,
                                 tuple(sorted(set(control_sites))), "instruction"))
    return tuple(evidence)


def _profile_capability(profile: dict[str, object]) -> Decision:
    serialized, reason = ready_poll_property(profile)
    if serialized is None:
        return Decision("missing", reason=reason or "unsupported-profile")
    evidence = _profile_evidence(profile)
    if not evidence or any(not item.locations for item in evidence):
        return Decision("missing", reason="profile-has-no-source-sites")
    property_name, property_value = serialized.split("=", 1)
    claims: list[ResourceClaim] = []
    if profile.get("signature") == "thumb-lcd-halfword-busy-clear-v1":
        claims.extend((
            ResourceClaim("address", "ready-poll-status", profile["status_address"],
                          profile["status_address"] + 2),
            ResourceClaim("address", "ready-poll-command", profile["command_address"],
                          profile["command_address"] + 2),
        ))
    else:
        claims.extend((
            ResourceClaim("address", "ready-poll-status", profile["status_address"],
                          profile["status_address"] + 1),
            ResourceClaim("address", "ready-poll-pulse", profile["pulse_address"],
                          profile["pulse_address"] + 1,
                          shared_resource="watchdog-ready-pulse",
                          semantics="byte-pulse-forwarding"),
        ))
        if "control_address" in profile:
            claims.append(ResourceClaim("address", "ready-poll-control",
                                        profile["control_address"],
                                        profile["control_address"] + 1))
    capability = Capability(
        name=f"ready-poll:{profile['signature']}",
        required_evidence=tuple(item.name for item in evidence), evidence=evidence,
        properties=((property_name, property_value),), claims=tuple(claims),
        alternative_group="ready-poll-protocol",
    )
    return Decision("accepted", capability=capability)


_READY_POLL_REGISTRY = CapabilityRegistry()
_READY_POLL_REGISTRY.register(CapabilityPredicate(
    "ready-poll", ("ready-poll-profile",),
    lambda facts: _profile_capability(facts.profile),
    alternative_group="ready-poll-protocol",
))


def _resolve_ready_poll_profile(profile: object = None) -> Resolution:
    """Resolve one code-backed profile into machine properties and resource claims."""
    if not isinstance(profile, dict):
        reason = "missing-profile" if profile is None else "malformed-profile"
        return Resolution(MachinePlan((), (), (), ()), (Decision("missing", reason=reason),))
    checked = profile
    if profile.get("signature") == "thumb-lcd-halfword-busy-clear-v1":
        checked = {**profile, "admission": "temporary-evidence-gated"}
    serialized, reason = ready_poll_property(checked)
    if serialized is None:
        return Resolution(MachinePlan((), (), (), ()), (Decision("missing", reason=reason),))
    evidence = _profile_evidence(checked)
    # The selected profile is produced by the closed finder; this named fact is
    # its entry point into the shared predicate registry.
    source = Evidence("ready-poll-profile", checked.get("signature"),
                     tuple(sorted({site for item in evidence for site in item.locations})),
                     "instruction")
    resolution = _READY_POLL_REGISTRY.resolve(
        SimpleNamespace(profile=checked, evidence=(source,)))
    if not evidence:
        return Resolution(MachinePlan((), (), (), ()),
                          (*resolution.decisions, Decision("missing",
                           reason="profile-has-no-source-sites")))
    return resolution


def _select_runtime_profile(image: bytes, config: object
                            ) -> tuple[dict[str, object] | None, str | None]:
    size = getattr(config, "flash_size", None)
    has_flash = (getattr(config, "load_address", None) == 0
                 and type(size) is int and size > 0)
    if (has_flash and size <= 0x02000000
            and not getattr(config, "nand_enabled", False)
            and not getattr(config, "upper_flash_size", 0)):
        profile = _find_lcd_halfword_ready_poll_profile(source_prefix(image, size))
        if profile is not None:
            return {**profile, "admission": "temporary-evidence-gated"}, "indexed-lcd"
    original = getattr(config, "ready_poll", None)
    source_image = source_prefix(image, size) if has_flash else image
    if has_flash and getattr(config, "uart_console", None) is None:
        source_profile = find_ready_poll_profile(source_image)
        if isinstance(original, dict) and source_profile == original:
            arm = find_arm_tx_empty_ready_poll_profile(source_image)
            fields = ("status_address", "mask", "pulse_address")
            members = original.get("variants", [original])
            rx_closed = isinstance(members, list) and any(
                isinstance(member, dict)
                and member.get("signature") == "thumb-uart-csr-sr-rx-empty-v1"
                for member in members)
            if (arm is not None and rx_closed
                    and all(original.get(key) == arm[key] for key in fields)):
                combined = {
                    "signature": "thumb-byte-ready-pulse-variants-v1",
                    "admission": "temporary-evidence-gated",
                    **{key: arm[key] for key in fields},
                    "variants": [*original.get("variants", [original]), arm],
                }
                if ready_poll_property(combined)[0] is not None:
                    return combined, "arm-tx"
    if isinstance(original, dict) and find_ready_poll_profile(source_image) == original:
        return original, None
    return None, None


def ready_poll_plan(image: bytes, config: object) -> Resolution:
    """Select and resolve the source-proven ready-poll plan for this boot."""
    profile, _owner = _select_runtime_profile(image, config)
    return _resolve_ready_poll_profile(profile)


def ready_poll_runtime_plan(image: bytes, config: object) -> tuple[Resolution, str | None]:
    """Return the resolved plan and legacy owner label for transport setup."""
    profile, owner = _select_runtime_profile(image, config)
    return _resolve_ready_poll_profile(profile), owner


def runtime_ready_poll_property(image: bytes, config: object
                                     ) -> tuple[str | None, str | None, str | None]:
    """Prefer a closed display consumer over an incidental UART boot helper.

    The LCD bridge completes writes synchronously. Its status register cannot
    echo the previous display payload as a persistent busy bit. The native
    source-PC/selector-bound profile already enforces this ownership. An ARM
    boot TX drain may join an already-closed Thumb UART/RX-empty contract;
    it cannot independently grant receive or configuration semantics.
    """
    profile, owner = _select_runtime_profile(image, config)
    resolution = _resolve_ready_poll_profile(profile)
    if resolution.plan.properties:
        name, value = resolution.plan.properties[0]
        return f"{name}={value}", None, owner
    # Preserve the established rejection diagnostic for malformed configured
    # profiles while preventing source-less profiles from authorizing a device.
    original = getattr(config, "ready_poll", None)
    if profile is None and owner is None:
        _, reason = ready_poll_property(original)
        return None, reason, None
    decision = next((item for item in resolution.decisions
                     if item.status in {"missing", "ambiguous", "conflict"}), None)
    return None, decision.reason if decision is not None else None, owner

__all__ = [name for name in globals() if name.startswith("_") or name in {"ready_poll_property", "ready_poll_plan", "ready_poll_runtime_plan", "runtime_ready_poll_property"}]
