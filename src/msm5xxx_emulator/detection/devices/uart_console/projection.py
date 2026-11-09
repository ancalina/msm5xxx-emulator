"""UART console machine-property and loaded-source admission."""
from __future__ import annotations

from ...contracts import loaded_source_matches, source_class_limit

_UART_WORD_FLAG_FF_SIGNATURE = "thumb-byte-uart-word-flag-fixed-ff-mixed-v1"
_UART_PROBE_FF_DD_SIGNATURE = "thumb-byte-uart-finite-ff-dd-console-v1"
_UART_PROBE_FF_CC_SIGNATURE = "thumb-byte-uart-finite-ff-cc-99-console-v1"
_UART_SOURCE_GUARDED_SIGNATURES = (
    _UART_WORD_FLAG_FF_SIGNATURE, _UART_PROBE_FF_DD_SIGNATURE,
    _UART_PROBE_FF_CC_SIGNATURE,
)
SOURCE_GUARDED_SIGNATURES = _UART_SOURCE_GUARDED_SIGNATURES


def requires_loaded_source(profile) -> bool:
    return (isinstance(profile, dict)
            and profile.get('signature') in SOURCE_GUARDED_SIGNATURES)


def permits_tail_padding(profile) -> bool:
    return (isinstance(profile, dict)
            and profile.get('signature') == _UART_PROBE_FF_CC_SIGNATURE)


def resource_windows(profile):
    return (((profile.get('base'), 0x24), (profile.get('pulse_address'), 1))
            if isinstance(profile, dict) else ())


def qemu_uart_console_property(
        profile: object, image_size: int) -> tuple[str | None, str | None]:
    """Admit only a source-bound isolated console class and its fixed aliases."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict):
        return None, "malformed-profile"
    signature = profile.get("signature")
    expected = {
        "thumb-uart-sync-console-v1": (2, 0x99),
        "thumb-uart-byte-sync-console-v1": (1, 0xFF),
        "thumb-uart-byte-tfwr16-sync-console-v1": (1, 0xFF),
        "thumb-uart-sync-console-dd-v1": (2, 0xDD),
        _UART_WORD_FLAG_FF_SIGNATURE: (2, 0xFF),
        _UART_PROBE_FF_DD_SIGNATURE: (2, 0xFF),
        _UART_PROBE_FF_CC_SIGNATURE: (2, 0xFF),
    }.get(signature) if isinstance(signature, str) else None
    if (expected is None
            or profile.get("admission") != "temporary-evidence-gated"
            or profile.get("policy") != "provisional-synchronous-null-console"):
        return None, "unsupported-contract"
    width = profile.get("register_width", 2 if expected == (2, 0x99) else None)
    csr = profile.get("csr_value", 0x99 if expected == (2, 0x99) else None)
    if (type(width) is not int or type(csr) is not int
            or (width, csr) != expected):
        return None, "unsupported-register-wire"
    base = profile.get("base")
    if (type(base) is not int or base % 4
            or not 0x03000000 <= base <= 0x04000000-0x24):
        return None, "invalid-register-window"
    for field, offset in (("status_address", 8), ("fifo_address", 12),
                          ("control_address", 16), ("isr_address", 20)):
        value = profile.get(field)
        if type(value) is not int or value != base+offset:
            return None, "inconsistent-register-aliases"
    pulse = profile.get("pulse_address")
    if (type(pulse) is not int or not 0x03000000 <= pulse < 0x04000000
            or base <= pulse < base+0x24):
        return None, "invalid-pulse-owner"
    if type(image_size) is not int or image_size <= 0:
        return None, "invalid-image-size"
    sites = [profile.get(name) for name in
             ("primary_entry", "init_entry", "tx_entry")]
    if (any(type(site) is not int or site % 2 or not 0 <= site < image_size
            for site in sites) or len(set(sites)) != len(sites)):
        return None, "invalid-bound-consumers"
    if signature in (_UART_PROBE_FF_DD_SIGNATURE, _UART_PROBE_FF_CC_SIGNATURE):
        sequence = ([0xFF, 0xDD] if signature == _UART_PROBE_FF_DD_SIGNATURE
                    else [0xFF, 0xCC, 0x99])
        if base != 0x03000F0C or profile.get("csr_sequence") != sequence:
            return None, "unsupported-probe-register-wire"
        wire = f"uart-console-probe={base:x}:" + ":".join(f"{v:x}" for v in sequence)
        reentry = profile.get("reset_reentry")
        if reentry is not None:
            if signature != _UART_PROBE_FF_DD_SIGNATURE or not isinstance(reentry, dict):
                return None, "unsupported-reset-reentry-contract"
            primary = profile["primary_entry"]
            init = profile["init_entry"]
            root = profile.get("console_root")
            if type(root) is not int or root % 2 or not 0 <= root < image_size:
                return None, "invalid-reset-reentry-root"
            expected_reentry = dict(
                write_pcs=[primary + 4, primary + 6],
                status_read_pc=primary + 0xA, root_lr=(root + 6) | 1,
                config_lr=(init + 0x1A) | 1, address=base + 0x10,
                width=1, value=0x20, status_address=base + 8, status_mask=8,
            )
            if reentry != expected_reentry or any(
                    type(value) is not int for key, value in reentry.items()
                    if key != "write_pcs") or any(
                    type(value) is not int for value in reentry["write_pcs"]):
                return None, "inconsistent-reset-reentry-sites"
            sites = [*reentry["write_pcs"], reentry["status_read_pc"],
                     reentry["root_lr"], reentry["config_lr"]]
            intervals = profile.get("code_intervals", [])
            if (not isinstance(intervals, (list, tuple))
                    or any(not 0 <= site <= 0xFFFFFFFF for site in sites)):
                return None, "reset-reentry-code-owner-unclosed"
            references = [(site, 2) for site in sites[:3]] + [
                ((site & ~1) - 4, 4) for site in sites[3:]]
            if any(not 0 <= address <= image_size - size or not any(
                    isinstance(span, (list, tuple)) and len(span) == 2
                    and all(type(value) is int for value in span)
                    and span[0] <= address and address + size <= span[1]
                    for span in intervals) for address, size in references):
                return None, "reset-reentry-code-owner-unclosed"
            wire += ",uart-console-rearm=" + ":".join(f"{site:x}" for site in sites)
        return wire, None
    wire = f"uart-console={base:x}"
    if signature == "thumb-uart-byte-tfwr16-sync-console-v1":
        return wire + f":{width:x}:{csr:x}:2", None
    return (wire if expected == (2, 0x99) else wire + f":{width:x}:{csr:x}"), None


def qemu_loaded_uart_console_property(
        profile: dict, original: bytes, loaded: bytes, config: object,
        *, ram_claimed: bool = False,
        nor_overlay: tuple[int, int] | None = None,
) -> tuple[str | None, str | None]:
    """Qualify source-bound boot consoles against their actual loaded source."""
    if not isinstance(profile, dict) or profile.get("signature") not in _UART_SOURCE_GUARDED_SIGNATURES:
        return None, "console-loaded-contract-unsupported"
    if not isinstance(original, bytes) or not isinstance(loaded, bytes):
        return None, "console-loaded-layout-unverified"
    wire, reason = qemu_uart_console_property(profile, len(loaded))
    if wire is None:
        return None, reason
    limit = source_class_limit(original, config)
    if (limit is not None and limit < config.flash_size
            and profile["signature"] == _UART_PROBE_FF_CC_SIGNATURE
            and getattr(config, "chipset", None) in ("MSM5100", "MSM5105")
            and getattr(config, "image_offset", None) == 0
            and not getattr(config, "missing_overlays", None)
            and not getattr(config, "ram_image_size", 0)
            and loaded == original.ljust(config.flash_size, b"\xff")):
        # Canonical NOR tail padding is not source evidence: every guarded
        # interval must still be wholly present in the original bytes below.
        limit = config.flash_size
    if limit is None or limit != config.flash_size or len(loaded) != limit:
        return None, "console-loaded-layout-unverified"
    if not all(profile.get(field) for field in
               ("code_intervals", "literal_intervals", "data_intervals", "boot_guard_intervals")):
        return None, "console-boot-guards-unclosed"
    if not loaded_source_matches(profile, original, loaded):
        return None, "console-loaded-source-mismatch"
    if ram_claimed:
        return None, "console-loaded-memory-owner-unclosed"
    if nor_overlay is not None:
        begin, end = nor_overlay
        spans = profile.get("guard_intervals")
        if (not 0 <= begin < end <= min(limit, config.ram_base)
                or not isinstance(spans, (list, tuple)) or not spans
                or any(not isinstance(span, (list, tuple)) or len(span) != 2
                       or any(type(value) is not int for value in span)
                       or not 0 <= span[0] < span[1] <= limit
                       or (span[0] < end and begin < span[1]) for span in spans)):
            return None, "console-loaded-nor-owner-unclosed"
    if getattr(config, "ram_bootstrap_profile", None) is not None:
        return None, "console-loaded-reserved-owner-unclosed"
    for field, begin, end in (("ram_intervals", config.ram_base,
                               config.ram_base + config.ram_size),
                              ("iram_intervals", 0x03800000, 0x03A00000)):
        spans = profile.get(field)
        if (field == "iram_intervals" and spans == []
                and profile["signature"] == _UART_PROBE_FF_DD_SIGNATURE):
            continue
        if (not isinstance(spans, (list, tuple)) or not spans
                or any(not isinstance(span, (list, tuple)) or len(span) != 2
                       or any(type(value) is not int for value in span)
                       or not begin <= span[0] < span[1] <= end for span in spans)):
            return None, "console-loaded-" + field + "-unverified"
    from . import find_uart_console_profile
    current, _ = find_uart_console_profile(
        loaded, getattr(config, "ready_poll", None),
        chipset=getattr(config, "chipset", None))
    if current != profile:
        return None, "console-loaded-owner-mismatch"
    return wire, None


