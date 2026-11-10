from __future__ import annotations

def find_audio_transport(image: bytes) -> dict[str, object]:
    """Return static ownership evidence; rejected classes stay fail-closed."""
    image = bytes(image) if isinstance(image, bytearray) else image
    from . import _command_status_candidates, _ma2_callback_irq_profile, _marker_families, _repeated_status_candidates, _sequence_status_profile, _transport_clusters, find_audio_irq_candidate, find_ma3_readback_candidate, find_ma5_readback_candidate
    families = _marker_families(image)
    if not families:
        family = "opaque"
        grammar = "command-status-data-v1"
        candidates = _command_status_candidates(image)
        if not candidates:
            repeated = _repeated_status_candidates(image)
            if repeated:
                if len(repeated) == 1:
                    profile = _sequence_status_profile(image, repeated[0])
                    if profile is not None:
                        return profile
                return { "family": "opaque", "grammar": "repeated-bit-status-v1", "static_status": "rejected", "reject_reason": ("protocol-unsupported" if len(repeated)
                    == 1 else "transport-ambiguous"), "candidates": repeated, }
            ma5 = find_ma5_readback_candidate(image)
            if ma5["static_status"] == "candidate":
                return ma5
            ma3 = find_ma3_readback_candidate(image)
            if ma3["static_status"] == "accepted":
                return ma3
            return { "family": "unknown", "grammar": None, "static_status": "not-detected", "reject_reason": "marker-none", }
    elif len(families) != 1:
        return { "family": "unknown", "grammar": None, "static_status": "rejected", "reject_reason": "marker-ambiguous", }
    else:
        family = families[0]
        if family == "ma3":
            return find_ma3_readback_candidate(image)
        grammar = "ma2-command-v1" if family == "ma2" else "indexed-rw-v1"
        candidates = [candidate for candidate in _transport_clusters(image) if grammar in candidate["grammars"]]
    if len(candidates) != 1:
        return { "family": family, "grammar": grammar, "static_status": "rejected", "reject_reason": ("transport-none" if not candidates else
            "transport-ambiguous"), }
    selected = candidates[0]
    sites = selected["sites"]
    irq = (find_audio_irq_candidate(image) if family == "ma2" else None)
    profile = (_ma2_callback_irq_profile(image) if family == "ma2" and selected["base"] == 0x02880000 else None)
    if profile is not None:
        irq = profile
    result = {
        "family": family,
        "grammar": grammar,
        "static_status": "accepted",
        "reject_reason": None,
        "base": selected["base"],
        "data_offset": selected["data_offset"],
        "begin": selected["begin"],
        "end": selected["end"],
        "sites": {
            f"{kind}_{port}": [
                int(site["offset"]) for site in sites
                if site["kind"] == kind and site["port_offset"] == port
            ]
            for kind in ("read", "write")
            for port in sorted({int(site["port_offset"]) for site in sites})
            if any(site["kind"] == kind and site["port_offset"] == port
                   for site in sites)
        },
        "block_write_offsets": selected["block_write_offsets"],
        **({"irq_controller_candidate": irq} if family == "ma2" else {}),
        **({"aperture_write_sites": selected["aperture_write_sites"]}
           if family == "ma5" else {}),
    }
    if profile is not None:
        result["sites"]["write_0"].append(profile["index_restore_site"])
    return result
