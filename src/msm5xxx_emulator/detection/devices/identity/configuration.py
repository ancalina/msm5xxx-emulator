"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'model': layout.model, 'chipset': layout.chipset, 'chipset_confidence': layout.confidence, 'verified_model': layout.verified_model if layout.override_model
        is None else None}

def note_support(chipset, confidence, detection_notes):
    if confidence == "unknown":
        detection_notes.append("no generation-specific clock/boot BSP marker")
    if chipset == "MSM6050":
        detection_notes.append("MSM6050 is outside the supported 5000/5100/5500 scope")

import re

def revision_text(image):
    revision_match = re.search(rb"(?:HW|BOARD)[ _-]?REV(?:ISION)?[^\x00\r\n]{0,24}", image, re.I)
    revision = revision_match.group().decode("ascii", "replace") if revision_match else "auto/unknown"
    return revision
