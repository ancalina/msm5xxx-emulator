"""Compose an independently proven boot contact with a selected keypad."""
from __future__ import annotations


_GRAMMARS = {"table-row-halfword-seven-v1", "sparse-halfword-six-row-v1",
             "sparse-halfword-seven-row-v1"}
_ROWS = {"table-row-halfword-seven-v1": 7,
         "sparse-halfword-six-row-v1": 6,
         "sparse-halfword-seven-row-v1": 7}
_BOOT_ADDRESS = 0x0300066c


def _matrix_reads(matrix):
    sites = set()
    for key in ("presence_site", "sense_site"):
        value = matrix.get(key)
        if type(value) is not int:
            return None
        sites.add(value)
    aliases = matrix.get("source_sites", ())
    if type(aliases) not in (list, tuple):
        return None
    for source in aliases:
        if type(source) is not dict:
            return None
        for key in ("presence_site", "sense_site"):
            value = source.get(key)
            if type(value) is not int:
                return None
            sites.add(value)
    return sites


def _parse_boot_property(value):
    prefix = "experimental-boot-contact="
    if not isinstance(value, str) or not value.startswith(prefix):
        return None
    fields = value[len(prefix):].split(":")
    if len(fields) != 4:
        return None
    try:
        address, read_pc, mask, width = (int(field, 16) for field in fields)
    except ValueError:
        return None
    return address, read_pc, mask, width


def wire_boot_contact_property(config, original, loaded, matrix, *,
                               layout_claimed=False, eeprom_window=None):
    """Bind the existing reset-linked boot read to a distinct matrix input."""
    if (type(matrix) is not dict or matrix.get("grammar") not in _GRAMMARS
            or type(matrix.get("rows")) is not int
            or matrix["rows"] != _ROWS[matrix["grammar"]]
            or type(matrix.get("columns")) is not int or matrix["columns"] != 4
            or type(matrix.get("no_key")) is not int or matrix["no_key"] != 15
            or matrix.get("sense_address") != _BOOT_ADDRESS):
        return None, "matrix-boot-contact-profile-unavailable"
    if not isinstance(original, bytes) or not isinstance(loaded, bytes):
        return None, "boot-contact-image-unavailable"
    reads = _matrix_reads(matrix)
    if reads is None:
        return None, "matrix-read-sites-unavailable"
    flash_size = getattr(config, "flash_size", None)
    if (type(flash_size) is not int or any(type(pc) is not int or pc & 1
            or not 0 <= pc < min(flash_size, len(original)) for pc in reads)):
        return None, "matrix-read-sites-unmapped"
    projected, reason = qemu_boot_contact_property(
        config, original, loaded, input_claimed=False,
        layout_claimed=layout_claimed, eeprom_window=eeprom_window)
    if projected is None:
        return None, reason or "boot-contact-source-unavailable"
    parsed = _parse_boot_property(projected)
    if parsed is None:
        return None, "boot-contact-property-malformed"
    address, read_pc, mask, width = parsed
    if (address != _BOOT_ADDRESS or type(flash_size) is not int
            or not 0 <= read_pc < min(flash_size, len(original))
            or read_pc & 1 or read_pc in reads
            or mask not in (1, 2, 4, 8) or width not in (1, 2)):
        return None, "boot-contact-not-independent-matrix-wire"
    return projected, {"address": address, "read_pc": read_pc,
                       "mask": mask, "width": width}


REQUIRES = {
    "qemu_boot_contact_property": ("external_bus.transport_projection",
                                   "qemu_boot_contact_property"),
}
