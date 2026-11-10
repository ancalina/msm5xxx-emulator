"""Admission and resource arbitration for native device properties."""
from __future__ import annotations

import struct

def select_primary(self, detector_image):
    primary_profile = find_primary_fsd_amd_x16_nor(detector_image[:self.config.flash_size], self.config.flash_id_address, self.config.flash_size,)
    intel_profile, intel_reject = direct_intel_x16_nor_profile(detector_image, self.config.primary_flash_probe_address, self.config.load_address, self.config.flash_size,
        0, self.config.ram_base, self.config.ram_size,)
    sharp_intel = None
    if intel_profile is None and self.config.load_address == 0:
        sharp_intel = find_sharp_intel_profile(detector_image, self.config.flash_size, self.config.ram_base, self.config.ram_size)
        if sharp_intel is not None:
            intel_profile = sharp_intel["geometry"]
    amd_profile, amd_reject = direct_amd_x16_nor_profile(detector_image, self.config.load_address, self.config.flash_size, 0, self.config.ram_base, self.config.ram_size,)
    direct_protocol_conflict = intel_profile is not None and amd_profile is not None
    if direct_protocol_conflict:
        sharp_intel = None
        intel_profile = None
        amd_profile = None
        self.config.detection_notes.append("direct x16 NOR protocol detectors conflict; " "native fallback retained")
    mapped_primary_profile, mapped_primary_reject = (mapped_primary_intel_x16_nor_profile(bytes(self.decoder.flash.data), self.config.flash_size, self.config.ram_base,))
    probe_profile, probe_reject = primary_probe_x16_nor_profile(detector_image, self.config.primary_flash_probe_address, self.config.load_address, self.config.flash_size,
        0, self.config.ram_base, self.config.ram_image_offset, self.config.ram_image_size, self.config.ram_size,)
    if not direct_protocol_conflict and all(profile is None for profile in (primary_profile, probe_profile, intel_profile, amd_profile, mapped_primary_profile)):
        seeded_profile, seeded_reject = seeded_amd_x16_nor_profile(detector_image, self.config.load_address, self.config.flash_size, self.config.ram_base, self.config.ram_size,)
        if seeded_profile is not None:
            probe_profile = seeded_profile
            self.config.detection_notes.append("temporary seeded x16 NOR descriptor/driver class; " "byte-sector geometry and read/write context verified")
        elif seeded_reject is not None:
            self.config.detection_notes.append(
                f"seeded x16 NOR detector rejected: {seeded_reject}; "
                "native fallback retained"
            )
    primary_profile, primary_regions, profile_reject = (select_primary_x16_nor_profile(primary_profile, probe_profile))
    return (amd_profile, amd_reject, direct_protocol_conflict, find_sharp_intel_profile, intel_profile, intel_reject, mapped_primary_profile,
        mapped_primary_reject, primary_profile, primary_regions, probe_profile, probe_reject, profile_reject, sharp_intel,)

def select_nand(self, detector_image, eeprom_profile, primary_seed, upper_nor_present):
    raw_nand_profile, raw_nand_reject = qemu_raw_nand_main_profile(detector_image, self.config)
    native_nand, native_nand_reject = qemu_native_nand_profile(primary_seed, self.config)
    if native_nand_reject is not None:
        self.config.detection_notes.append(
            f"QEMU timed NAND rejected: {native_nand_reject}; native fallback retained"
        )
    if native_nand is not None:
        raw_nand_profile, raw_nand_reject = None, None
    if raw_nand_profile is not None and upper_nor_present:
        raw_nand_profile = None
        raw_nand_reject = "upper-nor-conflict"
    elif raw_nand_profile is not None and eeprom_profile is not None:
        raw_nand_profile = None
        raw_nand_reject = "mtd-owner-conflict"
    middle_nand_ready = None
    if raw_nand_profile is not None and raw_nand_profile[0] == 0x01800000:
        source_profile = (find_guarded_middle_nand_profile(detector_image) or find_middle_nand_profile(detector_image) or find_static_middle_nand_profile(detector_image))
        loaded_profile = (find_guarded_middle_nand_profile(primary_seed[:len(detector_image)]) or find_middle_nand_profile(primary_seed[:len(detector_image)])
            or find_static_middle_nand_profile(primary_seed[:len(detector_image)]))
        if source_profile is None or source_profile != loaded_profile:
            raw_nand_profile, raw_nand_reject = None, "middle-loaded-source-mismatch"
        else:
            start, end = source_profile["source_interval"]
            if (primary_seed[start:end] != detector_image[start:end] or any(primary_seed[a:b] != detector_image[a:b] for a, b in source_profile["code_intervals"])):
                raw_nand_profile, raw_nand_reject = None, "middle-loaded-overlay-mismatch"
            else:
                middle_nand_ready = (source_profile["ready_address"], source_profile["ready_mask"])
    if raw_nand_reject is not None:
        self.config.detection_notes.append(
            f"QEMU raw NAND bridge rejected: {raw_nand_reject}; "
            "native fallback retained"
        )
    return (middle_nand_ready, native_nand, raw_nand_profile,)

def select_record(self, detector_image, primary_profile, intel_profile, amd_profile, profile_reject, probe_reject, intel_reject, amd_reject,
    mapped_primary_reject):
    record_profile = find_record_amd_x16_nor(detector_image[:self.config.flash_size], self.config.flash_size,)
    if record_profile is not None:
        record_base, record_size, _ = record_profile
        if (primary_profile is None or record_base + record_size != primary_profile[0] or primary_profile[0] + primary_profile[1] != self.config.flash_size):
            record_profile = None
            self.config.detection_notes.append("Record x16 NOR detector rejected: primary-tail-" "adjacency-mismatch; native fallback retained")
    catalog_profile = (find_catalog_amd_x16_nor(detector_image[:self.config.flash_size], self.config.flash_size, self.config.ram_base,) if record_profile is not
        None else None)
    if profile_reject is not None:
        self.config.detection_notes.append("primary x16 detectors conflict; native NOR fallback retained")
    elif (primary_profile is None and intel_profile is None and amd_profile is None and probe_reject is not None):
        self.config.detection_notes.append(
            f"primary x16 probe detector rejected: {probe_reject}; "
            "native NOR fallback retained"
        )
    if (intel_profile is None and amd_profile is None and primary_profile is None and intel_reject not in (None, "probe-shape-mismatch")):
        self.config.detection_notes.append(
            f"direct Intel x16 detector rejected: {intel_reject}; "
            "native fallback retained"
        )
    if (amd_profile is None and intel_profile is None and primary_profile is None and amd_reject is not None):
        self.config.detection_notes.append(
            f"direct AMD x16 detector rejected: {amd_reject}; "
            "native fallback retained"
        )
    if mapped_primary_reject is not None:
        self.config.detection_notes.append(
            "mapped primary Intel x16 detector rejected: "
            f"{mapped_primary_reject}; native fallback retained"
        )
    return (record_profile, catalog_profile,)

def select_overlay(self, detector_image, primary_seed, direct_protocol_conflict, upper_nor_present, profile_reject, primary_profile, probe_profile,
    record_profile, mapped_primary_profile, intel_profile, amd_profile, catalog_profile, ram_reserved, upper_x16_profile, dmd5100_property):
    if self.amd_bank_source_profile is not None:
        if find_embedded_fujitsu_x16_nor(detector_image[:self.config.flash_size], self.config.flash_size) is not None:
            self.amd_bank_source_profile = None
            self.amd_bank_reject_reason = "amd-bank-secondary-owner-conflict"
        else:
            profile = self.amd_bank_source_profile
            record_profile = profile['base'], profile['size'], profile['sector_size']
    if self.amd_bank_reject_reason is not None:
        self.config.detection_notes.append(
            f"QEMU bounded AMD bank rejected: {self.amd_bank_reject_reason}; "
            "native fallback retained"
        )
    legacy_nv_claimed = (direct_protocol_conflict or upper_nor_present or primary_seed[:len(detector_image)] != detector_image or any(value is not None for
        value in (profile_reject, primary_profile, probe_profile, record_profile, mapped_primary_profile, intel_profile, amd_profile, catalog_profile, self.amd_bank_source_profile,
        self.protected_nor_source_profile, ram_reserved, upper_x16_profile, dmd5100_property,)))
    legacy_nv_capability = select_legacy_nv_nor(detector_image, self.config, claimed=legacy_nv_claimed)
    legacy_nv_profile = legacy_nv_tuple(legacy_nv_capability)
    legacy_nv_properties = (dict(legacy_nv_capability.properties) if legacy_nv_capability is not None else {})
    if legacy_nv_profile is not None:
        kind, profile = legacy_nv_profile
        if kind == "word-offset-uniform":
            amd_profile = profile
        self.config.detection_notes.append("temporary source-closed missing NV NOR bank enabled; " "physical geometry and logical bounds kept distinct; "
            "compatible virtual device, original chip identity unverified")
    native_ram_size = self.config.ram_size
    if self.boot_format_nor_profile is not None:
        if any(p is not None for p in (amd_profile, intel_profile, primary_profile, record_profile, mapped_primary_profile, upper_x16_profile, ram_reserved)):
            raise ValueError("boot-format NOR conflicts with an existing owner")
        profile = self.boot_format_nor_profile
        amd_profile = (profile["base"], profile["size"], 0x2000, profile["id0"], profile["id1"], 0)
        # Bundled QEMU admits AMD devices inside its RAM allocation only.
        # Every byte of this extra backing is covered by the NOR device.
        native_ram_size = profile["base"] + profile["size"] - self.config.ram_base
        self.config.detection_notes.append("copied formatter: missing 0x01800000 AMD x16 NOR and pulse watchdog enabled; "
            "both compatible 8MiB parts use source-described mixed erase sectors")
    return (record_profile, amd_profile, legacy_nv_profile, legacy_nv_properties, native_ram_size,)

def select_secondary(self, detector_image, catalog_profile, primary_profile, legacy_nv_profile, loader_exclude):
    secondary = self.decoder.secondary_flash
    secondary_base = self.config.secondary_flash_address
    secondary_size = self.config.secondary_flash_size
    catalog_secondary = False
    legacy_nv_secondary = False
    if secondary_base is None and catalog_profile is not None:
        secondary_base, secondary_size, _ = catalog_profile
        catalog_secondary = True
    adjacent_amd = find_adjacent_amd_x16_nor(detector_image[:self.config.flash_size], self.config.flash_size,)
    embedded_secondary = None
    if secondary_base is None and primary_profile is None:
        embedded_secondary = find_embedded_fujitsu_x16_nor(bytes(self.decoder.flash.data), self.config.flash_size,)
        if embedded_secondary is not None:
            secondary_base, secondary_size, id0, id1 = embedded_secondary
            loader_exclude = (secondary_base, secondary_base + secondary_size,)
    if (secondary_base is None and legacy_nv_profile is not None and legacy_nv_profile[0] == "byte-offset-boot-sectors"):
        secondary_base, secondary_size, id0, id1 = legacy_nv_profile[1]
        legacy_nv_secondary = True
    if (secondary_base is None and self.config.secondary_flash_write_address is not None):
        candidate = self.config.load_address + self.config.flash_size
        candidate_ids = fujitsu_x16_flash_ids(detector_image, self.config.secondary_flash_write_address, self.config.load_address, candidate,)
        if (candidate_ids is not None and candidate + self.config.secondary_flash_size <= self.config.ram_base):
            secondary_base = candidate
    secondary_ids = ((0xFFFF, 0xFFFF) if catalog_secondary else (id0, id1) if embedded_secondary is not None or legacy_nv_secondary else fujitsu_x16_flash_ids(detector_image,
        self.config.secondary_flash_write_address, self.config.load_address, int(secondary_base or 0),))
    if secondary_ids is None:
        secondary_ids = adjacent_amd_x16_flash_ids(self.config, detector_image,)
    return (secondary, secondary_base, secondary_size, catalog_secondary, legacy_nv_secondary, adjacent_amd, embedded_secondary, secondary_ids, loader_exclude,)

def loaded_primary(self, loaded, size, sharp_intel, intel_profile):
    if sharp_intel is not None and find_sharp_intel_profile(loaded[:size], self.config.flash_size, self.config.ram_base, self.config.ram_size) != sharp_intel:
        sharp_intel = intel_profile = None
        self.config.detection_notes.append('Sharp EFS partition rejected: loaded source mismatch')
    return sharp_intel, intel_profile

def secondary_extension_matches(image, flash_size, base, size, identifiers):
    return find_adjacent_fujitsu_x16_nor(image, flash_size) == (base, size, *identifiers)

def initial_primary_flash_ids(config, read_memory, memory_errors) -> tuple[int, int] | None:
    """Infer NOR autoselect IDs only from one unambiguous firmware descriptor."""
    address = config.primary_flash_probe_address
    if address is None:
        return None
    try:
        signature = bytes(read_memory(address, len(PRIMARY_FLASH_PROBE_SIGNATURE)))
        _, flash_base_global, table_global = struct.unpack("<3I", read_memory(address + len(PRIMARY_FLASH_PROBE_SIGNATURE), 12))
        flash_base = struct.unpack("<I", read_memory(flash_base_global, 4))[0]
        first, terminator = struct.unpack("<2I", read_memory(table_global, 8))
        manufacturer, device = struct.unpack("<2H", read_memory(first + 0x124, 4))
    except (*memory_errors, struct.error):
        return None
    flash_end = config.load_address + config.flash_size
    ram_end = config.ram_base + config.ram_size
    if (signature != PRIMARY_FLASH_PROBE_SIGNATURE or not first or terminator or not config.ram_base <= flash_base_global <= ram_end - 4 or not config.ram_base
        <= table_global <= ram_end - 8 or not config.load_address <= flash_base < flash_end or not config.load_address <= first <= flash_end - 0x128 or
        manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF)):
        return None
    return manufacturer, device

REQUIRES = {'PRIMARY_FLASH_PROBE_SIGNATURE': ('storage.boot_rules', 'PRIMARY_FLASH_PROBE_SIGNATURE'), 'direct_amd_x16_nor_profile': ('storage.rules',
    'direct_amd_x16_nor_profile'), 'direct_intel_x16_nor_profile': ('storage.rules', 'direct_intel_x16_nor_profile'), 'find_guarded_middle_nand_profile': ('storage.guarded_middle_nand',
    'find_guarded_middle_nand_profile'), 'find_middle_nand_profile': ('storage.middle_nand', 'find_middle_nand_profile'), 'find_primary_fsd_amd_x16_nor': ('storage.rules',
    'find_primary_fsd_amd_x16_nor'), 'find_static_middle_nand_profile': ('storage.static_middle_nand', 'find_static_middle_nand_profile'),
    'mapped_primary_intel_x16_nor_profile': ('storage.rules', 'mapped_primary_intel_x16_nor_profile'), 'primary_probe_x16_nor_profile': ('storage.rules',
    'primary_probe_x16_nor_profile'), 'qemu_native_nand_profile': ('storage.transport_projection', 'qemu_native_nand_profile'), 'qemu_raw_nand_main_profile': ('storage.transport_projection',
    'qemu_raw_nand_main_profile'), 'seeded_amd_x16_nor_profile': ('storage.rules', 'seeded_amd_x16_nor_profile'), 'select_primary_x16_nor_profile': ('storage.transport_projection',
    'select_primary_x16_nor_profile'), 'find_sharp_intel_profile': ('storage.sharp_intel', 'find_sharp_intel_profile'), 'select_legacy_nv_nor': ('storage.nv_nor',
    'select_legacy_nv_nor'), 'legacy_nv_tuple': ('storage.nv_nor', 'legacy_nv_tuple'), 'find_catalog_amd_x16_nor': ('storage.rules', 'find_catalog_amd_x16_nor'),
    'find_record_amd_x16_nor': ('storage.rules', 'find_record_amd_x16_nor'), 'find_embedded_fujitsu_x16_nor': ('storage.rules', 'find_embedded_fujitsu_x16_nor'),
    'fujitsu_x16_flash_ids': ('storage.rules', 'fujitsu_x16_flash_ids'), 'find_adjacent_amd_x16_nor': ('storage.rules', 'find_adjacent_amd_x16_nor'),
    'adjacent_amd_x16_flash_ids': ('storage.transport_projection', 'adjacent_amd_x16_flash_ids'), 'find_adjacent_fujitsu_x16_nor': ('storage.rules',
    'find_adjacent_fujitsu_x16_nor')}
