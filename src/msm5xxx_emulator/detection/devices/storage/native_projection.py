"""Native machine-property formatting for admitted storage profiles."""

def primary_fragment(base, size, sector_size, id0, id1, primary_regions):
    fragment = ""
    fragment += (
        f",primary-x16-nor={base:x}:{size:x}:{sector_size:x}:"
        f"{id0:x}:{id1:x}"
    )
    if primary_regions is not None:
        fragment += "".join(
            f":{count:x}:{length:x}"
            for count, length in primary_regions
        )
        fragment += ",primary-x16-write-while-suspended=on"
    return fragment

def record_fragment(self, base, size, sector_size):
    fragment = ""
    fragment += f",record-x16-nor={base:x}:{size:x}:{sector_size:x}"
    if self.amd_bank_source_profile is not None:
        profile = self.amd_bank_source_profile
        fragment += f":{profile['id0']:x}:{profile['id1']:x}"
    return fragment

def mapped_fragment(base, size, sector_size):
    fragment = ""
    fragment += (
        f",mapped-primary-x16-nor={base:x}:{size:x}:"
        f"{sector_size:x}"
    )
    return fragment

def intel_fragment(base, size, sector_size, id0, id1, sharp_intel, loader_exclude):
    fragment = ""
    selector = "sharp-primary-nv" if sharp_intel is not None else "intel-x16-nor"
    if sharp_intel is not None:
        loader_exclude = base, base + size
        fragment += ",sharp-nv-status-mirror=on"
        if sharp_intel.get("signature") == "sharp-address-pcr-block-lock-x16-v1":
            fragment += ",sharp-nv-wp-high=on"
    fragment += (
        f",{selector}={base:x}:{size:x}:{sector_size:x}:"
        f"{id0:x}:{id1:x}"
    )
    return fragment, loader_exclude

def amd_fragment(base, size, sector_size, id0, id1, options, legacy_nv_properties):
    fragment = ""
    machine_value = legacy_nv_properties.get("amd-x16-nor")
    if machine_value is None:
        machine_value = (f"{base:x}:{size:x}:{sector_size:x}:"
                         f"{id0:x}:{id1:x}:{options:x}")
    fragment += f",amd-x16-nor={machine_value}"
    return fragment

def secondary_fragment(self, legacy_nv_properties, legacy_nv_secondary, secondary_base, secondary_size, secondary_ids):
    fragment = ""
    fujitsu_value = (legacy_nv_properties.get("fujitsu-x16-nor") if legacy_nv_secondary else None)
    if fujitsu_value is None:
        fujitsu_value = (
            f"{self.config.flash_size:x}:"
            f"{secondary_base:x}:{secondary_size:x}:"
            f"{secondary_ids[0]:x}:{secondary_ids[1]:x}")
    fragment += f",fujitsu-x16-nor={fujitsu_value}"
    return fragment

def raw_nand_fragment(data, address, command, data_size, page_size, pages_per_block, bus_width, middle_nand_ready):
    fragment = ""
    fragment += (
        f",raw-nand-main={data:x}:{address:x}:{command:x}:"
        f"{data_size:x}:{page_size:x}:{pages_per_block:x}:"
        f"{bus_width:x}"
    )
    if middle_nand_ready is not None:
        ready_address, ready_mask = middle_nand_ready
        fragment += f",raw-nand-ready={ready_address:x}:{ready_mask:x}"
    return fragment

def nand_fragment(profile):
    return ',experimental-small-page-nand=' + ':'.join(f'{profile[key]:x}' for key in (
        'data_address', 'address_address', 'command_address', 'ready_address', 'ready_mask', 'idle_reset_ns'))

def legacy_fragment(profile, properties):
    return f",amd-adjacent-nv={properties['amd-adjacent-nv']}" if profile is not None and profile[0] == 'word-offset-uniform' else ''

def upper_fragment(width):
    return f',upper-x{width}-nor=on'
