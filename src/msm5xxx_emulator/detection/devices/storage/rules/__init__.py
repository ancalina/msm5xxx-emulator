"""Firmware storage-driver detection."""
import hashlib
import re
import struct
from msm5xxx_emulator.detection.arm import arm_vector_score, thumb_bl_target, thumb_literal_value
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.signatures import find_all
from msm5xxx_emulator.detection.storage_facts import (parse_sector_table, parse_x16_descriptor, printable_name_end, sector_regions, sector_tables_before,
    uniform_sector_size)
from .catalog import (FUJITSU_MB84VD2219X_IDS, FUJITSU_X16_BULK_WRITE_MAX_SIZE, PRIMARY_FSD_AMD_X16_WRITER_PREFIX, PRIMARY_FSD_AMD_X16_WRITER_SIZE,
    PRIMARY_FSD_AMD_X16_WRITER_CALLS, PRIMARY_FSD_AMD_X16_WRITER_HASH, ADJACENT_AMD_X16_WRITER_PREFIX, ADJACENT_AMD_X16_WRITER_SIZE,
    ADJACENT_AMD_X16_WRITER_CALLS, ADJACENT_AMD_X16_WRITER_HASH, ADJACENT_AMD_X16_RECORD_PREFIX, ADJACENT_AMD_X16_RECORD_MARKER, ADJACENT_AMD_X16_RECORD_LOG,
    RECORD_AMD_X16_WRITER_PREFIX, RECORD_AMD_X16_WRITER_SIZE, RECORD_AMD_X16_WRITER_CALLS, RECORD_AMD_X16_WRITER_HASH, RECORD_AMD_X16_ERASER_PREFIX,
    RECORD_AMD_X16_ERASER_SIZE, RECORD_AMD_X16_ERASER_CALLS, RECORD_AMD_X16_ERASER_HASH, RECORD_AMD_X16_MAPPER_PREFIX, RECORD_AMD_X16_MAPPER_SIZE,
    RECORD_AMD_X16_MAPPER_CALLS, RECORD_AMD_X16_MAPPER_HASH, RECORD_AMD_X16_ERASE_WRAPPER_PREFIX, RECORD_AMD_X16_ERASE_WRAPPER_SIZE,
    RECORD_AMD_X16_ERASE_WRAPPER_CALLS, RECORD_AMD_X16_ERASE_WRAPPER_HASH, RECORD_AMD_X16_COPY_WRAPPER_PREFIX, RECORD_AMD_X16_COPY_WRAPPER_SIZE,
    RECORD_AMD_X16_COPY_WRAPPER_CALLS, RECORD_AMD_X16_COPY_WRAPPER_HASH, RECORD_AMD_X16_INIT_PREFIX, RECORD_AMD_X16_INIT_SIZE, RECORD_AMD_X16_INIT_CALLS,
    RECORD_AMD_X16_INIT_HASH, RECORD_AMD_X16_ENUMERATOR_PREFIX, RECORD_AMD_X16_ENUMERATOR_SIZE, RECORD_AMD_X16_ENUMERATOR_HASH, RECORD_AMD_X16_PROFILE,
    CATALOG_AMD_X16_PROFILE, PRIMARY_FSD_AMD_X16_ID_ROUTINE, FUJITSU_X16_BULK_WRITE_HASHED_SHAPES, FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX,
    FUJITSU_X16_BULK_WRITE_LEGACY_CALLS, FUJITSU_X16_BULK_WRITE_LEGACY_HASH, PAGE, DIRECT_INTEL_X16_CALLER_PREFIX, DIRECT_AMD_X16_PROBE_SIGNATURE,
    DIRECT_AMD_X16_CALLER_PREFIX, MAPPED_PRIMARY_INTEL_X16_SIGNATURES, PRIMARY_STATIC_TABLE_COPY_PATTERN, FUJITSU_X16_BULK_WRITE_PATTERNS, FLASH_IDS_BY_SIZE,
    FS_DEVICE_LOOKUP_TAIL, FS_DEVICE_OUTER_RESET, FS_DEVICE_LOOKUP_PREFIX, find_fs_device_flash_id, flash_id_for_size, _primary_fsd_amd_x16_writer_at,
    find_primary_fsd_amd_x16_nor, _adjacent_amd_x16_writer_at, find_adjacent_amd_x16_nor, _record_amd_x16_shape_at)
from .amd import (seeded_amd_x16_nor_profile, find_record_amd_x16_nor, find_catalog_amd_x16_nor, direct_amd_x16_nor_profile, _direct_x16_descriptor_profile,
    direct_intel_x16_nor_profile, mapped_primary_intel_x16_nor_profile)
from .primary import (primary_probe_x16_nor_profile, qualcomm_efs_seed, fujitsu_x16_bulk_write_mode_at, fujitsu_x16_bulk_write_at, find_fujitsu_x16_bulk_write,
    find_adjacent_fujitsu_x16_nor)
from .fujitsu import find_embedded_fujitsu_x16_nor, find_compound_fujitsu_layout, fujitsu_x16_flash_ids
REQUIRES = {'DIRECT_INTEL_X16_PROBE_SIGNATURE': ('storage.boot_rules', 'DIRECT_INTEL_X16_PROBE_SIGNATURE'), 'FLASH_ID_SIGNATURE': ('storage.boot_rules',
    'FLASH_ID_SIGNATURE'), 'PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE': ('storage.boot_rules', 'PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE'),
    'PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE': ('storage.boot_rules', 'PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE'),
    'PRIMARY_FLASH_PROBE_SIGNATURE': ('storage.boot_rules', 'PRIMARY_FLASH_PROBE_SIGNATURE')}
