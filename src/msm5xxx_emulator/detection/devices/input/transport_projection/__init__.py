"""Source-qualified machine properties owned by this device domain."""
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.detection.devices.input.distributed7 import find_seven_row_input_profile
from msm5xxx_emulator.detection.devices.input.seven_row import find_seven_row_scanners
from msm5xxx_emulator.detection.devices.input.boot_keysense import find_boot_keysense_release
from msm5xxx_emulator.detection.devices.input.halfword_status import resolve_indirect_board_status
from msm5xxx_emulator.detection.devices.input.descriptor import _descriptor_mmio_provenance
from msm5xxx_emulator.detection.devices.input.lg_kp import find_kp_legacy_scanner
from msm5xxx_emulator.detection.devices.input.lg_kp2600 import find_kp2600_scanner
from msm5xxx_emulator.detection.devices.input.sv130 import sv130_keypad_source
from msm5xxx_emulator.detection.devices.input.sd810 import sd810_gpio_board_status_profile
from msm5xxx_emulator.detection.devices.input.matrix import ASCII_KEY_EVENTS, _samsung_sideband_51_family_metadata
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.arm import _thumb_path_preserves_register, thumb_bl_target, thumb_literal_value
from msm5xxx_emulator.detection.contracts import boot_storage_profile as _boot_storage_profile
from msm5xxx_emulator.detection.contracts import source_class_limit as _source_class_limit
from .matrix import (HOST_INPUT, qemu_legacy_keypad_status_available, qemu_legacy_keypad_source_matches, matrix_senses, qemu_kp2600_matrix_property,
    qemu_kp2600_irq_compatible, qemu_sd810_sxs_menu_selection, qemu_low5_matrix_property, qemu_sd840_low5_contacts, qemu_sd9210_low5_contacts,
    qemu_sd840_numeric_profile, qemu_kp_low5_property, qemu_kp2100_low5_property, qemu_kp2100_status_source, qemu_lg_matrix_irq_property, qemu_matching_lg_irq)
from .contacts import (qemu_sd840_status_source, qemu_low5_rex_c80_property, qemu_sv130_initial_ram_seed, qemu_mapped_scan_gate_property,
    qemu_halfword_matrix_property, qemu_distributed_sideband_producer, qemu_distributed_matrix_property, qemu_seven_row_matrix_property)
from .halfword import (qemu_halfword_status_property, qemu_boot_keysense_property, qemu_row734_property, matrix_input_command, sideband_input_command)
REQUIRES = {'eeprom_gpio_profile': ('eeprom', 'eeprom_gpio_profile'), 'qemu_board_revision_property': ('boot.transport_projection',
    'qemu_board_revision_property'), '_required_board_contact_matrix_status_matches': ('board_contact', 'matrix_status_matches'), 'qemu_ready_poll_property': ('ready_poll',
    'ready_poll_property'), '_rex_legacy_irq_route_metadata_valid': ('rex.route_metadata', 'legacy_irq_route_metadata_valid')}
