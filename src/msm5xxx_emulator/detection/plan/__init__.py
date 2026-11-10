"""Firmware detection pipeline and configuration assembly."""
from .captures import LayoutCapture, DriverCapture, ResourceCapture
from msm5xxx_emulator.core.config import FirmwareConfig
from msm5xxx_emulator.detection.firmware_image import load_firmware_image
from msm5xxx_emulator.detection.facts import bind_facts
from msm5xxx_emulator.detection.layout_queries import (find_arm_vector_offset, find_linker_layout, find_overlays, restore_sparse_nor_gap)
from .configuration import ADDRESS_SPACE, DISABLEABLE_ADDRESS_FIELDS, _apply_overrides, _scan_layout
from .layout import _scan_drivers, _scan_resources
from .drivers import _assemble_config, detect
from msm5xxx_emulator.detection.registry import device_domain

chipset_confidence = device_domain('identity.chipset').chipset_confidence
detect_chipset = device_domain('identity.chipset').detect_chipset
detect_model = device_domain('identity.model').detect_model
_embedded_model_scores = device_domain('identity.model').embedded_model_scores
_verified_embedded_model = device_domain('identity.model').verified_embedded_model
