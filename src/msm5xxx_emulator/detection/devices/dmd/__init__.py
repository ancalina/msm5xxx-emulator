"""DMD source recognition and machine-property binding."""
from .detector import download_signature_position, find_dmd5100_profile
from .projection import padding_sources_requested, qemu_property

from .dual import board_revision_property, find_dmd5000_profile, qemu_dual_property
from .completion import (DMD_DOWNLOAD_5500_LITERALS, DMD_DOWNLOAD_5500_SIZE,
                         detect_dmd_download_5500, qemu_5500_property)

__all__ = ["download_signature_position", "find_dmd5100_profile",
           "find_dmd5000_profile", "padding_sources_requested", "qemu_property",
           "qemu_dual_property", "detect_dmd_download_5500", "qemu_5500_property",
           "board_revision_property"]
