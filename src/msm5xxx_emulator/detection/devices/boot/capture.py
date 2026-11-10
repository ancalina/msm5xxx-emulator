"""Domain-owned boot captures over shared evidence."""

from .rules import BUSY_DELAY_SIGNATURE
from .rules import DELAY_SIGNATURE
from .rules import FAST_BOOT_SIGNATURE
def capture_timing(layout, direct_signature):
    fast_boot_address = direct_signature("fast_boot_address", FAST_BOOT_SIGNATURE)
    delay_address = direct_signature("delay_address", DELAY_SIGNATURE)
    busy_delay_address = direct_signature("busy_delay_address", BUSY_DELAY_SIGNATURE)
    return (fast_boot_address, delay_address, busy_delay_address,)

from .rules import CRC16_SIGNATURE
def capture_checksum(layout, drivers):
    crc16_address = drivers.runtime_signature("crc16_address", CRC16_SIGNATURE)
    return crc16_address

from .rules import MSM5500_REVISION_BLOCK
from .rules import MSM5500_REVISION_DIAGNOSTIC
from .rules import detect_msm5500_revision_f025
import struct
def capture_revision(layout, drivers):
    unresolved_msm_revision = (MSM5500_REVISION_DIAGNOSTIC.search(layout.primary_image) is not None and struct.pack("<I", MSM5500_REVISION_BLOCK) in layout.primary_image)
    revision_profile, revision_note = (detect_msm5500_revision_f025(layout.primary_image, drivers.mapped_runtime, drivers.mapped_file) if
        unresolved_msm_revision and layout.scan_chipset == "MSM5500" else (False, "chipset is not MSM5500"))
    if revision_profile:
        layout.detection_notes.append(revision_note)
    elif unresolved_msm_revision:
        layout.detection_notes.append(
            "MSM revision marker + 0x03000740 found; automatic register/value rejected "
            f"without closed consumer class ({revision_note})"
        )
    return revision_profile

from msm5xxx_emulator.detection.arm import arm_vector_score
DCC_LOADER_MARKERS = (b"DumpNow DCC Loader.", b"Compile flags:")

def classify_image(image, image_offset, requested_image_offset, detection_notes):
    vector_score = arm_vector_score(image)
    image_kind = "firmware" if vector_score >= 2 else "data/non-bootable"
    if all(marker in image for marker in DCC_LOADER_MARKERS):
        image_kind = "auxiliary/debug-loader"
        detection_notes.append("paired DumpNow DCC loader markers")
    elif image_kind != "firmware":
        detection_notes.append("no valid ARM exception vector table")
    elif image_offset and requested_image_offset is None:
        detection_notes.append(
            f"skipped 0x{image_offset:X}-byte dump header before ARM vectors"
        )
    return image_kind
