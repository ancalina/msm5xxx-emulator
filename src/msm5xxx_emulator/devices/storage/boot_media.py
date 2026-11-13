"""Materialize private main/spare media and supplied bootstrap code."""
from pathlib import Path
import shutil


def prepare_boot_media(binding, firmware: Path, temporary: Path, *, source_image=None):
    if firmware.stat().st_size != binding.raw_size:
        raise ValueError('NAND source size changed after planning')
    working = temporary / 'bootstrap-nand.raw'
    if source_image is None:
        shutil.copyfile(firmware, working)
    else:
        if not isinstance(source_image, bytes) or len(source_image) != binding.raw_size:
            raise ValueError('NAND supplied media does not match planned size')
        working.write_bytes(source_image)
    if working.stat().st_size != binding.raw_size:
        raise ValueError('incomplete NAND working copy')
    with working.open('rb') as source:
        code = source.read(binding.high_code_size)
    if len(code) != binding.high_code_size:
        raise ValueError('incomplete NAND bootstrap code')
    high = temporary / 'bootstrap-high.raw'
    high.write_bytes(code)
    # QEMU's option parser represents a literal comma by doubling it.
    high_path = str(high).replace(',', ',,')
    media_path = str(working).replace(',', ',,')
    return (
        ('-device', f'loader,file={high_path},addr=0xffff0000,force-raw=on'),
        ('-drive', f'file={media_path},if=none,format=raw,'
                   'id=msm5xxx-bootstrap-nand,cache=writeback'),
    )
