"""Create private working media for an admitted external NOR aperture."""
from pathlib import Path


def prepare_secondary_media(binding, temporary: Path, *, source_image=None):
    length = binding.raw_size
    if (type(length) is not int or not 0 < length <= 0x800000
            or length % 0x10000):
        raise ValueError('invalid external NOR working-media extent')
    offset = getattr(binding, 'source_offset', None)
    if offset is not None:
        source_size = getattr(binding, 'firmware_size', None)
        if (type(offset) is not int or offset < 0
                or not isinstance(source_image, bytes)
                or type(source_size) is not int or len(source_image) != source_size
                or offset + length > source_size):
            raise ValueError('invalid external NOR supplied-media range')
    working = temporary / 'secondary-array.raw'
    erased_sector = b'\xff' * 0x10000
    with working.open('xb') as target:
        if offset is None:
            for _ in range(length // len(erased_sector)):
                target.write(erased_sector)
        else:
            target.write(source_image[offset:offset + length])
    media_path = str(working).replace(',', ',,')
    # This disposable array has no persistent-state durability contract.
    return ('-drive', f'file={media_path},if=none,format=raw,'
            'id=msm5xxx-protected-nor-state,cache=unsafe')
