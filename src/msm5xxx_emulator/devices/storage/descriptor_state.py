"""Restore a previously saved NOR extent without modifying the state file."""
from .nor import NORFlash


def load_truncated_nor_state(image, original_size, profile, path):
    if not isinstance(image, bytes) or not 0 < len(image) <= original_size:
        return None
    seed = image.ljust(original_size, b'\xff')
    imported = path.is_file()
    loaded = bytes(NORFlash(seed, path).data) if imported else seed
    if not isinstance(profile, tuple) or len(profile) != 5 or type(profile[0]) is not int:
        return None
    if not 0 < profile[0] <= min(len(image), len(loaded)):
        return None
    return (loaded, imported) if image[:profile[0]] == loaded[:profile[0]] else None
