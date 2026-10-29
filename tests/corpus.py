"""Private firmware corpus location; it never lives inside the repository."""
import os
from pathlib import Path

FIRMWARE_ROOT = Path(os.environ.get(
    "MSM5XXX_TEST_FIRMWARE_ROOT", Path(__file__).resolve().parents[2] / "firmwares"
)).expanduser()
