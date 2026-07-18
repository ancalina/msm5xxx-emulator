"""Load packaged modules from legacy source-checkout entry points."""
from __future__ import annotations

from importlib import import_module
from pathlib import Path
import sys


def package_module(name: str):
    source_root = Path(__file__).resolve().parent / "src"
    source_text = str(source_root)
    if source_text not in sys.path:
        sys.path.insert(0, source_text)
    return import_module(f"msm5xxx_emulator.{name}")
