"""Compatibility import for legacy ``nor_flash`` users."""
from __future__ import annotations

import sys

from _compat import package_module


sys.modules[__name__] = package_module("devices.storage.nor")
