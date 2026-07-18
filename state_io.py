"""Compatibility import for legacy ``state_io`` users."""
from __future__ import annotations

import sys

from _compat import package_module


sys.modules[__name__] = package_module("state_io")
