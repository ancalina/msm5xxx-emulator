"""Compatibility import for legacy ``runtime_log`` users."""
from __future__ import annotations

import sys

from _compat import package_module


sys.modules[__name__] = package_module("diagnostics.runtime_log")
