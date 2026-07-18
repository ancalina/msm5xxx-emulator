#!/usr/bin/env python3
"""Compatibility wrapper for ``python condition_report.py``."""
from __future__ import annotations

import sys

from _compat import package_module


_module = package_module("tools.condition_report")
if __name__ == "__main__":
    raise SystemExit(_module.main())
sys.modules[__name__] = _module
