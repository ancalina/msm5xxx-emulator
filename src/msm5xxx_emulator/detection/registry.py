"""Lazy access to detector device-domain packages."""
from __future__ import annotations

from functools import lru_cache
from importlib import import_module
from pkgutil import iter_modules
from types import ModuleType


def device_domains() -> tuple[str, ...]:
    """List installed domain packages without importing their code."""
    from . import devices

    return tuple(sorted(
        item.name for item in iter_modules(devices.__path__)
        if item.ispkg and not item.name.startswith("_")
    ))


@lru_cache(maxsize=None)
def device_domain(name: str) -> ModuleType:
    """Import and cache one named device-domain package on first use."""
    if not isinstance(name, str) or name not in device_domains():
        raise KeyError(f"unknown device domain: {name!r}")
    return import_module(f"{__package__}.devices.{name}")
