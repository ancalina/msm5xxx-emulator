"""Lazy access to detector device-domain packages."""
from __future__ import annotations
from importlib import import_module
from pkgutil import iter_modules
from types import ModuleType
from threading import RLock
import sys

_modules = {}
_bound = set()
_lock = RLock()

def device_domains() -> tuple[str, ...]:
    """List installed domain packages without importing their code."""
    from . import devices
    return tuple(sorted(item.name for item in iter_modules(devices.__path__) if item.ispkg and not item.name.startswith("_")))

def device_domain(name: str) -> ModuleType:
    """Discover a domain rule and compose its declared evidence prerequisites.

    Requirements name other registered evidence providers, keeping imports
    one way from rules to shared facts. Resolution is lazy; cycles can refer
    to already loaded functions without running a predicate during discovery.
    """
    if (not isinstance(name, str) or name.split('.')[0] not in device_domains() or any(not part.isidentifier() for part in name.split('.'))):
        raise KeyError(f"unknown device domain: {name!r}")
    with _lock:
        if name not in _modules:
            module = import_module(f"{__package__}.devices.{name}")
            _modules[name] = module
        # A rule can import its own helpers. Compose their prerequisites too,
        # including helpers first loaded while another requirement is resolved.
        prefix = f"{__package__}.devices."
        pending = [module for key, module in tuple(sys.modules.items()) if key.startswith(prefix) and key not in _bound and not getattr(getattr(module,
            '__spec__', None), '_initializing', False)]
        for module in pending:
            _bound.add(module.__name__)
            try:
                for symbol, (provider, attribute) in getattr(module, 'REQUIRES', {}).items():
                    dependency = device_domain(provider)
                    setattr(module, symbol, dependency if attribute is None else getattr(dependency, attribute))
            except Exception:
                _bound.discard(module.__name__)
                raise
        return _modules[name]
