"""Scoped and bounded reuse of immutable image analysis contexts."""
from __future__ import annotations

from .image_view import ImageView

from .fact_context import FirmwareFacts
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from threading import RLock


_cache: OrderedDict[tuple[int, int, int], FirmwareFacts] = OrderedDict()
_cache_lock = RLock()
_scope_bindings: ContextVar[dict[tuple[int, int], tuple[bytes, FirmwareFacts]] | None] = ContextVar(
    'firmware_facts_scope_bindings', default=None)
_scope_prefixes: ContextVar[dict[tuple[int, int, int], tuple[bytes, bytes, FirmwareFacts | None]] | None] = ContextVar(
    'firmware_facts_scope_prefixes', default=None)


def _remember_context(facts: FirmwareFacts) -> None:
    with _cache_lock:
        key = next((key for key, value in _cache.items() if value is facts),
                   (id(facts.image), facts.base, id(facts.view)))
        _cache[key] = facts
        _cache.move_to_end(key)
        while len(_cache) > 4:
            _cache.popitem(last=False)


@contextmanager
def fact_scope():
    """Isolate evidence-view bindings for one detector/transport operation."""
    token = _scope_bindings.set(dict(_scope_bindings.get() or {}))
    prefix_token = _scope_prefixes.set(dict(_scope_prefixes.get() or {}))
    try:
        yield
    finally:
        for _, facts in (_scope_bindings.get() or {}).values():
            _remember_context(facts)
        _scope_prefixes.reset(prefix_token)
        _scope_bindings.reset(token)


def with_fact_scope(function):
    """Run a callable with an isolated scoped facts registry."""
    @wraps(function)
    def scoped(*args, **kwargs):
        with fact_scope():
            return function(*args, **kwargs)
    return scoped


def bind_facts(image: bytes, view: ImageView, base: int = 0) -> FirmwareFacts | None:
    """Bind one immutable source object to its normalized view in this scope.

    Mutable byte buffers are intentionally ignored because their identity does
    not guarantee that the bytes used by the analysis remain unchanged.
    """
    if type(image) is not bytes:
        return None
    bindings = _scope_bindings.get()
    if bindings is None:
        raise ValueError('bind_facts requires an active fact_scope')
    key = (id(image), int(base))
    existing = bindings.get(key)
    if existing is not None and existing[0] is image and existing[1].view == view:
        return existing[1]
    # A later loader read can reuse analysis only after exact byte and mapping
    # equality, including holes, banks, phases and source provenance.
    with _cache_lock:
        reusable = next(((key, facts) for key, facts in reversed(_cache.items())
                         if facts.base == base and facts.image == image
                         and facts.view == view), None)
        if reusable is not None:
            cached_key, facts = reusable
            _cache.move_to_end(cached_key)
        else:
            facts = FirmwareFacts(image, base=base, view=view)
    updated = dict(bindings)
    updated[key] = (image, facts)
    _scope_bindings.set(updated)
    return facts


def source_prefix(image: bytes, size: int) -> bytes:
    """Return an immutable prefix, retaining any active normalized view.

    Prefixes created inside a facts scope are identity-cached and, when the
    original image has a default-base binding, receive a clipped view with the
    same source segments, origin, phases, banks, and provenance.
    """
    if not isinstance(size, int) or size < 0:
        raise ValueError('prefix size must be a nonnegative integer')
    if type(image) is not bytes:
        return bytes(image[:size])
    if size >= len(image):
        return image

    bindings = _scope_bindings.get()
    prefix_cache = _scope_prefixes.get()
    bound = None
    if bindings is not None:
        candidate = bindings.get((id(image), 0))
        if candidate is not None and candidate[0] is image:
            bound = candidate[1]
    if prefix_cache is None:
        prefix_cache = {}
    key = (id(image), size, id(bound) if bound is not None else 0)
    cached = prefix_cache.get(key)
    if cached is not None and cached[0] is image:
        return cached[1]

    prefix = image[:size]
    prefix_facts = None
    if bound is not None and bindings is not None:
        prefix_view = bound.view.normalized(size=len(prefix), base=bound.base)
        prefix_facts = bind_facts(prefix, prefix_view, base=bound.base)
    if _scope_prefixes.get() is not None:
        updated = dict(_scope_prefixes.get() or {})
        updated[key] = (image, prefix, prefix_facts)
        _scope_prefixes.set(updated)
    return prefix


def facts_for(image: bytes, base: int = 0,
              view: ImageView | None = None) -> FirmwareFacts:
    """Identity cache avoids hashing large images at every primitive read."""
    if type(image) is bytes and view is None:
        bindings = _scope_bindings.get()
        if bindings is not None:
            bound = bindings.get((id(image), int(base)))
            if bound is not None and bound[0] is image:
                return bound[1]
    if type(image) is not bytes:
        return FirmwareFacts(bytes(image), base=base, view=view)
    with _cache_lock:
        key = (id(image), base, id(view) if view is not None else 0)
        if key not in _cache:
            _cache[key] = FirmwareFacts(image, base=base, view=view)
            while len(_cache) > 4:
                _cache.popitem(last=False)
        _cache.move_to_end(key)
        return _cache[key]
