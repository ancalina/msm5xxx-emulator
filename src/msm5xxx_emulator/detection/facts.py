"""Shared bounded ARM/Thumb analysis API; observations never select devices."""
from __future__ import annotations

from .arm import thumb_bl_target as thumb_call_target
from .fact_context import FirmwareFacts
from .fact_models import (
    Literal, MemoryAccess, SymbolicAccess, Reference, ReachabilityFacts,
    LiteralAccessCandidate, BitTest, CallSiteFacts, BranchCondition,
    FunctionFacts, ScatterCandidate,
)
from .fact_cache import (
    _cache, _cache_lock, _scope_bindings, _scope_prefixes, _remember_context,
    fact_scope, with_fact_scope, bind_facts, source_prefix, facts_for,
)
from .values import (
    CodeAddress, SymbolicValue, UNKNOWN_VALUE, evaluate_value,
    _FLAG_N, _FLAG_Z, _FLAG_C, _FLAG_V, _FLAGS,
    _FLAG_ORIGIN_REGISTER, _FLAG_ORIGIN_MASK_REGISTER, _RECENT_POP_REGISTER,
    _ORIGIN_N, _ORIGIN_Z, _ORIGIN_C, _ORIGIN_V,
    _condition_flag_mask, _condition_holds, _contains_symbolic_load,
    _symbolic_cost, _symbolic_operation, _symbolic_load,
)
