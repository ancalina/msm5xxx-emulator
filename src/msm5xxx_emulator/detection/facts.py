"""Shared bounded analysis API; observations never select devices."""
from .fact_context import FirmwareFacts
from .fact_models import FunctionFacts, LiteralAccessCandidate, ScatterCandidate
from .fact_cache import fact_scope, with_fact_scope, bind_facts, source_prefix, facts_for
from .values import CodeAddress, SymbolicValue, UNKNOWN_VALUE, evaluate_value
