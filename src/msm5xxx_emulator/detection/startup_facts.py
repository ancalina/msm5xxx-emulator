"""Compatibility facade for shared startup copy and zero-table proofs."""
from __future__ import annotations

from .startup_driver import (
    _callbacks_share_state, _initializer_has_direct_caller, _state_initializer,
)
from .startup_models import (
    CopyConsumerProof, CopyLoopTransfer, OrderedCopyTransfer,
    ResetPrefixProof, StartupCopyRow, StartupProcedureProof,
    StartupSideEffectWrite, StartupStackWrite, VectorCopyRow,
)
from .startup_cfg import (
    _add_immediate, _definition_reaches, _dominates_iteration,
    _field_reaches_value, _increment_sites, _loop_iteration_cut,
    _loop_nodes, _loop_writes_are_safe, _memory_register, _move_zero,
    _pc_literal_load, _use_register, _zero_destination,
)
from .startup_procedure import (
    _close_startup_procedure, _prove_copy_consumer, prove_copy_consumer,
    prove_startup_copy_consumer, proven_startup_rows,
)
from .startup_loops import (
    _constant_register_value, _loop_condition, _loop_has_bound,
    _loop_has_evaluated_bound, _ordered_transfer_completion, _pointer_loop,
    _returns_to_link, _strict_loop_recurrence, _writes_register,
)
from .startup_transfer import (
    _close_ordered_transfer_writes, _compose_ordered_transfers,
    _loop_transfer, _stride_exit, prove_ordered_copy_transfer,
    prove_reset_prefix_completion,
)
from .startup_vectors import vector_copy_rows
