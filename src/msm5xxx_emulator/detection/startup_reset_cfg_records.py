"""Detailed reset-copy records for callers that close execution paths."""
from .startup_reset_cfg_copy import linked_thumb_cfg_word_copies


def linked_thumb_cfg_word_copy_records(facts, function, image, *, nor_end,
                                       ram_ranges):
    """Return loop proofs confined to the supplied disjoint RAM ranges."""
    return linked_thumb_cfg_word_copies(
        facts, function, image, nor_end=nor_end, detailed=True,
        ram_ranges=ram_ranges)
