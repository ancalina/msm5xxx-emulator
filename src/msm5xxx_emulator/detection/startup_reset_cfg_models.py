"""Records for source-closed reset copy proofs."""
from __future__ import annotations

from dataclasses import dataclass

from .facts import CodeAddress


@dataclass(frozen=True)
class LinkedThumbWordCopy:
    source: int
    target: int
    written_size: int
    evidence: tuple[tuple[int, int], ...]
    loop_exit: CodeAddress
    function: object
