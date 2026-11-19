"""Compose reset-installed code, bounded Thumb wrappers, and ARM copy proofs."""
from __future__ import annotations

from capstone import arm as a

from .facts import CodeAddress, facts_for
from .startup_aligned_copy import aligned_copy_evidence
from .startup_block_copy import (
    ResetLinkedBlockCopy,
    _call_registers,
    _copied_helper_entry,
)
from .startup_block_copy_safety import (
    _call_stack_effect,
    _path_preserves_copy,
    _stack_pointer_at_call,
)
from .startup_copy_wrapper import copy_wrapper_call
from .startup_entry import manual_interworking_entries, reset_vector_entry
from .startup_reset_cfg_records import linked_thumb_cfg_word_copy_records


_AUXILIARY_RAM = ((0x03800000, 0x03A00000),)


def _bounded_evidence(spans, flash_end):
    result = set()
    for address, size in spans:
        if (type(address) is not int or type(size) is not int or address < 0
                or size <= 0 or address + size > flash_end):
            return None
        result.add((address, size))
    return result


def _complete_function(facts, entry, stack_pointer):
    function = facts.function(
        entry, budget=2048,
        initial_registers={a.ARM_REG_SP: stack_pointer},
        symbolic_registers={})
    if (not function.complete or function.truncated or function.unresolved
            or not function.instructions):
        return None
    return function


def _function_source_spans(facts, function, flash_end):
    spans = set()
    for site in function.instructions:
        instruction = facts.decode(site)
        if instruction is None:
            return None
        spans.add((site.address, instruction.size))
    spans.update((literal.pool, 4) for literal in function.literals)
    return _bounded_evidence(spans, flash_end)


def reset_linked_wrapped_copies(image: bytes, ram_base: int,
                                ram_size: int, flash_size: int
                                ) -> tuple[ResetLinkedBlockCopy, ...]:
    """Return descriptor rows copied through a reset-installed helper.

    The reset route, auxiliary-code installer, Thumb argument-forwarding
    wrapper, veneer, and copied source body are all closed independently. This
    helper only accepts aligned payload copies no larger than one MiB, matching
    the wrapper's single-call path. Returned evidence contains ROM spans only;
    destination RAM ranges are checked but never emitted as source evidence.
    """
    if (type(image) is not bytes or type(ram_base) is not int
            or type(ram_size) is not int or type(flash_size) is not int
            or ram_base < 0 or ram_size <= 0 or flash_size <= 0):
        return ()
    ram_end = ram_base + ram_size
    flash_end = min(len(image), flash_size)
    if ram_end > 0x100000000 or flash_end <= 0:
        return ()
    configured_ram = (ram_base, ram_end)
    ranges = (configured_ram, *_AUXILIARY_RAM)
    if any(left[0] < right[1] and right[0] < left[1]
           for index, left in enumerate(ranges)
           for right in ranges[index + 1:]):
        return ()

    source_image = image[:flash_end]
    facts = facts_for(source_image)
    reset = reset_vector_entry(facts)
    if reset is None:
        return ()

    results = {}
    for reset_proof in manual_interworking_entries(facts, reset):
        if (reset_proof.target.isa != "thumb"
                or reset_proof.processor_mode != 0x13
                or not ram_base < reset_proof.stack_pointer <= ram_end):
            continue
        function = _complete_function(
            facts, reset_proof.target, reset_proof.stack_pointer)
        if function is None:
            continue
        route = _bounded_evidence(
            ((start, end - start)
             for start, end in reset_proof.source_spans), flash_end)
        function_spans = _function_source_spans(facts, function, flash_end)
        if route is None or function_spans is None:
            continue

        installers = linked_thumb_cfg_word_copy_records(
            facts, function, source_image, nor_end=flash_end,
            ram_ranges=ranges)
        for installer in installers:
            overlay_start, overlay_size = installer.target, installer.written_size
            if (installer.function is not function or overlay_size <= 0
                    or installer.source < 0
                    or installer.source + overlay_size > flash_end
                    or not any(start <= overlay_start
                               and overlay_start + overlay_size <= end
                               for start, end in _AUXILIARY_RAM)
                    or installer.loop_exit not in function.instructions):
                continue
            overlay_record = ResetLinkedBlockCopy(
                installer.source, overlay_start, overlay_size,
                installer.evidence, overlay_size)
            calls = sorted(
                ((site, target) for site, target in function.calls
                 if target.isa == "thumb"),
                key=lambda pair: pair[0].address)
            effects = {}
            accepted = {}
            for call_site, wrapper_target in calls:
                if not function.dominates(installer.loop_exit, call_site):
                    continue
                arguments = _call_registers(function, call_site)
                if arguments is None:
                    continue
                destination, source, size = arguments
                if (source < 0 or source & 3 or size <= 0 or size > 0x100000
                        or size & 3 or source + size > flash_end
                        or destination < ram_base
                        or destination + size > ram_end
                        or destination & 3):
                    continue
                call_sp = _stack_pointer_at_call(
                    facts, function, call_site, reset_proof.stack_pointer,
                    balanced_calls=tuple(effects))
                if call_sp is None:
                    continue
                wrapper = copy_wrapper_call(
                    source_image, wrapper_target.address, destination, source,
                    size, stack_pointer=call_sp)
                if (wrapper is None or wrapper.target.isa != "thumb"
                        or wrapper.stack_pointer != call_sp - wrapper.frame_bytes):
                    continue

                helper = _copied_helper_entry(
                    facts, function, wrapper.target, overlay_record)
                if helper is None:
                    continue
                helper_entry, veneer_spans = helper
                if (not isinstance(helper_entry, CodeAddress)
                        or not installer.source <= helper_entry.address
                        < installer.source + overlay_size):
                    continue
                verifier_entry = helper_entry.address | int(helper_entry.isa == "thumb")
                leaf = aligned_copy_evidence(
                    source_image, verifier_entry, source, destination, size,
                    code_start=installer.source, code_size=overlay_size,
                    stack_pointer=wrapper.stack_pointer)
                if leaf is None:
                    continue
                leaf_preserved = set(leaf.get("preserved_registers", ()))
                if (type(leaf.get("stack_frame_bytes")) is not int
                        or leaf["stack_frame_bytes"] < 0
                        or not (set(wrapper.required_preserved_registers)
                                | {a.ARM_REG_SP}) <= leaf_preserved):
                    continue
                frame_size = wrapper.frame_bytes + leaf["stack_frame_bytes"]
                spill = _call_stack_effect(
                    call_sp, ram_base, ram_end, overlay_start, overlay_size,
                    destination, size, frame_size)
                if spill is None:
                    continue
                spill_start, spill_size = spill
                if (spill_start < source + size
                        and source < spill_start + spill_size):
                    continue

                # The call writes the requested destination and its actual
                # nested stack frame; wrapper MMIO pulses are also explicit.
                effects[call_site] = (
                    (destination, size), spill, *wrapper.effects)
                accepted[call_site] = (
                    source, destination, size, wrapper, verifier_entry,
                    tuple(veneer_spans), leaf, spill)

            for call_site, details in accepted.items():
                if not _path_preserves_copy(
                        facts, function, installer.loop_exit, call_site,
                        overlay_start, overlay_size, effects):
                    continue
                (source, destination, size, wrapper, _helper_entry,
                 veneer_spans, leaf, _spill) = details
                evidence = (set(installer.evidence) | route | function_spans
                            | set(wrapper.evidence) | set(veneer_spans)
                            | set(leaf["code_spans"]))
                evidence.add((source, size))
                bounded = _bounded_evidence(evidence, flash_end)
                if bounded is None:
                    continue
                results[(source, destination, size)] = ResetLinkedBlockCopy(
                    source, destination, size, tuple(sorted(bounded)), size)
    return tuple(results[key] for key in sorted(results))
