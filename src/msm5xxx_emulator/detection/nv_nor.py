"""Registered static evidence rules for the two legacy NV NOR profiles."""
from __future__ import annotations

from dataclasses import dataclass

from .capabilities import (
    Capability, CapabilityPredicate, CapabilityRegistry, Evidence,
    ResourceClaim,
)
from .nv_nor_byte import ByteNORProof, find_byte_nv_nor_proof
from .nv_nor_word import WordNORProof, find_word_nv_nor_proof
from .storage import find_embedded_fujitsu_x16_nor


_ALTERNATIVE_GROUP = "NV-bank"
_NV_WINDOW = (0x00400000, 0x00600000)


@dataclass(frozen=True, slots=True)
class _SelectionInput:
    image: bytes
    config: object
    claimed: bool
    eligible: bool


def _eligible(image: bytes, config: object, claimed: bool) -> bool:
    if (claimed or type(getattr(config, "load_address", None)) is not int
            or config.load_address != 0
            or type(getattr(config, "flash_size", None)) is not int
            or config.flash_size != 0x400000 or len(image) > config.flash_size
            or type(getattr(config, "ram_base", None)) is not int
            or type(getattr(config, "ram_size", None)) is not int
            or config.ram_size <= 0
            or any(getattr(config, key, None) is not None for key in (
                "secondary_flash_address", "secondary_flash_write_address",
                "secondary_flash_image", "upper_flash_address", "nand_image",
                "native_nand_profile", "primary_flash_probe_address",
                "flash_id_address"))):
        return False
    return find_embedded_fujitsu_x16_nor(image, config.flash_size) is None


def _word_evidence(proof: WordNORProof) -> tuple[Evidence, ...]:
    descriptor = proof.descriptor
    source = descriptor.address
    callbacks = tuple((name, target.address, target.isa)
                      for name, target in descriptor.callbacks)
    commands = tuple(item.address for item in proof.probe_commands)
    commands += tuple(item.address for item in proof.erase_commands)
    copy = proof.vector_copy
    transfer = proof.transfer
    copy_sites = tuple(sorted({site for loop in transfer.copy_loops
                               for site in (loop.compare.address,
                                            *loop.back_edge)}))
    clear_sites = tuple(sorted({site for loop in transfer.clear_loops
                                for site in (loop.compare.address,
                                             *loop.back_edge)}))
    return (
        Evidence("nv-word-id", 0x225F0004, (source + 164,), "data"),
        Evidence("nv-word-geometry", (32, 0x10000, descriptor.physical_size,
                                       descriptor.logical_capacity),
                 (source + 4, source + 8, source + 176, source + 180), "data"),
        Evidence("nv-word-owner", (proof.state_address, proof.initializer.address,
                                   proof.wrapper.address, proof.probe.address,
                                   callbacks),
                 (proof.initializer.address, proof.wrapper.address,
                  proof.probe.address, source + 184, source + 188,
                  source + 192, source + 196),
                 "linkage"),
        Evidence("nv-word-command-path", tuple(commands), commands, "instruction"),
        Evidence("nv-word-copy-transfer",
                 (transfer.copied_source, transfer.copied_target,
                  transfer.cleared_target, transfer.copy_spans,
                  transfer.clear_spans,
                  (transfer.entry.address,
                   transfer.completion.address
                   if transfer.completion is not None else None)),
                 copy_sites + clear_sites, "instruction"),
        Evidence("nv-word-reset-prefix",
                 (proof.reset_prefix.reset_entry.address,
                  proof.reset_prefix.transfer_entry.address,
                  proof.reset_prefix.completion.address,
                  proof.reset_prefix.continuation_site.address
                  if proof.reset_prefix.continuation_site is not None else None,
                  proof.reset_prefix.continuation_target.address
                  if proof.reset_prefix.continuation_target is not None else None),
                 tuple(item for item in (
                     proof.reset_prefix.reset_entry.address,
                     proof.reset_prefix.transfer_entry.address,
                     proof.reset_prefix.completion.address,
                     proof.reset_prefix.continuation_site.address
                     if proof.reset_prefix.continuation_site is not None else None)
                       if item is not None), "linkage"),
        Evidence("nv-word-copy-pool",
                 (copy.table, copy.source, copy.target, proof.pool,
                  proof.pool_source, source + 164),
                 (copy.table, proof.pool, proof.pool_source, source + 164),
                 "data"),
    )


def _byte_evidence(proof: ByteNORProof) -> tuple[Evidence, ...]:
    source = proof.source_descriptor
    hardware = proof.hardware
    callbacks = tuple((name, target.address, target.isa)
                      for name, target in proof.callbacks)
    helpers = tuple((name, target.address) for name, target in hardware.helpers)
    row = proof.row
    consumer = proof.consumer
    helper_sites = tuple(target.address for _, target in hardware.helpers)
    command_sites = tuple(site.address for site in proof.command_sites)
    return (
        Evidence("nv-byte-id", 0x005F0004, (source + 164,), "data"),
        Evidence("nv-byte-geometry", (len(proof.sectors), proof.sectors,
                                       hardware.profile.capacity),
                 (source + 4, source + 8, source + 176, source + 180), "data"),
        Evidence("nv-byte-owner", (proof.state_address, proof.initializer.address,
                                   callbacks, helpers),
                 (proof.initializer.address, source + 184, source + 188,
                  source + 192, *helper_sites), "linkage"),
        Evidence("nv-byte-copy-consumer", (row.table, row.source, row.target,
                                           row.size, consumer.entry.address),
                 (row.table, consumer.entry.address, row.source), "instruction"),
        Evidence("nv-byte-command-path",
                 tuple((name, tuple((write.offset, write.value, write.width)
                                    for write in writes))
                       for name, writes in hardware.command_writes),
                 command_sites, "instruction"),
    )


def _capability(proof: WordNORProof | ByteNORProof,
                context: _SelectionInput) -> Capability:
    if isinstance(proof, WordNORProof):
        kind = "word-offset-uniform"
        base, size, sector, id0, id1, options = proof.profile
        properties = (
            ("amd-adjacent-nv", "on"),
            ("amd-x16-nor", f"{base:x}:{size:x}:{sector:x}:{id0:x}:{id1:x}:{options:x}"),
        )
        evidence = _word_evidence(proof)
        required = tuple(item.name for item in evidence)
    else:
        kind = "byte-offset-boot-sectors"
        base, size, id0, id1 = proof.profile
        flash_size = context.config.flash_size
        properties = (("fujitsu-x16-nor",
                       f"{flash_size:x}:{base:x}:{size:x}:{id0:x}:{id1:x}"),)
        evidence = _byte_evidence(proof)
        required = tuple(item.name for item in evidence)
    claim = ResourceClaim("address", "legacy-nv-nor-bank",
                          _NV_WINDOW[0], _NV_WINDOW[1],
                          address_space="physical")
    return Capability(
        name=f"legacy-nv-nor:{kind}",
        required_evidence=required, evidence=evidence,
        properties=properties, claims=(claim,),
        parameters=(("legacy-kind", kind), ("legacy-profile", proof.profile)),
    )


def _word_rule(context: _SelectionInput) -> Capability | None:
    if not context.eligible:
        return None
    config = context.config
    proof = find_word_nv_nor_proof(context.image, config.ram_base, config.ram_size)
    return None if proof is None else _capability(proof, context)


def _byte_rule(context: _SelectionInput) -> Capability | None:
    if not context.eligible:
        return None
    config = context.config
    proof = find_byte_nv_nor_proof(context.image, config.ram_base, config.ram_size)
    return None if proof is None else _capability(proof, context)


_NV_REGISTRY = CapabilityRegistry()
_NV_REGISTRY.register(CapabilityPredicate(
    "legacy-nv-word", (), _word_rule, alternative_group=_ALTERNATIVE_GROUP))
_NV_REGISTRY.register(CapabilityPredicate(
    "legacy-nv-byte", (), _byte_rule, alternative_group=_ALTERNATIVE_GROUP))


def select_legacy_nv_nor(image: bytes, config: object, *,
                         claimed: bool = False) -> Capability | None:
    """Select one uniquely owned, code-backed missing NV bank."""
    try:
        image = bytes(image)
    except (TypeError, ValueError):
        return None
    context = _SelectionInput(image, config, claimed,
                              _eligible(image, config, claimed))
    resolution = _NV_REGISTRY.resolve(context)
    if len(resolution.plan.capabilities) != 1:
        return None
    return resolution.plan.capabilities[0]


def legacy_nv_tuple(capability: Capability | None
                    ) -> tuple[str, tuple[int, ...]] | None:
    """Project a selected capability to the existing transport API tuple."""
    if capability is None:
        return None
    parameters = dict(capability.parameters)
    kind, profile = parameters.get("legacy-kind"), parameters.get("legacy-profile")
    if (kind not in ("word-offset-uniform", "byte-offset-boot-sectors")
            or not isinstance(profile, tuple)
            or any(type(value) is not int for value in profile)):
        return None
    return kind, profile
